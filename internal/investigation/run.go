package investigation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"
)

type message struct {
	Schema     string   `json:"schema"`
	Scope      Scope    `json:"scope"`
	Tool       string   `json:"tool"`
	Conclusion string   `json:"conclusion"`
	Refs       []string `json:"refs"`
	Query      *Query   `json:"query,omitempty"`
}
type Trace struct {
	Tool       string `json:"tool"`
	ResultSHA  string `json:"result_sha256"`
	RequestSHA string `json:"request_sha256,omitempty"`
}
type Report struct {
	Agent                  *AgentRun `json:"agent_run,omitempty"`
	PolicyHistoryAvailable bool      `json:"policy_history_available,omitempty"`
	PolicyBindingSHA       string    `json:"policy_binding_sha256,omitempty"`
	Schema                 string    `json:"schema"`
	Scope                  Scope     `json:"scope"`
	Outcome                string    `json:"outcome"`
	Completed              bool      `json:"completed"`
	PendingReview          bool      `json:"pending_review"`
	Refs                   []string  `json:"refs"`
	Trace                  []Trace   `json:"trace"`
	Usage                  Usage     `json:"shared_usage"`
	ObservationGaps        bool      `json:"observation_gaps"`
	Contested              bool      `json:"contested"`
	PartialRead            bool      `json:"partial_read,omitempty"`
	UnavailableTools       []string  `json:"unavailable_tools,omitempty"`
}
type provider interface {
	next(context.Context, Scope, []byte) ([]byte, error)
}

// Duplicate/null keys are rejected recursively before normal schema decoding.
func strict(data []byte, out any) error {
	return strictObject(data, 4096, out, "schema", "scope", "tool", "conclusion", "refs")
}
func strictObject(data []byte, max int, out any, required ...string) error {
	if len(data) > max {
		return errors.New("output limit")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	var visit func(int) error
	visit = func(depth int) error {
		if depth > 12 {
			return errors.New("nesting limit")
		}
		t, e := d.Token()
		if e != nil {
			return e
		}
		if t == nil {
			return errors.New("null field")
		}
		if x, ok := t.(json.Delim); ok {
			switch x {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					k, e := d.Token()
					if e != nil {
						return e
					}
					s, ok := k.(string)
					if !ok || seen[s] || s != strings.ToLower(s) {
						return errors.New("duplicate or aliased key")
					}
					seen[s] = true
					if e = visit(depth + 1); e != nil {
						return e
					}
				}
				_, e = d.Token()
				return e
			case '[':
				for d.More() {
					if e = visit(depth + 1); e != nil {
						return e
					}
				}
				_, e = d.Token()
				return e
			default:
				return errors.New("invalid delimiter")
			}
		}
		return nil
	}
	if err := visit(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("one value required")
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil {
		return errors.New("object required")
	}
	for _, k := range required {
		if _, ok := fields[k]; !ok {
			return errors.New("missing field")
		}
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	return d.Decode(out)
}

func RunFake(ctx context.Context, c *Case, b *Budget, scenario string) (Report, error) {
	if !validScenario(scenario) {
		return Report{}, errors.New("unknown fake scenario")
	}
	return run(ctx, c, b, &fake{scenario: scenario})
}
func validScenario(scenario string) bool {
	switch scenario {
	case "ok", "unknown", "malformed", "injection", "cross-tenant", "stale", "forged-ref", "early-final", "timeout", "refusal", "panic":
		return true
	default:
		return false
	}
}

type readFunc func(context.Context, Scope, string, *Query) ([]byte, []string, error)

func run(ctx context.Context, c *Case, b *Budget, p provider) (report Report, err error) {
	return runWithReader(ctx, c, b, p, func(_ context.Context, s Scope, t string, q *Query) ([]byte, []string, error) {
		if q != nil {
			return nil, nil, ErrToolQuery
		}
		return c.read(s, t)
	}, 200*time.Millisecond)
}
func runWithReader(ctx context.Context, c *Case, b *Budget, p provider, read readFunc, timeout time.Duration) (report Report, err error) {
	return runWithPreflight(ctx, c, b, p, read, timeout, false)
}
func runWithPreflight(ctx context.Context, c *Case, b *Budget, p provider, read readFunc, timeout time.Duration, preflight bool) (report Report, err error) {
	if c == nil || c.scope.Commit == "" || b == nil || p == nil {
		return report, errors.New("verified case, shared budget and provider required")
	}
	report = Report{Schema: "offline-investigation/1", Scope: c.scope, Outcome: "pending_review", PendingReview: true, Refs: []string{}, Trace: []Trace{}, ObservationGaps: c.gaps, Contested: c.contested}
	defer func() {
		if recover() != nil {
			report.Completed = false
			report.Outcome = "provider_failure"
			report.Refs = []string{}
			err = nil
		}
		report.Usage = b.Usage()
	}()
	if !b.enter(c.scope) {
		report.Outcome = "capacity"
		return report, nil
	}
	defer b.leave(c.scope)
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	seen := map[string]bool{}
	var input []byte
	reserve := b.reserve
	if preflight {
		reserve = b.reserveAgent
	}
	if preflight {
		if reserve(c.scope, true) != nil {
			report.Outcome = "budget"
			return report, nil
		}
		r := c.DefaultRequest("get_case")
		view, _, e := read(ctx, r.Scope, r.Tool, &r.Query)
		if e != nil {
			report.Outcome = "tool_refused"
			return report, nil
		}
		input = view
		report.Trace = append(report.Trace, Trace{Tool: r.Tool, ResultSHA: hash(json.RawMessage(view)), RequestSHA: hash(r)})
		var page ToolResponse
		if json.Unmarshal(view, &page) == nil {
			report.PartialRead = page.NextOffset >= 0
		}
	}
	for step := 0; step < 4; step++ {
		if ctx.Err() != nil {
			report.Outcome = "cancelled"
			return report, nil
		}
		if reserve(c.scope, false) != nil {
			report.Outcome = "budget"
			return report, nil
		}
		// The reader validates every model-selected query; hosted handoff is
		// separately enabled and bounded by this same context and step ceiling.
		raw, e := p.next(ctx, c.scope, append([]byte(nil), input...))
		if ctx.Err() != nil {
			report.Outcome = "cancelled"
			return report, nil
		}
		if e != nil {
			report.Outcome = "provider_failure"
			return report, nil
		}
		var m message
		if strict(raw, &m) != nil || m.Schema != "investigation-step/1" || m.Scope != c.scope || m.Refs == nil {
			report.Outcome = "invalid_output"
			return report, nil
		}
		if m.Tool != "" {
			if m.Conclusion != "" || len(m.Refs) != 0 {
				report.Outcome = "invalid_output"
				return report, nil
			}
			if reserve(c.scope, true) != nil {
				report.Outcome = "budget"
				return report, nil
			}
			view, refs, e := read(ctx, m.Scope, m.Tool, m.Query)
			if e != nil {
				report.Outcome = "tool_refused"
				return report, nil
			}
			for _, r := range refs {
				seen[r] = true
			}
			input = view
			trace := Trace{Tool: m.Tool, ResultSHA: hash(json.RawMessage(view))}
			if m.Query != nil {
				trace.RequestSHA = hash(ToolRequest{m.Scope, m.Tool, *m.Query})
				var page ToolResponse
				if json.Unmarshal(view, &page) == nil {
					if m.Tool == "get_policy_history" && page.Available {
						report.PolicyHistoryAvailable = true
						report.PolicyBindingSHA = page.PolicyBindingSHA
					}
					report.PartialRead = report.PartialRead || page.NextOffset >= 0
					if !page.Available {
						found := false
						for _, tool := range report.UnavailableTools {
							found = found || tool == m.Tool
						}
						if !found {
							report.UnavailableTools = append(report.UnavailableTools, m.Tool)
						}
					}
				}
			}
			report.Trace = append(report.Trace, trace)
			continue
		}
		if m.Conclusion != "needs_review" && m.Conclusion != "insufficient" && m.Conclusion != "unknown" {
			report.Outcome = "invalid_output"
			return report, nil
		}
		if m.Query != nil {
			report.Outcome = "invalid_output"
			return report, nil
		}
		if len(m.Refs) > 16 || (m.Conclusion == "needs_review" && len(m.Refs) == 0) || len(report.Trace) == 0 {
			report.Outcome = "invalid_output"
			return report, nil
		}
		unique := map[string]bool{}
		for _, r := range m.Refs {
			if !seen[r] || unique[r] {
				report.Outcome = "invalid_output"
				return report, nil
			}
			unique[r] = true
		}
		report.Outcome = m.Conclusion
		report.Completed = true
		report.Refs = append(report.Refs, m.Refs...)
		return report, nil
	}
	report.Outcome = "step_limit"
	return report, nil
}

type fake struct {
	scenario string
	step     int
	refs     []string
}

func (f *fake) next(ctx context.Context, s Scope, input []byte) ([]byte, error) {
	if f.scenario == "timeout" {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if f.scenario == "panic" {
		panic("fake panic")
	}
	if f.scenario == "refusal" {
		return nil, errors.New("refused")
	}
	m := message{Schema: "investigation-step/1", Scope: s, Refs: []string{}}
	if f.scenario == "malformed" {
		return []byte("{"), nil
	}
	if f.scenario == "injection" {
		m.Tool = "shell"
		return json.Marshal(m)
	}
	if f.scenario == "cross-tenant" {
		m.Scope.Tenant = "other"
	}
	if f.scenario == "stale" {
		m.Scope.Revision++
	}
	switch f.step {
	case 0:
		m.Tool = "get_case"
	case 1:
		m.Tool = "query_events"
	case 2:
		var view toolView
		if json.Unmarshal(input, &view) == nil {
			for _, v := range view.Facts {
				f.refs = append(f.refs, v.Ref)
			}
		}
		m.Tool = "get_sensor_health"
	default:
		m.Conclusion = "needs_review"
		m.Refs = append(m.Refs, f.refs...)
		if len(m.Refs) > 16 {
			m.Refs = m.Refs[:16]
		}
	}
	if f.scenario == "unknown" && f.step == 3 {
		m.Conclusion = "unknown"
	}
	if f.scenario == "forged-ref" && f.step == 3 {
		m.Refs = []string{"unseen"}
	}
	if f.scenario == "early-final" {
		m.Tool = ""
		m.Conclusion = "needs_review"
		m.Refs = []string{"unseen"}
	}
	f.step++
	return json.Marshal(m)
}
