package investigation

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

func ToolScenario(s string) bool {
	return validScenario(s) || s == "window" || s == "asset-context" || s == "policy-history"
}

// RunToolsFake keeps the existing four-step/three-read ceiling. All tool
// arguments are explicit, bounded and checked before an HTTP request.
func RunToolsFake(ctx context.Context, c *Case, b *Budget, a *APIClient, scenario string) (Report, error) {
	if c == nil || !ToolScenario(scenario) {
		return Report{}, errors.New("verified case and bounded tools scenario required")
	}
	p := &toolsFake{fake: fake{scenario: scenario}, source: c}
	read := func(ctx context.Context, s Scope, tool string, q *Query) ([]byte, []string, error) {
		if q == nil {
			return nil, nil, ErrToolQuery
		}
		r := ToolRequest{s, tool, *q}
		if a != nil {
			return a.ReadTool(ctx, c, r)
		}
		return c.ReadTool(r)
	}
	d := 200 * time.Millisecond
	if a != nil {
		d = 15 * time.Second
	}
	return runWithReader(ctx, c, b, p, read, d)
}

type toolsFake struct {
	fake
	source *Case
}

func (p *toolsFake) next(ctx context.Context, s Scope, input []byte) ([]byte, error) {
	raw, e := p.fake.next(ctx, s, input)
	if e != nil {
		return raw, e
	}
	var m message
	if json.Unmarshal(raw, &m) != nil {
		return raw, nil
	}
	if m.Tool == "get_sensor_health" {
		switch p.scenario {
		case "asset-context":
			m.Tool = "get_asset_context"
		case "policy-history":
			m.Tool = "get_policy_history"
		}
	}
	if m.Tool != "" {
		q := p.source.DefaultRequest(m.Tool).Query
		if m.Tool == "query_events" && p.scenario == "window" {
			q.Start, q.End = p.source.detail.window.End, p.source.detail.window.End
			q.Stream = "host-events"
			q.Limit = 1
		}
		m.Query = &q
	}
	if m.Tool == "" && p.scenario == "policy-history" {
		m.Conclusion = "unknown"
	}
	if m.Tool == "" && len(m.Refs) == 0 && p.scenario != "early-final" {
		m.Conclusion = "unknown"
	}
	return json.Marshal(m)
}
