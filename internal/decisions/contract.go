// Package decisions defines an offline classification contract. It has no
// transport, credential, tool execution or policy mutation capability.
package decisions

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"regexp"
	"time"
)

const QuestionVersion = "decision-questions-v1"
const MaxWire = 4096
const strictJSONMaxDepth = 32

var ErrStale = errors.New("decision binding is stale or foreign")
var id = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

type Question struct {
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	Options []string `json:"options,omitempty"`
	Rubric  string   `json:"rubric"`
}

// Questions returns a fresh copy. Priority is an ordinal score, not a
// probability of compromise. Choices are review candidates, never commands.
func Questions() []Question {
	return []Question{
		{"disposition", "choice", []string{"benign", "suspicious", "needs_review", "insufficient_evidence"}, "Use insufficient_evidence for gaps; preserve conflicts for review."},
		{"priority", "score", nil, "0 routine; 1 noteworthy; 2 review; 3 urgent. Fractional scores allowed."},
		{"candidate_action", "choice", []string{"observe", "request_evidence", "request_review", "temporary_limit_candidate"}, "No execution authority; missing evidence and conflicts require review."},
	}
}
func Hash(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func QuestionHash() string { return Hash(QuestionDocument()) }
func ValidHash(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == 32 && hex.EncodeToString(b) == s
}

// DecodeStrict rejects duplicate keys at every depth, unknown fields, excess
// nesting, oversized input and concatenated JSON. No raw prompt/log field exists.
func DecodeStrict(raw []byte, out any, limit int) error {
	if len(raw) > limit {
		return errors.New("JSON byte limit")
	}
	return decodeStrictJSON(raw, out)
}

type Observation struct {
	From          time.Time `json:"from"`
	To            time.Time `json:"to"`
	Coverage      string    `json:"sensor_coverage"`
	Quality       string    `json:"data_quality"`
	Redacted      bool      `json:"redaction_applied"`
	Truncated     bool      `json:"truncated"`
	AttackSignals int       `json:"attack_signals"`
	BenignSignals int       `json:"benign_signals"`
}

func (o *Observation) UnmarshalJSON(raw []byte) error {
	type wire Observation
	var v wire
	if err := DecodeStrict(raw, &v, MaxWire); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err
	}
	for _, k := range []string{"from", "to", "sensor_coverage", "data_quality", "redaction_applied", "truncated", "attack_signals", "benign_signals"} {
		if len(fields[k]) == 0 || bytes.Equal(fields[k], []byte("null")) {
			return errors.New("explicit observation fields required")
		}
	}
	*o = Observation(v)
	return o.Validate()
}
func (o Observation) Validate() error {
	if o.From.IsZero() || o.To.IsZero() || o.From.After(o.To) || o.To.Sub(o.From) > 24*time.Hour || !o.Redacted ||
		(o.Coverage != "complete" && o.Coverage != "partial" && o.Coverage != "missing") ||
		(o.Quality != "complete" && o.Quality != "partial" && o.Quality != "contested") ||
		o.AttackSignals < 0 || o.AttackSignals > 32 || o.BenignSignals < 0 || o.BenignSignals > 32 {
		return errors.New("bounded redacted observation required")
	}
	return nil
}
func (o Observation) NeedsReview() bool {
	return o.Coverage != "complete" || o.Quality != "complete" || o.Truncated || o.AttackSignals > 0 || o.BenignSignals == 0
}

type Input struct {
	Schema      string      `json:"schema"`
	Epoch       int         `json:"config_epoch"`
	SnapshotSHA string      `json:"snapshot_sha256"`
	CaseID      string      `json:"case_id"`
	Revision    int         `json:"revision"`
	Tenant      string      `json:"tenant_id"`
	Asset       string      `json:"asset_id"`
	Commit      string      `json:"source_commit"`
	QuestionSHA string      `json:"question_set_sha256"`
	Enqueued    time.Time   `json:"enqueued_at"`
	Expires     time.Time   `json:"expires_at"`
	Observation Observation `json:"observation"`
}

func (i Input) Validate() error {
	if i.Schema != "decision-input/1" || i.Epoch < 1 || i.Revision < 1 || i.Revision > 1000000 || !id.MatchString(i.CaseID) || !id.MatchString(i.Tenant) || !id.MatchString(i.Asset) || !ValidHash(i.Commit) || !ValidHash(i.SnapshotSHA) || i.QuestionSHA != QuestionHash() {
		return errors.New("decision input binding invalid")
	}
	if i.Enqueued.IsZero() || !i.Expires.After(i.Enqueued) || i.Expires.Sub(i.Enqueued) > 5*time.Second {
		return errors.New("enqueue-based classification deadline required")
	}
	if raw, err := json.Marshal(i); err != nil || len(raw) > MaxWire {
		return errors.New("bounded classification input required")
	}
	return i.Observation.Validate()
}

type Answer struct {
	Name         string             `json:"name"`
	Type         string             `json:"type"`
	Choice       *string            `json:"choice,omitempty"`
	Score        *float64           `json:"score,omitempty"`
	Distribution map[string]float64 `json:"distribution,omitempty"`
}
type Usage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}
type Provider struct {
	Name     string `json:"name"`
	Endpoint string `json:"endpoint"`
	Model    string `json:"model"`
	Revision string `json:"revision"`
}
type Result struct {
	Schema      string    `json:"schema"`
	ID          string    `json:"decision_id"`
	InputSHA    string    `json:"input_sha256"`
	Epoch       int       `json:"config_epoch"`
	QuestionSHA string    `json:"question_set_sha256"`
	Status      string    `json:"status"`
	Provider    Provider  `json:"provider"`
	Answers     []Answer  `json:"answers"`
	Started     time.Time `json:"started_at"`
	Completed   time.Time `json:"completed_at"`
	Usage       *Usage    `json:"usage"`
}

func (r Result) Validate(input Input) error {
	if err := input.Validate(); err != nil {
		return err
	}
	if r.InputSHA != Hash(input) || r.Epoch != input.Epoch || r.QuestionSHA != QuestionHash() {
		return ErrStale
	}
	if r.Schema != "decision-result/1" || !ValidHash(r.ID) || r.Started.IsZero() || r.Completed.Before(r.Started) || r.Completed.Sub(r.Started) > 3*time.Second ||
		r.Provider.Name != "local-fake" || r.Provider.Endpoint != "none" || r.Provider.Model != "scripted-classifier-v1" || r.Provider.Revision != "1" {
		return errors.New("offline decision result metadata invalid")
	}
	if r.Started.Before(input.Enqueued) || r.Completed.After(input.Expires) {
		return ErrStale
	}
	if r.Usage != nil {
		return errors.New("scripted provider has no real model usage")
	}
	switch r.Status {
	case "ok":
	case "refused", "timeout", "rate_limited", "invalid", "stale", "error":
		if len(r.Answers) != 0 {
			return errors.New("failed decision cannot contain answers")
		}
		return nil
	default:
		return errors.New("unknown decision status")
	}
	if len(r.Answers) != 3 {
		return errors.New("exactly three question answers required")
	}
	seen := map[string]bool{}
	questions := map[string]Question{}
	for _, q := range Questions() {
		questions[q.Name] = q
	}
	for _, a := range r.Answers {
		q, ok := questions[a.Name]
		if !ok || seen[a.Name] || a.Type != q.Type {
			return errors.New("question name/type invalid or duplicate")
		}
		seen[a.Name] = true
		if a.Type == "score" {
			if a.Score == nil || a.Choice != nil || len(a.Distribution) != 0 || math.IsNaN(*a.Score) || math.IsInf(*a.Score, 0) || *a.Score < 0 || *a.Score > 3 {
				return errors.New("ordinal score outside 0..3")
			}
			continue
		}
		if a.Choice == nil || a.Score != nil || len(a.Distribution) != len(q.Options) {
			return errors.New("choice distribution required")
		}
		total, selected := 0.0, false
		for _, option := range q.Options {
			p, exists := a.Distribution[option]
			if !exists || math.IsNaN(p) || math.IsInf(p, 0) || p < 0 || p > 1 {
				return errors.New("invalid probability distribution")
			}
			total += p
			selected = selected || option == *a.Choice
		}
		if !selected || math.Abs(total-1) > 1e-9 {
			return errors.New("unknown choice or distribution sum")
		}
	}
	return nil
}
func (r Result) Choice(name string) string {
	for _, a := range r.Answers {
		if a.Name == name && a.Choice != nil {
			return *a.Choice
		}
	}
	return ""
}
func (r Result) Priority() float64 {
	for _, a := range r.Answers {
		if a.Name == "priority" && a.Score != nil {
			return *a.Score
		}
	}
	return 0
}

// Fake uses declared counters, never labels or untrusted text. It is a transport
// and evaluation baseline, not a trained classifier or a Decisions API adapter.
func Fake(input Input, scenario string, now time.Time) (Result, error) {
	if err := input.Validate(); err != nil {
		return Result{}, err
	}
	r := Result{Schema: "decision-result/1", InputSHA: Hash(input), Epoch: input.Epoch, QuestionSHA: QuestionHash(), Status: "ok",
		Provider: Provider{"local-fake", "none", "scripted-classifier-v1", "1"}, Started: now, Completed: now, Answers: []Answer{}}
	r.ID = Hash([]string{r.InputSHA, scenario, now.Format(time.RFC3339Nano)})
	switch scenario {
	case "refused", "timeout", "rate_limited", "invalid", "stale", "error":
		r.Status = scenario
		return r, nil
	case "ok", "benign", "continue":
	default:
		return Result{}, errors.New("unknown scripted decision scenario")
	}
	disposition, action, priority := "benign", "observe", 0.0
	o := input.Observation
	if o.AttackSignals > 0 {
		disposition, action, priority = "suspicious", "request_review", 3
	}
	if o.Quality == "contested" || (o.AttackSignals > 0 && o.BenignSignals > 0) {
		disposition, action, priority = "needs_review", "request_review", 2
	}
	if o.Coverage != "complete" || o.Quality == "partial" || o.Truncated || scenario == "continue" {
		disposition, action, priority = "insufficient_evidence", "request_evidence", 2
	}
	if o.AttackSignals == 0 && o.BenignSignals == 0 {
		disposition, action, priority = "insufficient_evidence", "request_evidence", 2
	}
	if scenario == "benign" {
		disposition, action, priority = "benign", "observe", 0
	}
	for _, q := range Questions() {
		a := Answer{Name: q.Name, Type: q.Type}
		if q.Type == "score" {
			a.Score = &priority
		} else {
			choice := disposition
			if q.Name == "candidate_action" {
				choice = action
			}
			a.Choice = &choice
			a.Distribution = map[string]float64{}
			for _, option := range q.Options {
				a.Distribution[option] = 0
			}
			a.Distribution[choice] = 1
		}
		r.Answers = append(r.Answers, a)
	}
	return r, r.Validate(input)
}
