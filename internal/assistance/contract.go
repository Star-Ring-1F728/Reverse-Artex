// Package assistance is a shadow coordinator. Default Open has no transport.
// Explicit constructors enable authenticated reads or hosted-agent handoff;
// none has a policy mutation capability.
package assistance

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"time"

	"reverse-artex/internal/decisions"
	"reverse-artex/internal/investigation"
)

const (
	MaxJobs       = 256
	MaxParents    = 128
	MaxQueue      = 100
	TenantQueue   = 25
	HighReserve   = 10
	MaxEpochs     = 64
	MaxSnapshot   = 4096
	MaxOutput     = 4096
	MaxState      = 2 << 20
	Decision      = "decisions"
	Investigation = "investigator"
)

var identifier = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

type FakeSpec struct {
	Kind     string `json:"kind"`
	Scenario string `json:"scenario"`
	DelayMS  int    `json:"delay_ms"`
}
type Module struct {
	Enabled  bool     `json:"enabled"`
	Behavior string   `json:"behavior"`
	Provider FakeSpec `json:"provider"`
}
type Config struct {
	Schema string `json:"schema_version"`
	Base   struct {
		Enabled bool `json:"enabled"`
	} `json:"base"`
	Assistance struct {
		Decisions    Module `json:"decisions"`
		Investigator Module `json:"investigator"`
	} `json:"assistance"`
	Response struct {
		ModelProposals string `json:"model_proposals"`
		PolicyProfile  string `json:"policy_profile"`
	} `json:"response"`
}

func DefaultConfig() Config {
	var c Config
	c.Schema = "defense-mode/1"
	c.Base.Enabled = true
	m := Module{Behavior: "shadow", Provider: FakeSpec{Kind: "fake", Scenario: "ok"}}
	c.Assistance.Decisions, c.Assistance.Investigator = m, m
	c.Response.ModelProposals, c.Response.PolicyProfile = "shadow", "baseline-v1"
	return c
}
func (c Config) Profile() string {
	if c.Assistance.Decisions.Enabled && c.Assistance.Investigator.Enabled {
		return "combined"
	}
	if c.Assistance.Decisions.Enabled {
		return "decisions"
	}
	if c.Assistance.Investigator.Enabled {
		return "agent"
	}
	return "base"
}
func (c Config) module(kind string) Module {
	if kind == Decision {
		return c.Assistance.Decisions
	}
	return c.Assistance.Investigator
}
func (c Config) Validate() error {
	if c.Schema != "defense-mode/1" || !c.Base.Enabled || c.Response.ModelProposals != "shadow" || c.Response.PolicyProfile != "baseline-v1" {
		return errors.New("only mandatory base, baseline-v1 and shadow proposals are supported")
	}
	for _, m := range []Module{c.Assistance.Decisions, c.Assistance.Investigator} {
		if m.Behavior != "shadow" || (m.Provider.Kind != "fake" && m.Provider.Kind != CaseAPI && m.Provider.Kind != CaseTools && m.Provider.Kind != HostedAgent) || m.Provider.DelayMS < 0 || m.Provider.DelayMS > 1000 {
			return errors.New("bounded shadow modules required")
		}
		if m.Provider.Kind == HostedAgent {
			if m.Provider.Scenario != "hosted" || m.Provider.DelayMS != 0 {
				return errors.New("explicit hosted agent handoff required")
			}
			continue
		}
		if m.Provider.Kind == CaseAPI {
			if !bridgeScenario(m.Provider.Scenario) {
				return errors.New("unknown case API fake scenario")
			}
			continue
		}
		if m.Provider.Kind == CaseTools {
			if !investigation.ToolScenario(m.Provider.Scenario) {
				return errors.New("unknown case tools fake scenario")
			}
			continue
		}
		switch m.Provider.Scenario {
		case "ok", "benign", "continue", "timeout", "refusal", "invalid", "panic", "unavailable", "rate_limited", "stale":
		default:
			return errors.New("unknown fake scenario")
		}
	}
	if c.Assistance.Decisions.Provider.Kind == CaseAPI || c.Assistance.Decisions.Provider.Kind == CaseTools || c.Assistance.Decisions.Provider.Kind == HostedAgent || ((c.Assistance.Investigator.Provider.Kind == CaseAPI || c.Assistance.Investigator.Provider.Kind == CaseTools || c.Assistance.Investigator.Provider.Kind == HostedAgent) && (c.Assistance.Decisions.Enabled || c.Assistance.Investigator.Provider.DelayMS != 0)) {
		return errors.New("case API bridge requires L3-only bounded mode")
	}
	return nil
}
func DecodeConfig(r io.Reader) (Config, error) {
	var c Config
	data, err := io.ReadAll(io.LimitReader(r, 4097))
	if err != nil {
		return c, err
	}
	if len(data) > 4096 {
		return c, errors.New("configuration too large")
	}
	var fields struct {
		Assistance map[string]json.RawMessage `json:"assistance"`
	}
	if err = json.Unmarshal(data, &fields); err != nil {
		return c, err
	}
	for _, kind := range []string{Decision, Investigation} {
		if err = requireFields(fields.Assistance[kind], "enabled"); err != nil {
			return c, err
		}
	}
	err = strict(data, &c)
	if err == nil {
		err = c.Validate()
	}
	return c, err
}
func requireFields(data []byte, names ...string) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	for _, name := range names {
		value, ok := fields[name]
		if !ok || bytes.Equal(value, []byte("null")) {
			return errors.New("explicit non-null contract field required")
		}
	}
	return nil
}
func strict(data []byte, out any) error {
	return decisions.DecodeStrict(data, out, MaxState)
}
func hash(v any) string {
	data, _ := json.Marshal(v)
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}
func hashRaw(data []byte) string { h := sha256.Sum256(data); return hex.EncodeToString(h[:]) }

// Snapshot contains references and routing metadata only: no raw requests,
// credentials, free-form instructions, or response bodies are accepted.
type Snapshot struct {
	Observation           *decisions.Observation `json:"decision_observation,omitempty"`
	AgentSpecSHA          string                 `json:"agent_spec_sha256,omitempty"`
	PolicyHistorySHA      string                 `json:"policy_history_sha256,omitempty"`
	SourceCommit          string                 `json:"source_commit,omitempty"`
	CaseID                string                 `json:"case_id"`
	Revision              int                    `json:"revision"`
	QuestionSet           string                 `json:"question_set"`
	Tenant                string                 `json:"tenant_id"`
	Asset                 string                 `json:"asset_id"`
	Evidence              []string               `json:"evidence_refs"`
	RequiresInvestigation bool                   `json:"requires_investigation"`
	HighRisk              bool                   `json:"high_risk"`
}

func (s Snapshot) Validate() error {
	if s.QuestionSet == decisions.QuestionVersion {
		if s.Observation == nil || s.Observation.Validate() != nil || !toolHash(s.SourceCommit) || (s.Observation.NeedsReview() && !s.RequiresInvestigation) {
			return errors.New("typed decision requires committed observation and mandatory review for gaps/conflicts")
		}
	} else if s.Observation != nil {
		return errors.New("decision observation requires versioned question set")
	}
	if s.AgentSpecSHA != "" && (s.QuestionSet != "case-agent-v1" || s.SourceCommit == "" || !toolHash(s.AgentSpecSHA)) {
		return errors.New("bound hosted agent specification required")
	}
	if s.QuestionSet == "case-agent-v1" && s.AgentSpecSHA == "" {
		return errors.New("hosted agent specification required")
	}
	if s.PolicyHistorySHA != "" && ((s.QuestionSet != "case-tools-v2" && s.QuestionSet != "case-agent-v1") || s.SourceCommit == "" || !toolHash(s.PolicyHistorySHA)) {
		return errors.New("bound policy snapshot required")
	}
	if s.QuestionSet == "case-tools-v2" && s.PolicyHistorySHA == "" {
		return errors.New("policy binding commitment required")
	}
	if s.SourceCommit != "" {
		if len(s.SourceCommit) != 64 {
			return errors.New("commit hash required")
		}
		if _, err := hex.DecodeString(s.SourceCommit); err != nil {
			return errors.New("commit hash required")
		}
	}
	for _, id := range []string{s.CaseID, s.QuestionSet, s.Tenant, s.Asset} {
		if !identifier.MatchString(id) {
			return errors.New("invalid snapshot identifier")
		}
	}
	if s.Revision < 1 || s.Revision > 1000000 || len(s.Evidence) < 1 || len(s.Evidence) > 16 || (s.HighRisk && !s.RequiresInvestigation) {
		return errors.New("invalid snapshot scope")
	}
	seen := map[string]bool{}
	for _, ref := range s.Evidence {
		if !identifier.MatchString(ref) || seen[ref] {
			return errors.New("invalid evidence reference")
		}
		seen[ref] = true
	}
	data, _ := json.Marshal(s)
	if len(data) > MaxSnapshot {
		return errors.New("snapshot too large")
	}
	return nil
}
func DecodeSnapshot(data []byte) (Snapshot, error) {
	var s Snapshot
	if len(data) > MaxSnapshot {
		return s, errors.New("snapshot too large")
	}
	if err := requireFields(data, "case_id", "revision", "question_set", "tenant_id", "asset_id", "evidence_refs", "requires_investigation", "high_risk"); err != nil {
		return s, err
	}
	err := strict(data, &s)
	if err == nil {
		err = s.Validate()
	}
	return s, err
}
func (s Snapshot) parent() string { return hash([]string{s.Tenant, s.Asset, s.CaseID}) }
func freezeSnapshot(s Snapshot) Snapshot {
	data, _ := json.Marshal(s)
	var out Snapshot
	_ = json.Unmarshal(data, &out)
	return out
}
func (s Snapshot) key(epoch int) string {
	return hash([]any{s.Tenant, s.Asset, s.CaseID, s.Revision, s.QuestionSet, epoch})
}

type Call struct {
	Snapshot Snapshot  `json:"snapshot"`
	Epoch    int       `json:"epoch"`
	Hash     string    `json:"snapshot_hash"`
	Enqueued time.Time `json:"enqueued_at"`
	Expires  time.Time `json:"expires_at"`
}
type Result struct {
	Classification   *decisions.Result       `json:"classification,omitempty"`
	Agent            *investigation.AgentRun `json:"agent_run,omitempty"`
	AgentDisposition string                  `json:"agent_disposition,omitempty"`
	Schema           string                  `json:"schema"`
	Kind             string                  `json:"kind"`
	Epoch            int                     `json:"epoch"`
	Hash             string                  `json:"snapshot_hash"`
	Conclusion       string                  `json:"conclusion"`
	Complete         bool                    `json:"complete"`
	Evidence         []string                `json:"evidence_refs"`
	Reads            *ReadSummary            `json:"reads,omitempty"`
}
type ReadSummary struct {
	PolicyBindingSHA       string                `json:"policy_binding_sha256,omitempty"`
	Trace                  []investigation.Trace `json:"trace"`
	ObservationGaps        bool                  `json:"observation_gaps"`
	Contested              bool                  `json:"contested"`
	Historical             bool                  `json:"historical_snapshot"`
	PolicyHistoryAvailable bool                  `json:"policy_history_available"`
	PartialRead            bool                  `json:"partial_read,omitempty"`
	UnavailableTools       []string              `json:"unavailable_tools,omitempty"`
}

func decodeResult(data []byte, kind string, call Call) (Result, error) {
	var r Result
	if len(data) > MaxOutput {
		return r, errors.New("provider output exceeds reservation")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return r, err
	}
	for _, k := range []string{"schema", "kind", "epoch", "snapshot_hash", "conclusion", "complete", "evidence_refs"} {
		v, ok := fields[k]
		if !ok || bytes.Equal(v, []byte("null")) {
			return r, errors.New("missing result field")
		}
	}
	if err := strict(data, &r); err != nil {
		return r, err
	}
	hosted := kind == Investigation && call.Snapshot.QuestionSet == "case-agent-v1" && call.Snapshot.AgentSpecSHA != ""
	tools := kind == Investigation && (call.Snapshot.QuestionSet == "case-tools-v1" || call.Snapshot.QuestionSet == "case-tools-v2" || hosted) && call.Snapshot.SourceCommit != ""
	if hosted {
		if r.Agent == nil || r.Agent.Validate(call.Snapshot.AgentSpecSHA) != nil || (r.AgentDisposition != "unknown" && r.AgentDisposition != "insufficient" && r.AgentDisposition != "needs_review") {
			return r, errors.New("hosted agent provenance required")
		}
	} else if r.Agent != nil || r.AgentDisposition != "" {
		return r, errors.New("unexpected hosted agent result")
	}
	if r.Reads != nil {
		maxTrace := 3
		if hosted {
			maxTrace = 4
		}
		if !tools || !r.Complete || r.Conclusion != "unknown" || !r.Reads.Historical || len(r.Reads.Trace) < 1 || len(r.Reads.Trace) > maxTrace {
			return r, errors.New("invalid tools read summary")
		}
		for _, x := range r.Reads.Trace {
			switch x.Tool {
			case "get_case", "query_events", "get_asset_context", "get_sensor_health", "get_policy_history":
			default:
				return r, errors.New("invalid tools read trace")
			}
			if !toolHash(x.RequestSHA) || !toolHash(x.ResultSHA) {
				return r, errors.New("invalid tools read hash")
			}
		}
		if len(r.Reads.UnavailableTools) > 1 || (len(r.Reads.UnavailableTools) == 1 && r.Reads.UnavailableTools[0] != "get_policy_history") {
			return r, errors.New("invalid unavailable tools")
		}
		policyRead := false
		for _, x := range r.Reads.Trace {
			policyRead = policyRead || x.Tool == "get_policy_history"
		}
		if r.Reads.PolicyHistoryAvailable {
			if (call.Snapshot.QuestionSet != "case-tools-v2" && !hosted) || !policyRead || !toolHash(r.Reads.PolicyBindingSHA) || r.Reads.PolicyBindingSHA != call.Snapshot.PolicyHistorySHA || len(r.Reads.UnavailableTools) != 0 {
				return r, errors.New("unbound policy read summary")
			}
		} else if r.Reads.PolicyBindingSHA != "" {
			return r, errors.New("unexpected policy read commitment")
		}
	}
	if tools && r.Reads == nil {
		return r, errors.New("tools read summary required")
	}
	emptyUnknown := tools && r.Reads != nil && r.Conclusion == "unknown"
	if r.Schema != "mock-assistance-result/1" || r.Kind != kind || r.Epoch != call.Epoch || r.Hash != call.Hash || (len(r.Evidence) < 1 && !emptyUnknown) || len(r.Evidence) > 16 {
		return r, errors.New("result scope mismatch")
	}
	if (kind == Decision && (r.Conclusion != "review" && r.Conclusion != "benign" && r.Conclusion != "unknown")) ||
		(kind == Investigation && (r.Conclusion != "supported" && r.Conclusion != "insufficient" && r.Conclusion != "unknown")) {
		return r, errors.New("unknown result conclusion")
	}
	allowed := map[string]bool{}
	for _, id := range call.Snapshot.Evidence {
		allowed[id] = true
	}
	seen := map[string]bool{}
	for _, id := range r.Evidence {
		if !allowed[id] || seen[id] {
			return r, errors.New("unbound result evidence")
		}
		seen[id] = true
	}
	if kind == Decision && call.Snapshot.QuestionSet == decisions.QuestionVersion {
		if r.Classification == nil {
			return r, errors.New("typed decision classification required")
		}
		if err := r.Classification.Validate(classificationInput(call)); err != nil {
			return r, err
		}
		if r.Classification.Status != "ok" || !r.Complete || r.Conclusion != classificationConclusion(*r.Classification) {
			return r, errors.New("typed and generic decision outcomes disagree")
		}
	} else if r.Classification != nil {
		return r, errors.New("unexpected typed classification")
	}
	return r, nil
}
func toolHash(s string) bool {
	if len(s) != 64 {
		return false
	}
	b, e := hex.DecodeString(s)
	return e == nil && hex.EncodeToString(b) == s
}

// Usage is a pre-call worst-case reservation, not a claim of actual model
// tokens, money or tool I/O. No charge is refunded on failure or cancellation.
type Usage struct {
	HostedRequests int `json:"reserved_hosted_agent_requests,omitempty"`
	Calls          int `json:"calls"`
	Decisions      int `json:"decisions"`
	Tools          int `json:"mock_tool_reads"`
	Tokens         int `json:"reserved_mock_tokens"`
	Cost           int `json:"reserved_mock_cost_units"`
	InputBytes     int `json:"input_bytes"`
	OutputBytes    int `json:"reserved_output_bytes"`
}

func (u Usage) add(v Usage) Usage {
	return Usage{HostedRequests: u.HostedRequests + v.HostedRequests, Calls: u.Calls + v.Calls, Decisions: u.Decisions + v.Decisions, Tools: u.Tools + v.Tools, Tokens: u.Tokens + v.Tokens, Cost: u.Cost + v.Cost, InputBytes: u.InputBytes + v.InputBytes, OutputBytes: u.OutputBytes + v.OutputBytes}
}
func charge(kind string, s Snapshot) Usage {
	b, _ := json.Marshal(s)
	u := Usage{Calls: 1, Tokens: 512, Cost: 100, InputBytes: len(b), OutputBytes: MaxOutput}
	if kind == Decision {
		u.Decisions = 1
		if s.QuestionSet == decisions.QuestionVersion {
			u.InputBytes = MaxSnapshot
		}
	} else {
		u.Tools = 2
	}
	return u
}
func parentAllows(u Usage) bool {
	return u.HostedRequests >= 0 && u.HostedRequests <= u.Calls && u.Calls <= 4 && u.Decisions <= 1 && u.Tools <= 8 && u.Tokens <= 2048 && u.Cost <= 400 && u.InputBytes <= 4*MaxSnapshot+u.HostedRequests*(investigation.MaxAgentPacket-MaxSnapshot) && u.OutputBytes <= 4*MaxOutput
}
func windowAllows(u Usage) bool {
	return u.HostedRequests >= 0 && u.HostedRequests <= u.Calls && u.Calls <= 120 && u.Tokens <= 61440 && u.Cost <= 12000 && u.InputBytes <= 120*MaxSnapshot+u.HostedRequests*(investigation.MaxAgentPacket-MaxSnapshot) && u.OutputBytes <= 120*MaxOutput
}

type Attempt struct {
	Kind    string    `json:"kind"`
	Started time.Time `json:"started"`
	Window  time.Time `json:"window"`
	Charge  Usage     `json:"charge"`
	Outcome string    `json:"outcome"`
	Late    bool      `json:"late_result_discarded"`
	Result  *Result   `json:"result,omitempty"`
}
type Job struct {
	ID            string    `json:"id"`
	Epoch         int       `json:"epoch"`
	Snapshot      Snapshot  `json:"snapshot"`
	Hash          string    `json:"snapshot_hash"`
	Enqueued      time.Time `json:"enqueued"`
	Deadline      time.Time `json:"deadline"`
	Phase         string    `json:"phase"`
	Outcome       string    `json:"outcome"`
	PendingReview bool      `json:"pending_review"`
	Attempts      []Attempt `json:"attempts"`
}

func pending(phase string) bool {
	return phase == "queued_decisions" || phase == "queued_investigator" || phase == "running_decisions" || phase == "running_investigator"
}

type Activation struct {
	Epoch  int    `json:"epoch"`
	Config Config `json:"config"`
	Actor  string `json:"actor"`
}
type Breaker struct {
	Failures int       `json:"failures"`
	Until    time.Time `json:"until"`
	Last     string    `json:"last"`
}
type Window struct {
	Start   time.Time        `json:"start"`
	Usage   Usage            `json:"usage"`
	Tenants map[string]Usage `json:"tenants"`
}
type Parent struct {
	Usage    Usage     `json:"usage"`
	Deadline time.Time `json:"deadline"`
}
type State struct {
	Schema      string             `json:"schema"`
	Epoch       int                `json:"epoch"`
	Config      Config             `json:"config"`
	Activations []Activation       `json:"activations"`
	Jobs        []Job              `json:"jobs"`
	Parents     map[string]Parent  `json:"parents"`
	Window      Window             `json:"window"`
	Breakers    map[string]Breaker `json:"breakers"`
}

func cloneState(s State) State {
	b, _ := json.Marshal(s)
	var next State
	_ = json.Unmarshal(b, &next)
	return next
}
