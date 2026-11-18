package responsev2

import (
	"encoding/json"
	"net"
	"net/url"
	"reverse-artex/internal/decisions"
	"reverse-artex/internal/localassistant"
	"strings"
	"time"
	"unicode/utf8"
)

type L3Config struct {
	Enabled            bool   `json:"enabled"`
	Origin             string `json:"origin"`
	Model              string `json:"model"`
	Digest             string `json:"model_sha256"`
	AllowContain       bool   `json:"allow_containment"`
	DailyRuns          int    `json:"daily_runs"`
	BundleContext      bool   `json:"bundled_context,omitempty"`
	Prefetch           bool   `json:"prefetch_observations,omitempty"`
	ShortReferences    bool   `json:"short_references,omitempty"`
	GroundedAssessment bool   `json:"grounded_assessment,omitempty"`
	DiagnosticTimings  bool   `json:"diagnostic_timings,omitempty"`
	AdaptiveStrategy   bool   `json:"adaptive_strategy,omitempty"`
}

func (c L3Config) Validate() error {
	if !c.Enabled {
		return nil
	}
	if c.Prefetch && !c.BundleContext {
		return ErrStale
	}
	if c.AdaptiveStrategy && (!c.BundleContext || !c.Prefetch) {
		return ErrStale
	}
	if c.ShortReferences && (!c.BundleContext || !c.Prefetch) {
		return ErrStale
	}
	if c.GroundedAssessment && (!c.BundleContext || !c.Prefetch || !c.ShortReferences || c.AllowContain) {
		return ErrStale
	}
	u, err := url.Parse(c.Origin)
	if err != nil || u.Scheme != "http" || u.User != nil || u.Port() == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery || u.RawPath != "" {
		return ErrStale
	}
	ip := net.ParseIP(u.Hostname())
	if ip == nil || !ip.IsLoopback() {
		return ErrStale
	}
	if len(c.Model) < 1 || len(c.Model) > 128 || strings.HasSuffix(c.Model, ":cloud") || strings.HasSuffix(c.Model, "-cloud") || strings.IndexFunc(c.Model, func(r rune) bool { return r < 33 || r > 126 }) >= 0 || !decisions.ValidHash(c.Digest) || c.DailyRuns < 1 || c.DailyRuns > 128 {
		return ErrStale
	}
	return nil
}

type L3Request struct {
	ID        string `json:"run_id"`
	Tenant    string `json:"tenant"`
	CaseID    string `json:"case_id"`
	CaseSHA   string `json:"case_sha256"`
	Mode      string `json:"mode"`
	SourceRun string `json:"source_run_id,omitempty"`
}
type L3Step struct {
	Number    int       `json:"number"`
	Tool      string    `json:"tool"`
	ArgsSHA   string    `json:"arguments_sha256"`
	ResultSHA string    `json:"result_sha256,omitempty"`
	State     string    `json:"state"`
	At        time.Time `json:"at"`
	Executor  string    `json:"executor,omitempty"` // Empty is a model-selected tool; server reads are explicit.
}
type L3Assessment struct {
	Classification string   `json:"classification"`
	Summary        string   `json:"summary"`
	Evidence       []string `json:"evidence_ids"`
}

// L3ModelTiming measures the native host's provider boundary, including the
// provider transport. It is not a claim about time spent generating tokens.
// Optional receipts keep older runs readable without changing call budgets.
type L3ModelTiming struct {
	Number          int                          `json:"number"`
	Started         time.Time                    `json:"started_at"`
	CheckUS         int64                        `json:"provider_check_us"`
	NextUS          int64                        `json:"provider_next_us"`
	State           string                       `json:"state"`
	ErrorStage      string                       `json:"error_stage,omitempty"`
	ProviderFailure *localassistant.ServiceError `json:"provider_failure,omitempty"`
}
type L3Run struct {
	Schema          string           `json:"schema"`
	Request         L3Request        `json:"request"`
	Epoch           int              `json:"cancel_epoch"`
	ConfigSHA       string           `json:"config_sha256"`
	Status          string           `json:"status"`
	Started         time.Time        `json:"started_at"`
	Deadline        time.Time        `json:"deadline"`
	Ended           *time.Time       `json:"ended_at,omitempty"`
	ModelDigest     string           `json:"observed_model_digest,omitempty"`
	Calls           int              `json:"model_calls"`
	ModelTimings    []L3ModelTiming  `json:"model_timings,omitempty"`
	InputBytes      int              `json:"cumulative_input_bytes"`
	Steps           []L3Step         `json:"steps"`
	ActionIntent    string           `json:"action_intent,omitempty"`
	ActionCandidate string           `json:"action_candidate_id,omitempty"`
	Receipt         *Receipt         `json:"receipt,omitempty"`
	Binding         *PolicyBinding   `json:"owned_binding,omitempty"`
	Assessment      *L3Assessment    `json:"assessment,omitempty"`
	Cancelled       bool             `json:"cancel_requested"`
	CaseChanged     bool             `json:"case_changed_after_action"`
	Error           string           `json:"error,omitempty"`
	ReferenceScheme string           `json:"reference_scheme,omitempty"`
	GroundingScheme string           `json:"grounding_scheme,omitempty"`
	Strategy        *DefenseStrategy `json:"strategy,omitempty"`
	RevisedStrategy *DefenseStrategy `json:"revised_strategy,omitempty"`
}
type PolicyBinding struct {
	PolicyID   string `json:"policy_id"`
	Episode    string `json:"episode_id"`
	Generation int    `json:"generation"`
	Scope      Scope  `json:"scope"`
}

func validRequestID(id string) bool {
	return len(id) > 0 && len(id) <= 96 && strings.IndexFunc(id, func(r rune) bool {
		return !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_')
	}) < 0
}
func validAssessment(a L3Assessment, refs map[string]bool) bool {
	if a.Classification != "suspicious" && a.Classification != "needs_review" && a.Classification != "benign" && a.Classification != "insufficient_evidence" {
		return false
	}
	if len(strings.TrimSpace(a.Summary)) == 0 || len(a.Summary) > 5600 || utf8.RuneCountInString(a.Summary) > 1400 || len(a.Evidence) < 1 || len(a.Evidence) > 32 {
		return false
	}
	seen := map[string]bool{}
	for _, id := range a.Evidence {
		if !refs[id] || seen[id] {
			return false
		}
		seen[id] = true
	}
	raw, err := json.Marshal(a)
	return err == nil && len(raw) <= 8192
}
