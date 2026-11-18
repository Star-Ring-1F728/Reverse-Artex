package casefile

import (
	"encoding/json"
	"errors"
	"io"
	"reverse-artex/internal/hostguard"
	"time"
)

const MaxHypotheses = 16
const MaxRevisions = 64

// ContextBundle extends a version-1 HTTP fixture without changing its wire
// format or hashes. Enrichment and asset context are local fixture declarations.
type ContextBundle struct {
	Schema     string         `json:"schema_version"`
	HTTP       Bundle         `json:"http"`
	Previous   string         `json:"previous_revision_sha256"`
	Assets     []AssetContext `json:"asset_context"`
	Sensors    []HostSensor   `json:"host_sensors"`
	Records    []HostRecord   `json:"host_records"`
	Hypotheses []Hypothesis   `json:"hypotheses"`
}
type AssetContext struct {
	Asset       string `json:"asset_id"`
	Criticality string `json:"criticality"`
	Owner       string `json:"service_owner_id"`
}
type HostSensor struct {
	ID               string `json:"sensor_id"`
	Tenant           string `json:"tenant_id"`
	Asset            string `json:"asset_id"`
	Service          string `json:"service_id"`
	Workload         string `json:"workload_id"`
	Status           string `json:"status"`
	RequestNamespace string `json:"request_namespace"`
	ProcessAuthority *bool  `json:"process_authority"`
	RequestAuthority *bool  `json:"request_authority"`
}

// A zero identity is explicitly unknown. A partial identity is invalid.
// This sidecar is hash-bound to the reference but is not native /proc proof.
type ProcessIdentity struct {
	BootID       string `json:"boot_id"`
	PIDNamespace string `json:"pid_namespace"`
	Container    string `json:"container_id"`
	PID          int64  `json:"pid"`
	StartTicks   int64  `json:"start_ticks"`
}
type HostRecord struct {
	Line    string          `json:"line"`
	LineSHA string          `json:"line_sha256"`
	Process ProcessIdentity `json:"process_identity"`
}
type HostEvidence struct {
	ID             string          `json:"ref_id"`
	Stream         string          `json:"stream"`
	Tenant         string          `json:"tenant_id"`
	Asset          string          `json:"asset_id"`
	Sensor         string          `json:"sensor_id"`
	EventID        string          `json:"event_id"`
	LineSHA        string          `json:"line_sha256"`
	BindingSHA     string          `json:"binding_sha256"`
	Time           time.Time       `json:"event_time"`
	IngestTime     time.Time       `json:"ingest_time"`
	Type           string          `json:"event_type"`
	Classification string          `json:"classification"`
	Service        string          `json:"service_id"`
	Workload       string          `json:"workload_id"`
	ProcessKey     string          `json:"process_key"`
	ParentKey      string          `json:"parent_key"`
	Lineage        string          `json:"lineage"`
	RequestID      string          `json:"request_id"`
	Quality        string          `json:"data_quality"`
	Process        ProcessIdentity `json:"process_identity"`
	IdentityBasis  string          `json:"identity_basis"`
}
type HostCoverage struct {
	Sensor  HostSensor `json:"registration"`
	Status  string     `json:"coverage_status"`
	Records int        `json:"unique_records"`
}
type ProcessGroup struct {
	ID    string   `json:"group_id"`
	Asset string   `json:"asset_id"`
	Refs  []string `json:"evidence_refs"`
}
type Hypothesis struct {
	ID            string   `json:"hypothesis_id"`
	Asset         string   `json:"asset_id"`
	Code          string   `json:"code"`
	Supporting    []string `json:"supporting_refs"`
	Contradicting []string `json:"contradicting_refs"`
}
type Candidate struct {
	Hypothesis Hypothesis `json:"hypothesis"`
	Kind       string     `json:"kind"`
	Status     string     `json:"status"`
}
type ContextEnvelope struct {
	Schema     string         `json:"schema_version"`
	Scope      string         `json:"scope"`
	HTTP       Envelope       `json:"http"`
	Previous   string         `json:"previous_revision_sha256"`
	Assets     []AssetContext `json:"asset_context"`
	Evidence   []HostEvidence `json:"host_evidence"`
	Coverage   []HostCoverage `json:"host_coverage"`
	Processes  []ProcessGroup `json:"process_groups"`
	Assertions []Assertion    `json:"context_assertions"`
	Hypotheses []Candidate    `json:"hypotheses"`
	Quality    string         `json:"data_quality"`
}
type ContextDocument struct {
	Envelope ContextEnvelope `json:"envelope"`
	SHA256   string          `json:"envelope_sha256"`
}

func (p ProcessIdentity) validate() error {
	if p == (ProcessIdentity{}) {
		return nil
	}
	if !hostguard.ID.MatchString(p.BootID) || !hostguard.ID.MatchString(p.PIDNamespace) || !hostguard.ID.MatchString(p.Container) || p.PID < 1 || p.PID > 1<<30 || p.StartTicks < 1 || p.StartTicks > 1<<62 {
		return errors.New("complete scoped process identity or explicit unknown required")
	}
	return nil
}

func DecodeContext(r io.Reader) (ContextBundle, error) {
	var b ContextBundle
	err := decodeBounded(r, &b, MaxBundle)
	return b, err
}

func decodeBounded(r io.Reader, out any, limit int64) error {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return err
	}
	if int64(len(data)) > limit {
		return errors.New("bounded context document required")
	}
	if err = wire(data); err != nil {
		return err
	}
	return strictContext(data, out)
}

// Copying through JSON freezes nested slices and pointer-valued declarations.
func copyContext[T any](v T) T {
	data, _ := json.Marshal(v)
	var out T
	_ = json.Unmarshal(data, &out)
	return out
}
