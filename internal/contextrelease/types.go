// Package contextrelease persists signed approvals for bounded feature-v2
// canary observation. It cannot activate a production model or change policy.
package contextrelease

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reverse-artex/internal/actioncontext"
	"reverse-artex/internal/casememory"
	"reverse-artex/internal/contextadmission"
	"reverse-artex/internal/contextlearning"
	"reverse-artex/internal/contextshadow"
	"time"
)

var (
	ErrInvalid     = errors.New("invalid v2 canary release contract")
	ErrConflict    = errors.New("v2 canary release revision or nonce conflict")
	ErrUnavailable = errors.New("v2 canary release journal unavailable; preserve original")
	ErrLimit       = errors.New("v2 canary release capacity reached")
)

const MaxJournal = 32 << 20
const MaxRecord = 2 << 20
const MaxChanges = 128
const MaxPackages = 16
const stopReserve = 8192

//go:embed types.go policy.go store.go live.go profile.go
var sources embed.FS

func SourceSHA() string {
	v := []string{contextadmission.SourceSHA(), contextshadow.SourceSHA()}
	for _, name := range []string{"types.go", "policy.go", "store.go", "live.go", "profile.go"} {
		raw, _ := sources.ReadFile(name)
		s := sha256.Sum256(raw)
		v = append(v, name, hex.EncodeToString(s[:]))
	}
	return contextlearning.Digest(v)
}

type Approver struct {
	ID        string `json:"key_id"`
	Actor     string `json:"actor"`
	Role      string `json:"role"`
	PublicKey string `json:"public_key_base64"`
	Revoked   bool   `json:"revoked"`
}
type Policy struct {
	Schema             string     `json:"schema"`
	Tenant             string     `json:"tenant_id"`
	Revision           int        `json:"revision"`
	Enabled            bool       `json:"enabled"`
	Scope              string     `json:"scope"`
	AdmissionPolicySHA string     `json:"admission_policy_sha256"`
	SourceSHA          string     `json:"release_source_sha256"`
	Approvers          []Approver `json:"approvers"`
}

func DefaultPolicy(tenant, admission string, keys []Approver) Policy {
	return Policy{Schema: "case-context-canary-policy/2", Tenant: tenant, Revision: 1, Scope: "canary_observation/2", AdmissionPolicySHA: admission, SourceSHA: SourceSHA(), Approvers: keys}
}

type Config struct {
	Policy      Policy                   `json:"release_policy"`
	Admission   contextadmission.Policy  `json:"admission_policy"`
	Authorities casememory.LearningTrust `json:"authorities"`
	Context     actioncontext.Trust      `json:"context_trust"`
}
type Bundle struct {
	Capsule     contextlearning.Capsule      `json:"capsule"`
	Endorsement contextadmission.Endorsement `json:"endorsement"`
}

func BundleSHA(b Bundle) string { return contextlearning.Digest(b) }

type Baseline struct {
	SourceSHA string   `json:"source_snapshot_sha256"`
	Cases     []string `json:"case_ids"`
	Evidence  []string `json:"evidence_keys_sha256"`
}
type Request struct {
	Expected    int       `json:"expected_revision"`
	Previous    string    `json:"previous_release_sha256"`
	Action      string    `json:"action"`
	BundleSHA   string    `json:"bundle_sha256"`
	PolicySHA   string    `json:"release_policy_sha256"`
	BaselineSHA string    `json:"baseline_sha256"`
	Percent     int       `json:"candidate_percent"`
	Until       time.Time `json:"canary_until"`
	Nonce       string    `json:"nonce"`
	Reason      string    `json:"reason"`
}
type Approval struct {
	Schema    string    `json:"schema"`
	Tenant    string    `json:"tenant_id"`
	Request   Request   `json:"request"`
	KeyID     string    `json:"key_id"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Signature string    `json:"signature_base64"`
}

func SigningBytes(a Approval) []byte {
	a.Signature = ""
	raw, _ := json.Marshal(a)
	return append([]byte("reverse-artex/context-canary-release/2\n"), raw...)
}

type Change struct {
	Schema    string    `json:"schema"`
	Revision  int       `json:"revision"`
	Previous  string    `json:"previous_sha256"`
	SourceSHA string    `json:"release_source_sha256"`
	Tenant    string    `json:"tenant_id"`
	Action    string    `json:"action"`
	At        time.Time `json:"changed_at"`
	Reason    string    `json:"reason"`
	Config    *Config   `json:"config,omitempty"`
	Bundle    *Bundle   `json:"bundle,omitempty"`
	Baseline  *Baseline `json:"baseline,omitempty"`
	Approval  *Approval `json:"approval,omitempty"`
	SHA       string    `json:"change_sha256"`
}

func changeSHA(c Change) string { c.SHA = ""; return contextlearning.Digest(c) }

type Version struct {
	Revision     int       `json:"revision"`
	SHA          string    `json:"release_sha256"`
	Action       string    `json:"action"`
	CandidateSHA string    `json:"candidate_sha256"`
	BundleSHA    string    `json:"bundle_sha256"`
	Percent      int       `json:"candidate_percent"`
	Until        time.Time `json:"canary_until"`
	At           time.Time `json:"changed_at"`
	Reason       string    `json:"reason"`
}
type View struct {
	Tenant            string    `json:"tenant_id"`
	Revision          int       `json:"revision"`
	Head              string    `json:"head_sha256"`
	State             string    `json:"state"`
	Current           *Version  `json:"current,omitempty"`
	History           []Version `json:"history"`
	Blockers          []string  `json:"blockers"`
	DeploymentAllowed bool      `json:"deployment_allowed"`
}
type Advice struct {
	Schema                   string    `json:"schema"`
	Mode                     string    `json:"mode"`
	ReleaseSHA               string    `json:"release_sha256"`
	CandidateSHA             string    `json:"candidate_sha256"`
	ModelSHA                 string    `json:"model_sha256"`
	CaseID                   string    `json:"case_id"`
	CaseSHA                  string    `json:"case_sha256"`
	SourceSHA                string    `json:"source_snapshot_sha256"`
	AttemptSHA               string    `json:"attempt_sha256"`
	Branch                   string    `json:"branch"`
	Prediction               string    `json:"prediction"`
	Eligible                 bool      `json:"cohort_eligible"`
	Exclusion                string    `json:"exclusion_reason"`
	InferredAt               time.Time `json:"inferred_at"`
	ValidUntil               time.Time `json:"valid_until"`
	MandatoryReviewPreserved bool      `json:"mandatory_review_preserved"`
	PolicyMutations          int       `json:"policy_mutations"`
	DeploymentAllowed        bool      `json:"deployment_allowed"`
}
