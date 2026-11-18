// Package contextactivation provides separately signed, full-coverage v2
// incident triage after a completed canary. It grants no policy authority.
package contextactivation

import (
	"embed"
	"encoding/json"
	"errors"
	"reverse-artex/internal/contextevaluation"
	"reverse-artex/internal/contextlearning"
	"reverse-artex/internal/contextrelease"
	"time"
)

var ErrInvalid = errors.New("invalid context production activation contract")
var ErrConflict = errors.New("context production activation revision or review changed")
var ErrUnavailable = errors.New("context activation unavailable; preserve journal and history")
var ErrLimit = errors.New("context activation capacity reached")

const MaxJournal = 32 << 20
const MaxRecord = 2 << 20
const MaxChanges = 64
const stopReserve = 8192

//go:embed types.go policy.go store.go profile.go live.go
var sources embed.FS

func SourceSHA() string {
	v := []string{contextevaluation.SourceSHA(), contextevaluation.ActivationAdapterSHA()}
	for _, name := range []string{"types.go", "policy.go", "store.go", "profile.go", "live.go"} {
		raw, _ := sources.ReadFile(name)
		v = append(v, name, contextlearning.Digest(string(raw)))
	}
	return contextlearning.Digest(v)
}

func clone[T any](v T) T { raw, _ := json.Marshal(v); var out T; json.Unmarshal(raw, &out); return out }

type Policy struct {
	Schema    string                    `json:"schema"`
	Tenant    string                    `json:"tenant_id"`
	Revision  int                       `json:"revision"`
	Enabled   bool                      `json:"enabled"`
	Scope     string                    `json:"scope"`
	SourceSHA string                    `json:"activation_source_sha256"`
	Approvers []contextrelease.Approver `json:"approvers"`
}

func DefaultPolicy(tenant string, keys []contextrelease.Approver) Policy {
	return Policy{Schema: "case-context-production-policy/2", Tenant: tenant, Revision: 1, Scope: "incident_triage_context/2", SourceSHA: SourceSHA(), Approvers: keys}
}

type Basis struct {
	Config  contextrelease.Config            `json:"canary_config"`
	Version contextrelease.EvaluationRelease `json:"canary_version"`
	Report  contextevaluation.Report         `json:"canary_report"`
}

func BasisSHA(b Basis) string {
	b = clone(b)
	b.Report.EvaluatedAt = time.Time{}
	b.Report.SHA = ""
	return contextlearning.Digest(b)
}

type Request struct {
	Expected     int       `json:"expected_revision"`
	Previous     string    `json:"previous_activation_sha256"`
	Action       string    `json:"action"`
	PolicySHA    string    `json:"activation_policy_sha256"`
	BasisSHA     string    `json:"review_basis_sha256"`
	ReviewSHA    string    `json:"current_review_sha256"`
	ReleaseSHA   string    `json:"canary_release_sha256"`
	CandidateSHA string    `json:"candidate_sha256"`
	PlanSHA      string    `json:"evaluation_plan_sha256"`
	Until        time.Time `json:"valid_until"`
	Nonce        string    `json:"nonce"`
	Reason       string    `json:"reason"`
}
type Approval struct {
	Schema            string    `json:"schema"`
	Tenant            string    `json:"tenant_id"`
	Request           Request   `json:"request"`
	KeyID             string    `json:"key_id"`
	IndependentReview bool      `json:"independent_review_confirmed"`
	CheckpointSHA     string    `json:"external_review_checkpoint_sha256"`
	IssuedAt          time.Time `json:"issued_at"`
	ExpiresAt         time.Time `json:"expires_at"`
	Signature         string    `json:"signature_base64"`
}

func SigningBytes(a Approval) []byte {
	a.Signature = ""
	raw, _ := json.Marshal(a)
	return append([]byte("reverse-artex/context-production-approval/2\n"), raw...)
}

type Change struct {
	Schema    string    `json:"schema"`
	Revision  int       `json:"revision"`
	Previous  string    `json:"previous_sha256"`
	SourceSHA string    `json:"activation_source_sha256"`
	Tenant    string    `json:"tenant_id"`
	Action    string    `json:"action"`
	At        time.Time `json:"changed_at"`
	Reason    string    `json:"reason"`
	Policy    *Policy   `json:"policy,omitempty"`
	Basis     *Basis    `json:"basis,omitempty"`
	Approval  *Approval `json:"approval,omitempty"`
	SHA       string    `json:"change_sha256"`
}

func changeSHA(c Change) string { c.SHA = ""; return contextlearning.Digest(c) }

type View struct {
	Tenant                   string  `json:"tenant_id"`
	Revision                 int     `json:"revision"`
	Head                     string  `json:"head_sha256"`
	State                    string  `json:"state"`
	Current                  *Change `json:"current,omitempty"`
	DeploymentAllowed        bool    `json:"deployment_allowed"`
	MandatoryReviewPreserved bool    `json:"mandatory_review_preserved"`
	PolicyMutations          int     `json:"policy_mutations"`
}
