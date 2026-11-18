// Package contextadmission checks independently endorsed feature-v2 quality
// evidence before release approval. It never serves a model or writes policy.
package contextadmission

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reverse-artex/internal/contextlearning"
	"reverse-artex/internal/contextshadow"
	"reverse-artex/internal/contractjson"
	"time"
)

var ErrInvalid = errors.New("invalid context quality admission contract")

//go:embed types.go validate.go
var sources embed.FS

func SourceSHA() string {
	values := []string{contextlearning.RuntimeSHA(), contextshadow.SourceSHA(), contractjson.SourceSHA()}
	for _, name := range []string{"types.go", "validate.go"} {
		raw, _ := sources.ReadFile(name)
		sum := sha256.Sum256(raw)
		values = append(values, name, hex.EncodeToString(sum[:]))
	}
	return contextlearning.Digest(values)
}

type Policy struct {
	Schema                  string `json:"schema"`
	Tenant                  string `json:"tenant_id"`
	Revision                int    `json:"revision"`
	Enabled                 bool   `json:"enabled"`
	Scope                   string `json:"scope"`
	AuthorityTrustSHA       string `json:"authority_trust_sha256"`
	ContextTrustSHA         string `json:"context_trust_sha256"`
	FeatureSHA              string `json:"feature_schema_sha256"`
	RuntimeSHA              string `json:"runtime_source_sha256"`
	AdmissionSHA            string `json:"admission_source_sha256"`
	MaximumReportAgeSeconds int    `json:"maximum_report_age_seconds"`
}

func DefaultPolicy(tenant, authorities, context string) Policy {
	return Policy{Schema: "case-context-admission-policy/2", Tenant: tenant, Revision: 1,
		Scope: "incident_triage_context/2", AuthorityTrustSHA: authorities, ContextTrustSHA: context,
		FeatureSHA: contextlearning.Digest(contextlearning.FeatureNames), RuntimeSHA: contextlearning.RuntimeSHA(),
		AdmissionSHA: SourceSHA(), MaximumReportAgeSeconds: 86400}
}

// Endorsement leaves the original nondeploying scorer report unchanged. A
// separately signed envelope attests external provenance and access separation.
// A signature proves the installed key made these claims, not their reality.
type Endorsement struct {
	Schema        string                 `json:"schema"`
	Tenant        string                 `json:"tenant_id"`
	TrustSHA      string                 `json:"authority_trust_sha256"`
	CapsuleSHA    string                 `json:"capsule_sha256"`
	Report        contextlearning.Report `json:"report"`
	CheckpointSHA string                 `json:"custody_checkpoint_sha256"`
	Independent   bool                   `json:"independence_attested"`
	Isolation     bool                   `json:"isolation_attested"`
	KeyID         string                 `json:"key_id"`
	IssuedAt      time.Time              `json:"issued_at"`
	ExpiresAt     time.Time              `json:"expires_at"`
	Signature     string                 `json:"signature_base64"`
}

func SigningBytes(e Endorsement) []byte {
	e.Signature = ""
	raw, _ := json.Marshal(e)
	return append([]byte("reverse-artex/context-independent-quality/2\n"), raw...)
}

type Decision struct {
	Schema            string    `json:"schema"`
	Tenant            string    `json:"tenant_id"`
	PolicySHA         string    `json:"policy_sha256"`
	CapsuleSHA        string    `json:"capsule_sha256"`
	CandidateSHA      string    `json:"candidate_sha256"`
	ModelSHA          string    `json:"model_sha256"`
	FeatureSHA        string    `json:"feature_schema_sha256"`
	RuntimeSHA        string    `json:"runtime_source_sha256"`
	AdmissionSHA      string    `json:"admission_source_sha256"`
	ContextTrustSHA   string    `json:"context_trust_sha256"`
	AuthorityTrustSHA string    `json:"authority_trust_sha256"`
	ReportSHA         string    `json:"report_sha256"`
	EndorsementSHA    string    `json:"endorsement_sha256"`
	CheckpointSHA     string    `json:"custody_checkpoint_sha256"`
	State             string    `json:"state"`
	Accepted          bool      `json:"accepted"`
	NumericPassed     bool      `json:"numeric_criteria_passed"`
	Reasons           []string  `json:"reasons"`
	CheckedAt         time.Time `json:"checked_at"`
	ValidUntil        time.Time `json:"valid_until"`
	DeploymentAllowed bool      `json:"deployment_allowed"`
	SHA               string    `json:"decision_sha256"`
}

func DecisionSHA(d Decision) string { d.SHA = ""; return contextlearning.Digest(d) }
