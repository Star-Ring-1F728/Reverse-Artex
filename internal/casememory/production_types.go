package casememory

import "time"

type ProductionRequest struct {
	Expected    int    `json:"expected_revision"`
	Action      string `json:"action"`
	PlanID      string `json:"plan_id"`
	QualitySHA  string `json:"quality_sha256"`
	PolicySHA   string `json:"production_policy_sha256"`
	RuntimeSHA  string `json:"runtime_source_sha256"`
	ReviewRunID string `json:"review_run_id"`
	ReviewSHA   string `json:"review_decision_sha256"`
	CanarySHA   string `json:"canary_sha256"`
	Percent     int    `json:"percent"`
	Reason      string `json:"reason"`
}
type SignedProductionChange struct {
	Schema    string            `json:"schema"`
	Tenant    string            `json:"tenant_id"`
	TrustSHA  string            `json:"trust_sha256"`
	Request   ProductionRequest `json:"request"`
	KeyID     string            `json:"key_id"`
	IssuedAt  time.Time         `json:"issued_at"`
	ExpiresAt time.Time         `json:"expires_at"`
	Signature string            `json:"signature_base64"`
}
type ProductionChange struct {
	BaselineEvidence []string                `json:"baseline_evidence_sha256"`
	Schema           string                  `json:"schema"`
	Tenant           string                  `json:"tenant_id"`
	Revision         int                     `json:"revision"`
	Previous         string                  `json:"previous_sha256"`
	Request          ProductionRequest       `json:"request"`
	Authorization    *SignedProductionChange `json:"authorization,omitempty"`
	Baseline         []string                `json:"baseline_case_ids"`
	At               time.Time               `json:"changed_at"`
	SHA              string                  `json:"change_sha256"`
}
type RuntimeReceipt struct {
	Schema                   string            `json:"schema"`
	Tenant                   string            `json:"tenant_id"`
	CaseID                   string            `json:"case_id"`
	CaseSHA                  string            `json:"case_sha256"`
	SourceSHA                string            `json:"source_snapshot_sha256"`
	ReleaseSHA               string            `json:"release_sha256"`
	ModelSHA                 string            `json:"model_sha256"`
	FeatureSHA               string            `json:"feature_schema_sha256"`
	RuntimeSHA               string            `json:"runtime_source_sha256"`
	Features                 [featureCount]int `json:"features"`
	Prediction               string            `json:"prediction"`
	Route                    string            `json:"route"`
	CohortEligible           bool              `json:"cohort_eligible"`
	Exclusion                string            `json:"exclusion_reason"`
	At                       time.Time         `json:"inferred_at"`
	MandatoryReviewPreserved bool              `json:"mandatory_review_preserved"`
	PolicyMutations          int               `json:"policy_mutations"`
	SHA                      string            `json:"receipt_sha256"`
}
type RuntimeBatch struct {
	Tenant string           `json:"tenant_id"`
	At     time.Time        `json:"inferred_at"`
	Rows   []RuntimeReceipt `json:"rows"`
}
type ProductionCanary struct {
	ReleaseSHA       string        `json:"release_sha256"`
	Total            int           `json:"total"`
	BaselineExcluded int           `json:"baseline_excluded"`
	CandidateTotal   int           `json:"candidate_total"`
	ReferenceTotal   int           `json:"reference_total"`
	Scored           int           `json:"scored"`
	Excluded         int           `json:"excluded"`
	Awaiting         int           `json:"awaiting"`
	Counts           QualityCounts `json:"counts"`
	Seconds          int           `json:"seconds"`
	Ready            bool          `json:"ready"`
	Reasons          []string      `json:"reasons"`
	LabelBindings    []string      `json:"label_bindings"`
	SHA              string        `json:"canary_sha256"`
}
type ProductionView struct {
	Policy           *ProductionPolicy  `json:"policy"`
	Revision         int                `json:"revision"`
	State            string             `json:"state"`
	Current          *ProductionChange  `json:"current"`
	History          []ProductionChange `json:"history"`
	Blockers         []string           `json:"blockers"`
	Canary           *ProductionCanary  `json:"canary"`
	RuntimeEnabled   bool               `json:"runtime_enabled"`
	Scope            string             `json:"scope"`
	RuntimeSourceSHA string             `json:"runtime_source_sha256"`
	Latest           []RuntimeReceipt   `json:"latest_receipts"`
}
