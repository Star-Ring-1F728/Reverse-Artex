package casememory

import "time"

// The deployable G09 artifact is a stateless 14-feature incident classifier.
// This contract cannot deploy an LLM, a new feature extractor or a policy writer.
type QualityCriteria struct {
	MinimumCases               int `json:"minimum_cases"`
	MinimumAttack              int `json:"minimum_attack"`
	MinimumBenign              int `json:"minimum_benign"`
	MinimumFamilies            int `json:"minimum_families"`
	MinimumSourceGroups        int `json:"minimum_source_groups"`
	MinimumCoverageBPS         int `json:"minimum_coverage_bps"`
	MaximumFalseBenignUpperBPS int `json:"maximum_false_benign_upper_bps"`
	MaximumFalseAttackUpperBPS int `json:"maximum_false_attack_upper_bps"`
	MaximumCaseMilliseconds    int `json:"maximum_case_milliseconds"`
}
type CanaryCriteria struct {
	MinimumCases               int `json:"minimum_candidate_cases"`
	MinimumAttack              int `json:"minimum_candidate_attack"`
	MinimumBenign              int `json:"minimum_candidate_benign"`
	MinimumSeconds             int `json:"minimum_seconds"`
	MinimumCoverageBPS         int `json:"minimum_coverage_bps"`
	MaximumFalseBenignUpperBPS int `json:"maximum_false_benign_upper_bps"`
	MaximumFalseAttackUpperBPS int `json:"maximum_false_attack_upper_bps"`
}
type ProductionPolicy struct {
	Schema                  string          `json:"schema"`
	Tenant                  string          `json:"tenant_id"`
	Revision                int             `json:"revision"`
	TrustSHA                string          `json:"trust_sha256"`
	Enabled                 bool            `json:"enabled"`
	Scope                   string          `json:"scope"`
	Quality                 QualityCriteria `json:"quality"`
	Canary                  CanaryCriteria  `json:"canary"`
	MaximumReportAgeSeconds int             `json:"maximum_report_age_seconds"`
}

func DefaultProductionPolicy(tenant, trust string) ProductionPolicy {
	return ProductionPolicy{Schema: "case-production-policy/1", Tenant: tenant, Revision: 1, TrustSHA: trust, Scope: "incident_triage/1",
		Quality: QualityCriteria{60, 30, 30, 3, 3, 10000, 1000, 1000, 30000},
		Canary:  CanaryCriteria{60, 30, 30, 3600, 10000, 1000, 1000}, MaximumReportAgeSeconds: 86400}
}

type QualityPlan struct {
	TrainingEvidenceSHA string          `json:"training_evidence_sha256"`
	Schema              string          `json:"schema"`
	ID                  string          `json:"plan_id"`
	Tenant              string          `json:"tenant_id"`
	CandidateID         string          `json:"candidate_id"`
	CandidateSHA        string          `json:"candidate_sha256"`
	ModelSHA            string          `json:"model_sha256"`
	FeatureSHA          string          `json:"feature_schema_sha256"`
	TrainerSHA          string          `json:"trainer_source_sha256"`
	RuntimeSHA          string          `json:"runtime_source_sha256"`
	PolicySHA           string          `json:"production_policy_sha256"`
	TrustSHA            string          `json:"trust_sha256"`
	Incumbent           CandidateModel  `json:"incumbent_model"`
	IncumbentSHA        string          `json:"incumbent_model_sha256"`
	Criteria            QualityCriteria `json:"criteria"`
	CreatedAt           time.Time       `json:"created_at"`
}
type CohortSeal struct {
	MembershipSHA      string    `json:"membership_sha256"`
	Schema             string    `json:"schema"`
	PlanID             string    `json:"plan_id"`
	Tenant             string    `json:"tenant_id"`
	TrustSHA           string    `json:"trust_sha256"`
	DatasetID          string    `json:"dataset_id"`
	InputsSHA          string    `json:"inputs_sha256"`
	GoldSHA            string    `json:"gold_sha256"`
	ProvenanceSHA      string    `json:"provenance_sha256"`
	Planned            int       `json:"planned"`
	Families           int       `json:"families"`
	SourceGroups       int       `json:"source_groups"`
	IndependentCustody bool      `json:"independent_custody_attested"`
	RuntimeGoldDenied  bool      `json:"runtime_gold_access_denied_attested"`
	TrainingOverlap    int       `json:"training_overlap"`
	KeyID              string    `json:"key_id"`
	IssuedAt           time.Time `json:"issued_at"`
	ExpiresAt          time.Time `json:"expires_at"`
	Signature          string    `json:"signature_base64"`
}
type CohortRecord struct {
	Statement CohortSeal `json:"statement"`
	At        time.Time  `json:"admitted_at"`
	SHA       string     `json:"cohort_sha256"`
}
type QualityCapsule struct {
	Schema            string         `json:"schema"`
	Plan              QualityPlan    `json:"plan"`
	Model             CandidateModel `json:"model"`
	ForbiddenEvidence []string       `json:"training_evidence_sha256"`
	Cohort            CohortRecord   `json:"cohort"`
	SHA               string         `json:"capsule_sha256"`
}
type QualityInputRow struct {
	EvidenceKeys []string          `json:"evidence_keys_sha256"`
	ID           string            `json:"id"`
	Family       string            `json:"family"`
	SourceGroup  string            `json:"source_group"`
	EvidenceSHA  string            `json:"evidence_sha256"`
	Features     [featureCount]int `json:"features"`
}
type QualityInputs struct {
	Schema    string            `json:"schema"`
	DatasetID string            `json:"dataset_id"`
	Rows      []QualityInputRow `json:"rows"`
}
type QualityPrediction struct {
	ID         string `json:"id"`
	Status     string `json:"status"`
	Candidate  string `json:"candidate"`
	Incumbent  string `json:"incumbent"`
	DurationMS int    `json:"duration_ms"`
}
type QualityPredictions struct {
	Schema     string              `json:"schema"`
	CapsuleSHA string              `json:"capsule_sha256"`
	InputsSHA  string              `json:"inputs_sha256"`
	StartedAt  time.Time           `json:"started_at"`
	FinishedAt time.Time           `json:"finished_at"`
	Rows       []QualityPrediction `json:"rows"`
}
type QualityGoldRow struct {
	ID    string `json:"id"`
	Value string `json:"value"`
}
type QualityGold struct {
	Schema    string           `json:"schema"`
	DatasetID string           `json:"dataset_id"`
	Rows      []QualityGoldRow `json:"rows"`
}
type QualityCounts struct {
	Attack      int `json:"attack"`
	Benign      int `json:"benign"`
	TrueAttack  int `json:"true_attack"`
	FalseBenign int `json:"false_benign"`
	TrueBenign  int `json:"true_benign"`
	FalseAttack int `json:"false_attack"`
}
type FamilyQuality struct {
	Family    string        `json:"family"`
	Planned   int           `json:"planned"`
	Candidate QualityCounts `json:"candidate"`
	Incumbent QualityCounts `json:"incumbent"`
}
type QualityReport struct {
	Schema                  string          `json:"schema"`
	PlanID                  string          `json:"plan_id"`
	CapsuleSHA              string          `json:"capsule_sha256"`
	CohortSHA               string          `json:"cohort_sha256"`
	InputsSHA               string          `json:"inputs_sha256"`
	GoldSHA                 string          `json:"gold_sha256"`
	PredictionsSHA          string          `json:"predictions_sha256"`
	RuntimeSHA              string          `json:"runtime_source_sha256"`
	Planned                 int             `json:"planned"`
	Families                int             `json:"families"`
	SourceGroups            int             `json:"source_groups"`
	Scored                  int             `json:"scored"`
	Unknown                 int             `json:"unknown"`
	Failures                int             `json:"failures"`
	MaximumCaseMilliseconds int             `json:"maximum_case_milliseconds"`
	Candidate               QualityCounts   `json:"candidate"`
	Incumbent               QualityCounts   `json:"incumbent"`
	ByFamily                []FamilyQuality `json:"by_family"`
	StartedAt               time.Time       `json:"started_at"`
	FinishedAt              time.Time       `json:"finished_at"`
	Passed                  bool            `json:"passed"`
	Reasons                 []string        `json:"reasons"`
}
type SignedQualityReport struct {
	Schema               string        `json:"schema"`
	Tenant               string        `json:"tenant_id"`
	TrustSHA             string        `json:"trust_sha256"`
	Report               QualityReport `json:"report"`
	IndependenceAttested bool          `json:"independence_attested"`
	IsolationAttested    bool          `json:"isolation_attested"`
	KeyID                string        `json:"key_id"`
	IssuedAt             time.Time     `json:"issued_at"`
	ExpiresAt            time.Time     `json:"expires_at"`
	Signature            string        `json:"signature_base64"`
}
type QualityRecord struct {
	Statement SignedQualityReport `json:"statement"`
	At        time.Time           `json:"admitted_at"`
	SHA       string              `json:"quality_sha256"`
}
type QualityView struct {
	Capsule  QualityCapsule `json:"capsule"`
	Proof    *QualityRecord `json:"proof"`
	State    string         `json:"state"`
	Blockers []string       `json:"blockers"`
}
