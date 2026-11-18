// Package contextevaluation evaluates post-freeze v2 canary predictions against
// later signed case labels. Reports cannot activate a model or mutate policy.
package contextevaluation

import (
	"embed"
	"errors"
	"reverse-artex/internal/casememory"
	"reverse-artex/internal/contextlearning"
	"reverse-artex/internal/contextrelease"
	"reverse-artex/internal/contextshadow"
	"time"
)

var ErrInvalid = errors.New("invalid context-canary evaluation contract; preserve original")
var ErrConflict = errors.New("context-canary evaluation plan or source changed")

//go:embed types.go plan.go score.go
var sources embed.FS

func SourceSHA() string {
	values := []string{contextrelease.SourceSHA(), contextrelease.EvaluationReaderSHA(), contextshadow.HistoryReaderSHA(), contextlearning.RuntimeSHA()}
	for _, n := range []string{"types.go", "plan.go", "score.go"} {
		raw, _ := sources.ReadFile(n)
		values = append(values, n, contextlearning.Digest(string(raw)))
	}
	return contextlearning.Digest(values)
}

type Plan struct {
	Schema          string                    `json:"schema"`
	Tenant          string                    `json:"tenant_id"`
	ReleaseSHA      string                    `json:"release_sha256"`
	BundleSHA       string                    `json:"bundle_sha256"`
	ConfigSHA       string                    `json:"release_config_sha256"`
	EvaluationSHA   string                    `json:"evaluation_source_sha256"`
	LabelTrustSHA   string                    `json:"label_trust_sha256"`
	Criteria        casememory.CanaryCriteria `json:"criteria"`
	CreatedAt       time.Time                 `json:"frozen_at"`
	Until           time.Time                 `json:"canary_until"`
	Baseline        contextrelease.Baseline   `json:"baseline"`
	HistorySequence int                       `json:"history_sequence_at_freeze"`
	HistoryHead     string                    `json:"history_head_at_freeze"`
	SHA             string                    `json:"plan_sha256"`
}

func PlanSHA(p Plan) string { p.SHA = ""; return contextlearning.Digest(p) }

type Arm struct {
	Planned             int                      `json:"planned"`
	Scored              int                      `json:"scored"`
	Counts              casememory.QualityCounts `json:"counts"`
	FalseBenignUpperBPS int                      `json:"false_benign_upper_bps"`
	FalseAttackUpperBPS int                      `json:"false_attack_upper_bps"`
}
type ResultRow struct {
	CaseID         string    `json:"case_id"`
	CaseSHA        string    `json:"case_sha256"`
	Branch         string    `json:"branch"`
	AttemptSHA     string    `json:"attempt_sha256"`
	PredictedAt    time.Time `json:"predicted_at"`
	CommitBoundary time.Time `json:"prediction_committed_before"`
	Prediction     string    `json:"candidate_prediction"`
	LabelSHA       string    `json:"label_sha256"`
	LabelRevision  int       `json:"label_revision"`
	Label          string    `json:"label"`
	Status         string    `json:"status"`
	Reason         string    `json:"reason"`
}
type Report struct {
	Schema                            string                   `json:"schema"`
	Tenant                            string                   `json:"tenant_id"`
	PlanSHA                           string                   `json:"plan_sha256"`
	ReleaseSHA                        string                   `json:"release_sha256"`
	CandidateSHA                      string                   `json:"candidate_sha256"`
	SourceSHA                         string                   `json:"source_snapshot_sha256"`
	LabelSnapshotSHA                  string                   `json:"label_snapshot_sha256"`
	HistorySHA                        string                   `json:"history_sha256"`
	JournalHead                       string                   `json:"release_journal_head_sha256"`
	EvaluationSHA                     string                   `json:"evaluation_source_sha256"`
	WindowStart                       time.Time                `json:"window_start"`
	WindowEnd                         time.Time                `json:"window_end"`
	WindowClosed                      bool                     `json:"window_closed"`
	EvaluatedAt                       time.Time                `json:"evaluated_at"`
	TenantCases                       int                      `json:"tenant_cases"`
	Excluded                          int                      `json:"excluded"`
	Planned                           int                      `json:"planned"`
	Scored                            int                      `json:"scored"`
	Unresolved                        int                      `json:"unresolved"`
	Unknown                           int                      `json:"unknown_labels"`
	Corrected                         int                      `json:"corrected_labels"`
	FailedChecks                      int                      `json:"failed_observation_checks"`
	CoverageBPS                       int                      `json:"coverage_bps"`
	ObservedSpanSeconds               int64                    `json:"observed_span_seconds"`
	MaximumBatchMilliseconds          int64                    `json:"maximum_batch_milliseconds"`
	CandidateArm                      Arm                      `json:"candidate_arm"`
	ReferenceArm                      Arm                      `json:"reference_arm"`
	PairedCandidate                   casememory.QualityCounts `json:"paired_candidate"`
	PairedReference                   casememory.QualityCounts `json:"paired_reference"`
	QualityValidNow                   bool                     `json:"quality_valid_now"`
	CriteriaPassed                    bool                     `json:"criteria_passed"`
	ReleaseReviewReady                bool                     `json:"release_review_ready"`
	State                             string                   `json:"state"`
	Reasons                           []string                 `json:"reasons"`
	Rows                              []ResultRow              `json:"rows"`
	IndependentCanaryEvaluationProven bool                     `json:"independent_canary_evaluation_proven"`
	DeploymentAllowed                 bool                     `json:"deployment_allowed"`
	PolicyMutations                   int                      `json:"policy_mutations"`
	MandatoryReviewPreserved          bool                     `json:"mandatory_review_preserved"`
	SHA                               string                   `json:"report_sha256"`
}

func ReportSHA(r Report) string { r.SHA = ""; return contextlearning.Digest(r) }
