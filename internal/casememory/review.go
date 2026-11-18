package casememory

import (
	"embed"
	"reflect"
	"strings"
	"time"
	"unicode/utf8"
)

const MaxReviewDecisions = 32

//go:embed review.go review_v1.go
var reviewSources embed.FS

type ReviewCriteria struct {
	MinimumAttack         int `json:"minimum_confirmed_attack"`
	MinimumBenign         int `json:"minimum_confirmed_benign"`
	MinimumSeconds        int `json:"minimum_observation_seconds"`
	MinimumCoverageBPS    int `json:"minimum_label_coverage_bps"`
	MaximumFalseAttackBPS int `json:"maximum_false_attack_bps"`
}

func DefaultReviewCriteria() ReviewCriteria { return ReviewCriteria{20, 20, 3600, 9000, 1000} }

type ReviewPlan struct {
	Schema          string         `json:"schema"`
	RunID           string         `json:"run_id"`
	Tenant          string         `json:"tenant_id"`
	ShadowPlanSHA   string         `json:"shadow_plan_sha256"`
	CandidateSHA    string         `json:"candidate_sha256"`
	ModelSHA        string         `json:"model_sha256"`
	SourceSHA       string         `json:"review_source_sha256"`
	Criteria        ReviewCriteria `json:"criteria"`
	RegisteredAt    time.Time      `json:"registered_at"`
	JournalSequence int            `json:"journal_sequence"`
	SHA             string         `json:"review_plan_sha256"`
}

type ReviewAssessment struct {
	Schema                string              `json:"schema"`
	CriteriaMet           bool                `json:"local_criteria_met"`
	Reasons               []string            `json:"reasons"`
	Total                 int                 `json:"total"`
	Scored                int                 `json:"scored"`
	Attack                int                 `json:"confirmed_attack"`
	Benign                int                 `json:"confirmed_benign"`
	CoverageBPS           int                 `json:"label_coverage_bps"`
	ObservationSeconds    int                 `json:"observation_seconds"`
	Comparison            CandidateComparison `json:"comparison"`
	IndependentEvaluation bool                `json:"independent_evaluation"`
	DeploymentAllowed     bool                `json:"deployment_allowed"`
}

type ReviewRequest struct {
	Expected    int    `json:"expected_review_revision"`
	PlanSHA     string `json:"review_plan_sha256"`
	SnapshotSHA string `json:"shadow_snapshot_sha256"`
	Decision    string `json:"decision"`
	Reason      string `json:"reason"`
}

type ReviewDecision struct {
	Schema           string           `json:"schema"`
	ID               string           `json:"decision_id"`
	RunID            string           `json:"run_id"`
	Tenant           string           `json:"tenant_id"`
	Revision         int              `json:"revision"`
	Previous         string           `json:"previous_sha256"`
	PlanSHA          string           `json:"review_plan_sha256"`
	CandidateSHA     string           `json:"candidate_sha256"`
	SnapshotSHA      string           `json:"shadow_snapshot_sha256"`
	SnapshotRevision int              `json:"shadow_revision"`
	Request          ReviewRequest    `json:"request"`
	Assessment       ReviewAssessment `json:"assessment"`
	Actor            string           `json:"actor"`
	At               time.Time        `json:"reviewed_at"`
	SHA              string           `json:"decision_sha256"`
}

type ReviewView struct {
	Defaults              ReviewCriteria   `json:"default_criteria"`
	Plan                  *ReviewPlan      `json:"plan"`
	Decisions             []ReviewDecision `json:"decisions"`
	Assessment            ReviewAssessment `json:"assessment"`
	LatestSnapshotSHA     string           `json:"latest_shadow_snapshot_sha256"`
	ExpectedRevision      int              `json:"expected_review_revision"`
	State                 string           `json:"state"`
	Blockers              []string         `json:"blockers"`
	ReviewSourceCurrent   bool             `json:"review_source_current"`
	ApprovalAvailable     bool             `json:"approval_for_evaluation_available"`
	RefreshRequired       bool             `json:"refresh_required"`
	ReevaluationRequired  bool             `json:"reevaluation_required"`
	ReviewStale           bool             `json:"review_stale"`
	IndependentEvaluation bool             `json:"independent_evaluation"`
	DeploymentAllowed     bool             `json:"deployment_allowed"`
}

type reviewState struct {
	Plan      ReviewPlan
	Decisions []ReviewDecision
}

func reviewSourceSHA() string {
	values := []string{}
	for _, name := range []string{"review.go", "review_v1.go"} {
		raw, _ := reviewSources.ReadFile(name)
		values = append(values, name, hash(raw))
	}
	return hash(values)
}

func validReviewCriteria(c ReviewCriteria) bool {
	return c.MinimumAttack >= 2 && c.MinimumBenign >= 2 && c.MinimumAttack <= MaxCases && c.MinimumBenign <= MaxCases && c.MinimumAttack+c.MinimumBenign <= MaxCases &&
		c.MinimumSeconds >= 0 && c.MinimumSeconds <= 7*86400 && c.MinimumCoverageBPS >= 1 && c.MinimumCoverageBPS <= 10000 && c.MaximumFalseAttackBPS >= 0 && c.MaximumFalseAttackBPS <= 10000
}

func (s *Store) makeReviewPlan(state shadowState, c ReviewCriteria, at time.Time, source string) ReviewPlan {
	p := ReviewPlan{Schema: "case-shadow-review-plan/1", RunID: state.Plan.ID, Tenant: state.Plan.Tenant,
		ShadowPlanSHA: state.Plan.SHA, CandidateSHA: state.Plan.CandidateSHA, ModelSHA: state.Plan.ModelSHA, SourceSHA: source,
		Criteria: c, RegisteredAt: at, JournalSequence: s.sequence + 1}
	p.SHA = hash(p)
	return p
}

func (s *Store) validateReviewPlan(p ReviewPlan) error {
	state, ok := s.shadows[p.RunID]
	if !ok || state.Plan.Tenant != p.Tenant {
		return ErrNotFound
	}
	if _, ok := s.reviews[p.RunID]; ok {
		return ErrConflict
	}
	if len(s.reviews) >= MaxShadowRuns {
		return ErrLimit
	}
	if !validReviewCriteria(p.Criteria) || !digest.MatchString(p.SourceSHA) || p.RegisteredAt.IsZero() || p.RegisteredAt.Before(state.Plan.StartedAt) {
		return ErrInvalid
	}
	if len(state.Snapshots) != 0 || s.selectCases(p.Tenant).SHA != state.Plan.Baseline.SHA || len(s.trainingChanges(s.candidates[state.Plan.CandidateID])) > 0 {
		return ErrConflict
	}
	want := s.makeReviewPlan(state, p.Criteria, p.RegisteredAt, p.SourceSHA)
	if !reflect.DeepEqual(want, p) {
		return ErrInvalid
	}
	return nil
}

func reviewSnapshot(state shadowState) *ShadowSnapshot {
	if len(state.Snapshots) == 0 {
		return nil
	}
	snapshot := state.Snapshots[len(state.Snapshots)-1]
	return &snapshot
}

func assessReview(plan ReviewPlan, snapshot *ShadowSnapshot) (ReviewAssessment, error) {
	switch plan.Schema {
	case "case-shadow-review-plan/1":
		return assessReviewV1(plan, snapshot), nil
	default:
		return ReviewAssessment{}, ErrInvalid
	}
}

func canonicalReview(q ReviewRequest) (ReviewRequest, error) {
	q.Reason = strings.TrimSpace(q.Reason)
	if q.Expected < 0 || q.Expected > MaxReviewDecisions || !digest.MatchString(q.PlanSHA) ||
		(q.SnapshotSHA != "" && !digest.MatchString(q.SnapshotSHA)) || q.Reason == "" || !utf8.ValidString(q.Reason) || utf8.RuneCountInString(q.Reason) > 1000 ||
		(q.Decision != "approve_for_evaluation" && q.Decision != "reject" && q.Decision != "defer") {
		return q, ErrInvalid
	}
	return q, nil
}

func reviewRequestID(run string, q ReviewRequest) string {
	return hash(struct {
		Run     string
		Request ReviewRequest
	}{run, q})
}

func makeReviewDecision(state reviewState, shadow shadowState, q ReviewRequest, at time.Time) (ReviewDecision, error) {
	snapshot := reviewSnapshot(shadow)
	assessment, err := assessReview(state.Plan, snapshot)
	if err != nil {
		return ReviewDecision{}, err
	}
	d := ReviewDecision{Schema: "case-shadow-review-decision/1", ID: reviewRequestID(state.Plan.RunID, q), RunID: state.Plan.RunID, Tenant: state.Plan.Tenant,
		Revision: len(state.Decisions) + 1, PlanSHA: state.Plan.SHA, CandidateSHA: state.Plan.CandidateSHA, Request: q, Assessment: assessment, Actor: "local-operator", At: at}
	if len(state.Decisions) > 0 {
		d.Previous = state.Decisions[len(state.Decisions)-1].SHA
	}
	if snapshot != nil {
		d.SnapshotSHA = snapshot.SHA
		d.SnapshotRevision = snapshot.Revision
	}
	d.SHA = hash(d)
	return d, nil
}

func (s *Store) validateReviewDecision(d ReviewDecision) error {
	state, ok := s.reviews[d.RunID]
	if !ok || state.Plan.Tenant != d.Tenant {
		return ErrNotFound
	}
	if len(state.Decisions) >= MaxReviewDecisions {
		return ErrLimit
	}
	q, err := canonicalReview(d.Request)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(q, d.Request) || q.Expected != len(state.Decisions) || q.PlanSHA != state.Plan.SHA {
		return ErrConflict
	}
	shadow := s.shadows[d.RunID]
	snapshot := reviewSnapshot(shadow)
	snapshotSHA := ""
	if snapshot != nil {
		snapshotSHA = snapshot.SHA
	}
	if q.SnapshotSHA != snapshotSHA {
		return ErrConflict
	}
	if d.At.IsZero() || d.At.Before(state.Plan.RegisteredAt) || (len(state.Decisions) > 0 && d.At.Before(state.Decisions[len(state.Decisions)-1].At)) {
		return ErrInvalid
	}
	if q.Decision == "approve_for_evaluation" {
		assessment, err := assessReview(state.Plan, snapshot)
		if err != nil {
			return err
		}
		if !assessment.CriteriaMet || snapshot == nil || snapshot.InputSHA != s.selectCases(d.Tenant).SHA || len(s.trainingChanges(s.candidates[shadow.Plan.CandidateID])) > 0 {
			return ErrConflict
		}
	}
	want, err := makeReviewDecision(state, shadow, q, d.At)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(want, d) {
		return ErrInvalid
	}
	return nil
}

func (s *Store) reviewView(shadow shadowState) ReviewView {
	v := ReviewView{Defaults: DefaultReviewCriteria(), Decisions: []ReviewDecision{}, Blockers: []string{}, State: "REVIEW_PLAN_REQUIRED"}
	source := s.shadowView(shadow, 0)
	v.RefreshRequired, v.ReevaluationRequired = source.RefreshRequired, source.ReevaluationRequired
	if source.RefreshRequired {
		v.Blockers = append(v.Blockers, "shadow_refresh_required")
	}
	if source.ReevaluationRequired {
		v.Blockers = append(v.Blockers, "training_or_observer_changed")
	}
	snapshot := reviewSnapshot(shadow)
	if snapshot != nil {
		v.LatestSnapshotSHA = snapshot.SHA
	}
	state, ok := s.reviews[shadow.Plan.ID]
	if !ok {
		v.Blockers = append(v.Blockers, "preregistration_required")
		return v
	}
	p := state.Plan
	v.Plan = &p
	v.Decisions = state.Decisions
	v.ExpectedRevision = len(state.Decisions)
	v.ReviewSourceCurrent = p.SourceSHA == reviewSourceSHA()
	if !v.ReviewSourceCurrent {
		v.Blockers = append(v.Blockers, "review_implementation_changed")
		v.ReevaluationRequired = true
	}
	v.Assessment, _ = assessReview(p, snapshot)
	v.ApprovalAvailable = v.Assessment.CriteriaMet && len(v.Blockers) == 0
	v.State = "CRITERIA_NOT_MET"
	if v.ApprovalAvailable {
		v.State = "READY_FOR_LOCAL_REVIEW"
	}
	if len(state.Decisions) > 0 {
		latest := state.Decisions[len(state.Decisions)-1]
		v.ReviewStale = latest.SnapshotSHA != v.LatestSnapshotSHA || len(v.Blockers) > 0
		if v.ReviewStale {
			v.State = "REVIEW_STALE"
		} else {
			switch latest.Request.Decision {
			case "approve_for_evaluation":
				v.State = "APPROVED_FOR_EVALUATION"
			case "reject":
				v.State = "REJECTED"
			case "defer":
				v.State = "DEFERRED"
			}
		}
	}
	return v
}

func (s *Store) RegisterReview(tenant, run string, c ReviewCriteria) (ReviewView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return ReviewView{}, err
	}
	shadow, ok := s.shadows[run]
	if !ok || shadow.Plan.Tenant != tenant {
		return ReviewView{}, ErrNotFound
	}
	if !validReviewCriteria(c) {
		return ReviewView{}, ErrInvalid
	}
	if old, ok := s.reviews[run]; ok {
		if old.Plan.Criteria != c {
			return ReviewView{}, ErrConflict
		}
		return clone(s.reviewView(shadow)), nil
	}
	view := s.shadowView(shadow, 0)
	if view.ReevaluationRequired {
		return ReviewView{}, ErrConflict
	}
	p := s.makeReviewPlan(shadow, c, time.Now().UTC(), reviewSourceSHA())
	if err := s.append(record{ReviewPlan: &p}); err != nil {
		return ReviewView{}, err
	}
	return clone(s.reviewView(shadow)), nil
}

func (s *Store) Review(tenant, run string) (ReviewView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return ReviewView{}, err
	}
	shadow, ok := s.shadows[run]
	if !ok || shadow.Plan.Tenant != tenant {
		return ReviewView{}, ErrNotFound
	}
	return clone(s.reviewView(shadow)), nil
}

func (s *Store) SubmitReview(tenant, run string, q ReviewRequest) (ReviewView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return ReviewView{}, err
	}
	state, ok := s.reviews[run]
	if !ok || state.Plan.Tenant != tenant {
		return ReviewView{}, ErrNotFound
	}
	q, err := canonicalReview(q)
	if err != nil {
		return ReviewView{}, err
	}
	shadow := s.shadows[run]
	id := reviewRequestID(run, q)
	for _, d := range state.Decisions {
		if d.ID == id {
			return clone(s.reviewView(shadow)), nil
		}
	}
	view := s.reviewView(shadow)
	if q.Decision == "approve_for_evaluation" && !view.ApprovalAvailable {
		return ReviewView{}, ErrConflict
	}
	d, err := makeReviewDecision(state, shadow, q, time.Now().UTC())
	if err != nil {
		return ReviewView{}, err
	}
	if err := s.append(record{ReviewDecision: &d}); err != nil {
		return ReviewView{}, err
	}
	return clone(s.reviewView(shadow)), nil
}
