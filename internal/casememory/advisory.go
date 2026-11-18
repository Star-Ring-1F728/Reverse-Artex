package casememory

import (
	"crypto/sha256"
	"embed"
	"encoding/binary"
	"reflect"
	"strings"
	"time"
)

const MaxAdvisoryChanges = 32

//go:embed advisory.go automatic.go verified.go
var advisorySources embed.FS

// This selects local metadata-model suggestions only. It cannot authorize a
// provider, guard bypass, response intent or production model deployment.
type AdvisoryRequest struct {
	Expected    int    `json:"expected_revision"`
	Action      string `json:"action"`
	RunID       string `json:"run_id"`
	ReviewSHA   string `json:"review_decision_sha256"`
	SnapshotSHA string `json:"shadow_snapshot_sha256"`
	Percent     int    `json:"percent"`
	Reason      string `json:"reason"`
}

type AdvisoryChange struct {
	Authorization  *AdvisoryAuthorization `json:"authorization,omitempty"`
	Schema         string                 `json:"schema"`
	Tenant         string                 `json:"tenant_id"`
	Revision       int                    `json:"revision"`
	Previous       string                 `json:"previous_sha256"`
	Request        AdvisoryRequest        `json:"request"`
	CandidateID    string                 `json:"candidate_id"`
	ModelSHA       string                 `json:"model_sha256"`
	SourceSHA      string                 `json:"advisory_source_sha256"`
	CohortSequence int                    `json:"cohort_start_journal_sequence"`
	At             time.Time              `json:"changed_at"`
	SHA            string                 `json:"change_sha256"`
}

type AdvisorySuggestion struct {
	CaseID     string `json:"case_id"`
	CaseSHA    string `json:"prediction_case_sha256"`
	Prediction string `json:"suggested_disposition"`
	Route      string `json:"route"`
	Bucket     int    `json:"bucket"`
	Status     string `json:"shadow_status"`
}

type AdvisoryView struct {
	Revision                      int                  `json:"revision"`
	State                         string               `json:"state"`
	Current                       *AdvisoryChange      `json:"current"`
	History                       []AdvisoryChange     `json:"history"`
	Blockers                      []string             `json:"blockers"`
	SnapshotSHA                   string               `json:"projection_shadow_snapshot_sha256"`
	Suggestions                   []AdvisorySuggestion `json:"suggestions"`
	CanaryAssessment              *ReviewAssessment    `json:"canary_assessment"`
	ReviewStale                   bool                 `json:"latest_review_stale"`
	IndependentEvaluation         bool                 `json:"independent_evaluation"`
	DeploymentAllowed             bool                 `json:"deployment_allowed"`
	VerifiedAuthorizationRequired bool                 `json:"verified_authorization_required"`
}

func advisorySourceSHA() string {
	values := []string{}
	for _, name := range []string{"advisory.go", "automatic.go", "verified.go"} {
		raw, _ := advisorySources.ReadFile(name)
		values = append(values, name, hash(raw))
	}
	return hash(values)
}

// Stable within a candidate's shadow run, independent of labels/features.
func advisoryBucket(run, tenant, id string) int {
	sum := sha256.Sum256([]byte(hash([]string{"advisory-bucket/1", run, tenant, id})))
	return int(binary.BigEndian.Uint64(sum[:8]) % 100)
}

func (s *Store) makeAdvisory(tenant string, q AdvisoryRequest, at time.Time, source string) (AdvisoryChange, error) {
	history := s.advisory[tenant]
	c := AdvisoryChange{Schema: "case-advisory-change/1", Tenant: tenant, Revision: len(history) + 1, Request: q, SourceSHA: source, At: at}
	if len(history) > 0 {
		c.Previous = history[len(history)-1].SHA
	}
	if q.Action != "stop" {
		shadow, ok := s.shadows[q.RunID]
		if !ok || shadow.Plan.Tenant != tenant {
			return c, ErrNotFound
		}
		c.CandidateID, c.ModelSHA = shadow.Plan.CandidateID, shadow.Plan.ModelSHA
		c.CohortSequence = s.sequence + 1
		if q.Action == "activate" && len(history) > 0 {
			c.CohortSequence = history[len(history)-1].CohortSequence
		}
		if q.Action == "rollback" {
			for _, old := range history {
				if old.Request.Action == "activate" && old.Request.RunID == q.RunID {
					c.CohortSequence = old.CohortSequence
				}
			}
		}
	}
	c.SHA = hash(c)
	return c, nil
}

func (s *Store) canaryAssessment(change AdvisoryChange) ReviewAssessment {
	state := s.shadows[change.Request.RunID]
	snapshot := reviewSnapshot(state)
	p := s.reviews[change.Request.RunID].Plan
	p.RegisteredAt = change.At
	if snapshot == nil {
		return assessReviewV1(p, nil)
	}
	selected := *snapshot
	selected.Rows = nil
	selected.Total = 0
	selected.Scored = 0
	selected.Awaiting = 0
	selected.Excluded = 0
	scored := []CandidateRow{}
	for _, row := range snapshot.Rows {
		if row.PredictionSequence <= change.CohortSequence || advisoryBucket(change.Request.RunID, change.Tenant, row.CaseID) >= change.Request.Percent {
			continue
		}
		selected.Total++
		switch row.Status {
		case "scored":
			selected.Scored++
			scored = append(scored, CandidateRow{Features: row.Features, Label: row.Label})
		case "awaiting_label":
			selected.Awaiting++
		default:
			selected.Excluded++
		}
	}
	selected.Comparison = CandidateComparison{measure(CandidateModel{Kind: "all_alerts_suspicious", Feature: -1}, scored, false), measure(s.candidates[state.Plan.CandidateID].Model, scored, false)}
	return assessReviewV1(p, &selected)
}

func (s *Store) validateAdvisory(c AdvisoryChange) error {
	q := c.Request
	history := s.advisory[c.Tenant]
	if !identity.MatchString(c.Tenant) || !digest.MatchString(c.SourceSHA) || c.At.IsZero() || !validReason(q.Reason) || strings.TrimSpace(q.Reason) != q.Reason {
		return ErrInvalid
	}
	if len(history) >= MaxAdvisoryChanges || (q.Action != "stop" && len(history) >= MaxAdvisoryChanges-1) {
		return ErrLimit
	}
	if q.Expected != len(history) {
		return ErrConflict
	}
	if len(history) > 0 && c.At.Before(history[len(history)-1].At) {
		return ErrInvalid
	}
	switch q.Action {
	case "stop":
		if q.RunID != "" || q.ReviewSHA != "" || q.SnapshotSHA != "" || q.Percent != 0 {
			return ErrInvalid
		}
	case "canary", "activate", "rollback":
		if !digest.MatchString(q.RunID) || !digest.MatchString(q.ReviewSHA) || !digest.MatchString(q.SnapshotSHA) {
			return ErrInvalid
		}
		shadow, ok := s.shadows[q.RunID]
		if !ok || shadow.Plan.Tenant != c.Tenant {
			return ErrNotFound
		}
		reviews := s.reviews[q.RunID]
		snapshot := reviewSnapshot(shadow)
		if len(reviews.Decisions) == 0 || snapshot == nil {
			return ErrConflict
		}
		decision := reviews.Decisions[len(reviews.Decisions)-1]
		if decision.SHA != q.ReviewSHA || decision.Request.Decision != "approve_for_evaluation" || decision.SnapshotSHA != snapshot.SHA || q.SnapshotSHA != snapshot.SHA ||
			snapshot.InputSHA != s.selectCases(c.Tenant).SHA || len(s.trainingChanges(s.candidates[shadow.Plan.CandidateID])) > 0 || c.At.Before(decision.At) {
			return ErrConflict
		}
		switch q.Action {
		case "canary":
			if q.Percent < 1 || q.Percent > 50 {
				return ErrInvalid
			}
			if len(history) > 0 && history[len(history)-1].Request.Action == "canary" {
				return ErrConflict
			}
		case "activate":
			if q.Percent != 100 || len(history) == 0 {
				return ErrConflict
			}
			prior := history[len(history)-1]
			if prior.Request.Action != "canary" || prior.Request.RunID != q.RunID || !s.canaryAssessment(prior).CriteriaMet {
				return ErrConflict
			}
		case "rollback":
			if q.Percent != 100 {
				return ErrInvalid
			}
			found := false
			for _, old := range history {
				if old.Request.Action == "activate" && old.Request.RunID == q.RunID {
					found = true
				}
			}
			if !found {
				return ErrConflict
			}
		}
	default:
		return ErrInvalid
	}
	if err := s.validateAdvisoryAuthorization(c); err != nil {
		return err
	}
	want, err := s.makeAdvisory(c.Tenant, q, c.At, c.SourceSHA)
	if err != nil {
		return err
	}
	want.Authorization = c.Authorization
	want.SHA = ""
	want.SHA = hash(want)
	if !reflect.DeepEqual(c, want) {
		return ErrInvalid
	}
	return nil
}

func (s *Store) advisoryView(tenant string) AdvisoryView {
	history := s.advisory[tenant]
	v := AdvisoryView{VerifiedAuthorizationRequired: s.trust[tenant].Schema != "", Revision: len(history), State: "stopped", History: append([]AdvisoryChange{}, history...), Blockers: []string{}, Suggestions: []AdvisorySuggestion{}}
	if len(history) == 0 {
		return v
	}
	current := history[len(history)-1]
	v.Current = &current
	if current.Request.Action == "stop" {
		return v
	}
	v.State = current.Request.Action
	if s.trust[tenant].Schema != "" && current.Authorization == nil {
		v.Blockers = append(v.Blockers, "verified_release_authorization_required")
	}
	shadow := s.shadows[current.Request.RunID]
	source := s.shadowView(shadow, 0)
	if source.ReevaluationRequired {
		v.Blockers = append(v.Blockers, "training_or_observer_changed")
	}
	if source.RefreshRequired {
		v.Blockers = append(v.Blockers, "shadow_refresh_required")
	}
	if current.SourceSHA != advisorySourceSHA() {
		v.Blockers = append(v.Blockers, "advisory_implementation_changed")
	}
	reviews := s.reviews[current.Request.RunID].Decisions
	if current.Authorization != nil {
		snapshot := reviewSnapshot(shadow)
		if current.Authorization.Statement.TrustSHA != hash(s.trust[tenant]) {
			v.Blockers = append(v.Blockers, "learning_trust_policy_changed")
		}
		if snapshot == nil || snapshot.SHA != current.Request.SnapshotSHA || len(reviews) == 0 || reviews[len(reviews)-1].SHA != current.Request.ReviewSHA {
			v.Blockers = append(v.Blockers, "signed_release_refresh_required")
		}
	}
	if len(reviews) > 0 && reviews[len(reviews)-1].Request.Decision != "approve_for_evaluation" {
		v.Blockers = append(v.Blockers, "review_withdrawn")
	}
	v.ReviewStale = s.reviewView(shadow).ReviewStale
	if v.ReviewStale {
		v.Blockers = append(v.Blockers, "latest_review_required")
	}
	if current.Request.Action == "canary" {
		a := s.canaryAssessment(current)
		v.CanaryAssessment = &a
	}
	if len(v.Blockers) > 0 {
		v.State = "blocked"
		return v
	}
	snapshot := reviewSnapshot(shadow)
	if snapshot == nil {
		return v
	}
	v.SnapshotSHA = snapshot.SHA
	for _, row := range snapshot.Rows {
		if row.PredictionSequence <= current.CohortSequence {
			continue
		}
		prediction, route := "", "excluded"
		bucket := advisoryBucket(current.Request.RunID, tenant, row.CaseID)
		if row.Status == "scored" || row.Status == "awaiting_label" {
			prediction, route = "suspicious", "reference"
			if bucket < current.Request.Percent {
				prediction, route = row.Prediction, "candidate"
			}
		}
		v.Suggestions = append(v.Suggestions, AdvisorySuggestion{row.CaseID, row.CaseSHA, prediction, route, bucket, row.Status})
	}
	return v
}

func (s *Store) Advisory(tenant string) (AdvisoryView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return AdvisoryView{}, err
	}
	if !identity.MatchString(tenant) {
		return AdvisoryView{}, ErrInvalid
	}
	return clone(s.advisoryView(tenant)), nil
}

func (s *Store) ChangeAdvisory(tenant string, q AdvisoryRequest) (AdvisoryView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return AdvisoryView{}, err
	}
	return s.changeAdvisoryLocked(tenant, q, nil)
}

func (s *Store) changeAdvisoryLocked(tenant string, q AdvisoryRequest, authorization *AdvisoryAuthorization) (AdvisoryView, error) {
	q.Reason = strings.TrimSpace(q.Reason)
	for _, old := range s.advisory[tenant] {
		if old.Request == q && reflect.DeepEqual(old.Authorization, authorization) {
			return clone(s.advisoryView(tenant)), nil
		}
	}
	if q.Action != "stop" {
		shadow, ok := s.shadows[q.RunID]
		if !ok || shadow.Plan.Tenant != tenant {
			return AdvisoryView{}, ErrNotFound
		}
		review := s.reviewView(shadow)
		if review.State != "APPROVED_FOR_EVALUATION" {
			return AdvisoryView{}, ErrConflict
		}
	}
	change, err := s.makeAdvisory(tenant, q, time.Now().UTC(), advisorySourceSHA())
	if err != nil {
		return AdvisoryView{}, err
	}
	change.Authorization = authorization
	change.SHA = ""
	change.SHA = hash(change)
	if err = s.append(record{AdvisoryChange: &change}); err != nil {
		return AdvisoryView{}, err
	}
	return clone(s.advisoryView(tenant)), nil
}
