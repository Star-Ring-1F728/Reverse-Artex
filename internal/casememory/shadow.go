package casememory

import (
	"embed"
	"sort"
	"time"

	"reverse-artex/internal/incident"
)

const MaxShadowRuns = 16
const MaxShadowSnapshots = 32

//go:embed shadow.go shadow_v1.go candidate.go dataset.go
var shadowSources embed.FS

type ShadowPlan struct {
	Schema        string    `json:"schema"`
	ID            string    `json:"run_id"`
	Tenant        string    `json:"tenant_id"`
	CandidateID   string    `json:"candidate_id"`
	CandidateSHA  string    `json:"candidate_sha256"`
	ModelSHA      string    `json:"model_sha256"`
	FeatureSHA    string    `json:"feature_schema_sha256"`
	TrainerSHA    string    `json:"trainer_source_sha256"`
	ObserverSHA   string    `json:"observer_source_sha256"`
	StartSequence int       `json:"start_journal_sequence"`
	StartedAt     time.Time `json:"started_at"`
	Baseline      Selection `json:"baseline_selection"`
	SHA           string    `json:"plan_sha256"`
}

type ShadowRow struct {
	CaseID             string            `json:"case_id"`
	CaseSHA            string            `json:"prediction_case_sha256"`
	SourceSHA          string            `json:"prediction_source_snapshot_sha256"`
	PredictedAt        time.Time         `json:"prediction_at"`
	PredictionSequence int               `json:"prediction_journal_sequence"`
	Features           [featureCount]int `json:"features"`
	Prediction         string            `json:"suggested_disposition,omitempty"`
	CaptureExclusion   string            `json:"capture_exclusion_reason,omitempty"`
	Status             string            `json:"status"`
	LabelSHA           string            `json:"label_sha256,omitempty"`
	Label              string            `json:"label,omitempty"`
	LabelRevision      int               `json:"label_revision,omitempty"`
}

type ShadowSnapshot struct {
	Schema                string              `json:"schema"`
	RunID                 string              `json:"run_id"`
	Revision              int                 `json:"revision"`
	JournalSequence       int                 `json:"journal_sequence"`
	Previous              string              `json:"previous_sha256"`
	At                    time.Time           `json:"captured_at"`
	InputSHA              string              `json:"case_memory_selection_sha256"`
	Rows                  []ShadowRow         `json:"rows"`
	Total                 int                 `json:"total"`
	Predicted             int                 `json:"predicted"`
	Scored                int                 `json:"scored"`
	Awaiting              int                 `json:"awaiting_label"`
	Excluded              int                 `json:"excluded"`
	Comparison            CandidateComparison `json:"comparison"`
	IndependentEvaluation bool                `json:"independent_evaluation"`
	DeploymentAllowed     bool                `json:"deployment_allowed"`
	SHA                   string              `json:"snapshot_sha256"`
}

type ShadowHistory struct {
	Revision int       `json:"revision"`
	At       time.Time `json:"captured_at"`
	SHA      string    `json:"snapshot_sha256"`
	Total    int       `json:"total"`
	Scored   int       `json:"scored"`
}

type ShadowView struct {
	Plan                 ShadowPlan      `json:"plan"`
	Snapshot             *ShadowSnapshot `json:"snapshot"`
	History              []ShadowHistory `json:"history"`
	RefreshRequired      bool            `json:"refresh_required"`
	ReevaluationRequired bool            `json:"reevaluation_required"`
	TrainingChanged      []string        `json:"training_changed_cases"`
	TrainerCurrent       bool            `json:"trainer_current"`
	ObserverCurrent      bool            `json:"observer_current"`
}

type ShadowSummary struct {
	ID                   string    `json:"run_id"`
	CandidateID          string    `json:"candidate_id"`
	StartedAt            time.Time `json:"started_at"`
	Revision             int       `json:"revision"`
	Total                int       `json:"total"`
	Scored               int       `json:"scored"`
	RefreshRequired      bool      `json:"refresh_required"`
	ReevaluationRequired bool      `json:"reevaluation_required"`
}

type shadowState struct {
	Plan      ShadowPlan
	Snapshots []ShadowSnapshot
}

func observerSHA() string {
	values := []string{}
	for _, name := range []string{"shadow.go", "shadow_v1.go", "candidate.go", "dataset.go"} {
		raw, _ := shadowSources.ReadFile(name)
		values = append(values, name, hash(raw))
	}
	return hash(values)
}

// New cases are expected during shadow observation. Only changes to the
// original candidate's case/label bindings invalidate its frozen training base.
func (s *Store) trainingChanges(candidate LearningCandidate) []string {
	changed := []string{}
	if candidate.Selection.TrustSHA != "" && candidate.Selection.TrustSHA != hash(s.trust[candidate.Tenant]) {
		changed = append(changed, "learning_trust_policy_changed")
	}
	for _, binding := range candidate.Selection.Items {
		entry, ok := s.cases[caseKey(candidate.Tenant, binding.CaseID)]
		labelSHA := ""
		if len(entry.Labels) > 0 {
			labelSHA = entry.Labels[len(entry.Labels)-1].SHA
		}
		if !ok || entry.Revisions[len(entry.Revisions)-1].SHA != binding.CaseSHA || labelSHA != binding.LabelSHA {
			changed = append(changed, binding.CaseID)
		}
	}
	return changed
}

func (s *Store) shadowPlan(candidate LearningCandidate, at time.Time, source string) ShadowPlan {
	baseline := s.selectCases(candidate.Tenant)
	p := ShadowPlan{Schema: "case-shadow-plan/1", Tenant: candidate.Tenant, CandidateID: candidate.ID,
		CandidateSHA: candidate.SHA, ModelSHA: candidate.ModelSHA, FeatureSHA: candidate.FeatureSHA, TrainerSHA: candidate.TrainerSHA,
		ObserverSHA: source, StartSequence: s.sequence + 1, StartedAt: at, Baseline: baseline}
	p.ID = hash([]string{p.CandidateSHA, baseline.SHA, source})
	p.SHA = hash(p)
	return p
}

func evidenceKey(ref incident.EvidenceRef) string {
	return hash([]string{ref.Stream, ref.Tenant, ref.Asset, ref.EventID, ref.LineSHA})
}

func (s *Store) shadowCases(tenant string) []Entry {
	entries := []Entry{}
	for _, entry := range s.cases {
		if entry.Revisions[0].Case.Tenant == tenant {
			entries = append(entries, entry)
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Revisions[0].Case.ID < entries[j].Revisions[0].Case.ID })
	return entries
}

func (s *Store) shadowSnapshot(state shadowState, candidate LearningCandidate, at time.Time) (ShadowSnapshot, error) {
	switch state.Plan.Schema {
	case "case-shadow-plan/1":
		return s.shadowSnapshotV1(state, candidate, at), nil
	default:
		return ShadowSnapshot{}, ErrInvalid
	}
}

func (s *Store) StartShadow(tenant, candidateID string) (ShadowView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return ShadowView{}, err
	}
	candidate, ok := s.candidates[candidateID]
	if !ok || candidate.Tenant != tenant {
		return ShadowView{}, ErrNotFound
	}
	if candidate.TrainingStatus != "fit_complete" || candidate.TrainerSHA != trainerSHA() || len(s.trainingChanges(candidate)) > 0 {
		return ShadowView{}, ErrConflict
	}
	p := s.shadowPlan(candidate, time.Now().UTC(), observerSHA())
	if old, ok := s.shadows[p.ID]; ok {
		return clone(s.shadowView(old, 0)), nil
	}
	if err := s.append(record{ShadowPlan: &p}); err != nil {
		return ShadowView{}, err
	}
	return clone(s.shadowView(s.shadows[p.ID], 0)), nil
}

func (s *Store) CaptureShadow(tenant, id string) (ShadowView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return ShadowView{}, err
	}
	state, ok := s.shadows[id]
	if !ok || state.Plan.Tenant != tenant {
		return ShadowView{}, ErrNotFound
	}
	view := s.shadowView(state, 0)
	if view.ReevaluationRequired {
		return ShadowView{}, ErrConflict
	}
	if !view.RefreshRequired && len(state.Snapshots) > 0 {
		return clone(view), nil
	}
	snapshot, err := s.shadowSnapshot(state, s.candidates[state.Plan.CandidateID], time.Now().UTC())
	if err != nil {
		return ShadowView{}, err
	}
	if err := s.append(record{ShadowSnapshot: &snapshot}); err != nil {
		return ShadowView{}, err
	}
	return clone(s.shadowView(s.shadows[id], 0)), nil
}

func (s *Store) shadowView(state shadowState, revision int) ShadowView {
	return s.shadowViewAt(state, revision, s.selectCases(state.Plan.Tenant).SHA)
}

func (s *Store) shadowViewAt(state shadowState, revision int, currentSHA string) ShadowView {
	candidate := s.candidates[state.Plan.CandidateID]
	changed := s.trainingChanges(candidate)
	v := ShadowView{Plan: state.Plan, History: []ShadowHistory{}, TrainingChanged: changed,
		TrainerCurrent: candidate.TrainerSHA == trainerSHA(), ObserverCurrent: state.Plan.ObserverSHA == observerSHA()}
	v.ReevaluationRequired = len(changed) > 0 || !v.TrainerCurrent || !v.ObserverCurrent
	input := state.Plan.Baseline.SHA
	for _, snapshot := range state.Snapshots {
		v.History = append(v.History, ShadowHistory{snapshot.Revision, snapshot.At, snapshot.SHA, snapshot.Total, snapshot.Scored})
		if revision == 0 || revision == snapshot.Revision {
			copy := snapshot
			v.Snapshot = &copy
			input = snapshot.InputSHA
		}
	}
	v.RefreshRequired = input != currentSHA || (revision > 0 && revision != len(state.Snapshots))
	return v
}

func (s *Store) Shadow(tenant, id string, revision int) (ShadowView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return ShadowView{}, err
	}
	state, ok := s.shadows[id]
	if !ok || state.Plan.Tenant != tenant || revision < 0 || revision > len(state.Snapshots) {
		return ShadowView{}, ErrNotFound
	}
	return clone(s.shadowView(state, revision)), nil
}

func (s *Store) Shadows(tenant string) ([]ShadowSummary, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return nil, err
	}
	result := []ShadowSummary{}
	currentSHA := s.selectCases(tenant).SHA
	for _, state := range s.shadows {
		if state.Plan.Tenant != tenant {
			continue
		}
		view := s.shadowViewAt(state, 0, currentSHA)
		summary := ShadowSummary{ID: state.Plan.ID, CandidateID: state.Plan.CandidateID, StartedAt: state.Plan.StartedAt, RefreshRequired: view.RefreshRequired, ReevaluationRequired: view.ReevaluationRequired}
		if view.Snapshot != nil {
			summary.Revision = view.Snapshot.Revision
			summary.Total = view.Snapshot.Total
			summary.Scored = view.Snapshot.Scored
		}
		result = append(result, summary)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return clone(result), nil
}
