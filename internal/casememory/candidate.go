package casememory

import (
	"embed"
	"reflect"
	"sort"
	"time"

	"reverse-artex/internal/incident"
)

const MaxCandidates = 64
const featureCount = 14

// Compile-time source bytes pin this local implementation without reading
// arbitrary paths at runtime. They are a local fingerprint, not attestation.
//
//go:embed candidate.go dataset.go store.go verified.go
var trainerSources embed.FS

var featureNames = [featureCount]string{"evidence_count", "alert_count", "duration_seconds_capped_86400", "http_evidence_count", "host_evidence_count", "distinct_rules", "ra001_count", "ra002_count", "ra003_count", "ra004_count", "ra005_count", "ra006_count", "ra007_count", "ra008_count"}

type LearningConfig struct {
	Algorithm string `json:"algorithm"`
	MinClass  int    `json:"minimum_fit_per_class"`
	SourceCap int    `json:"per_snapshot_fit_limit"`
	AssetCap  int    `json:"per_asset_fit_limit"`
	FitCap    int    `json:"fit_limit"`
}

func learningConfig() LearningConfig {
	return LearningConfig{"case-metadata-stump/1", 2, 8, 32, 128}
}

type CandidateModel struct {
	Kind            string `json:"kind"`
	Feature         int    `json:"feature_index"`
	Threshold       int    `json:"threshold"`
	SuspiciousAbove bool   `json:"suspicious_at_or_above"`
}

// Prediction receives only the fixed feature vector; never IDs, labels, hashes,
// reviewer text, tenant names, or exclusion flags.
func (m CandidateModel) suspicious(vector [featureCount]int) bool {
	if m.Kind == "all_alerts_suspicious" {
		return true
	}
	return (vector[m.Feature] >= m.Threshold) == m.SuspiciousAbove
}

type CandidateRow struct {
	CaseID     string            `json:"case_id"`
	CaseSHA    string            `json:"case_sha256"`
	LabelSHA   string            `json:"label_sha256"`
	SourceSHA  string            `json:"source_snapshot_sha256"`
	Asset      string            `json:"asset_id"`
	Label      string            `json:"label"`
	Features   [featureCount]int `json:"features"`
	Exclusion  string            `json:"fit_exclusion_reason,omitempty"`
	Prediction string            `json:"suggested_disposition"`
}

type CandidateMetrics struct {
	Compared    int `json:"compared"`
	TrueAttack  int `json:"true_attack"`
	FalseAttack int `json:"false_attack"`
	TrueBenign  int `json:"true_benign"`
	FalseBenign int `json:"false_benign"`
}

type CandidateComparison struct {
	Reference CandidateMetrics `json:"all_alerts_suspicious_reference"`
	Candidate CandidateMetrics `json:"candidate"`
}

type LearningCandidate struct {
	Schema               string               `json:"schema"`
	ID                   string               `json:"candidate_id"`
	Tenant               string               `json:"tenant_id"`
	CreatedAt            time.Time            `json:"created_at"`
	State                string               `json:"state"`
	TrainingStatus       string               `json:"training_status"`
	Selection            Selection            `json:"selection"`
	DatasetSHA           string               `json:"dataset_sha256"`
	TrainerSHA           string               `json:"trainer_source_sha256"`
	FeatureSHA           string               `json:"feature_schema_sha256"`
	ConfigSHA            string               `json:"config_sha256"`
	ModelSHA             string               `json:"model_sha256"`
	Config               LearningConfig       `json:"config"`
	FeatureNames         [featureCount]string `json:"feature_names"`
	Rows                 []CandidateRow       `json:"rows"`
	FitCount             int                  `json:"fit_count"`
	FitAttack            int                  `json:"fit_attack"`
	FitBenign            int                  `json:"fit_benign"`
	SnapshotGroups       int                  `json:"source_snapshot_groups"`
	Model                CandidateModel       `json:"model"`
	FitComparison        CandidateComparison  `json:"fit_comparison"`
	SelectedComparison   CandidateComparison  `json:"selected_cohort_comparison"`
	EvaluationScope      string               `json:"evaluation_scope"`
	IndependentEvaluated bool                 `json:"independent_evaluation"`
	ReviewRequired       bool                 `json:"review_required"`
	DeploymentAllowed    bool                 `json:"deployment_allowed"`
	SHA                  string               `json:"candidate_sha256"`
}

type CandidateView struct {
	Candidate      LearningCandidate `json:"candidate"`
	Reevaluation   bool              `json:"reevaluation_required"`
	Changed        []string          `json:"changed_cases"`
	TrainerCurrent bool              `json:"trainer_current"`
}

// Lists contain bounded summaries; full rows are retrieved one candidate at a
// time so the 64-candidate capacity cannot exceed the console response budget.
type CandidateSummary struct {
	ID             string    `json:"candidate_id"`
	CreatedAt      time.Time `json:"created_at"`
	TrainingStatus string    `json:"training_status"`
	FitCount       int       `json:"fit_count"`
	Total          int       `json:"selection_total"`
	Reevaluation   bool      `json:"reevaluation_required"`
	ChangedCount   int       `json:"changed_case_count"`
}

func trainerSHA() string {
	values := []string{}
	for _, name := range []string{"candidate.go", "dataset.go", "store.go", "verified.go"} {
		raw, _ := trainerSources.ReadFile(name) // fixed compile-time embed paths
		values = append(values, name, hash(raw))
	}
	return hash(values)
}

func candidateID(dataset, source string) string {
	return hash([]string{dataset, source, hash(learningConfig()), hash(featureNames)})
}

func caseFeatures(c incident.Case) [featureCount]int {
	v := [featureCount]int{len(c.Evidence), len(c.Alerts), int(min(c.Last.Sub(c.First)/time.Second, 86400))}
	for _, e := range c.Evidence {
		if e.Stream == "events" {
			v[3]++
		} else if e.Stream == "host-events" {
			v[4]++
		}
	}
	rules := map[string]bool{}
	for _, a := range c.Alerts {
		rules[a.Rule] = true
		for index, rule := range []string{"RA-001", "RA-002", "RA-003", "RA-004", "RA-005", "RA-006", "RA-007", "RA-008"} {
			if a.Rule == rule {
				v[index+6]++
			}
		}
	}
	v[5] = len(rules)
	return v
}

func measure(model CandidateModel, rows []CandidateRow, fitOnly bool) CandidateMetrics {
	m := CandidateMetrics{}
	for _, row := range rows {
		if fitOnly && row.Exclusion != "" {
			continue
		}
		attack := row.Label == "confirmed_attack"
		predicted := model.suspicious(row.Features)
		m.Compared++
		switch {
		case attack && predicted:
			m.TrueAttack++
		case attack:
			m.FalseBenign++
		case predicted:
			m.FalseAttack++
		default:
			m.TrueBenign++
		}
	}
	return m
}

func trainCandidate(dataset TrainingDataset, at time.Time, source string) LearningCandidate {
	config := learningConfig()
	reference := CandidateModel{Kind: "all_alerts_suspicious", Feature: -1}
	c := LearningCandidate{Schema: "case-learning-candidate/1", ID: candidateID(dataset.SHA, source), Tenant: dataset.Tenant,
		CreatedAt: at, State: "QUARANTINED_LOCAL_ONLY", TrainingStatus: "insufficient_confirmed_classes",
		Selection: dataset.Selection, DatasetSHA: dataset.SHA, TrainerSHA: source, FeatureSHA: hash(featureNames),
		ConfigSHA: hash(config), Config: config, FeatureNames: featureNames, Rows: []CandidateRow{}, Model: reference,
		EvaluationScope: "same_selected_cohort_with_training_overlap", ReviewRequired: true}
	sources, assets, groups := map[string]int{}, map[string]int{}, map[string]bool{}
	for _, sample := range dataset.Samples {
		r := CandidateRow{CaseID: sample.Case.ID, CaseSHA: sample.CaseSHA, LabelSHA: sample.LabelSHA,
			SourceSHA: sample.SourceSHA, Asset: sample.Case.Asset, Label: sample.Label, Features: caseFeatures(sample.Case)}
		groups[r.SourceSHA] = true
		switch {
		case c.FitCount >= config.FitCap:
			r.Exclusion = "fit_limit"
		case sources[r.SourceSHA] >= config.SourceCap:
			r.Exclusion = "snapshot_limit"
		case assets[r.Asset] >= config.AssetCap:
			r.Exclusion = "asset_limit"
		default:
			c.FitCount++
			sources[r.SourceSHA]++
			assets[r.Asset]++
			if r.Label == "confirmed_attack" {
				c.FitAttack++
			} else {
				c.FitBenign++
			}
		}
		c.Rows = append(c.Rows, r)
	}
	c.SnapshotGroups = len(groups)
	best := measure(reference, c.Rows, true)
	if c.FitAttack >= config.MinClass && c.FitBenign >= config.MinClass {
		c.TrainingStatus = "fit_complete"
		for feature := range featureNames {
			thresholds := map[int]bool{0: true}
			for _, row := range c.Rows {
				if row.Exclusion == "" {
					thresholds[row.Features[feature]+1] = true
				}
			}
			ordered := []int{}
			for threshold := range thresholds {
				ordered = append(ordered, threshold)
			}
			sort.Ints(ordered)
			for _, threshold := range ordered {
				for _, above := range []bool{true, false} {
					model := CandidateModel{"case-metadata-stump/1", feature, threshold, above}
					metrics := measure(model, c.Rows, true)
					// Preserve the incumbent on ties. Minimize false benign first;
					// this is a fit objective, never an authorization to deploy.
					if metrics.FalseBenign < best.FalseBenign || metrics.FalseBenign == best.FalseBenign && metrics.FalseAttack < best.FalseAttack {
						best, c.Model = metrics, model
					}
				}
			}
		}
	}
	for i := range c.Rows {
		c.Rows[i].Prediction = "benign"
		if c.Model.suspicious(c.Rows[i].Features) {
			c.Rows[i].Prediction = "suspicious"
		}
	}
	c.ModelSHA = hash(c.Model)
	c.FitComparison = CandidateComparison{measure(reference, c.Rows, true), measure(c.Model, c.Rows, true)}
	c.SelectedComparison = CandidateComparison{measure(reference, c.Rows, false), measure(c.Model, c.Rows, false)}
	c.SHA = hash(c)
	return c
}

// CreateCandidate freezes the exact saved/current selection under the case
// memory lock. Repeating it returns the same immutable candidate, without a new
// journal record. No model/network provider or policy writer is involved.
func (s *Store) CreateCandidate(tenant, selectionSHA string) (CandidateView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !identity.MatchString(tenant) || !digest.MatchString(selectionSHA) {
		return CandidateView{}, ErrInvalid
	}
	dataset, err := s.dataset(tenant, selectionSHA)
	if err != nil {
		return CandidateView{}, err
	}
	key := candidateID(dataset.SHA, trainerSHA())
	if c, ok := s.candidates[key]; ok {
		return clone(s.candidateView(c)), nil
	}
	c := trainCandidate(dataset, time.Now().UTC(), trainerSHA())
	if err := s.append(record{Candidate: &c}); err != nil {
		return CandidateView{}, err
	}
	return clone(s.candidateView(c)), nil
}

func (s *Store) candidateView(c LearningCandidate) CandidateView {
	current := s.selectionFor(c.Selection)
	return candidateView(c, current)
}

func candidateView(c LearningCandidate, current Selection) CandidateView {
	bindings := map[string]Binding{}
	for _, b := range c.Selection.Items {
		bindings[b.CaseID] = b
	}
	changed := []string{}
	for _, b := range current.Items {
		if old, ok := bindings[b.CaseID]; !ok || !reflect.DeepEqual(old, b) {
			changed = append(changed, b.CaseID)
		}
	}
	fresh := c.TrainerSHA == trainerSHA()
	return CandidateView{c, current.SHA != c.Selection.SHA || !fresh, changed, fresh}
}

func (s *Store) Candidate(tenant, id string) (CandidateView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return CandidateView{}, err
	}
	c, ok := s.candidates[id]
	if !ok || c.Tenant != tenant {
		return CandidateView{}, ErrNotFound
	}
	return clone(s.candidateView(c)), nil
}

func (s *Store) Candidates(tenant string) ([]CandidateSummary, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return nil, err
	}
	out := []CandidateSummary{}
	current := s.selectCases(tenant)
	var verified Selection
	for _, c := range s.candidates {
		if c.Tenant == tenant {
			selected := current
			if c.Selection.TrustSHA != "" {
				if verified.Schema == "" {
					verified = s.selectVerified(tenant)
				}
				selected = verified
			}
			view := candidateView(c, selected)
			out = append(out, CandidateSummary{c.ID, c.CreatedAt, c.TrainingStatus, c.FitCount, c.Selection.Total, view.Reevaluation, len(view.Changed)})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return clone(out), nil
}
