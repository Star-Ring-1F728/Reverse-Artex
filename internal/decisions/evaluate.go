package decisions

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"
)

type QuestionSet struct {
	Schema    string     `json:"schema"`
	Version   string     `json:"version"`
	Questions []Question `json:"questions"`
}

func QuestionDocument() QuestionSet {
	return QuestionSet{"decision-question-set/1", QuestionVersion, Questions()}
}

type Manifest struct {
	Schema      string            `json:"schema"`
	Purpose     string            `json:"purpose"`
	DatasetID   string            `json:"dataset_id"`
	QuestionSHA string            `json:"question_set_sha256"`
	Files       map[string]string `json:"files"`
}
type EvaluationCase struct {
	ID             string `json:"id"`
	Family         string `json:"family"`
	Input          Input  `json:"input"`
	RequiredReview bool   `json:"required_review"`
}
type EvaluationInputs struct {
	Schema string           `json:"schema"`
	Cases  []EvaluationCase `json:"cases"`
}
type EvaluationLabels struct {
	Schema string            `json:"schema"`
	Cases  map[string]string `json:"cases"`
}
type Dataset struct {
	Manifest    Manifest
	ManifestSHA string
	Cases       []EvaluationCase
	labels      map[string]string
	path        string
	files       map[string]string
}

func bytesHash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func boundedFile(path string, limit int64) ([]byte, error) {
	abs, e := filepath.Abs(path)
	if e != nil {
		return nil, e
	}
	real, e := filepath.EvalSymlinks(abs)
	if e != nil {
		return nil, e
	}
	if real != abs {
		return nil, errors.New("canonical non-symlink input required")
	}
	f, e := os.Open(abs)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil {
		return nil, e
	}
	if !st.Mode().IsRegular() || st.Size() > limit {
		return nil, errors.New("bounded regular input required")
	}
	b, e := io.ReadAll(io.LimitReader(f, limit+1))
	if e != nil {
		return nil, e
	}
	if int64(len(b)) > limit {
		return nil, errors.New("input byte limit")
	}
	return b, nil
}
func LoadDataset(path string, expectedSHA string) (*Dataset, error) {
	raw, e := boundedFile(path, 64<<10)
	if e != nil {
		return nil, e
	}
	if expectedSHA != "" && (!ValidHash(expectedSHA) || bytesHash(raw) != expectedSHA) {
		return nil, errors.New("public manifest pin mismatch")
	}
	var m Manifest
	if e = DecodeStrict(raw, &m, 64<<10); e != nil {
		return nil, e
	}
	if m.Schema != "decisions-public-evaluation/1" || m.Purpose != "public_synthetic_calibration" || !id.MatchString(m.DatasetID) || m.QuestionSHA != QuestionHash() || len(m.Files) != 3 {
		return nil, errors.New("public synthetic dataset required; holdout input prohibited")
	}
	files := map[string][]byte{}
	for _, name := range []string{"inputs.json", "labels.json", "questions.json"} {
		digest := m.Files[name]
		if !ValidHash(digest) {
			return nil, errors.New("fixed public file set required")
		}
		b, e := boundedFile(filepath.Join(filepath.Dir(path), name), 256<<10)
		if e != nil {
			return nil, e
		}
		if bytesHash(b) != digest {
			return nil, errors.New("public payload hash differs")
		}
		files[name] = b
	}
	var questions QuestionSet
	if e = DecodeStrict(files["questions.json"], &questions, MaxWire); e != nil {
		return nil, e
	}
	if Hash(questions) != Hash(QuestionDocument()) {
		return nil, errors.New("question definitions or rubric differ")
	}
	var inputs EvaluationInputs
	var labels EvaluationLabels
	if e = DecodeStrict(files["inputs.json"], &inputs, 256<<10); e != nil {
		return nil, e
	}
	if e = DecodeStrict(files["labels.json"], &labels, 256<<10); e != nil {
		return nil, e
	}
	if inputs.Schema != "decision-evaluation-inputs/1" || labels.Schema != "decision-evaluation-labels/1" || len(inputs.Cases) < 1 || len(inputs.Cases) > 64 || len(labels.Cases) != len(inputs.Cases) {
		return nil, errors.New("bounded complete public cohort required")
	}
	seen := map[string]bool{}
	for _, c := range inputs.Cases {
		if !id.MatchString(c.ID) || !id.MatchString(c.Family) || c.Input.CaseID != c.ID || seen[c.ID] || c.Input.Validate() != nil || (c.Input.Observation.NeedsReview() && !c.RequiredReview) {
			return nil, errors.New("case scope or required review invalid")
		}
		seen[c.ID] = true
		switch labels.Cases[c.ID] {
		case "benign", "suspicious", "needs_review", "insufficient_evidence":
		default:
			return nil, errors.New("public label missing or invalid")
		}
	}
	d := &Dataset{Manifest: m, ManifestSHA: bytesHash(raw), Cases: inputs.Cases, labels: labels.Cases, path: path, files: m.Files}
	return d, d.Unchanged()
}
func (d *Dataset) Unchanged() error {
	b, e := boundedFile(d.path, 64<<10)
	if e != nil {
		return e
	}
	if bytesHash(b) != d.ManifestSHA {
		return errors.New("manifest changed during evaluation")
	}
	for _, name := range []string{"inputs.json", "labels.json", "questions.json"} {
		b, e = boundedFile(filepath.Join(filepath.Dir(d.path), name), 256<<10)
		if e != nil {
			return e
		}
		if bytesHash(b) != d.files[name] {
			return errors.New("payload changed during evaluation")
		}
	}
	return nil
}

type Fraction struct {
	Numerator   int      `json:"numerator"`
	Denominator int      `json:"denominator"`
	Value       *float64 `json:"value"`
}

func fraction(n, d int) Fraction {
	r := Fraction{Numerator: n, Denominator: d}
	if d > 0 {
		v := float64(n) / float64(d)
		r.Value = &v
	}
	return r
}

type Metrics struct {
	Planned             int                       `json:"planned"`
	Statuses            map[string]int            `json:"statuses"`
	Confusion           map[string]map[string]int `json:"confusion"`
	DefinitiveCoverage  Fraction                  `json:"definitive_coverage"`
	SuspiciousPrecision Fraction                  `json:"suspicious_precision"`
	SuspiciousRecall    Fraction                  `json:"suspicious_recall_all_positive_labels"`
	Deferred            int                       `json:"deferred"`
	Failed              int                       `json:"failed"`
	FalseBenign         int                       `json:"false_benign"`
	RequiredReviews     Fraction                  `json:"required_reviews_preserved"`
	Brier               *float64                  `json:"suspicious_brier_score"`
	CalibrationEligible int                       `json:"calibration_eligible_binary_labels"`
	CalibrationObserved int                       `json:"calibration_observed"`
	CalibrationMissing  int                       `json:"calibration_missing"`
	WallP50NS           int64                     `json:"local_scripted_wall_p50_ns"`
	WallP95NS           int64                     `json:"local_scripted_wall_p95_ns"`
}
type EvaluationRow struct {
	ID             string `json:"id"`
	Family         string `json:"family"`
	Label          string `json:"public_label"`
	Prediction     string `json:"prediction"`
	Status         string `json:"status"`
	Route          string `json:"shadow_route"`
	RequiredReview bool   `json:"required_review"`
	ElapsedNS      int64  `json:"local_scripted_wall_ns"`
	Result         Result `json:"result"`
}
type EvaluationReport struct {
	Schema                string             `json:"schema"`
	DatasetID             string             `json:"dataset_id"`
	ManifestSHA           string             `json:"manifest_sha256"`
	QuestionSHA           string             `json:"question_set_sha256"`
	Candidate             string             `json:"candidate"`
	Metrics               Metrics            `json:"metrics"`
	Families              map[string]Metrics `json:"families"`
	Rows                  []EvaluationRow    `json:"rows"`
	ActualModelCalls      int                `json:"actual_model_calls"`
	ActualCost            *float64           `json:"actual_model_cost"`
	UsageKnown            bool               `json:"model_usage_known"`
	IndependentHoldout    bool               `json:"independent_holdout"`
	OperationalAcceptance bool               `json:"operational_acceptance"`
	ClaimBoundary         string             `json:"claim_boundary"`
}

// Evaluate never supplies labels, family or required-review flags to the
// classifier. All planned cases, including failed and deferred ones, are kept.
func Evaluate(d *Dataset, candidate string) (EvaluationReport, error) {
	scenario := "ok"
	switch candidate {
	case "rules-v1", "scripted-v1":
	case "forced-benign":
		scenario = "benign"
	case "refused", "timeout", "rate_limited", "invalid", "stale", "error":
		scenario = candidate
	default:
		return EvaluationReport{}, errors.New("unknown local comparison candidate")
	}
	r := EvaluationReport{Schema: "decision-public-comparison/1", DatasetID: d.Manifest.DatasetID, ManifestSHA: d.ManifestSHA,
		QuestionSHA: QuestionHash(), Candidate: candidate, Rows: []EvaluationRow{}, Families: map[string]Metrics{},
		ClaimBoundary: "Public synthetic, label-informed development fixtures and deterministic scripted baselines only. No model quality, API latency/cost, secrecy or independent acceptance claim."}
	for _, c := range d.Cases {
		start := time.Now()
		prediction, e := Fake(c.Input, scenario, c.Input.Enqueued)
		if e != nil {
			return r, e
		}
		if candidate == "rules-v1" {
			// Intentionally simple counter-only incumbent, with no coverage model.
			base := c.Input
			base.Observation.Coverage = "complete"
			base.Observation.Quality = "complete"
			base.Observation.Truncated = false
			if base.Observation.AttackSignals > 0 {
				base.Observation.BenignSignals = 0
			} else {
				base.Observation.BenignSignals = 1
			}
			prediction, e = Fake(base, "ok", c.Input.Enqueued)
			if e != nil {
				return r, e
			}
			prediction.InputSHA = Hash(c.Input)
		}
		if e = prediction.Validate(c.Input); e != nil {
			return r, e
		}
		row := EvaluationRow{ID: c.ID, Family: c.Family, Label: d.labels[c.ID], Prediction: "unknown", Status: prediction.Status,
			Route: "pending_review", RequiredReview: c.RequiredReview, ElapsedNS: time.Since(start).Nanoseconds(), Result: prediction}
		if prediction.Status == "ok" {
			row.Prediction = prediction.Choice("disposition")
		}
		if !row.RequiredReview && row.Status == "ok" && row.Prediction == "benign" {
			row.Route = "shadow_only"
		}
		r.Rows = append(r.Rows, row)
	}
	r.Metrics = aggregate(r.Rows)
	groups := map[string][]EvaluationRow{}
	for _, row := range r.Rows {
		groups[row.Family] = append(groups[row.Family], row)
	}
	for name, rows := range groups {
		r.Families[name] = aggregate(rows)
	}
	return r, d.Unchanged()
}
func aggregate(rows []EvaluationRow) Metrics {
	m := Metrics{Planned: len(rows), Statuses: map[string]int{}, Confusion: map[string]map[string]int{}}
	definitive, tp, predicted, positive, required, preserved := 0, 0, 0, 0, 0, 0
	brier := 0.0
	durations := []int64{}
	for _, r := range rows {
		m.Statuses[r.Status]++
		if m.Confusion[r.Label] == nil {
			m.Confusion[r.Label] = map[string]int{}
		}
		m.Confusion[r.Label][r.Prediction]++
		if r.Status != "ok" {
			m.Failed++
		} else if r.Prediction == "needs_review" || r.Prediction == "insufficient_evidence" {
			m.Deferred++
		} else {
			definitive++
		}
		if r.Label == "suspicious" {
			positive++
		}
		if r.Prediction == "suspicious" {
			predicted++
			if r.Label == "suspicious" {
				tp++
			}
		}
		if r.Prediction == "benign" && r.Label == "suspicious" {
			m.FalseBenign++
		}
		if r.RequiredReview {
			required++
			if r.Route == "pending_review" {
				preserved++
			}
		}
		if r.Label == "benign" || r.Label == "suspicious" {
			m.CalibrationEligible++
			if r.Status == "ok" {
				for _, a := range r.Result.Answers {
					if a.Name == "disposition" {
						target := 0.0
						if r.Label == "suspicious" {
							target = 1
						}
						err := a.Distribution["suspicious"] - target
						brier += err * err
						m.CalibrationObserved++
					}
				}
			}
		}
		durations = append(durations, r.ElapsedNS)
	}
	m.DefinitiveCoverage = fraction(definitive, len(rows))
	m.SuspiciousPrecision = fraction(tp, predicted)
	m.SuspiciousRecall = fraction(tp, positive)
	m.RequiredReviews = fraction(preserved, required)
	m.CalibrationMissing = m.CalibrationEligible - m.CalibrationObserved
	if m.CalibrationObserved > 0 {
		v := brier / float64(m.CalibrationObserved)
		m.Brier = &v
	}
	sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
	if len(durations) > 0 {
		m.WallP50NS = durations[(len(durations)-1)/2]
		m.WallP95NS = durations[(len(durations)*95+99)/100-1]
	}
	return m
}
