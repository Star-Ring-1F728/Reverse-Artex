package casememory

import (
	"math"
	"reflect"
	"sort"
	"time"
)

func LearningDocumentDigest(v any) string          { return hash(v) }
func QualityCapsuleDigest(c QualityCapsule) string { c.SHA = ""; return hash(c) }
func validLearningModel(m CandidateModel) bool {
	if m.Kind == "all_alerts_suspicious" {
		return m.Feature == -1 && m.Threshold == 0 && !m.SuspiciousAbove
	}
	return m.Kind == "case-metadata-stump/1" && m.Feature >= 0 && m.Feature < featureCount && m.Threshold >= 0 && m.Threshold <= 86401
}
func validVector(v [featureCount]int) bool {
	for i, n := range v {
		limit := 1024
		if i == 2 {
			limit = 86400
		}
		if n < 0 || n > limit {
			return false
		}
	}
	return true
}
func PredictLearningVector(m CandidateModel, v [featureCount]int) (string, error) {
	if !validLearningModel(m) || !validVector(v) {
		return "", ErrInvalid
	}
	if m.suspicious(v) {
		return "suspicious", nil
	}
	return "benign", nil
}
func validQualityCriteria(c QualityCriteria) bool {
	return c.MinimumCases >= 24 && c.MinimumCases <= 512 && c.MinimumAttack >= 1 && c.MinimumAttack <= 512 && c.MinimumBenign >= 1 && c.MinimumBenign <= 512 && c.MinimumAttack+c.MinimumBenign <= 512 && c.MinimumFamilies >= 3 && c.MinimumFamilies <= 32 && c.MinimumSourceGroups >= 3 && c.MinimumSourceGroups <= 512 && c.MinimumCoverageBPS >= 1 && c.MinimumCoverageBPS <= 10000 && c.MaximumFalseBenignUpperBPS >= 0 && c.MaximumFalseBenignUpperBPS <= 10000 && c.MaximumFalseAttackUpperBPS >= 0 && c.MaximumFalseAttackUpperBPS <= 10000 && c.MaximumCaseMilliseconds >= 1 && c.MaximumCaseMilliseconds <= 30000
}
func validCanaryCriteria(c CanaryCriteria) bool {
	return c.MinimumCases >= 2 && c.MinimumCases <= 512 && c.MinimumAttack >= 1 && c.MinimumAttack <= 512 && c.MinimumBenign >= 1 && c.MinimumBenign <= 512 && c.MinimumAttack+c.MinimumBenign <= 512 && c.MinimumSeconds >= 0 && c.MinimumSeconds <= 604800 && c.MinimumCoverageBPS >= 1 && c.MinimumCoverageBPS <= 10000 && c.MaximumFalseBenignUpperBPS >= 0 && c.MaximumFalseBenignUpperBPS <= 10000 && c.MaximumFalseAttackUpperBPS >= 0 && c.MaximumFalseAttackUpperBPS <= 10000
}

// One-sided 95% Wilson upper bound. It assumes independent Bernoulli samples;
// custodian provenance is separately attested, never inferred from a signature.
func ErrorUpperBPS(errors, total int) int {
	if total <= 0 || errors < 0 || errors > total {
		return 10000
	}
	n := float64(total)
	q := float64(errors) / n
	z := 1.6448536269514722
	z2 := z * z
	upper := (q + z2/(2*n) + z*math.Sqrt(q*(1-q)/n+z2/(4*n*n))) / (1 + z2/n)
	return int(math.Min(10000, math.Ceil(upper*10000)))
}
func validCounts(c QualityCounts) bool {
	return c.Attack >= 0 && c.Attack <= 512 && c.Benign >= 0 && c.Benign <= 512 && c.Attack+c.Benign <= 512 && c.TrueAttack >= 0 && c.TrueAttack <= 512 && c.FalseBenign >= 0 && c.FalseBenign <= 512 && c.TrueBenign >= 0 && c.TrueBenign <= 512 && c.FalseAttack >= 0 && c.FalseAttack <= 512 && c.TrueAttack+c.FalseBenign == c.Attack && c.TrueBenign+c.FalseAttack == c.Benign
}
func addCount(c *QualityCounts, label, prediction string) {
	if label == "confirmed_attack" {
		c.Attack++
		if prediction == "suspicious" {
			c.TrueAttack++
		} else {
			c.FalseBenign++
		}
	} else if label == "confirmed_benign" {
		c.Benign++
		if prediction == "benign" {
			c.TrueBenign++
		} else {
			c.FalseAttack++
		}
	}
}
func qualityReasons(r QualityReport, c QualityCriteria) []string {
	reasons := []string{}
	if r.Planned < c.MinimumCases || r.Planned > 512 {
		reasons = append(reasons, "insufficient_planned_cases")
	}
	if r.Candidate.Attack < c.MinimumAttack {
		reasons = append(reasons, "insufficient_attack")
	}
	if r.Candidate.Benign < c.MinimumBenign {
		reasons = append(reasons, "insufficient_benign")
	}
	if r.Families < c.MinimumFamilies || r.SourceGroups < c.MinimumSourceGroups {
		reasons = append(reasons, "insufficient_independent_groups")
	}
	if r.Planned == 0 || r.Scored*10000 < c.MinimumCoverageBPS*r.Planned {
		reasons = append(reasons, "coverage_below_minimum")
	}
	if r.Failures != 0 {
		reasons = append(reasons, "failed_or_missing_predictions")
	}
	if r.MaximumCaseMilliseconds > c.MaximumCaseMilliseconds {
		reasons = append(reasons, "latency_above_maximum")
	}
	if ErrorUpperBPS(r.Candidate.FalseBenign, r.Candidate.Attack) > c.MaximumFalseBenignUpperBPS {
		reasons = append(reasons, "false_benign_confidence_bound")
	}
	if ErrorUpperBPS(r.Candidate.FalseAttack, r.Candidate.Benign) > c.MaximumFalseAttackUpperBPS {
		reasons = append(reasons, "false_attack_confidence_bound")
	}
	if r.Candidate.FalseBenign > r.Incumbent.FalseBenign || r.Candidate.FalseAttack > r.Incumbent.FalseAttack {
		reasons = append(reasons, "incumbent_regression")
	}
	if r.Candidate.FalseBenign+r.Candidate.FalseAttack >= r.Incumbent.FalseBenign+r.Incumbent.FalseAttack {
		reasons = append(reasons, "no_measured_improvement")
	}
	for _, family := range r.ByFamily {
		if family.Candidate.Attack == 0 || family.Candidate.Benign == 0 || family.Candidate.FalseBenign > family.Incumbent.FalseBenign || family.Candidate.FalseAttack > family.Incumbent.FalseAttack {
			reasons = append(reasons, "family_coverage_or_regression")
			break
		}
	}
	return reasons
}
func validateCapsule(c QualityCapsule) error {
	plan := c.Plan
	copy := plan
	copy.ID = ""
	cohort := c.Cohort
	cohort.SHA = ""
	if c.Schema != "case-quality-capsule/1" || c.SHA != QualityCapsuleDigest(c) || hash(c.ForbiddenEvidence) != plan.TrainingEvidenceSHA || plan.ID != hash(copy) || plan.RuntimeSHA != ProductionRuntimeSourceSHA() || plan.ModelSHA != hash(c.Model) || plan.IncumbentSHA != hash(plan.Incumbent) || plan.FeatureSHA != hash(featureNames) || !validLearningModel(c.Model) || !validLearningModel(plan.Incumbent) || !validQualityCriteria(plan.Criteria) || c.Cohort.SHA != hash(cohort) || c.Cohort.Statement.PlanID != plan.ID || len(c.ForbiddenEvidence) > 4096 {
		return ErrInvalid
	}
	return nil
}
func validateQualityInputs(c QualityCapsule, input QualityInputs) error {
	if err := validateCapsule(c); err != nil {
		return err
	}
	seal := c.Cohort.Statement
	if input.Schema != "case-quality-inputs/1" || input.DatasetID != seal.DatasetID || hash(input) != seal.InputsSHA || len(input.Rows) != seal.Planned || len(input.Rows) > 512 {
		return ErrInvalid
	}
	forbidden := map[string]bool{}
	for _, v := range c.ForbiddenEvidence {
		forbidden[v] = true
	}
	ids, evidence, families, sources := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, r := range input.Rows {
		if !identity.MatchString(r.ID) || !identity.MatchString(r.Family) || !identity.MatchString(r.SourceGroup) || !digest.MatchString(r.EvidenceSHA) || !validVector(r.Features) || ids[r.ID] || evidence[r.EvidenceSHA] || forbidden[r.EvidenceSHA] {
			return ErrConflict
		}
		if len(r.EvidenceKeys) == 0 || len(r.EvidenceKeys) > 1024 || !sort.StringsAreSorted(r.EvidenceKeys) || r.EvidenceSHA != hash(r.EvidenceKeys) {
			return ErrInvalid
		}
		for _, key := range r.EvidenceKeys {
			if !digest.MatchString(key) || evidence[key] || forbidden[key] {
				return ErrConflict
			}
			evidence[key] = true
		}
		ids[r.ID] = true
		evidence[r.EvidenceSHA] = true
		families[r.Family] = true
		sources[r.SourceGroup] = true
	}
	membership := []string{}
	for _, row := range input.Rows {
		membership = append(membership, row.EvidenceKeys...)
	}
	sort.Strings(membership)
	if hash(membership) != seal.MembershipSHA {
		return ErrInvalid
	}
	if len(families) != seal.Families || len(sources) != seal.SourceGroups || len(families) > 32 {
		return ErrInvalid
	}
	return nil
}

// RunQuality has no gold parameter and consumes only fixed feature vectors.
func RunQuality(c QualityCapsule, input QualityInputs) (QualityPredictions, error) {
	if err := validateQualityInputs(c, input); err != nil {
		return QualityPredictions{}, err
	}
	r := QualityPredictions{Schema: "case-quality-predictions/1", CapsuleSHA: c.SHA, InputsSHA: hash(input), StartedAt: time.Now().UTC(), Rows: []QualityPrediction{}}
	for _, row := range input.Rows {
		start := time.Now()
		prediction, _ := PredictLearningVector(c.Model, row.Features)
		reference, _ := PredictLearningVector(c.Plan.Incumbent, row.Features)
		r.Rows = append(r.Rows, QualityPrediction{ID: row.ID, Status: "ok", Candidate: prediction, Incumbent: reference, DurationMS: int(time.Since(start).Milliseconds())})
	}
	r.FinishedAt = time.Now().UTC()
	return r, nil
}

// ScoreQuality is a distinct, label-reading tool. Missing/failed/tampered
// predictions remain in the denominator and cannot produce a passing report.
func ScoreQuality(c QualityCapsule, input QualityInputs, predictions QualityPredictions, gold QualityGold) (QualityReport, error) {
	if err := validateQualityInputs(c, input); err != nil {
		return QualityReport{}, err
	}
	if gold.Schema != "case-quality-gold/1" || gold.DatasetID != input.DatasetID || hash(gold) != c.Cohort.Statement.GoldSHA || len(gold.Rows) != len(input.Rows) || predictions.Schema != "case-quality-predictions/1" || predictions.CapsuleSHA != c.SHA || predictions.InputsSHA != hash(input) || predictions.StartedAt.Before(c.Cohort.At) || predictions.FinishedAt.Before(predictions.StartedAt) || len(predictions.Rows) > len(input.Rows) {
		return QualityReport{}, ErrInvalid
	}
	labels := map[string]string{}
	known := map[string]bool{}
	for _, row := range input.Rows {
		known[row.ID] = true
	}
	for _, row := range gold.Rows {
		if !known[row.ID] || labels[row.ID] != "" || !validLabel(row.Value) {
			return QualityReport{}, ErrInvalid
		}
		labels[row.ID] = row.Value
	}
	output := map[string]QualityPrediction{}
	for _, row := range predictions.Rows {
		if !known[row.ID] || output[row.ID].ID != "" {
			return QualityReport{}, ErrInvalid
		}
		output[row.ID] = row
	}
	r := QualityReport{Schema: "case-quality-report/1", PlanID: c.Plan.ID, CapsuleSHA: c.SHA, CohortSHA: c.Cohort.SHA, InputsSHA: hash(input), GoldSHA: hash(gold), PredictionsSHA: hash(predictions), RuntimeSHA: c.Plan.RuntimeSHA, Planned: len(input.Rows), Families: c.Cohort.Statement.Families, SourceGroups: c.Cohort.Statement.SourceGroups, StartedAt: predictions.StartedAt, FinishedAt: predictions.FinishedAt, ByFamily: []FamilyQuality{}}
	families := map[string]*FamilyQuality{}
	for _, row := range input.Rows {
		f := families[row.Family]
		if f == nil {
			f = &FamilyQuality{Family: row.Family}
			families[row.Family] = f
		}
		f.Planned++
		got, exists := output[row.ID]
		expected, _ := PredictLearningVector(c.Model, row.Features)
		reference, _ := PredictLearningVector(c.Plan.Incumbent, row.Features)
		successful := exists && got.Status == "ok" && got.Candidate == expected && got.Incumbent == reference && got.DurationMS >= 0 && got.DurationMS <= 30000
		if !successful {
			r.Failures++
			got.Candidate = ""
			got.Incumbent = ""
		}
		if got.DurationMS > r.MaximumCaseMilliseconds {
			r.MaximumCaseMilliseconds = got.DurationMS
		}
		label := labels[row.ID]
		if label == "uncertain" || label == "disputed" {
			r.Unknown++
			continue
		}
		if successful {
			r.Scored++
		}
		addCount(&r.Candidate, label, got.Candidate)
		addCount(&r.Incumbent, label, got.Incumbent)
		addCount(&f.Candidate, label, got.Candidate)
		addCount(&f.Incumbent, label, got.Incumbent)
	}
	names := []string{}
	for name := range families {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		r.ByFamily = append(r.ByFamily, *families[name])
	}
	r.Reasons = qualityReasons(r, c.Plan.Criteria)
	r.Passed = len(r.Reasons) == 0
	return r, nil
}
func validateQualityReport(r QualityReport, c QualityCapsule) error {
	if r.Schema != "case-quality-report/1" || r.PlanID != c.Plan.ID || r.CapsuleSHA != c.SHA || r.CohortSHA != c.Cohort.SHA || r.InputsSHA != c.Cohort.Statement.InputsSHA || r.GoldSHA != c.Cohort.Statement.GoldSHA || !digest.MatchString(r.PredictionsSHA) || r.RuntimeSHA != c.Plan.RuntimeSHA || r.Planned != c.Cohort.Statement.Planned || r.Families != c.Cohort.Statement.Families || r.SourceGroups != c.Cohort.Statement.SourceGroups || r.Failures < 0 || r.Unknown < 0 || r.Scored < 0 || r.Scored+r.Unknown > r.Planned || r.Failures > r.Planned || r.Failures < r.Planned-r.Unknown-r.Scored || r.Failures > r.Planned-r.Scored || r.MaximumCaseMilliseconds < 0 || r.MaximumCaseMilliseconds > 30000 || !validCounts(r.Candidate) || !validCounts(r.Incumbent) || r.Candidate.Attack != r.Incumbent.Attack || r.Candidate.Benign != r.Incumbent.Benign || r.Candidate.Attack+r.Candidate.Benign+r.Unknown != r.Planned || r.StartedAt.Before(c.Cohort.At) || r.FinishedAt.Before(r.StartedAt) || len(r.ByFamily) != r.Families {
		return ErrInvalid
	}
	total := 0
	sumC, sumI := QualityCounts{}, QualityCounts{}
	seen := map[string]bool{}
	for _, f := range r.ByFamily {
		if !identity.MatchString(f.Family) || seen[f.Family] || f.Planned <= 0 || !validCounts(f.Candidate) || !validCounts(f.Incumbent) || f.Candidate.Attack != f.Incumbent.Attack || f.Candidate.Benign != f.Incumbent.Benign || f.Candidate.Attack+f.Candidate.Benign > f.Planned {
			return ErrInvalid
		}
		seen[f.Family] = true
		total += f.Planned
		sumC = sumCounts(sumC, f.Candidate)
		sumI = sumCounts(sumI, f.Incumbent)
	}
	reasons := qualityReasons(r, c.Plan.Criteria)
	if total != r.Planned || sumC != r.Candidate || sumI != r.Incumbent || r.Passed != (len(reasons) == 0) || !reflect.DeepEqual(reasons, r.Reasons) {
		return ErrInvalid
	}
	return nil
}
func sumCounts(a, b QualityCounts) QualityCounts {
	return QualityCounts{a.Attack + b.Attack, a.Benign + b.Benign, a.TrueAttack + b.TrueAttack, a.FalseBenign + b.FalseBenign, a.TrueBenign + b.TrueBenign, a.FalseAttack + b.FalseAttack}
}
