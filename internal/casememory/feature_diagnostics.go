package casememory

// FeatureDiagnostics contains aggregates only. It never returns feature values,
// row IDs, labels, fitted lookup rules, or a replacement prediction/model.
type FeatureDiagnostics struct {
	Schema                string   `json:"schema"`
	Scope                 string   `json:"scope"`
	Cases                 int      `json:"cases"`
	Attack                int      `json:"attack"`
	Benign                int      `json:"benign"`
	Unknown               int      `json:"unknown"`
	FeatureGroups         int      `json:"feature_groups"`
	MixedGroups           int      `json:"mixed_label_feature_groups"`
	MixedRows             int      `json:"rows_in_mixed_groups"`
	UnavoidableErrors     int      `json:"minimum_empirical_errors_any_deterministic_classifier"`
	AllowedFalseBenign    int      `json:"allowed_false_benign_at_frozen_bound"`
	AllowedFalseAttack    int      `json:"allowed_false_attack_at_frozen_bound"`
	MinimumFalseAttack    int      `json:"minimum_false_attack_with_false_benign_budget"`
	GlobalBoundsFeasible  bool     `json:"necessary_global_bounds_feasible"`
	Reasons               []string `json:"reasons"`
	ProductionApproval    bool     `json:"production_approval"`
	IndependentEvaluation bool     `json:"independent_evaluation"`
}

type featureLabel struct {
	vector [featureCount]int
	label  string
}
type featureCounts struct{ attack, benign int }

func errorBudget(total, maximum int) int {
	budget := -1
	for n := 0; n <= total; n++ {
		if ErrorUpperBPS(n, total) <= maximum {
			budget = n
		}
	}
	return budget
}

// diagnoseFeatures is an optimistic empirical feasibility bound, not a learner.
// Each identical vector must receive the same binary prediction. A DP considers
// all assignments without revealing any assignment or returning a lookup model.
// A failed bound rules out even an overfitted deterministic classifier on these
// rows. Feasibility proves neither generalization nor the other quality gates.
func diagnoseFeatures(rows []featureLabel, criteria QualityCriteria, scope string) (FeatureDiagnostics, error) {
	r := FeatureDiagnostics{Schema: "case-feature-diagnostics/1", Scope: scope, Cases: len(rows), Reasons: []string{}, MinimumFalseAttack: -1}
	if len(rows) > MaxCases || !validQualityCriteria(criteria) {
		return FeatureDiagnostics{}, ErrInvalid
	}
	groups := map[[featureCount]int]featureCounts{}
	for _, row := range rows {
		if !validVector(row.vector) || !validLabel(row.label) {
			return FeatureDiagnostics{}, ErrInvalid
		}
		g := groups[row.vector]
		switch row.label {
		case "confirmed_attack":
			g.attack++
			r.Attack++
		case "confirmed_benign":
			g.benign++
			r.Benign++
		default:
			r.Unknown++
			continue
		}
		groups[row.vector] = g
	}
	r.FeatureGroups = len(groups)
	for _, g := range groups {
		if g.attack > 0 && g.benign > 0 {
			r.MixedGroups++
			r.MixedRows += g.attack + g.benign
		}
		r.UnavoidableErrors += min(g.attack, g.benign)
	}
	r.AllowedFalseBenign = errorBudget(r.Attack, criteria.MaximumFalseBenignUpperBPS)
	r.AllowedFalseAttack = errorBudget(r.Benign, criteria.MaximumFalseAttackUpperBPS)
	if r.Attack < criteria.MinimumAttack || r.Benign < criteria.MinimumBenign || r.AllowedFalseBenign < 0 || r.AllowedFalseAttack < 0 {
		r.Reasons = append(r.Reasons, "insufficient_confirmed_class_support")
	}
	if r.Unknown > 0 {
		r.Reasons = append(r.Reasons, "unresolved_labels")
	}
	if r.AllowedFalseBenign >= 0 && r.AllowedFalseAttack >= 0 {
		const impossible = MaxCases + 1
		dp := make([]int, r.AllowedFalseBenign+1)
		for n := 1; n < len(dp); n++ {
			dp[n] = impossible
		}
		for _, g := range groups {
			next := make([]int, len(dp))
			for n := range next {
				next[n] = impossible
			}
			for fn, fp := range dp {
				if fp == impossible {
					continue
				}
				next[fn] = min(next[fn], fp+g.benign)
				if fn+g.attack < len(next) {
					next[fn+g.attack] = min(next[fn+g.attack], fp)
				}
			}
			dp = next
		}
		best := impossible
		for _, fp := range dp {
			best = min(best, fp)
		}
		if best != impossible {
			r.MinimumFalseAttack = best
		}
		if best > r.AllowedFalseAttack {
			r.Reasons = append(r.Reasons, "identical_features_cannot_meet_error_bounds")
		}
	}
	r.GlobalBoundsFeasible = len(r.Reasons) == 0
	return r, nil
}

type CandidateFeatureDiagnostics struct {
	CandidateID  string             `json:"candidate_id"`
	CandidateSHA string             `json:"candidate_sha256"`
	FeatureSHA   string             `json:"feature_schema_sha256"`
	PolicySHA    string             `json:"criteria_policy_sha256"`
	Reevaluation bool               `json:"reevaluation_required"`
	SelectedRows int                `json:"selected_rows"`
	FitExcluded  int                `json:"fit_excluded_rows"`
	Fit          FeatureDiagnostics `json:"fit"`
}

// CandidateFeatureDiagnostics is read-only and considers exactly the frozen fit
// rows. Fit caps/exclusions stay visible; no holdout is silently used for fitting.
func (s *Store) CandidateFeatureDiagnostics(tenant, id string) (CandidateFeatureDiagnostics, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return CandidateFeatureDiagnostics{}, err
	}
	c, ok := s.candidates[id]
	if !ok || c.Tenant != tenant {
		return CandidateFeatureDiagnostics{}, ErrNotFound
	}
	policy, ok := s.productionPolicies[tenant]
	if !ok {
		policy = DefaultProductionPolicy(tenant, "")
	}
	rows := []featureLabel{}
	excluded := 0
	for _, row := range c.Rows {
		if row.Exclusion != "" {
			excluded++
			continue
		}
		rows = append(rows, featureLabel{row.Features, row.Label})
	}
	d, err := diagnoseFeatures(rows, policy.Quality, "frozen_training_fit_only_not_holdout")
	if err != nil {
		return CandidateFeatureDiagnostics{}, err
	}
	view := s.candidateView(c)
	return CandidateFeatureDiagnostics{c.ID, c.SHA, c.FeatureSHA, hash(policy), view.Reevaluation, len(c.Rows), excluded, d}, nil
}

type QualityFeatureDiagnostics struct {
	CapsuleSHA          string             `json:"capsule_sha256"`
	PlanID              string             `json:"plan_id"`
	InputsSHA           string             `json:"inputs_sha256"`
	GoldSHA             string             `json:"gold_sha256"`
	CohortFeedbackSpent bool               `json:"cohort_feedback_spent"`
	Diagnostics         FeatureDiagnostics `json:"diagnostics"`
}

// DiagnoseQualityFeatures is a label-reading, scorer-only post-evaluation tool.
// It cannot sign/admit a quality report or modify the frozen model/quality gate.
func DiagnoseQualityFeatures(c QualityCapsule, input QualityInputs, gold QualityGold, prior QualityReport) (QualityFeatureDiagnostics, error) {
	if err := validateQualityInputs(c, input); err != nil {
		return QualityFeatureDiagnostics{}, err
	}
	if err := validateQualityReport(prior, c); err != nil {
		return QualityFeatureDiagnostics{}, err
	}
	if gold.Schema != "case-quality-gold/1" || gold.DatasetID != input.DatasetID || hash(gold) != c.Cohort.Statement.GoldSHA || len(gold.Rows) != len(input.Rows) {
		return QualityFeatureDiagnostics{}, ErrInvalid
	}
	vectors := map[string][featureCount]int{}
	for _, row := range input.Rows {
		vectors[row.ID] = row.Features
	}
	seen := map[string]bool{}
	rows := []featureLabel{}
	for _, row := range gold.Rows {
		v, ok := vectors[row.ID]
		if !ok || seen[row.ID] || !validLabel(row.Value) {
			return QualityFeatureDiagnostics{}, ErrInvalid
		}
		seen[row.ID] = true
		rows = append(rows, featureLabel{v, row.Value})
	}
	d, err := diagnoseFeatures(rows, c.Plan.Criteria, "spent_cohort_posthoc_not_independent_evaluation")
	if err != nil {
		return QualityFeatureDiagnostics{}, err
	}
	return QualityFeatureDiagnostics{c.SHA, c.Plan.ID, hash(input), hash(gold), true, d}, nil
}
