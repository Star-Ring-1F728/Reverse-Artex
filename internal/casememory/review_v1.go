package casememory

// Persisted v1 local-review criteria. Future behavior must use a new schema
// while retaining this replay contract. Passing is never deployment authority.
func assessReviewV1(plan ReviewPlan, snapshot *ShadowSnapshot) ReviewAssessment {
	a := ReviewAssessment{Schema: "case-shadow-review-assessment/1", Reasons: []string{}}
	if snapshot == nil {
		a.Reasons = append(a.Reasons, "observation_required")
		return a
	}
	a.Total, a.Scored, a.Comparison = snapshot.Total, snapshot.Scored, snapshot.Comparison
	m := a.Comparison.Candidate
	a.Attack = m.TrueAttack + m.FalseBenign
	a.Benign = m.TrueBenign + m.FalseAttack
	if a.Total > 0 {
		a.CoverageBPS = a.Scored * 10000 / a.Total
	}
	if !snapshot.At.Before(plan.RegisteredAt) {
		a.ObservationSeconds = int(snapshot.At.Sub(plan.RegisteredAt).Seconds())
	} else {
		a.Reasons = append(a.Reasons, "observation_precedes_review_plan")
	}
	c := plan.Criteria
	if a.Attack < c.MinimumAttack {
		a.Reasons = append(a.Reasons, "insufficient_confirmed_attack")
	}
	if a.Benign < c.MinimumBenign {
		a.Reasons = append(a.Reasons, "insufficient_confirmed_benign")
	}
	if a.ObservationSeconds < c.MinimumSeconds {
		a.Reasons = append(a.Reasons, "observation_window_too_short")
	}
	if a.Total == 0 || a.Scored*10000 < c.MinimumCoverageBPS*a.Total {
		a.Reasons = append(a.Reasons, "label_coverage_below_minimum")
	}
	if m.FalseBenign > a.Comparison.Reference.FalseBenign {
		a.Reasons = append(a.Reasons, "false_benign_regression")
	}
	if m.FalseAttack > a.Comparison.Reference.FalseAttack {
		a.Reasons = append(a.Reasons, "false_attack_regression")
	}
	if a.Benign == 0 || m.FalseAttack*10000 > c.MaximumFalseAttackBPS*a.Benign {
		a.Reasons = append(a.Reasons, "false_attack_rate_above_maximum")
	}
	a.CriteriaMet = len(a.Reasons) == 0
	return a
}
