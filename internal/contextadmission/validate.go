package contextadmission

import (
	"crypto/ed25519"
	"encoding/base64"
	"reflect"
	"regexp"
	"reverse-artex/internal/actioncontext"
	"reverse-artex/internal/casememory"
	"reverse-artex/internal/contextlearning"
	"reverse-artex/internal/contextshadow"
	"sort"
	"time"
)

var pin = regexp.MustCompile(`^[a-f0-9]{64}$`)
var identifier = regexp.MustCompile(`^[A-Za-z0-9_.:/{}-]{1,128}$`)

func validAuthorities(t casememory.LearningTrust) bool {
	if t.Schema != "case-learning-trust/1" || !identifier.MatchString(t.Tenant) || t.Revision < 1 || len(t.Keys) != 3 {
		return false
	}
	ids, actors, pubs, roles := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, k := range t.Keys {
		pub, err := base64.StdEncoding.Strict().DecodeString(k.PublicKey)
		if err != nil || len(pub) != ed25519.PublicKeySize || k.Revoked || !identifier.MatchString(k.ID) || !identifier.MatchString(k.Actor) || ids[k.ID] || actors[k.Actor] || pubs[string(pub)] || roles[k.Role] || (k.Role != "label_reviewer" && k.Role != "evaluation_custodian" && k.Role != "independent_evaluator") {
			return false
		}
		ids[k.ID], actors[k.Actor], pubs[string(pub)], roles[k.Role] = true, true, true, true
	}
	return true
}

func signed(t casememory.LearningTrust, id, role string, raw []byte, signature string) bool {
	sig, err := base64.StdEncoding.Strict().DecodeString(signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	for _, k := range t.Keys {
		if k.ID == id && k.Role == role && !k.Revoked {
			pub, err := base64.StdEncoding.Strict().DecodeString(k.PublicKey)
			return err == nil && ed25519.Verify(pub, raw, sig)
		}
	}
	return false
}

func validPolicy(p Policy) bool {
	return p.Schema == "case-context-admission-policy/2" && identifier.MatchString(p.Tenant) && p.Revision > 0 &&
		p.Scope == "incident_triage_context/2" && pin.MatchString(p.AuthorityTrustSHA) && pin.MatchString(p.ContextTrustSHA) &&
		p.FeatureSHA == contextlearning.Digest(contextlearning.FeatureNames) && p.RuntimeSHA == contextlearning.RuntimeSHA() &&
		p.AdmissionSHA == SourceSHA() && p.MaximumReportAgeSeconds >= 60 && p.MaximumReportAgeSeconds <= 86400
}

func PolicyTemplate(tenant string, a casememory.LearningTrust, context actioncontext.Trust) (Policy, error) {
	if !identifier.MatchString(tenant) || !validAuthorities(a) || a.Tenant != tenant || context.Validate() != nil {
		return Policy{}, ErrInvalid
	}
	return DefaultPolicy(tenant, casememory.LearningTrustDigest(a), contextlearning.Digest(context)), nil
}

func validCapsule(c contextlearning.Capsule, a casememory.LearningTrust, trust actioncontext.Trust, now time.Time) bool {
	if !validAuthorities(a) || contextshadow.ValidateCandidate(c.Candidate, c.Candidate.SHA, a, trust) != nil ||
		c.Schema != "case-context-quality-capsule/2" || c.SHA != contextlearning.CapsuleSHA(c) ||
		casememory.LearningTrustDigest(c.Authorities) != casememory.LearningTrustDigest(a) {
		return false
	}
	for _, authority := range a.Keys {
		pub, _ := base64.StdEncoding.Strict().DecodeString(authority.PublicKey)
		for _, sensor := range trust.Keys {
			other, _ := base64.StdEncoding.Strict().DecodeString(sensor.PublicKey)
			if string(pub) == string(other) {
				return false
			}
		}
	}
	p := c.Plan
	p.ID = ""
	if c.Plan.Schema != "case-context-quality-plan/2" || c.Plan.ID != contextlearning.Digest(p) ||
		c.Plan.CandidateSHA != c.Candidate.SHA || c.Plan.RuntimeSHA != contextlearning.RuntimeSHA() ||
		c.Plan.FeatureSHA != contextlearning.Digest(contextlearning.FeatureNames) ||
		c.Plan.AuthorityTrustSHA != casememory.LearningTrustDigest(a) || c.Plan.RecipeSHA != c.Candidate.TrainingRecipeSHA ||
		c.Plan.Criteria != casememory.DefaultProductionPolicy(c.Candidate.Tenant, "").Quality ||
		c.Plan.CreatedAt.Before(c.Candidate.CreatedAt) || c.Plan.CreatedAt.After(now) {
		return false
	}
	s := c.Cohort
	if s.Schema != "case-context-cohort/2" || s.PlanID != c.Plan.ID || !identifier.MatchString(s.DatasetID) ||
		!pin.MatchString(s.InputsSHA) || !pin.MatchString(s.GoldSHA) || !pin.MatchString(s.SourceSHA) || !pin.MatchString(s.MembershipSHA) ||
		s.InputsSHA == c.Candidate.TrainingInputsSHA || s.GoldSHA == c.Candidate.TrainingGoldSHA || s.SourceSHA == c.Candidate.TrainingSourceSHA ||
		s.Planned < 1 || s.Planned > 512 || s.Families < 1 || s.Families > 32 || s.SourceGroups < 1 || s.SourceGroups > 512 ||
		s.TrainingOverlap != 0 || s.IssuedAt.Before(c.Plan.CreatedAt) || s.IssuedAt.After(now) ||
		!signed(a, s.KeyID, "evaluation_custodian", contextlearning.SealBytes(s), s.Signature) {
		return false
	}
	return true
}

func validCounts(c casememory.QualityCounts) bool {
	values := []int{c.Attack, c.Benign, c.TrueAttack, c.FalseBenign, c.TrueBenign, c.FalseAttack}
	for _, n := range values {
		if n < 0 || n > 512 {
			return false
		}
	}
	return c.Attack+c.Benign <= 512 && c.TrueAttack+c.FalseBenign == c.Attack && c.TrueBenign+c.FalseAttack == c.Benign
}

func sameClasses(a, b casememory.QualityCounts) bool {
	return a.Attack == b.Attack && a.Benign == b.Benign
}
func incumbent(c casememory.QualityCounts, failures int) bool {
	// A missing/failed prediction is kept as a false negative in the frozen
	// scorer's reference counts too. With zero failures the reference is exact.
	return c.FalseBenign <= failures && c.TrueBenign == 0 && c.FalseAttack == c.Benign
}
func add(a *casememory.QualityCounts, b casememory.QualityCounts) {
	a.Attack += b.Attack
	a.Benign += b.Benign
	a.TrueAttack += b.TrueAttack
	a.FalseBenign += b.FalseBenign
	a.TrueBenign += b.TrueBenign
	a.FalseAttack += b.FalseAttack
}

func reportReasons(c contextlearning.Capsule, r contextlearning.Report) ([]string, bool) {
	if r.Schema != "case-context-quality-report/2" || r.PlanID != c.Plan.ID || r.CapsuleSHA != c.SHA ||
		r.InputsSHA != c.Cohort.InputsSHA || r.GoldSHA != c.Cohort.GoldSHA || !pin.MatchString(r.PredictionsSHA) ||
		r.ExternalIndependenceProven || r.ProductionApproval || r.Planned != c.Cohort.Planned ||
		r.Scored < 0 || r.Scored > r.Planned || r.Unknown < 0 || r.Unknown > r.Planned || r.Failures < 0 || r.Failures > r.Planned ||
		r.Scored+r.Unknown > r.Planned || r.Failures < r.Planned-r.Scored-r.Unknown || r.Failures > r.Planned-r.Scored || r.MaximumCaseMilliseconds < 0 ||
		!validCounts(r.Candidate) || !validCounts(r.Incumbent) || !sameClasses(r.Candidate, r.Incumbent) ||
		r.Candidate.Attack+r.Candidate.Benign+r.Unknown != r.Planned || !incumbent(r.Incumbent, r.Failures) ||
		r.StartedAt.Before(c.Cohort.IssuedAt) || r.FinishedAt.Before(r.StartedAt) || r.StartedAt.IsZero() ||
		len(r.ByFamily) != c.Cohort.Families || len(r.ByFamily) > 32 {
		return nil, false
	}
	var total, reference casememory.QualityCounts
	planned, names := 0, []string{}
	for _, f := range r.ByFamily {
		if !identifier.MatchString(f.Family) || f.Planned < 1 || f.Planned > 512 || !validCounts(f.Candidate) ||
			!validCounts(f.Incumbent) || !sameClasses(f.Candidate, f.Incumbent) || !incumbent(f.Incumbent, r.Failures) ||
			f.Candidate.Attack+f.Candidate.Benign > f.Planned {
			return nil, false
		}
		planned += f.Planned
		names = append(names, f.Family)
		add(&total, f.Candidate)
		add(&reference, f.Incumbent)
	}
	if !sort.StringsAreSorted(names) || planned != r.Planned || total != r.Candidate || reference != r.Incumbent {
		return nil, false
	}
	for i := 1; i < len(names); i++ {
		if names[i] == names[i-1] {
			return nil, false
		}
	}
	fn := casememory.ErrorUpperBPS(r.Candidate.FalseBenign, r.Candidate.Attack)
	fp := casememory.ErrorUpperBPS(r.Candidate.FalseAttack, r.Candidate.Benign)
	if r.FalseBenignUpperBPS != fn || r.FalseAttackUpperBPS != fp {
		return nil, false
	}
	q := c.Plan.Criteria
	reasons := []string{}
	if r.Planned < q.MinimumCases {
		reasons = append(reasons, "insufficient_cases")
	}
	if r.Candidate.Attack < q.MinimumAttack || r.Candidate.Benign < q.MinimumBenign {
		reasons = append(reasons, "insufficient_classes")
	}
	if len(r.ByFamily) < q.MinimumFamilies || c.Cohort.SourceGroups < q.MinimumSourceGroups {
		reasons = append(reasons, "insufficient_groups")
	}
	if r.Scored*10000 < r.Planned*q.MinimumCoverageBPS {
		reasons = append(reasons, "coverage_below_minimum")
	}
	if r.Failures != 0 {
		reasons = append(reasons, "failed_or_missing_predictions")
	}
	if r.MaximumCaseMilliseconds > q.MaximumCaseMilliseconds {
		reasons = append(reasons, "latency_above_maximum")
	}
	if fn > q.MaximumFalseBenignUpperBPS {
		reasons = append(reasons, "false_benign_confidence_bound")
	}
	if fp > q.MaximumFalseAttackUpperBPS {
		reasons = append(reasons, "false_attack_confidence_bound")
	}
	if r.Candidate.FalseBenign > r.Incumbent.FalseBenign || r.Candidate.FalseAttack > r.Incumbent.FalseAttack {
		reasons = append(reasons, "incumbent_regression")
	}
	if r.Candidate.FalseBenign+r.Candidate.FalseAttack >= r.Incumbent.FalseBenign+r.Incumbent.FalseAttack {
		reasons = append(reasons, "no_measured_improvement")
	}
	for _, f := range r.ByFamily {
		if f.Candidate.Attack == 0 || f.Candidate.Benign == 0 || f.Candidate.FalseBenign > f.Incumbent.FalseBenign || f.Candidate.FalseAttack > f.Incumbent.FalseAttack {
			reasons = append(reasons, "family_coverage_or_regression")
			break
		}
	}
	if r.Passed != (len(reasons) == 0) || !reflect.DeepEqual(r.Reasons, reasons) {
		return nil, false
	}
	return reasons, true
}

// Assess requires operator-pinned current trust; self-contained capsule keys
// cannot grant their own admission. A successful check still needs separate
// release approval, canary and serving integration; DeploymentAllowed is false.
func Assess(p Policy, c contextlearning.Capsule, e Endorsement, authorities casememory.LearningTrust, context actioncontext.Trust, now time.Time) (Decision, error) {
	if now.IsZero() || !validPolicy(p) || p.Tenant != c.Candidate.Tenant ||
		p.AuthorityTrustSHA != casememory.LearningTrustDigest(authorities) || p.ContextTrustSHA != contextlearning.Digest(context) ||
		!validCapsule(c, authorities, context, now) || e.Schema != "case-context-independent-quality/2" ||
		e.Tenant != p.Tenant || e.TrustSHA != p.AuthorityTrustSHA || e.CapsuleSHA != c.SHA ||
		!pin.MatchString(e.CheckpointSHA) || e.IssuedAt.Before(e.Report.FinishedAt) || e.IssuedAt.After(now) ||
		e.ExpiresAt.Before(e.IssuedAt) || e.ExpiresAt.Equal(e.IssuedAt) || e.ExpiresAt.Sub(e.IssuedAt) > 24*time.Hour ||
		!signed(authorities, e.KeyID, "independent_evaluator", SigningBytes(e), e.Signature) {
		return Decision{}, ErrInvalid
	}
	numeric, ok := reportReasons(c, e.Report)
	if !ok {
		return Decision{}, ErrInvalid
	}
	reasons := append([]string{}, numeric...)
	if !p.Enabled {
		reasons = append(reasons, "admission_policy_disabled")
	}
	if !c.Cohort.IndependentCustody {
		reasons = append(reasons, "independent_custody_not_attested")
	}
	if !c.Cohort.RuntimeGoldDenied {
		reasons = append(reasons, "runtime_gold_denial_not_attested")
	}
	if !e.Independent {
		reasons = append(reasons, "independent_evaluation_not_attested")
	}
	if !e.Isolation {
		reasons = append(reasons, "evaluator_isolation_not_attested")
	}
	until := minTime(e.ExpiresAt, e.Report.FinishedAt.Add(time.Duration(p.MaximumReportAgeSeconds)*time.Second))
	if !now.Before(until) {
		reasons = append(reasons, "quality_evidence_expired")
	}
	d := Decision{Schema: "case-context-admission-decision/2", Tenant: p.Tenant, PolicySHA: contextlearning.Digest(p),
		CapsuleSHA: c.SHA, CandidateSHA: c.Candidate.SHA, ModelSHA: c.Candidate.ModelSHA, FeatureSHA: p.FeatureSHA,
		RuntimeSHA: p.RuntimeSHA, AdmissionSHA: p.AdmissionSHA, ContextTrustSHA: p.ContextTrustSHA,
		AuthorityTrustSHA: p.AuthorityTrustSHA, ReportSHA: contextlearning.Digest(e.Report),
		EndorsementSHA: contextlearning.Digest(e), CheckpointSHA: e.CheckpointSHA, NumericPassed: len(numeric) == 0,
		State: "BLOCKED", Reasons: reasons, CheckedAt: now.UTC(), ValidUntil: until, Accepted: len(reasons) == 0}
	if d.Accepted {
		d.State = "QUALITY_ACCEPTED_RELEASE_APPROVAL_REQUIRED"
	}
	d.SHA = DecisionSHA(d)
	return d, nil
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
