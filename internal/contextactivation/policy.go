package contextactivation

import (
	"crypto/ed25519"
	"encoding/base64"
	"regexp"
	"reverse-artex/internal/casememory"
	"reverse-artex/internal/contextadmission"
	"reverse-artex/internal/contextevaluation"
	"reverse-artex/internal/contextlearning"
	"reverse-artex/internal/contextrelease"
	"strings"
	"time"
)

var pin = regexp.MustCompile(`^[a-f0-9]{64}$`)
var identifier = regexp.MustCompile(`^[A-Za-z0-9_.:/{}-]{1,128}$`)

func reasonValid(v string) bool { return strings.TrimSpace(v) != "" && len(v) <= 512 }

func ValidatePolicy(p Policy, c contextrelease.Config) error {
	if contextrelease.ValidateConfig(c) != nil || p.Schema != "case-context-production-policy/2" || p.Tenant != c.Policy.Tenant || !identifier.MatchString(p.Tenant) || p.Revision < 1 || p.Scope != "incident_triage_context/2" || p.SourceSHA != SourceSHA() || len(p.Approvers) < 1 || len(p.Approvers) > 4 {
		return ErrInvalid
	}
	ids, actors, pubs := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, k := range c.Authorities.Keys {
		actors[k.Actor] = true
		raw, _ := base64.StdEncoding.Strict().DecodeString(k.PublicKey)
		pubs[string(raw)] = true
	}
	for _, k := range c.Context.Keys {
		raw, _ := base64.StdEncoding.Strict().DecodeString(k.PublicKey)
		pubs[string(raw)] = true
	}
	for _, k := range c.Policy.Approvers {
		actors[k.Actor] = true
		raw, _ := base64.StdEncoding.Strict().DecodeString(k.PublicKey)
		pubs[string(raw)] = true
	}
	active := false
	for _, k := range p.Approvers {
		raw, e := base64.StdEncoding.Strict().DecodeString(k.PublicKey)
		if e != nil || len(raw) != 32 || !identifier.MatchString(k.ID) || !identifier.MatchString(k.Actor) || k.Role != "context_production_approver" || ids[k.ID] || actors[k.Actor] || pubs[string(raw)] {
			return ErrInvalid
		}
		ids[k.ID], actors[k.Actor], pubs[string(raw)] = true, true, true
		active = active || !k.Revoked
	}
	if !active {
		return ErrInvalid
	}
	return nil
}

// ReviewSHA binds the completed evaluation cohort, current per-case labels,
// predictions and quality decision. Unrelated later incidents and assessment
// timestamps do not invalidate it; a corrected cohort label always does.
func ReviewSHA(r contextevaluation.Report) string {
	r.EvaluatedAt = time.Time{}
	r.SourceSHA = ""
	r.LabelSnapshotSHA = ""
	r.SHA = ""
	r.TenantCases = 0
	r.Excluded = 0
	return contextlearning.Digest(r)
}

func validCounts(c casememory.QualityCounts) bool {
	return c.Attack >= 0 && c.Benign >= 0 && c.TrueAttack >= 0 && c.TrueBenign >= 0 && c.FalseAttack >= 0 && c.FalseBenign >= 0 && c.TrueAttack+c.FalseBenign == c.Attack && c.TrueBenign+c.FalseAttack == c.Benign
}
func validateBasis(b Basis, at time.Time) (time.Time, error) {
	r, v := b.Report, b.Version
	if v.Release.Config == nil || v.Release.Approval == nil || contextlearning.Digest(b.Config) != contextlearning.Digest(*v.Release.Config) || r.Schema != "case-context-canary-evaluation/2" || r.SHA != contextevaluation.ReportSHA(r) || r.EvaluationSHA != contextevaluation.SourceSHA() || !pin.MatchString(r.PlanSHA) || r.ReleaseSHA != v.Release.SHA || r.JournalHead != v.JournalHead || r.Tenant != b.Config.Policy.Tenant || r.CandidateSHA != v.Bundle.Capsule.Candidate.SHA || !r.WindowClosed || !r.CriteriaPassed || !r.ReleaseReviewReady || !r.QualityValidNow || r.State != "CANARY_CRITERIA_MET_SEPARATE_RELEASE_REVIEW_REQUIRED" || r.DeploymentAllowed || r.PolicyMutations != 0 || !r.MandatoryReviewPreserved || len(r.Reasons) != 0 || r.EvaluatedAt.After(at) || r.WindowEnd.After(at) || r.ObservedSpanSeconds < 3600 || r.CoverageBPS != 10000 || r.Unresolved != 0 || r.Unknown != 0 || r.FailedChecks != 0 || r.MaximumBatchMilliseconds > 30000 || r.Scored != r.Planned || r.Planned != len(r.Rows) {
		return time.Time{}, ErrInvalid
	}
	for _, a := range []contextevaluation.Arm{r.CandidateArm, r.ReferenceArm} {
		c := a.Counts
		if !validCounts(c) || a.Planned < 60 || a.Scored != a.Planned || c.Attack < 30 || c.Benign < 30 || a.Scored != c.Attack+c.Benign {
			return time.Time{}, ErrInvalid
		}
	}
	c, a := r.CandidateArm, r.CandidateArm.Counts
	if c.FalseBenignUpperBPS != casememory.ErrorUpperBPS(a.FalseBenign, a.Attack) || c.FalseAttackUpperBPS != casememory.ErrorUpperBPS(a.FalseAttack, a.Benign) || c.FalseBenignUpperBPS > 1000 || c.FalseAttackUpperBPS > 1000 {
		return time.Time{}, ErrInvalid
	}
	x, y := r.PairedCandidate, r.PairedReference
	if !validCounts(x) || !validCounts(y) || x.Attack != y.Attack || x.Benign != y.Benign || x.FalseBenign > y.FalseBenign || x.FalseAttack > y.FalseAttack || x.FalseBenign+x.FalseAttack >= y.FalseBenign+y.FalseAttack {
		return time.Time{}, ErrInvalid
	}
	d, e := contextadmission.Assess(b.Config.Admission, v.Bundle.Capsule, v.Bundle.Endorsement, b.Config.Authorities, b.Config.Context, at)
	if e != nil || !d.Accepted {
		return time.Time{}, ErrInvalid
	}
	return d.ValidUntil, nil
}

func verifyApproval(p Policy, b Basis, a Approval, at time.Time) error {
	until, e := validateBasis(b, at)
	if e != nil || ValidatePolicy(p, b.Config) != nil || !p.Enabled {
		return ErrInvalid
	}
	q := a.Request
	if a.Schema != "case-context-production-approval/2" || a.Tenant != p.Tenant || !a.IndependentReview || !pin.MatchString(a.CheckpointSHA) || q.Action != "activate" && q.Action != "rollback" || q.PolicySHA != contextlearning.Digest(p) || q.BasisSHA != BasisSHA(b) || q.ReviewSHA != ReviewSHA(b.Report) || q.ReleaseSHA != b.Report.ReleaseSHA || q.PlanSHA != b.Report.PlanSHA || q.CandidateSHA != b.Report.CandidateSHA || !at.Before(q.Until) || q.Until.After(until) || !pin.MatchString(q.Nonce) || !reasonValid(q.Reason) || a.IssuedAt.IsZero() || a.IssuedAt.After(at) || !at.Before(a.ExpiresAt) || a.ExpiresAt.Sub(a.IssuedAt) > 15*time.Minute || !a.ExpiresAt.After(a.IssuedAt) {
		return ErrInvalid
	}
	sig, e := base64.StdEncoding.Strict().DecodeString(a.Signature)
	if e != nil || len(sig) != 64 {
		return ErrInvalid
	}
	for _, k := range p.Approvers {
		if k.ID == a.KeyID && !k.Revoked {
			pub, _ := base64.StdEncoding.Strict().DecodeString(k.PublicKey)
			if ed25519.Verify(pub, SigningBytes(a), sig) {
				return nil
			}
		}
	}
	return ErrInvalid
}
