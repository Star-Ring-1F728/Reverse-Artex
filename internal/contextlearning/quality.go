package contextlearning

import (
	"encoding/json"
	"reverse-artex/internal/casememory"
	"sort"
	"time"
)

func domain(prefix string, v any) []byte {
	b, _ := json.Marshal(v)
	return append([]byte(prefix), b...)
}

type Plan struct {
	Schema            string                     `json:"schema"`
	ID                string                     `json:"plan_id"`
	CandidateSHA      string                     `json:"candidate_sha256"`
	RuntimeSHA        string                     `json:"runtime_source_sha256"`
	FeatureSHA        string                     `json:"feature_schema_sha256"`
	AuthorityTrustSHA string                     `json:"authority_trust_sha256"`
	RecipeSHA         string                     `json:"recipe_sha256"`
	Criteria          casememory.QualityCriteria `json:"criteria"`
	CreatedAt         time.Time                  `json:"created_at"`
}
type Seal struct {
	Schema             string    `json:"schema"`
	PlanID             string    `json:"plan_id"`
	DatasetID          string    `json:"dataset_id"`
	InputsSHA          string    `json:"inputs_sha256"`
	GoldSHA            string    `json:"gold_sha256"`
	SourceSHA          string    `json:"source_snapshot_sha256"`
	MembershipSHA      string    `json:"membership_sha256"`
	Planned            int       `json:"planned"`
	Families           int       `json:"families"`
	SourceGroups       int       `json:"source_groups"`
	TrainingOverlap    int       `json:"training_overlap"`
	IndependentCustody bool      `json:"independent_custody_attested"`
	RuntimeGoldDenied  bool      `json:"runtime_gold_access_denied_attested"`
	KeyID              string    `json:"key_id"`
	IssuedAt           time.Time `json:"issued_at"`
	Signature          string    `json:"signature_base64"`
}

func SealBytes(s Seal) []byte { s.Signature = ""; return domain("reverse-artex/context-cohort/2\n", s) }

type Capsule struct {
	Schema      string                   `json:"schema"`
	Candidate   Candidate                `json:"candidate"`
	Plan        Plan                     `json:"plan"`
	Authorities casememory.LearningTrust `json:"authorities"`
	Cohort      Seal                     `json:"cohort"`
	SHA         string                   `json:"capsule_sha256"`
}

func CapsuleSHA(c Capsule) string { c.SHA = ""; return Digest(c) }
func validateCandidate(c Candidate) error {
	if c.Schema != "case-context-candidate/2" || c.SHA != CandidateSHA(c) || c.RuntimeSHA != RuntimeSHA() || c.FeatureSHA != Digest(FeatureNames) || c.ModelSHA != Digest(c.Model) || !validModel(c.Model) || c.DeploymentAllowed || !identifier.MatchString(c.Tenant) || !pin.MatchString(c.ContextTrustSHA) || !pin.MatchString(c.TrainingRecipeSHA) || !pin.MatchString(c.TrainingSourceSHA) || !pin.MatchString(c.TrainingInputsSHA) || !pin.MatchString(c.TrainingGoldSHA) || !pin.MatchString(c.ReviewSHA) || !pin.MatchString(c.ReviewTrustSHA) || c.CreatedAt.IsZero() || len(c.TrainingEvidence) == 0 || len(c.TrainingEvidence) > 4096 || !sort.StringsAreSorted(c.TrainingEvidence) {
		return ErrInvalid
	}
	last := ""
	for _, k := range c.TrainingEvidence {
		if !pin.MatchString(k) || k == last {
			return ErrInvalid
		}
		last = k
	}
	return nil
}
func Freeze(c Candidate, trust casememory.LearningTrust, recipeSHA string) (Plan, error) {
	if !validAuthorities(trust) || validateCandidate(c) != nil || trust.Tenant != c.Tenant || !pin.MatchString(recipeSHA) || c.TrainingRecipeSHA != recipeSHA {
		return Plan{}, ErrInvalid
	}
	p := Plan{Schema: "case-context-quality-plan/2", CandidateSHA: c.SHA, RuntimeSHA: RuntimeSHA(), FeatureSHA: Digest(FeatureNames), AuthorityTrustSHA: casememory.LearningTrustDigest(trust), RecipeSHA: recipeSHA, Criteria: casememory.DefaultProductionPolicy(c.Tenant, "").Quality, CreatedAt: time.Now().UTC()}
	p.ID = Digest(p)
	return p, nil
}
func validateCapsule(c Capsule) error {
	if !validAuthorities(c.Authorities) || validateCandidate(c.Candidate) != nil || c.Schema != "case-context-quality-capsule/2" || c.SHA != CapsuleSHA(c) {
		return ErrInvalid
	}
	p := c.Plan
	p.ID = ""
	if c.Plan.ID != Digest(p) || c.Plan.Criteria != casememory.DefaultProductionPolicy(c.Candidate.Tenant, "").Quality || c.Plan.Schema != "case-context-quality-plan/2" || c.Plan.CandidateSHA != c.Candidate.SHA || c.Plan.RuntimeSHA != RuntimeSHA() || c.Plan.FeatureSHA != Digest(FeatureNames) || c.Plan.CreatedAt.Before(c.Candidate.CreatedAt) || c.Authorities.Tenant != c.Candidate.Tenant || c.Plan.AuthorityTrustSHA != casememory.LearningTrustDigest(c.Authorities) {
		return ErrInvalid
	}
	s := c.Cohort
	if s.Schema != "case-context-cohort/2" || s.PlanID != c.Plan.ID || s.IssuedAt.Before(c.Plan.CreatedAt) || !s.RuntimeGoldDenied || s.TrainingOverlap != 0 || !verify(c.Authorities, s.KeyID, "evaluation_custodian", SealBytes(s), s.Signature) {
		return ErrInvalid
	}
	return nil
}
func validateHeldout(c Capsule, in Inputs) error {
	if validateCapsule(c) != nil || validateInputs(in, "holdout", c.Candidate.TrainingEvidence) != nil {
		return ErrInvalid
	}
	s := c.Cohort
	if in.CreatedAt.Before(c.Plan.CreatedAt) || in.RecipeSHA != c.Plan.RecipeSHA || s.IssuedAt.Before(in.CreatedAt) || in.Tenant != c.Candidate.Tenant || in.ContextTrustSHA != c.Candidate.ContextTrustSHA || in.SourceSHA == c.Candidate.TrainingSourceSHA || in.SourceSHA != s.SourceSHA || Digest(in) == c.Candidate.TrainingInputsSHA || Digest(in) != s.InputsSHA || in.DatasetID != s.DatasetID || len(in.Rows) != s.Planned {
		return ErrInvalid
	}
	keys := []string{}
	families, groups := map[string]bool{}, map[string]bool{}
	for _, r := range in.Rows {
		keys = append(keys, r.EvidenceKeys...)
		families[r.Family] = true
		groups[r.SourceGroup] = true
	}
	sort.Strings(keys)
	if Digest(keys) != s.MembershipSHA || len(families) != s.Families || len(groups) != s.SourceGroups {
		return ErrInvalid
	}
	return nil
}

type Prediction struct {
	ID         string `json:"id"`
	Candidate  string `json:"candidate"`
	Incumbent  string `json:"incumbent"`
	Status     string `json:"status"`
	DurationMS int    `json:"duration_ms"`
}
type Predictions struct {
	Schema     string       `json:"schema"`
	CapsuleSHA string       `json:"capsule_sha256"`
	InputsSHA  string       `json:"inputs_sha256"`
	StartedAt  time.Time    `json:"started_at"`
	FinishedAt time.Time    `json:"finished_at"`
	Rows       []Prediction `json:"rows"`
}

func Run(c Capsule, in Inputs) (Predictions, error) {
	if validateHeldout(c, in) != nil {
		return Predictions{}, ErrInvalid
	}
	p := Predictions{Schema: "case-context-predictions/2", CapsuleSHA: c.SHA, InputsSHA: Digest(in), StartedAt: time.Now().UTC(), Rows: []Prediction{}}
	for _, r := range in.Rows {
		start := time.Now()
		v, _ := Predict(c.Candidate.Model, r.Features)
		p.Rows = append(p.Rows, Prediction{r.ID, v, "suspicious", "ok", int(time.Since(start) / time.Millisecond)})
	}
	p.FinishedAt = time.Now().UTC()
	return p, nil
}

type Report struct {
	Schema                     string                     `json:"schema"`
	PlanID                     string                     `json:"plan_id"`
	CapsuleSHA                 string                     `json:"capsule_sha256"`
	InputsSHA                  string                     `json:"inputs_sha256"`
	GoldSHA                    string                     `json:"gold_sha256"`
	PredictionsSHA             string                     `json:"predictions_sha256"`
	Planned                    int                        `json:"planned"`
	Scored                     int                        `json:"scored"`
	Unknown                    int                        `json:"unknown"`
	Failures                   int                        `json:"failures"`
	MaximumCaseMilliseconds    int                        `json:"maximum_case_milliseconds"`
	Candidate                  casememory.QualityCounts   `json:"candidate"`
	Incumbent                  casememory.QualityCounts   `json:"incumbent"`
	ByFamily                   []casememory.FamilyQuality `json:"by_family"`
	FalseBenignUpperBPS        int                        `json:"false_benign_upper_bps"`
	FalseAttackUpperBPS        int                        `json:"false_attack_upper_bps"`
	StartedAt                  time.Time                  `json:"started_at"`
	FinishedAt                 time.Time                  `json:"finished_at"`
	Passed                     bool                       `json:"passed"`
	Reasons                    []string                   `json:"reasons"`
	ExternalIndependenceProven bool                       `json:"external_independence_proven"`
	ProductionApproval         bool                       `json:"production_approval"`
}

func add(c *casememory.QualityCounts, y, p string) {
	if y == "confirmed_attack" {
		c.Attack++
		if p == "suspicious" {
			c.TrueAttack++
		} else {
			c.FalseBenign++
		}
	} else {
		c.Benign++
		if p == "benign" {
			c.TrueBenign++
		} else {
			c.FalseAttack++
		}
	}
}
func Score(c Capsule, in Inputs, g Gold, p Predictions) (Report, error) {
	if validateHeldout(c, in) != nil || Digest(g) != c.Cohort.GoldSHA || Digest(g) == c.Candidate.TrainingGoldSHA || p.Schema != "case-context-predictions/2" || p.CapsuleSHA != c.SHA || p.InputsSHA != Digest(in) || p.StartedAt.Before(c.Cohort.IssuedAt) || p.FinishedAt.Before(p.StartedAt) || len(p.Rows) > len(in.Rows) {
		return Report{}, ErrInvalid
	}
	y, e := labels(in, g)
	if e != nil {
		return Report{}, e
	}
	known := map[string]bool{}
	for _, row := range in.Rows {
		known[row.ID] = true
	}
	preds := map[string]Prediction{}
	for _, r := range p.Rows {
		if !known[r.ID] || preds[r.ID].ID != "" {
			return Report{}, ErrInvalid
		}
		preds[r.ID] = r
	}
	r := Report{Schema: "case-context-quality-report/2", PlanID: c.Plan.ID, CapsuleSHA: c.SHA, InputsSHA: Digest(in), GoldSHA: Digest(g), PredictionsSHA: Digest(p), Planned: len(in.Rows), ByFamily: []casememory.FamilyQuality{}, StartedAt: p.StartedAt, FinishedAt: p.FinishedAt, Reasons: []string{}}
	families := map[string]*casememory.FamilyQuality{}
	for _, row := range in.Rows {
		f := families[row.Family]
		if f == nil {
			f = &casememory.FamilyQuality{Family: row.Family}
			families[row.Family] = f
		}
		f.Planned++
		got, ok := preds[row.ID]
		expected, _ := Predict(c.Candidate.Model, row.Features)
		success := ok && got.Status == "ok" && got.Candidate == expected && got.Incumbent == "suspicious" && got.DurationMS >= 0 && got.DurationMS <= 30000
		if !success {
			r.Failures++
			got.Candidate = ""
			got.Incumbent = ""
		}
		r.MaximumCaseMilliseconds = max(r.MaximumCaseMilliseconds, got.DurationMS)
		label := y[row.ID]
		if label == "uncertain" || label == "disputed" {
			r.Unknown++
			continue
		}
		if success {
			r.Scored++
		}
		add(&r.Candidate, label, got.Candidate)
		add(&r.Incumbent, label, got.Incumbent)
		add(&f.Candidate, label, got.Candidate)
		add(&f.Incumbent, label, got.Incumbent)
	}
	names := []string{}
	for name := range families {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		r.ByFamily = append(r.ByFamily, *families[name])
	}
	q := c.Plan.Criteria
	if r.Planned < q.MinimumCases || r.Planned > 512 {
		r.Reasons = append(r.Reasons, "insufficient_cases")
	}
	if r.Candidate.Attack < q.MinimumAttack || r.Candidate.Benign < q.MinimumBenign {
		r.Reasons = append(r.Reasons, "insufficient_classes")
	}
	if len(families) < q.MinimumFamilies || c.Cohort.SourceGroups < q.MinimumSourceGroups {
		r.Reasons = append(r.Reasons, "insufficient_groups")
	}
	if r.Scored*10000 < r.Planned*q.MinimumCoverageBPS {
		r.Reasons = append(r.Reasons, "coverage_below_minimum")
	}
	if r.Failures != 0 {
		r.Reasons = append(r.Reasons, "failed_or_missing_predictions")
	}
	if r.MaximumCaseMilliseconds > q.MaximumCaseMilliseconds {
		r.Reasons = append(r.Reasons, "latency_above_maximum")
	}
	r.FalseBenignUpperBPS = casememory.ErrorUpperBPS(r.Candidate.FalseBenign, r.Candidate.Attack)
	r.FalseAttackUpperBPS = casememory.ErrorUpperBPS(r.Candidate.FalseAttack, r.Candidate.Benign)
	if r.FalseBenignUpperBPS > q.MaximumFalseBenignUpperBPS {
		r.Reasons = append(r.Reasons, "false_benign_confidence_bound")
	}
	if r.FalseAttackUpperBPS > q.MaximumFalseAttackUpperBPS {
		r.Reasons = append(r.Reasons, "false_attack_confidence_bound")
	}
	if r.Candidate.FalseBenign > r.Incumbent.FalseBenign || r.Candidate.FalseAttack > r.Incumbent.FalseAttack {
		r.Reasons = append(r.Reasons, "incumbent_regression")
	}
	if r.Candidate.FalseBenign+r.Candidate.FalseAttack >= r.Incumbent.FalseBenign+r.Incumbent.FalseAttack {
		r.Reasons = append(r.Reasons, "no_measured_improvement")
	}
	for _, f := range r.ByFamily {
		if f.Candidate.Attack == 0 || f.Candidate.Benign == 0 || f.Candidate.FalseBenign > f.Incumbent.FalseBenign || f.Candidate.FalseAttack > f.Incumbent.FalseAttack {
			r.Reasons = append(r.Reasons, "family_coverage_or_regression")
			break
		}
	}
	r.Passed = len(r.Reasons) == 0
	return r, nil
}

type Attestation struct {
	Schema      string    `json:"schema"`
	Report      Report    `json:"report"`
	TrustSHA    string    `json:"trust_sha256"`
	Independent bool      `json:"independence_attested"`
	Isolation   bool      `json:"isolation_attested"`
	KeyID       string    `json:"key_id"`
	IssuedAt    time.Time `json:"issued_at"`
	Signature   string    `json:"signature_base64"`
}

func AttestationBytes(a Attestation) []byte {
	a.Signature = ""
	return domain("reverse-artex/context-quality-attestation/2\n", a)
}

func VerifyAttestation(c Capsule, a Attestation) error {
	if validateCapsule(c) != nil || a.Schema != "case-context-quality-attestation/2" || a.TrustSHA != c.Plan.AuthorityTrustSHA || a.Independent || !a.Isolation || a.Report.ExternalIndependenceProven || a.Report.ProductionApproval || a.Report.PlanID != c.Plan.ID || a.Report.CapsuleSHA != c.SHA || a.IssuedAt.Before(a.Report.FinishedAt) || !verify(c.Authorities, a.KeyID, "independent_evaluator", AttestationBytes(a), a.Signature) {
		return ErrInvalid
	}
	return nil
}
