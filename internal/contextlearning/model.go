package contextlearning

import (
	"crypto/ed25519"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"regexp"
	"reverse-artex/internal/actioncontext"
	"reverse-artex/internal/casememory"
	"reverse-artex/internal/contractjson"
	"reverse-artex/internal/event"
	"sort"
	"sync"
	"time"
)

//go:embed features.go model.go quality.go training.go feedback.go
var sources embed.FS
var identifier = regexp.MustCompile(`^[A-Za-z0-9_.:/{}-]{1,128}$`)
var pin = regexp.MustCompile(`^[a-f0-9]{64}$`)
var runtimeFingerprintOnce sync.Once
var runtimeFingerprint string

func rawSHA(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func RuntimeSHA() string {
	// Embedded source cannot change during a process. Cache its fingerprint,
	// never caller data, label revisions, trust keys or a quality decision.
	runtimeFingerprintOnce.Do(func() {
		v := []string{actioncontext.SourceSHA(), event.ContextContractSHA(), contractjson.SourceSHA(), casememory.ProductionRuntimeSourceSHA()}
		for _, n := range []string{"features.go", "model.go", "quality.go", "training.go", "feedback.go"} {
			b, _ := sources.ReadFile(n)
			v = append(v, n, rawSHA(b))
		}
		runtimeFingerprint = Digest(v)
	})
	return runtimeFingerprint
}

type Model struct {
	Kind      string `json:"kind"`
	Feature   int    `json:"feature_index"`
	Threshold int    `json:"threshold"`
	Above     bool   `json:"suspicious_at_or_above"`
	Rules     []Rule `json:"rules,omitempty"`
}

// Rule contains observable counts only, never case IDs, labels or credentials.
type Rule struct {
	Feature   int  `json:"feature_index"`
	Threshold int  `json:"threshold"`
	Above     bool `json:"suspicious_at_or_above"`
}

const MaxRules = 4

func validRule(r Rule) bool {
	return r.Feature >= 0 && r.Feature < FeatureCount && r.Threshold >= 0 && r.Threshold <= 86401
}

func validVector(v [FeatureCount]int) bool {
	for i, n := range v {
		max := 1024
		if i == 2 {
			max = 86400
		}
		if n < 0 || n > max {
			return false
		}
	}
	return true
}
func validModel(m Model) bool {
	if m.Kind == "context-metadata-rules/3" {
		if m.Feature != -1 || m.Threshold != 0 || m.Above || len(m.Rules) < 2 || len(m.Rules) > MaxRules {
			return false
		}
		for i, r := range m.Rules {
			if !validRule(r) || i > 0 && !ruleLess(m.Rules[i-1], r) {
				return false
			}
		}
		return true
	}
	if len(m.Rules) != 0 {
		return false
	}
	return m.Kind == "all_alerts_suspicious" && m.Feature == -1 && m.Threshold == 0 && !m.Above || m.Kind == "context-metadata-stump/2" && validRule(Rule{m.Feature, m.Threshold, m.Above})
}
func Predict(m Model, v [FeatureCount]int) (string, error) {
	if !validModel(m) || !validVector(v) {
		return "", ErrInvalid
	}
	if m.Kind == "all_alerts_suspicious" {
		return "suspicious", nil
	}
	if m.Kind == "context-metadata-rules/3" {
		for _, r := range m.Rules {
			if (v[r.Feature] >= r.Threshold) == r.Above {
				return "suspicious", nil
			}
		}
		return "benign", nil
	}
	if (v[m.Feature] >= m.Threshold) == m.Above {
		return "suspicious", nil
	}
	return "benign", nil
}
func validateInputs(in Inputs, purpose string, forbidden []string) error {
	if in.Schema != Schema || in.Purpose != purpose || !identifier.MatchString(in.DatasetID) || !identifier.MatchString(in.Tenant) || in.CreatedAt.IsZero() || !pin.MatchString(in.RecipeSHA) || !pin.MatchString(in.SourceSHA) || !pin.MatchString(in.ContextTrustSHA) || len(in.Rows) < 1 || len(in.Rows) > 512 {
		return ErrInvalid
	}
	ids, keys := map[string]bool{}, map[string]bool{}
	for _, x := range forbidden {
		keys[x] = true
	}
	total := 0
	for _, r := range in.Rows {
		if !identifier.MatchString(r.ID) || !identifier.MatchString(r.Family) || !identifier.MatchString(r.SourceGroup) || ids[r.ID] || len(r.EvidenceKeys) == 0 || len(r.EvidenceKeys) > 128 || !sort.StringsAreSorted(r.EvidenceKeys) || !validVector(r.Features) || r.ContextCoverageBPS != 10000 {
			return ErrInvalid
		}
		ids[r.ID] = true
		for _, k := range r.EvidenceKeys {
			if !pin.MatchString(k) || keys[k] {
				return ErrInvalid
			}
			keys[k] = true
			total++
		}
	}
	if total > 4096 {
		return ErrInvalid
	}
	return nil
}
func labels(in Inputs, g Gold) (map[string]string, error) {
	if g.Schema != "case-context-gold/2" || g.DatasetID != in.DatasetID || len(g.Rows) != len(in.Rows) {
		return nil, ErrInvalid
	}
	known := map[string]bool{}
	for _, r := range in.Rows {
		known[r.ID] = true
	}
	out := map[string]string{}
	for _, r := range g.Rows {
		if !known[r.ID] || out[r.ID] != "" || (r.Value != "confirmed_attack" && r.Value != "confirmed_benign" && r.Value != "uncertain" && r.Value != "disputed") {
			return nil, ErrInvalid
		}
		out[r.ID] = r.Value
	}
	return out, nil
}
func validAuthorities(t casememory.LearningTrust) bool {
	if t.Schema != "case-learning-trust/1" || !identifier.MatchString(t.Tenant) || t.Revision < 1 || len(t.Keys) != 3 {
		return false
	}
	ids, pubs, roles := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, k := range t.Keys {
		p, e := base64.StdEncoding.Strict().DecodeString(k.PublicKey)
		if e != nil || len(p) != 32 || !identifier.MatchString(k.ID) || !identifier.MatchString(k.Actor) || ids[k.ID] || pubs[hex.EncodeToString(p)] || roles[k.Role] || (k.Role != "label_reviewer" && k.Role != "evaluation_custodian" && k.Role != "independent_evaluator") {
			return false
		}
		ids[k.ID] = true
		pubs[hex.EncodeToString(p)] = true
		roles[k.Role] = true
	}
	return true
}
func verify(trust casememory.LearningTrust, id, role string, payload []byte, sig string) bool {
	for _, k := range trust.Keys {
		if k.ID == id && k.Role == role && !k.Revoked {
			pub, e := base64.StdEncoding.Strict().DecodeString(k.PublicKey)
			s, f := base64.StdEncoding.Strict().DecodeString(sig)
			return e == nil && f == nil && len(pub) == 32 && len(s) == 64 && ed25519.Verify(pub, payload, s)
		}
	}
	return false
}

type Review struct {
	Schema    string    `json:"schema"`
	Tenant    string    `json:"tenant_id"`
	TrustSHA  string    `json:"trust_sha256"`
	InputsSHA string    `json:"inputs_sha256"`
	GoldSHA   string    `json:"gold_sha256"`
	KeyID     string    `json:"key_id"`
	IssuedAt  time.Time `json:"issued_at"`
	Signature string    `json:"signature_base64"`
}

func ReviewBytes(r Review) []byte {
	r.Signature = ""
	return domain("reverse-artex/context-fit-review/2\n", r)
}

type Candidate struct {
	TrainingRecipeSHA string                   `json:"training_recipe_sha256"`
	Schema            string                   `json:"schema"`
	Tenant            string                   `json:"tenant_id"`
	Model             Model                    `json:"model"`
	ModelSHA          string                   `json:"model_sha256"`
	FeatureSHA        string                   `json:"feature_schema_sha256"`
	RuntimeSHA        string                   `json:"runtime_source_sha256"`
	TrainingInputsSHA string                   `json:"training_inputs_sha256"`
	TrainingGoldSHA   string                   `json:"training_gold_sha256"`
	TrainingSourceSHA string                   `json:"training_source_sha256"`
	ContextTrustSHA   string                   `json:"context_trust_sha256"`
	ReviewSHA         string                   `json:"label_review_sha256"`
	ReviewTrustSHA    string                   `json:"review_trust_sha256"`
	TrainingEvidence  []string                 `json:"training_evidence_sha256"`
	Fit               casememory.QualityCounts `json:"fit_counts"`
	FitExcluded       int                      `json:"fit_excluded"`
	CreatedAt         time.Time                `json:"created_at"`
	DeploymentAllowed bool                     `json:"deployment_allowed"`
	SHA               string                   `json:"candidate_sha256"`
}

func CandidateSHA(c Candidate) string { c.SHA = ""; return Digest(c) }
func counts(m Model, in Inputs, y map[string]string) casememory.QualityCounts {
	r := casememory.QualityCounts{}
	for _, row := range in.Rows {
		p, _ := Predict(m, row.Features)
		switch y[row.ID] {
		case "confirmed_attack":
			r.Attack++
			if p == "suspicious" {
				r.TrueAttack++
			} else {
				r.FalseBenign++
			}
		case "confirmed_benign":
			r.Benign++
			if p == "benign" {
				r.TrueBenign++
			} else {
				r.FalseAttack++
			}
		}
	}
	return r
}
func Train(in Inputs, g Gold, review Review, trust casememory.LearningTrust) (Candidate, error) {
	if !validAuthorities(trust) || validateInputs(in, "training", nil) != nil {
		return Candidate{}, ErrInvalid
	}
	y, e := labels(in, g)
	if e != nil {
		return Candidate{}, e
	}
	if review.Schema != "case-context-fit-review/2" || review.Tenant != in.Tenant || trust.Tenant != in.Tenant || review.TrustSHA != casememory.LearningTrustDigest(trust) || review.InputsSHA != Digest(in) || review.GoldSHA != Digest(g) || review.IssuedAt.Before(in.CreatedAt) || review.IssuedAt.IsZero() || review.IssuedAt.After(time.Now().UTC().Add(time.Minute)) || !verify(trust, review.KeyID, "label_reviewer", ReviewBytes(review), review.Signature) {
		return Candidate{}, ErrInvalid
	}
	bestModel := Model{Kind: "all_alerts_suspicious", Feature: -1}
	best := counts(bestModel, in, y)
	if best.Attack < 30 || best.Benign < 30 {
		return Candidate{}, ErrInvalid
	}
	families, groups := map[string]bool{}, map[string]bool{}
	for _, row := range in.Rows {
		families[row.Family] = true
		groups[row.SourceGroup] = true
	}
	if len(families) < 3 || len(groups) < 3 {
		return Candidate{}, ErrInvalid
	}
	bestModel, best = fitModel(in, y)
	evidence := []string{}
	for _, row := range in.Rows {
		evidence = append(evidence, row.EvidenceKeys...)
	}
	sort.Strings(evidence)
	c := Candidate{Schema: "case-context-candidate/2", Tenant: in.Tenant, Model: bestModel, ModelSHA: Digest(bestModel), FeatureSHA: Digest(FeatureNames), RuntimeSHA: RuntimeSHA(), TrainingInputsSHA: Digest(in), TrainingGoldSHA: Digest(g), TrainingSourceSHA: in.SourceSHA, TrainingRecipeSHA: in.RecipeSHA, ContextTrustSHA: in.ContextTrustSHA, ReviewSHA: Digest(review), ReviewTrustSHA: casememory.LearningTrustDigest(trust), TrainingEvidence: evidence, Fit: best, FitExcluded: len(in.Rows) - best.Attack - best.Benign, CreatedAt: time.Now().UTC()}
	c.SHA = CandidateSHA(c)
	return c, nil
}
