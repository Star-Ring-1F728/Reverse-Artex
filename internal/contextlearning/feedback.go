package contextlearning

import (
	"reverse-artex/internal/casememory"
	"sort"
	"time"
)

// TrainingBoundary gives the trainer public membership hashes only. The
// custodian retains holdout observations, labels and signing credentials.
type TrainingBoundary struct {
	Schema    string    `json:"schema"`
	Tenant    string    `json:"tenant_id"`
	TrustSHA  string    `json:"trust_sha256"`
	Sources   []string  `json:"reserved_source_sha256"`
	Evidence  []string  `json:"reserved_evidence_sha256"`
	KeyID     string    `json:"key_id"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Signature string    `json:"signature_base64"`
}

func TrainingBoundaryBytes(b TrainingBoundary) []byte {
	b.Signature = ""
	return domain("reverse-artex/context-training-boundary/1\n", b)
}

func sortedPins(v []string, maximum int) bool {
	if len(v) == 0 || len(v) > maximum || !sort.StringsAreSorted(v) {
		return false
	}
	for i, p := range v {
		if !pin.MatchString(p) || i > 0 && p == v[i-1] {
			return false
		}
	}
	return true
}

func validateBoundary(b TrainingBoundary, in Inputs, trust casememory.LearningTrust, now time.Time) error {
	if b.Schema != "case-context-training-boundary/1" || b.Tenant != in.Tenant || b.TrustSHA != casememory.LearningTrustDigest(trust) || !sortedPins(b.Sources, 64) || !sortedPins(b.Evidence, 4096) || b.IssuedAt.IsZero() || b.IssuedAt.After(now.Add(time.Minute)) || !b.ExpiresAt.After(now) || !b.ExpiresAt.After(b.IssuedAt) || b.ExpiresAt.Sub(b.IssuedAt) > 30*24*time.Hour || !verify(trust, b.KeyID, "evaluation_custodian", TrainingBoundaryBytes(b), b.Signature) {
		return ErrInvalid
	}
	if i := sort.SearchStrings(b.Sources, in.SourceSHA); i < len(b.Sources) && b.Sources[i] == in.SourceSHA {
		return ErrInvalid
	}
	for _, row := range in.Rows {
		for _, key := range row.EvidenceKeys {
			if i := sort.SearchStrings(b.Evidence, key); i < len(b.Evidence) && b.Evidence[i] == key {
				return ErrInvalid
			}
		}
	}
	return nil
}

type FeedbackUpdate struct {
	Schema                  string                   `json:"schema"`
	PreviousCandidateSHA    string                   `json:"previous_candidate_sha256"`
	BoundarySHA             string                   `json:"training_boundary_sha256"`
	Candidate               Candidate                `json:"candidate"`
	Before                  casememory.QualityCounts `json:"previous_on_current_training"`
	After                   casememory.QualityCounts `json:"candidate_on_current_training"`
	NewEvidence             int                      `json:"new_evidence_count"`
	ReplayEvidence          int                      `json:"replayed_evidence_count"`
	ReadyForShadow          bool                     `json:"ready_for_shadow"`
	RequiresFreshEvaluation bool                     `json:"requires_fresh_evaluation"`
	DeploymentAllowed       bool                     `json:"deployment_allowed"`
	PolicyMutations         int                      `json:"policy_mutations"`
	State                   string                   `json:"state"`
}

// Update retrains on a newly reviewed cumulative batch, not on its own
// predictions. Retaining every earlier evidence key prevents silent forgetting;
// reaching the 512-case bound requires an explicit new series, not eviction.
// A training improvement is a shadow candidate, never independent acceptance.
func Update(previous Candidate, in Inputs, gold Gold, review Review, trust casememory.LearningTrust, boundary TrainingBoundary) (FeedbackUpdate, error) {
	now := time.Now().UTC()
	if validateCandidate(previous) != nil || !validAuthorities(trust) || validateInputs(in, "training", nil) != nil || previous.Tenant != in.Tenant || trust.Tenant != in.Tenant || previous.ContextTrustSHA != in.ContextTrustSHA || previous.TrainingRecipeSHA != in.RecipeSHA || previous.ReviewTrustSHA != casememory.LearningTrustDigest(trust) || in.CreatedAt.Before(previous.CreatedAt) || in.SourceSHA == previous.TrainingSourceSHA || validateBoundary(boundary, in, trust, now) != nil {
		return FeedbackUpdate{}, ErrInvalid
	}
	keys := map[string]bool{}
	for _, row := range in.Rows {
		for _, key := range row.EvidenceKeys {
			keys[key] = true
		}
	}
	for _, key := range previous.TrainingEvidence {
		if !keys[key] {
			return FeedbackUpdate{}, ErrInvalid
		}
	}
	added := len(keys) - len(previous.TrainingEvidence)
	if added <= 0 || Digest(in) == previous.TrainingInputsSHA {
		return FeedbackUpdate{}, ErrInvalid
	}
	candidate, err := Train(in, gold, review, trust)
	if err != nil {
		return FeedbackUpdate{}, err
	}
	y, err := labels(in, gold)
	if err != nil {
		return FeedbackUpdate{}, err
	}
	before := counts(previous.Model, in, y)
	after := candidate.Fit
	improved := after.FalseBenign <= before.FalseBenign && after.FalseAttack <= before.FalseAttack && (after.FalseBenign < before.FalseBenign || after.FalseAttack < before.FalseAttack)
	state := "NO_VERIFIED_TRAINING_IMPROVEMENT"
	if improved {
		state = "TRAINING_IMPROVED_FRESH_EVALUATION_REQUIRED"
	}
	return FeedbackUpdate{Schema: "case-context-feedback-update/1", PreviousCandidateSHA: previous.SHA, BoundarySHA: Digest(boundary), Candidate: candidate, Before: before, After: after, NewEvidence: added, ReplayEvidence: len(previous.TrainingEvidence), ReadyForShadow: improved, RequiresFreshEvaluation: true, State: state}, nil
}
