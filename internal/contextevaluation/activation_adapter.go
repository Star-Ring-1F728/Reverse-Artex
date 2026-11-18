package contextevaluation

import (
	"embed"
	"encoding/json"
	"reverse-artex/internal/casememory"
	"reverse-artex/internal/contextlearning"
	"reverse-artex/internal/contextrelease"
	"time"
)

// The activation consumer pins this adapter separately. Existing evaluation,
// model and canary-journal source commitments remain unchanged.
//
//go:embed activation_adapter.go
var activationAdapter embed.FS

func ActivationAdapterSHA() string {
	raw, _ := activationAdapter.ReadFile("activation_adapter.go")
	return contextlearning.Digest(string(raw))
}

// ApprovalBinding returns detached inputs while the caller holds the release
// owner. It never treats a stored report as a fresh assessment.
func (s *Session) ApprovalBinding() (contextrelease.Config, contextrelease.EvaluationRelease, error) {
	if err := s.fresh(); err != nil {
		return contextrelease.Config{}, contextrelease.EvaluationRelease{}, err
	}
	var cfg contextrelease.Config
	var version contextrelease.EvaluationRelease
	raw, _ := json.Marshal(s.cfg)
	json.Unmarshal(raw, &cfg)
	raw, _ = json.Marshal(s.version)
	json.Unmarshal(raw, &version)
	return cfg, version, nil
}

// CurrentInputSHA authenticates the frozen plan/history and current labels for
// reuse of a previously computed assessment of identical source bytes. It does
// not substitute a cached report for changed labels, keys, history or a plan.
func (s *Session) CurrentInputSHA(memory *casememory.Store, expectedPlan string, at time.Time) (string, error) {
	if memory == nil || s.fresh() != nil {
		return "", ErrConflict
	}
	p, e := s.loadPlan(expectedPlan)
	if e != nil {
		return "", e
	}
	h, e := s.history()
	if e != nil {
		return "", e
	}
	if verifyPrefix(p, h) != nil || s.validateHistory(h, at) != nil {
		return "", ErrInvalid
	}
	trust, e := memory.LearningTrust(p.Tenant)
	if e != nil || casememory.LearningTrustDigest(trust) != p.LabelTrustSHA {
		return "", ErrConflict
	}
	views, e := memory.List(p.Tenant)
	if e != nil {
		return "", e
	}
	for i := range views {
		views[i].Production = nil
	}
	return contextlearning.Digest(struct {
		Plan    string     `json:"plan_sha256"`
		History string     `json:"history_sha256"`
		Journal string     `json:"journal_sha256"`
		Labels  labelInput `json:"labels"`
	}{p.SHA, h.SHA, s.version.JournalHead, labelInput{trust, views}}), nil
}
