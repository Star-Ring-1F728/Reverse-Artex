package contextactivation

import (
	"context"
	"errors"
	"path/filepath"
	"reverse-artex/internal/casememory"
	"reverse-artex/internal/contextevaluation"
	"reverse-artex/internal/contextlearning"
	"reverse-artex/internal/contextshadow"
	"reverse-artex/internal/evidence"
	"reverse-artex/internal/incident"
	"sync"
	"time"
)

type Advice struct {
	Schema                   string    `json:"schema"`
	Mode                     string    `json:"mode"`
	ActivationSHA            string    `json:"activation_sha256"`
	CandidateSHA             string    `json:"candidate_sha256"`
	ModelSHA                 string    `json:"model_sha256"`
	ReviewSHA                string    `json:"review_sha256"`
	CaseID                   string    `json:"case_id"`
	CaseSHA                  string    `json:"case_sha256"`
	SourceSHA                string    `json:"source_snapshot_sha256"`
	AttemptSHA               string    `json:"attempt_sha256"`
	Prediction               string    `json:"prediction"`
	InferredAt               time.Time `json:"inferred_at"`
	ValidUntil               time.Time `json:"valid_until"`
	CandidatePercent         int       `json:"candidate_percent"`
	DeploymentAllowed        bool      `json:"deployment_allowed"`
	MandatoryReviewPreserved bool      `json:"mandatory_review_preserved"`
	PolicyMutations          int       `json:"policy_mutations"`
}
type Status struct {
	Release     View                      `json:"release"`
	Configured  bool                      `json:"configured"`
	Running     bool                      `json:"running"`
	LastError   string                    `json:"last_error"`
	Observation *contextshadow.LiveStatus `json:"observation,omitempty"`
}
type Service struct {
	mu                                           sync.Mutex
	evalMu                                       sync.Mutex
	store                                        *Store
	eval                                         *contextevaluation.Session
	memory                                       *casememory.Store
	live                                         *contextshadow.Live
	profile, journal, canary, tenant, activation string
	capture                                      func(context.Context) (*evidence.Snapshot, error)
	closed, stopped                              bool
	lastError                                    string
	beforeFinalAdvice                            func()
	cacheSource, cacheInput, cacheActivation     string
	assessments, cacheHits                       int
	disableAssessmentCache                       bool
	pollCancel                                   context.CancelFunc
	pollDone                                     chan struct{}
}

func OpenProfileService(profile, expectedContext string, memory *casememory.Store, capture func(context.Context) (*evidence.Snapshot, error)) (*Service, error) {
	p, c, journal, canary, e := LoadProfile(profile)
	if e != nil || memory == nil || capture == nil || contextlearning.Digest(c.Context) != expectedContext {
		return nil, ErrInvalid
	}
	st, e := Open(journal)
	if e != nil {
		return nil, e
	}
	s := &Service{store: st, memory: memory, profile: profile, journal: journal, canary: canary, tenant: p.Tenant, capture: capture}
	r, e := st.Current(p, time.Now().UTC())
	if e != nil {
		s.lastError = "activation absent, stopped, expired or unavailable"
		return s, nil
	}
	s.activation = r.SHA
	s.eval, e = contextevaluation.Open(canary, r.Approval.Request.ReleaseSHA)
	if e != nil {
		s.lastError = "canary history requires review"
		return s, nil
	}
	limits := contextshadow.StorageLimits{ActiveAttempts: 64, ActiveBytes: 8 << 20, ArchiveSegments: 2, TotalBytes: 32 << 20}
	s.live, e = contextshadow.OpenLiveWithStorage(filepath.Join(journal+".observations", r.Approval.Request.CandidateSHA), r.Basis.Version.Bundle.Capsule.Candidate, c.Authorities, c.Context, func(ctx context.Context) (*evidence.Snapshot, error) {
		snapshot, e := capture(ctx)
		if e != nil {
			return nil, e
		}
		if _, e = s.revalidate(snapshot, time.Now().UTC()); e != nil {
			return nil, e
		}
		return snapshot, nil
	}, limits)
	if e != nil {
		s.lastError = "activation observation history requires review"
		return s, nil
	}
	pollContext, cancel := context.WithCancel(context.Background())
	s.pollCancel, s.pollDone = cancel, make(chan struct{})
	go s.poll(pollContext, r.Approval.Request.CandidateSHA)
	return s, nil
}

// Identical source bytes are not a new inference sample. Avoid filling the
// bounded durable history with duplicate copies of an idle collector.
func (s *Service) poll(ctx context.Context, candidate string) {
	defer close(s.pollDone)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		st := s.live.Status()
		if st.Error != "" {
			s.mu.Lock()
			s.lastError = st.Error
			s.mu.Unlock()
			return
		}
		if !st.Busy && !st.Queued {
			snapshot, e := s.capture(ctx)
			if ctx.Err() != nil {
				return
			}
			changed := e != nil || st.Latest == nil || st.Latest.Receipt == nil
			if !changed {
				changed = st.Latest.Receipt.SourceSHA != snapshot.SHA256()
			}
			if changed {
				if e = s.live.Request(candidate, false); e != nil {
					s.mu.Lock()
					s.lastError = e.Error()
					s.mu.Unlock()
					return
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
func (s *Service) Tenant() string { return s.tenant }
func (s *Service) revalidate(snapshot *evidence.Snapshot, at time.Time) (Change, error) {
	s.evalMu.Lock()
	defer s.evalMu.Unlock()
	s.mu.Lock()
	off := s.closed || s.stopped
	s.mu.Unlock()
	if off || s.eval == nil {
		return Change{}, ErrUnavailable
	}
	p, _, journal, canary, e := LoadProfile(s.profile)
	if e != nil || journal != s.journal || canary != s.canary {
		return Change{}, ErrConflict
	}
	c, e := s.store.Current(p, at)
	if e != nil || c.SHA != s.activation {
		return Change{}, ErrUnavailable
	}
	inputs := ""
	if !s.disableAssessmentCache {
		inputs, e = s.eval.CurrentInputSHA(s.memory, c.Approval.Request.PlanSHA, at)
		if e != nil {
			return Change{}, e
		}
		if s.cacheSource == snapshot.SHA256() && s.cacheInput == inputs && s.cacheActivation == c.SHA {
			s.cacheHits++
			return c, nil
		}
	}
	s.assessments++
	r, e := s.eval.Assess(snapshot, s.memory, c.Approval.Request.PlanSHA, at)
	if e != nil || !r.ReleaseReviewReady || ReviewSHA(r) != c.Approval.Request.ReviewSHA {
		return Change{}, ErrConflict
	}
	s.cacheSource, s.cacheInput, s.cacheActivation = snapshot.SHA256(), inputs, c.SHA
	return c, nil
}
func (s *Service) Advice(c incident.Case, sourceSHA string) *Advice {
	if c.Tenant != s.tenant || s.live == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	snapshot, e := s.capture(ctx)
	if e != nil || snapshot.SHA256() != sourceSHA {
		return nil
	}
	r, e := s.revalidate(snapshot, time.Now().UTC())
	if e != nil {
		return nil
	}
	s.mu.Lock()
	beforeFinal := s.beforeFinalAdvice
	s.mu.Unlock()
	if beforeFinal != nil {
		beforeFinal()
	}
	status := s.live.Status()
	a := status.Latest
	if a == nil || a.Error != "" || a.Receipt == nil || a.StartedAt.Before(r.At) || a.Receipt.SourceSHA != sourceSHA {
		return nil
	}
	for _, row := range a.Receipt.Rows {
		if row.CaseID == c.ID && row.CaseSHA == contextlearning.Digest(c) && row.Status == "observed" {
			// Serialize the final publication decision with Stop/Close. A stop
			// that won this lock cannot be followed by cached active advice.
			s.mu.Lock()
			defer s.mu.Unlock()
			if s.closed || s.stopped {
				return nil
			}
			p, cfg, journal, canary, err := LoadProfile(s.profile)
			if err != nil || journal != s.journal || canary != s.canary {
				return nil
			}
			current, err := s.store.Current(p, time.Now().UTC())
			if err != nil || current.SHA != r.SHA || contextlearning.Digest(cfg) != contextlearning.Digest(r.Basis.Config) {
				return nil
			}
			return &Advice{Schema: "case-context-production-advice/2", Mode: "production_triage", ActivationSHA: r.SHA, CandidateSHA: r.Approval.Request.CandidateSHA, ModelSHA: r.Basis.Version.Bundle.Capsule.Candidate.ModelSHA, ReviewSHA: r.Approval.Request.ReviewSHA, CaseID: c.ID, CaseSHA: row.CaseSHA, SourceSHA: sourceSHA, AttemptSHA: a.SHA, Prediction: row.Prediction, InferredAt: a.FinishedAt, ValidUntil: r.Approval.Request.Until, CandidatePercent: 100, DeploymentAllowed: true, MandatoryReviewPreserved: true}
		}
	}
	return nil
}
func (s *Service) Status() Status {
	v := s.store.View()
	out := Status{Release: v, Configured: true}
	s.mu.Lock()
	off := s.closed || s.stopped
	out.LastError = s.lastError
	s.mu.Unlock()
	if s.live != nil {
		st := s.live.Status()
		out.Observation = &st
	}
	if off || v.Current == nil || v.Current.Action == "stop" {
		return out
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	snapshot, e := s.capture(ctx)
	if e == nil {
		_, e = s.revalidate(snapshot, time.Now().UTC())
	}
	if e != nil {
		out.Release.State = "BLOCKED"
		out.LastError = "current evidence, labels, policy, keys or lease require review"
		return out
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current := s.store.View()
	if s.closed || s.stopped || current.Head != out.Release.Head {
		out.Release = current
		out.Running = false
		return out
	}
	p, cfg, journal, canary, err := LoadProfile(s.profile)
	active, activeErr := s.store.Current(p, time.Now().UTC())
	if err != nil || activeErr != nil || journal != s.journal || canary != s.canary || active.Basis == nil || contextlearning.Digest(cfg) != contextlearning.Digest(active.Basis.Config) {
		out.Release.State = "BLOCKED"
		out.LastError = "current configuration changed during review"
		return out
	}
	out.Release.State = "PRODUCTION_TRIAGE"
	out.Release.DeploymentAllowed = true
	out.Running = s.pollDone != nil && out.LastError == ""
	return out
}
func (s *Service) Stop(expected int, reason string) (View, error) {
	s.mu.Lock()
	v := s.store.View()
	if s.closed || expected != v.Revision || !reasonValid(reason) {
		s.mu.Unlock()
		return View{}, ErrConflict
	}
	s.stopped = true
	s.mu.Unlock()
	if s.pollCancel != nil {
		s.pollCancel()
	}
	if s.live != nil {
		s.live.Stop()
	}
	if s.pollDone != nil {
		<-s.pollDone
	}
	return s.store.Stop(s.tenant, expected, reason, time.Now().UTC())
}
func (s *Service) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()
	if s.pollCancel != nil {
		s.pollCancel()
	}
	if s.live != nil {
		s.live.Close()
	}
	if s.pollDone != nil {
		<-s.pollDone
	}
	s.evalMu.Lock()
	defer s.evalMu.Unlock()
	var e error
	if s.eval != nil {
		e = s.eval.Close()
	}
	return errors.Join(e, s.store.Close())
}
