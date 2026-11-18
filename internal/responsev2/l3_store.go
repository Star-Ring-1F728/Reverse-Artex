package responsev2

import (
	"context"
	"reverse-artex/internal/decisions"
	"time"
)

func (s *Store) l3Start(q L3Request, cfg L3Config) (L3Run, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if err := s.check(now); err != nil {
		return L3Run{}, err
	}
	if !validRequestID(q.ID) || (q.Mode != "analyze" && q.Mode != "contain" && q.Mode != "release") {
		return L3Run{}, ErrStale
	}
	if cfg.GroundedAssessment && (!cfg.Enabled || cfg.Validate() != nil || q.Mode != "analyze") {
		return L3Run{}, ErrStale
	}
	if old, ok := s.l3Runs[q.ID]; ok {
		if decisions.Hash(old.Request) != decisions.Hash(q) || old.ConfigSHA != decisions.Hash(cfg) {
			return L3Run{}, ErrStale
		}
		return s.l3ReadLocked(old), nil
	}
	if s.paused || len(s.l3Runs) >= 128 {
		return L3Run{}, ErrLimit
	}
	view, err := s.viewLocked(q.Tenant, q.CaseID, now)
	if err != nil || view.Case.SHA != q.CaseSHA {
		return L3Run{}, ErrStale
	}
	if q.Mode == "contain" && !cfg.AllowContain {
		return L3Run{}, ErrStale
	}
	if q.Mode == "release" {
		source, ok := s.l3Runs[q.SourceRun]
		if !ok || source.Request.Tenant != q.Tenant || source.Request.CaseID != q.CaseID || source.Request.Mode != "contain" {
			return L3Run{}, ErrStale
		}
		if _, ok := s.bindings[source.ActionIntent]; !ok {
			return L3Run{}, ErrStale
		}
	} else if q.SourceRun != "" {
		return L3Run{}, ErrStale
	}
	pending, tenantPending, daily := 0, 0, 0
	day := now.UTC().Format("2006-01-02")
	for _, run := range s.l3Runs {
		if cfg.ShortReferences && run.ReferenceScheme == l3ReferenceScheme && l3ReferenceTag(run.Request) == l3ReferenceTag(q) {
			return L3Run{}, ErrLimit
		}
		if run.Status == "reserved" || run.Status == "running" {
			pending++
			if run.Request.Tenant == q.Tenant {
				tenantPending++
			}
		}
		if run.Started.UTC().Format("2006-01-02") == day {
			daily++
		}
	}
	if pending >= 4 || tenantPending >= 2 || daily >= cfg.DailyRuns {
		return L3Run{}, ErrLimit
	}
	run := L3Run{Schema: "l3-run/2", Request: q, Epoch: s.epoch, ConfigSHA: decisions.Hash(cfg), Status: "reserved", Started: now.UTC(), Deadline: now.Add(30 * time.Second).UTC(), Steps: []L3Step{}}
	if cfg.ShortReferences {
		run.ReferenceScheme = l3ReferenceScheme
	}
	if cfg.GroundedAssessment {
		run.GroundingScheme = l3GroundingScheme
	}
	if cfg.AdaptiveStrategy {
		if cfg.Validate() != nil {
			return L3Run{}, ErrStale
		}
		strategy := s.strategyLocked(view, now)
		run.Strategy = &strategy
	}
	if err = s.commit(record{Operation: "l3-reserved", L3: &run}); err != nil {
		return L3Run{}, err
	}
	return clone(run), nil
}
func (s *Store) l3Update(id string, change func(*L3Run)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed || s.closed {
		return ErrUnavailable
	}
	old, ok := s.l3Runs[id]
	if !ok {
		return ErrStale
	}
	run := clone(old)
	change(&run)
	return s.commit(record{Operation: "l3-progress", L3: &run})
}
func (s *Store) l3ReadLocked(run L3Run) L3Run {
	run = clone(run)
	if run.ActionIntent != "" {
		if receipt, ok := s.receipts[run.ActionIntent]; ok {
			run.Receipt = &receipt
		}
		if binding, ok := s.bindings[run.ActionIntent]; ok {
			b := binding
			run.Binding = &b
		}
	}
	return run
}
func (s *Store) L3Run(tenant, id string) (L3Run, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	run, ok := s.l3Runs[id]
	if !ok || run.Request.Tenant != tenant {
		return L3Run{}, ErrStale
	}
	return s.l3ReadLocked(run), nil
}
func (s *Store) l3Pin(id string, allowChanged bool) (L3Run, CaseView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.l3PinLocked(id, allowChanged, time.Now())
}
func (s *Store) l3PinLocked(id string, allowChanged bool, now time.Time) (L3Run, CaseView, error) {
	if err := s.check(now); err != nil {
		return L3Run{}, CaseView{}, err
	}
	run, ok := s.l3Runs[id]
	if !ok || run.Cancelled || run.Epoch != s.epoch || s.paused || !now.Before(run.Deadline) || run.Status != "running" {
		return L3Run{}, CaseView{}, ErrStale
	}
	v, err := s.viewLocked(run.Request.Tenant, run.Request.CaseID, now)
	if err != nil {
		return L3Run{}, CaseView{}, err
	}
	if v.Case.SHA != run.Request.CaseSHA && !allowChanged {
		return L3Run{}, CaseView{}, ErrStale
	}
	run.CaseChanged = v.Case.SHA != run.Request.CaseSHA
	return s.l3ReadLocked(run), v, nil
}

// Completion must recheck the run under the same lock as the final commit.
// A cancellation, epoch change or expired deadline cannot become completed.
func (s *Store) l3Complete(id string, assessment L3Assessment, allowChanged bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	current, view, err := s.l3PinLocked(id, allowChanged, now)
	if err != nil {
		return err
	}
	if current.GroundingScheme != "" {
		if current.GroundingScheme != l3GroundingScheme || current.Request.Mode != "analyze" || allowChanged {
			return ErrStale
		}
		if err = l3ValidateGroundedAssessment(view, assessment, now); err != nil {
			return err
		}
	}
	run := clone(s.l3Runs[id])
	run.Assessment = &assessment
	run.CaseChanged = current.CaseChanged
	run.Status = "completed"
	ended := now.UTC()
	run.Ended = &ended
	return s.commit(record{Operation: "l3-progress", L3: &run})
}

func (s *Store) l3RunOutcome(id string) (Outcome, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	run, _, err := s.l3PinLocked(id, true, now)
	if err != nil {
		return Outcome{}, err
	}
	source := run
	if run.Request.Mode == "release" {
		var ok bool
		source, ok = s.l3Runs[run.Request.SourceRun]
		if !ok || source.Request.Tenant != run.Request.Tenant || source.Request.CaseID != run.Request.CaseID {
			return Outcome{}, ErrStale
		}
	}
	binding, ok := s.bindings[source.ActionIntent]
	if !ok {
		return Outcome{}, ErrStale
	}
	return s.outcomeLocked(run.Request.Tenant, binding.PolicyID, binding.Episode, now)
}
func (s *Store) l3Apply(ctx context.Context, id, candidate string) (Receipt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	run, ok := s.l3Runs[id]
	if !ok || run.Request.Mode != "contain" || run.Status != "running" || run.Cancelled || !now.Before(run.Deadline) || run.ActionCandidate != candidate || run.ActionIntent == "" {
		return Receipt{}, ErrStale
	}
	if run.Strategy != nil {
		view, err := s.viewLocked(run.Request.Tenant, run.Request.CaseID, now)
		if err != nil || !strategyAllows(*run.Strategy, candidate) || !strategyAllows(s.strategyLocked(view, now), candidate) {
			return Receipt{}, ErrStale
		}
	}
	return s.applyLocked(ctx, run.Request.Tenant, Intent{ID: run.ActionIntent, CaseID: run.Request.CaseID, CaseSHA: run.Request.CaseSHA, CandidateID: candidate, Owner: "l3", Run: id, Epoch: run.Epoch}, now)
}

// Atomically record the post-action plan together with the outcome used to
// revise it. No extra model turn, policy mutation or unbounded retry is added.
func (s *Store) l3OutcomeObservation(id string) (any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	run, view, err := s.l3PinLocked(id, true, now)
	if err != nil {
		return nil, err
	}
	source := run
	if run.Request.Mode == "release" {
		source = s.l3Runs[run.Request.SourceRun]
	}
	binding, ok := s.bindings[source.ActionIntent]
	if !ok || source.Request.Tenant != run.Request.Tenant || source.Request.CaseID != run.Request.CaseID {
		return nil, ErrStale
	}
	out, err := s.outcomeLocked(run.Request.Tenant, binding.PolicyID, binding.Episode, now)
	if err != nil || run.Strategy == nil {
		return out, err
	}
	strategy := s.strategyLocked(view, now)
	stored := clone(s.l3Runs[id])
	stored.RevisedStrategy = &strategy
	if err := s.commit(record{Operation: "l3-progress", L3: &stored}); err != nil {
		return nil, err
	}
	// New case revisions can introduce candidates with no alias in this run.
	// The next investigation must bind selection references afresh.
	display := strategyWithoutCandidates(strategy)
	display["priority_candidate_count"] = len(strategy.Candidates)
	display["candidate_selection"] = "requires_new_bound_investigation"
	return struct {
		Outcome
		NextStrategy map[string]any `json:"next_strategy"`
	}{out, display}, nil
}
func (s *Store) l3Cancel(tenant, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	run, ok := s.l3Runs[id]
	if !ok || run.Request.Tenant != tenant || (run.Status != "reserved" && run.Status != "running") {
		return ErrStale
	}
	run = clone(run)
	run.Cancelled = true
	if run.Status == "reserved" {
		now := time.Now().UTC()
		run.Status = "cancelled"
		run.Ended = &now
	}
	return s.commit(record{Operation: "l3-cancelled", L3: &run})
}

// ReleaseL3 is operator recovery without inference. The source run, current
// case/epoch, episode, exact generation, and l3 owner are derived/rechecked.
func (s *Store) ReleaseL3(ctx context.Context, tenant, sourceID, caseSHA, intent string, epoch, generation int) (Receipt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.releaseL3Locked(ctx, tenant, sourceID, caseSHA, intent, epoch, generation, false)
}
func (s *Store) releaseL3Locked(ctx context.Context, tenant, sourceID, caseSHA, intent string, epoch, generation int, model bool) (Receipt, error) {
	source, ok := s.l3Runs[sourceID]
	if !ok || source.Request.Tenant != tenant || source.Request.Mode != "contain" {
		return Receipt{}, ErrStale
	}
	c := s.cases[source.Request.CaseID]
	if c.SHA != caseSHA || epoch != s.epoch || (model && s.paused) {
		return Receipt{}, ErrStale
	}
	binding, ok := s.bindings[source.ActionIntent]
	if !ok {
		return Receipt{}, ErrStale
	}
	current, ok := s.leases[binding.PolicyID]
	if !ok || current.Episode != binding.Episode || current.Scope != binding.Scope {
		return Receipt{}, ErrStale
	}
	return s.releaseLocked(ctx, tenant, binding.PolicyID, "l3", sourceID, intent, generation, time.Now())
}
func (s *Store) l3Release(ctx context.Context, id string) (Receipt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	run, ok := s.l3Runs[id]
	now := time.Now()
	if !ok || run.Request.Mode != "release" || run.Status != "running" || run.Cancelled || !now.Before(run.Deadline) || run.ActionIntent == "" {
		return Receipt{}, ErrStale
	}
	source, ok := s.l3Runs[run.Request.SourceRun]
	if !ok {
		return Receipt{}, ErrStale
	}
	binding, ok := s.bindings[source.ActionIntent]
	if !ok {
		return Receipt{}, ErrStale
	}
	l, ok := s.leases[binding.PolicyID]
	if !ok {
		return Receipt{}, ErrStale
	}
	return s.releaseL3Locked(ctx, run.Request.Tenant, run.Request.SourceRun, run.Request.CaseSHA, run.ActionIntent, run.Epoch, l.Generation, true)
}
func (s *Store) l3Outcome(tenant, sourceID string) (Outcome, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	run, ok := s.l3Runs[sourceID]
	if !ok || run.Request.Tenant != tenant {
		return Outcome{}, ErrStale
	}
	binding, ok := s.bindings[run.ActionIntent]
	if !ok {
		return Outcome{}, ErrStale
	}
	return s.outcomeLocked(tenant, binding.PolicyID, binding.Episode, time.Now())
}
