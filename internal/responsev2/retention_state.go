package responsev2

import (
	"errors"
	"maps"
	"reverse-artex/internal/decisions"
	"reverse-artex/internal/protection"
	"time"
)

type retainedState struct {
	Cases             map[string]Case                `json:"cases"`
	Events            map[string]Evidence            `json:"events"`
	Leases            map[string]Lease               `json:"leases"`
	Intents           map[string]string              `json:"intents"`
	Receipts          map[string]Receipt             `json:"receipts"`
	Jobs              map[string]Job                 `json:"jobs"`
	Histories         map[string]PolicyHistory       `json:"histories"`
	Bindings          map[string]PolicyBinding       `json:"bindings"`
	Attempts          map[string]ResponseAttempt     `json:"attempts"`
	Observations      map[string]ResponseObservation `json:"observations"`
	L3Runs            map[string]L3Run               `json:"l3_runs"`
	Outcomes          map[string]outcomeFacts        `json:"completed_outcome_facts"`
	Epoch             int                            `json:"epoch"`
	Paused            bool                           `json:"paused"`
	OutcomeFailed     bool                           `json:"outcome_failed"`
	TotalEvents       int                            `json:"total_events"`
	TotalAttempts     int                            `json:"total_attempts"`
	TotalObservations int                            `json:"total_observations"`
}
type retainedCompletion struct {
	BootID   string `json:"enforcer_boot_id"`
	WriteSHA string `json:"write_sha256"`
}

func (s *Store) retainedState() retainedState {
	return retainedState{s.cases, s.events, s.leases, s.intents, s.receipts, s.jobs, s.histories, s.bindings, s.attempts, s.observations, s.l3Runs, s.outcomeFacts, s.epoch, s.paused, s.outcomeFailed, s.totalEvents, s.totalAttempts, s.totalObservations}
}
func (s *Store) installRetainedState(v retainedState) {
	s.cases = v.Cases
	s.events = v.Events
	s.leases = v.Leases
	s.intents = v.Intents
	s.receipts = v.Receipts
	s.jobs = v.Jobs
	s.histories = v.Histories
	s.bindings = v.Bindings
	s.attempts = v.Attempts
	s.observations = v.Observations
	s.rebuildPendingCases()
	s.l3Runs = v.L3Runs
	s.outcomeFacts = v.Outcomes
	s.epoch = v.Epoch
	s.paused = v.Paused
	s.outcomeFailed = v.OutcomeFailed
	s.totalEvents = v.TotalEvents
	s.totalAttempts = v.TotalAttempts
	s.totalObservations = v.TotalObservations
	s.requests = map[string]string{}
	for id, e := range s.events {
		s.requests[e.Request] = id
	}
}
func (s *Store) rebuildPendingCases() {
	clear(s.pendingCases)
	for id, a := range s.attempts {
		if _, completed := s.observations[id]; !completed {
			s.pendingCases[a.CaseID]++
		}
	}
}
func (s *Store) markInterrupted() {
	for id, j := range s.jobs {
		if j.Status == "reserved" || j.Status == "dispatched" {
			j.Status = "interrupted_unknown"
			s.jobs[id] = j
		}
	}
	for id, run := range s.l3Runs {
		if run.Status == "reserved" || run.Status == "running" {
			run.Status = "interrupted_unknown"
			run.Error = "previous process ended; model and actions not replayed"
			s.l3Runs[id] = run
		}
	}
	for id := range s.attempts {
		if _, ok := s.observations[id]; !ok {
			s.outcomeFailed = true
		}
	}
}

// Build a separate hot view. Publication installs it only after the checkpoint
// and successor journal are durable. The full original records remain sealed.
func (s *Store) compactedState() (retainedState, map[string]retainedCompletion, map[string]string, error) {
	next := s.retainedState()
	next.Events = maps.Clone(next.Events)
	next.Attempts = maps.Clone(next.Attempts)
	next.Observations = maps.Clone(next.Observations)
	next.Outcomes = maps.Clone(next.Outcomes)
	for key, facts := range next.Outcomes {
		next.Outcomes[key] = cloneOutcomeFacts(facts)
	}
	view := &Store{histories: next.Histories}
	windows := make(map[string]outcomeWindow, len(next.Histories))
	for key, history := range next.Histories {
		windows[key] = view.outcomeWindowLocked(history, s.high)
	}
	completed := map[string]retainedCompletion{}
	requests := map[string]string{}
	keep := map[string]bool{}
	for _, c := range next.Cases {
		for _, id := range c.Refs {
			keep[id] = true
		}
	}
	for _, run := range next.L3Runs {
		if run.Assessment != nil {
			for _, id := range run.Assessment.Evidence {
				keep[id] = true
			}
		}
	}
	for id, a := range next.Attempts {
		obs, done := next.Observations[id]
		if !done || a.PreparedAt.After(s.high) || s.high.Sub(a.PreparedAt) < protection.ProofLifetime {
			keep[a.EvidenceID] = true
			continue
		}
		e, ok := next.Events[a.EvidenceID]
		if !ok {
			return retainedState{}, nil, nil, errors.New("checkpoint response lacks signed evidence")
		}
		for key, h := range next.Histories {
			facts := next.Outcomes[key]
			facts.include(h, windows[key], a, e, &obs)
			next.Outcomes[key] = facts
		}
		completed[id] = retainedCompletion{a.BootID, decisions.Hash(obs.Write)}
		delete(next.Attempts, id)
		delete(next.Observations, id)
	}
	for id, e := range next.Events {
		if !keep[id] && !s.high.Before(e.Binding.Started) && s.high.Sub(e.Binding.Started) >= protection.ProofLifetime {
			requests[e.Request] = e.ID
			delete(next.Events, id)
		}
	}
	return next, completed, requests, nil
}
func (s *Store) retainedStatusLocked() map[string]any {
	if s.retained == nil {
		return map[string]any{"enabled": false}
	}
	r := s.retained
	return map[string]any{"enabled": true, "schema": "response-retention-status/1", "generation": r.generation, "checkpoint_sha256": r.checkpointSHA,
		"segment_bytes": s.size, "storage_bytes": r.bytes, "max_storage_bytes": r.config.MaxBytes, "max_segment_bytes": r.config.SegmentBytes,
		"remaining_storage_bytes": r.config.MaxBytes - r.bytes, "remaining_generations": r.config.MaxGenerations - r.generation,
		"max_generations": r.config.MaxGenerations, "hot_events": len(s.events), "hot_attempts": len(s.attempts), "hot_observations": len(s.observations),
		"hot_cases": len(s.cases), "max_hot_cases": s.caseLimit(),
		"total_events": s.totalEvents, "total_attempts": s.totalAttempts, "total_observations": s.totalObservations, "archive_deletion": "never automatic"}
}
func (s *Store) Checkpoint() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.retained == nil {
		return ErrUnavailable
	}
	if s.closed || s.failed {
		return ErrUnavailable
	}
	return s.rotateRetained()
}
func (s *Store) ensureHotCapacity(needEvent, needAttempt bool) error {
	if s.retained == nil || ((!needEvent || len(s.events) < 8192) && (!needAttempt || len(s.attempts) < 8192)) {
		return nil
	}
	next, _, _, err := s.compactedState()
	if err != nil {
		return err
	}
	if (needEvent && len(next.Events) >= 8192) || (needAttempt && len(next.Attempts) >= 8192) {
		return ErrLimit
	}
	return s.rotateRetained()
}
func (s *Store) restoreDeadlines(now time.Time) {
	for id, l := range s.leases {
		if l.Expires.After(now) {
			s.deadlines[id] = now.Add(l.Expires.Sub(now))
		}
	}
}
