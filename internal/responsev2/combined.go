package responsev2

import (
	"reverse-artex/internal/decisions"
	"reverse-artex/internal/protection"
	"time"
)

// ObserveAndPrepareCurrent atomically publishes signed evidence and its exact
// response plan in one durable commit. Actual server writes remain separately
// recorded afterward. It is unsuitable when a caller must act between the
// observation and response preparation (native/automatic decision admission).
func (s *Store) ObserveAndPrepareCurrent(raw string, binding protection.RequestBinding, status int, body []byte) (protection.GateDecision, error) {
	started := s.timingStart()
	s.mu.Lock()
	s.timingEnd(timingObserveWait, started)
	defer s.mu.Unlock()
	return s.observeAndPrepareCurrentLocked(raw, binding, status, body)
}

func (s *Store) observeAndPrepareCurrentLocked(raw string, binding protection.RequestBinding, status int, body []byte) (protection.GateDecision, error) {
	return s.observeAndPrepareAtLocked(raw, binding, status, body, time.Now())
}

// Explicit authority time keeps deterministic persistence fixtures on the same
// signed-evidence, response-window and durable-commit path as the live wrapper.
func (s *Store) observeAndPrepareAtLocked(raw string, binding protection.RequestBinding, status int, body []byte, now time.Time) (protection.GateDecision, error) {
	_, observation, err := s.observationRecordLocked(raw, binding, status, body, now)
	if err != nil {
		return protection.GateDecision{}, err
	}
	var e Evidence
	var c Case
	if observation != nil {
		e, c = *observation.Event, *observation.Case
	} else {
		e = s.events[decisions.Hash(raw)]
		c = s.cases[caseID(e.Scope)]
	}
	attempt, err := s.responseAttemptLocked(binding.Tenant, e, c, now)
	if err != nil {
		return protection.GateDecision{}, err
	}
	if observation == nil {
		observation = &record{At: now.UTC(), Operation: "response-prepared"}
	} else {
		observation.Operation = "adjudicate-and-prepare"
	}
	observation.Attempt = &attempt
	if err = s.commit(*observation); err != nil {
		return protection.GateDecision{}, err
	}
	return decisionFor(attempt), nil
}
