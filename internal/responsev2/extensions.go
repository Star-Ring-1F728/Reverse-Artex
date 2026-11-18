package responsev2

import (
	"errors"
	"reverse-artex/internal/decisions"
)

func (s *Store) validateExtension(r record) error {
	if err := s.validateCaseRetirement(r); err != nil {
		return err
	}
	if r.Event != nil || r.Case != nil {
		if r.Event == nil || r.Case == nil || (r.Operation != "adjudicate-and-publish" && r.Operation != "adjudicate-and-prepare") || !r.Event.At.Equal(r.At) {
			return errors.New("invalid case evidence transition")
		}
		if _, exists := s.events[r.Event.ID]; exists {
			return errors.New("duplicate case evidence")
		}
		if _, exists := s.requests[r.Event.Request]; exists {
			return errors.New("duplicate case request")
		}
		expected := caseWithEvidence(s.cases[caseID(r.Event.Scope)], *r.Event)
		if decisions.Hash(expected) != decisions.Hash(*r.Case) {
			return errors.New("invalid case revision or evidence references")
		}
	}
	if r.Operation == "writer-started" {
		if len(r.WriterBoot) != 32 || r.Event != nil || r.Case != nil || r.Attempt != nil || r.Observation != nil || r.Lease != nil || r.Intent != nil || r.Receipt != nil || r.Job != nil || r.L3 != nil || r.Epoch != nil || r.Paused != nil || r.CommandID != "" || r.CommandSHA != "" {
			return errors.New("invalid writer restart fence")
		}
	} else if r.WriterBoot != "" {
		return errors.New("writer boot on unrelated record")
	}

	combined := r.Operation == "adjudicate-and-prepare"
	if combined {
		if r.Event == nil || r.Case == nil || r.Attempt == nil || r.Observation != nil || r.Lease != nil || r.Intent != nil || r.Receipt != nil || r.Job != nil || r.L3 != nil || r.Epoch != nil || r.Paused != nil || r.CommandID != "" || r.CommandSHA != "" {
			return errors.New("invalid combined response record")
		}
		if !r.Attempt.PreparedAt.Equal(r.At) {
			return errors.New("invalid combined case revision")
		}
	}
	if r.Attempt != nil {
		a := r.Attempt
		e, ok := s.events[a.EvidenceID]
		c := s.cases[a.CaseID]
		if combined {
			e, c, ok = *r.Event, *r.Case, a.EvidenceID == r.Event.ID
		}
		if !ok || a.Schema != "response-attempt/1" || a.Scope != e.Scope || a.CaseID != caseID(e.Scope) || a.PreparedSequence != r.Sequence || a.PreparedAt.IsZero() || a.BootID == "" || a.CaseSHA != c.SHA || a.SDKStatus != e.Status || a.PreparedAt.Before(e.At) || a.ID != decisions.Hash([]any{e.ID, a.PolicyID, a.Episode, a.Generation, a.BootID}) {
			return errors.New("invalid response attempt")
		}
		if a.PolicyID == "" && (a.Episode != "" || a.Generation != 0 || a.PlannedStatus != e.Status) {
			return errors.New("invalid empty policy snapshot")
		}
		if a.PolicyID != "" {
			l, ok := s.leases[a.PolicyID]
			if !ok || l.Episode != a.Episode || l.Generation != a.Generation || l.Scope != a.Scope || a.PlannedStatus != 429 || !a.PreparedAt.Before(l.Expires) {
				return errors.New("invalid response policy binding")
			}
		}
	}
	if r.Observation != nil {
		observation := r.Observation
		if observation.Schema != "response-observation/1" || observation.Sequence != r.Sequence {
			return errors.New("invalid response observation")
		}
		if a, ok := s.attempts[observation.Write.AttemptID]; !ok || !validResponseWrite(a, observation.Write) {
			return errors.New("unknown response attempt")
		}
		if _, ok := s.observations[observation.Write.AttemptID]; ok {
			return errors.New("duplicate response observation")
		}
	}
	if r.L3 != nil {
		run := r.L3
		if (run.Strategy != nil && (!validStrategy(*run.Strategy, run.Request, true) || run.Strategy.Epoch != run.Epoch || run.Strategy.Sequence >= r.Sequence)) || (run.RevisedStrategy != nil && (run.Strategy == nil || !validStrategy(*run.RevisedStrategy, run.Request, false) || run.RevisedStrategy.Epoch != run.Epoch || run.RevisedStrategy.Sequence >= r.Sequence || run.RevisedStrategy.Sequence < run.Strategy.Sequence)) {
			return errors.New("invalid defensive strategy snapshot")
		}
		if old, exists := s.l3Runs[run.Request.ID]; exists {
			if decisions.Hash(old.Strategy) != decisions.Hash(run.Strategy) {
				return errors.New("changed defensive strategy snapshot")
			}
		}
		if run.ReferenceScheme != "" && run.ReferenceScheme != l3ReferenceScheme {
			return errors.New("invalid L3 reference scheme")
		}
		if run.Schema != "l3-run/2" || !validRequestID(run.Request.ID) || run.Request.Tenant == "" || run.Request.CaseID == "" || !decisions.ValidHash(run.Request.CaseSHA) || run.Epoch < 1 || run.Calls < 0 || run.InputBytes < 0 || run.Calls > 6 || len(run.Steps) > 6 || run.InputBytes > 256<<10 {
			return errors.New("invalid L3 journal record")
		}
		if len(run.ModelTimings) > 6 || len(run.ModelTimings) > run.Calls+1 {
			return errors.New("invalid L3 provider timing count")
		}
		for i, timing := range run.ModelTimings {
			if timing.Number != i+1 || timing.Started.IsZero() || timing.CheckUS < 0 || timing.NextUS < 0 || (timing.State != "requesting" && timing.State != "returned" && timing.State != "failed") {
				return errors.New("invalid L3 provider timing receipt")
			}
			if timing.ProviderFailure != nil && (timing.State != "failed" || !timing.ProviderFailure.Valid()) {
				return errors.New("invalid L3 provider failure")
			}
			if timing.State != "failed" && timing.ErrorStage != "" {
				return errors.New("invalid L3 provider error stage")
			}
		}
	}
	return nil
}
func (s *Store) applyExtension(r record) {
	if r.Lease != nil {
		l := clone(*r.Lease)
		key := historyKey(l.ID, l.Episode)
		h, exists := s.histories[key]
		if !exists {
			h = PolicyHistory{Binding: PolicyBinding{PolicyID: l.ID, Episode: l.Episode, Generation: l.Generation, Scope: l.Scope}, InstalledSequence: r.Sequence, InstalledAt: r.At, Releases: []ReleaseFrame{}}
		}
		h.Latest = l
		if r.Operation == "release-owned-claim" && r.Receipt != nil {
			h.Releases = append(h.Releases, ReleaseFrame{Sequence: r.Sequence, At: r.At, State: r.Receipt.State, Intent: r.Receipt.Intent})
		}
		s.histories[key] = h
	}
	if r.Intent != nil && r.Receipt != nil {
		if l, ok := s.leases[r.Receipt.PolicyID]; ok {
			s.bindings[r.Intent.ID] = PolicyBinding{PolicyID: l.ID, Episode: l.Episode, Generation: r.Receipt.Generation, Scope: l.Scope}
		}
	}
	if r.Attempt != nil {
		s.totalAttempts++
		if _, exists := s.attempts[r.Attempt.ID]; !exists {
			s.pendingCases[r.Attempt.CaseID]++
		}
		s.attempts[r.Attempt.ID] = *r.Attempt
	}
	if r.Observation != nil {
		s.totalObservations++
		id := r.Observation.Write.AttemptID
		caseID := s.attempts[id].CaseID
		if _, exists := s.observations[id]; !exists {
			if count := s.pendingCases[caseID]; count > 1 {
				s.pendingCases[caseID] = count - 1
			} else {
				delete(s.pendingCases, caseID)
			}
		}
		s.observations[id] = *r.Observation
	}
	if r.L3 != nil {
		s.l3Runs[r.L3.Request.ID] = clone(*r.L3)
	}
}
