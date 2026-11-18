package actionapproval

import (
	"errors"
	"time"

	"reverse-artex/internal/actionproposal"
	"reverse-artex/internal/decisions"
)

type SimulationReceipt struct {
	Schema         string                 `json:"schema"`
	Scope          string                 `json:"scope"`
	Authority      string                 `json:"authority"`
	Entry          Entry                  `json:"entry"`
	Observation    *SimulationObservation `json:"observation,omitempty"`
	ApplyInvoked   bool                   `json:"apply_invoked"`
	ReleaseInvoked bool                   `json:"release_invoked"`
}

func simulationReceipt(e Entry) SimulationReceipt {
	return SimulationReceipt{Schema: "action-simulation-receipt/1", Scope: "local_policy_replica_only", Authority: "simulation_only", Entry: cloneEntry(e)}
}

// operationClock advances even for a fixed replay clock while I/O runs. A raw
// clock rollback is rejected; no queued or delayed operation gets a fresh TTL.
func operationClock(clock func() time.Time) (func() (time.Time, error), error) {
	if clock == nil {
		return nil, errors.New("explicit trusted/replay clock required")
	}
	anchor := clock()
	if anchor.IsZero() {
		return nil, errors.New("explicit clock required")
	}
	started := time.Now()
	last := anchor
	return func() (time.Time, error) {
		at := clock()
		if at.Before(anchor) {
			return time.Time{}, errors.New("dispatch clock moved backwards")
		}
		elapsed := anchor.Add(time.Since(started))
		if at.Before(elapsed) {
			at = elapsed
		}
		if at.Before(last) {
			return time.Time{}, errors.New("dispatch clock moved backwards")
		}
		last = at
		return at, nil
	}, nil
}

func (l *Ledger) freshSimulation(e Entry, req actionproposal.Request, at time.Time) error {
	if err := l.ready(at); err != nil {
		return err
	}
	if terminal(e.Phase) || e.CancelRequested || l.state.Stopped[e.Proposal.Target.Tenant] || !at.Before(e.ActionExpires) {
		return errors.New("stopped, cancelled, terminal or expired simulation intent")
	}
	approval, exists := l.approvals[e.ApprovalSHA]
	if !exists || verifySignature(l.trust, l.state.ID, approval, at) != nil || verifyApproval(approval.Command, e.Proposal) != nil {
		return errors.New("fresh original signed approval required at dispatch")
	}
	return actionproposal.Verify(e.Proposal, req, at)
}

// RunPolicySimulation is the private-replica consume+effect path. The ledger mutex and
// current-case lock cover preflight, durable attempt and local effect. Signed
// stop/cancel and source updates therefore linearize before or after dispatch.
// It cannot select an arbitrary/real adapter and never signs an observation.
func (l *Ledger) RunPolicySimulation(req actionproposal.Request, authorization Signed, current *LocalCaseSource, sim *PolicySimulation, clock func() time.Time) (SimulationReceipt, error) {
	if sim == nil || current == nil {
		return SimulationReceipt{}, errors.New("explicit local policy simulation and current case source required")
	}
	tick, err := operationClock(clock)
	if err != nil {
		return SimulationReceipt{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	at, err := tick()
	if err != nil {
		return SimulationReceipt{}, err
	}
	e, err := l.consumeLocked(req, authorization, at)
	if err != nil {
		return SimulationReceipt{}, err
	}
	result := simulationReceipt(e)
	if e.Phase != "intent_recorded" || e.Simulation != nil {
		return result, errors.New("intent already observed, cancelled, recovered or attempted; no replay")
	}
	if err := l.freshSimulation(e, req, at); err != nil {
		return result, l.abortSimulation(e.ID, at, err)
	}
	err = current.withCurrent(e.Proposal, func() error {
		at, err = tick()
		if err != nil {
			return err
		}
		if err := l.freshSimulation(e, req, at); err != nil {
			return err
		}
		attempt := &SimulationAttempt{Schema: "action-simulation-attempt/1", ID: decisions.Hash([]string{l.state.ID, e.ID, "local-policy-simulation"}),
			SimulatorID: sim.identity(), Version: simulationVersion, EntryBeforeSHA: decisions.Hash(e), RequestSHA: decisions.Hash(req), Started: at}
		if err := l.append(record{Kind: "simulation_dispatch", Time: at, EntryID: e.ID, Simulation: attempt, Request: &req}); err != nil {
			return err
		}
		e = cloneEntry(l.state.Entries[e.ID])
		result.Entry = e
		at, err = tick()
		if err != nil {
			return err
		}
		if err := l.freshSimulation(e, req, at); err != nil {
			return err
		}
		result.ApplyInvoked = true
		if err := sim.apply(e, at); err != nil {
			return err
		}
		at, err = tick()
		if err != nil {
			return err
		}
		if err := l.ready(at); err != nil {
			return err
		}
		observation, err := sim.observe(e, at)
		if err != nil {
			return err
		}
		result.Observation = &observation
		if observation.State != "active" {
			return errors.New("simulation apply was not confirmed active within fixed expiry")
		}
		return nil
	})
	if err != nil {
		// A failed dispatch is never retried, even when no effect is later found.
		if when, timeErr := tick(); timeErr == nil {
			err = l.abortSimulation(e.ID, when, err)
		}
		result.Entry = cloneEntry(l.state.Entries[e.ID])
		return result, err
	}
	result.Entry = cloneEntry(l.state.Entries[e.ID])
	return result, nil
}

func (l *Ledger) abortSimulation(id string, at time.Time, cause error) error {
	e, exists := l.state.Entries[id]
	if !exists || terminal(e.Phase) || e.Phase == "unknown" {
		return cause
	}
	if err := l.append(record{Kind: "simulation_unknown", Time: at, EntryID: id}); err != nil {
		return errors.Join(cause, err)
	}
	return cause
}

// ObservePolicySimulation is a read of the specific original simulator only.
// Its receipt may be reviewed/signed by an observer; it grants no approval.
func (l *Ledger) ObservePolicySimulation(id string, sim *PolicySimulation, now time.Time) (SimulationReceipt, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, exists := l.state.Entries[id]
	if !exists {
		return SimulationReceipt{}, errors.New("unknown simulation entry")
	}
	r := simulationReceipt(e)
	if err := l.ready(now); err != nil {
		return r, err
	}
	if sim == nil {
		return r, errors.New("original simulation required")
	}
	o, err := sim.observe(e, now)
	if err != nil {
		err = l.abortSimulation(id, now, err)
		r.Entry = cloneEntry(l.state.Entries[id])
		return r, err
	}
	r.Observation = &o
	return r, nil
}

// ReleasePolicySimulation requires a previously signed cancellation. It writes
// a one-shot release intent before changing the replica, then queries absence.
// Repeated calls only observe; they cannot repeat an ambiguous release effect.
func (l *Ledger) ReleasePolicySimulation(id string, sim *PolicySimulation, clock func() time.Time) (SimulationReceipt, error) {
	tick, err := operationClock(clock)
	if err != nil {
		return SimulationReceipt{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	e, exists := l.state.Entries[id]
	if !exists {
		return SimulationReceipt{}, errors.New("unknown simulation entry")
	}
	r := simulationReceipt(e)
	at, err := tick()
	if err != nil {
		return r, err
	}
	if err = l.ready(at); err != nil {
		return r, err
	}
	if sim == nil || !e.CancelRequested || e.Simulation == nil {
		return r, errors.New("signed cancellation and original simulation attempt required")
	}
	o, err := sim.observe(e, at)
	if err != nil {
		return r, l.abortSimulation(id, at, err)
	}
	r.Observation = &o
	if o.State != "active" || terminal(e.Phase) || e.Simulation.ReleaseStarted != nil {
		return r, nil
	}
	if err = l.append(record{Kind: "simulation_release", Time: at, EntryID: id}); err != nil {
		return r, err
	}
	e = cloneEntry(l.state.Entries[id])
	r.Entry = e
	at, err = tick()
	if err != nil {
		return r, err
	}
	r.ReleaseInvoked = true
	if err = sim.release(e, at); err != nil {
		err = l.abortSimulation(id, at, err)
		r.Entry = cloneEntry(l.state.Entries[id])
		return r, err
	}
	at, err = tick()
	if err != nil {
		return r, err
	}
	o, err = sim.observe(e, at)
	if err != nil {
		err = l.abortSimulation(id, at, err)
		r.Entry = cloneEntry(l.state.Entries[id])
		return r, err
	}
	r.Observation = &o
	if o.State == "active" {
		return r, l.abortSimulation(id, at, errors.New("simulation release acknowledgment did not confirm absence"))
	}
	return r, nil
}

func (l *Ledger) simulationTransition(next *state, r record) error {
	bad := errors.New("invalid local simulation transition")
	if l.state.Sequence == 0 || r.Authorization != nil || !decisions.ValidHash(r.EntryID) {
		return bad
	}
	e, exists := next.Entries[r.EntryID]
	if !exists || terminal(e.Phase) {
		return bad
	}
	switch r.Kind {
	case "simulation_dispatch":
		if e.Phase != "intent_recorded" || e.Simulation != nil || r.Request == nil || r.Simulation == nil || l.freshSimulation(e, *r.Request, r.Time) != nil {
			return bad
		}
		a := *r.Simulation
		if a.Schema != "action-simulation-attempt/1" || a.ID != decisions.Hash([]string{next.ID, e.ID, "local-policy-simulation"}) || !decisions.ValidHash(a.SimulatorID) || a.Version != simulationVersion || a.EntryBeforeSHA != decisions.Hash(e) || a.RequestSHA != decisions.Hash(r.Request) || !a.Started.Equal(r.Time) || a.ReleaseStarted != nil {
			return bad
		}
		e.Simulation = &a
		e.Phase = "dispatching"
	case "simulation_unknown":
		if r.Request != nil || r.Simulation != nil || e.Phase == "unknown" {
			return bad
		}
		e.Phase = "unknown"
	case "simulation_release":
		if r.Request != nil || r.Simulation != nil || !e.CancelRequested || e.Simulation == nil || e.Simulation.ReleaseStarted != nil {
			return bad
		}
		a := *e.Simulation
		at := r.Time
		a.ReleaseStarted = &at
		e.Simulation = &a
		e.Phase = "release_pending"
	default:
		return bad
	}
	next.Entries[e.ID] = e
	return nil
}
