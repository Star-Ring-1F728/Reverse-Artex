package actionapproval

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"reverse-artex/internal/actionproposal"
	"reverse-artex/internal/decisions"
	"reverse-artex/internal/policy"
)

const simulationVersion = "local-policy-simulation/1"

type SimulationAttempt struct {
	Schema         string     `json:"schema"`
	ID             string     `json:"attempt_id"`
	SimulatorID    string     `json:"simulator_id"`
	Version        string     `json:"adapter_version"`
	EntryBeforeSHA string     `json:"entry_before_sha256"`
	RequestSHA     string     `json:"request_sha256"`
	Started        time.Time  `json:"started_at"`
	ReleaseStarted *time.Time `json:"release_started_at,omitempty"`
}

type SimulationObservation struct {
	Schema      string    `json:"schema"`
	SimulatorID string    `json:"simulator_id"`
	Version     string    `json:"adapter_version"`
	AttemptID   string    `json:"attempt_id"`
	EntryID     string    `json:"entry_id"`
	ProposalSHA string    `json:"proposal_sha256"`
	TargetSHA   string    `json:"target_sha256"`
	Issued      time.Time `json:"issued_at"`
	Expires     time.Time `json:"expires_at"`
	Observed    time.Time `json:"observed_at"`
	State       string    `json:"state"`
	Reason      string    `json:"reason"`
	EvidenceSHA string    `json:"evidence_sha256"`
}

type simulationEffect struct {
	Entry Entry
	State string
}

// PolicySimulation can change only its private policy.Replica. It exposes no
// arbitrary adapter interface, URL, command, control client or OS policy writer.
// Its random identity is process-local; losing it is unknown, never absence.
type PolicySimulation struct {
	mu      sync.Mutex
	id      string
	key     []byte
	replica *policy.Replica
	version uint64
	effects map[string]simulationEffect
	last    time.Time
	// Fault hooks are unexported and used only by in-package tests.
	beforeApply              func(Entry) error
	afterApply               func(Entry) error
	afterRelease             func(Entry) error
	applyCalls, releaseCalls int
}

func NewPolicySimulation() (*PolicySimulation, error) {
	b := make([]byte, 64)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return &PolicySimulation{id: hex.EncodeToString(b[:32]), key: append([]byte(nil), b[32:]...), replica: policy.NewReplica(), effects: map[string]simulationEffect{}}, nil
}

func (s *PolicySimulation) identity() string { return s.id }
func simulationPolicy(e Entry) policy.Policy {
	return policy.Policy{ID: "sim-" + e.ID[:32], CaseID: e.Proposal.CaseID, Tenant: e.Proposal.Target.Tenant, Asset: e.Proposal.Target.Asset,
		Principal: e.Proposal.Target.Principal, Session: e.Proposal.Target.Session, Route: e.Proposal.Target.Route,
		RuleVersion: "simulation-1", Issued: e.Consumed, Expires: e.ActionExpires, Version: 1}
}
func (s *PolicySimulation) ready(now time.Time) error {
	if now.IsZero() || now.Before(s.last) {
		return errors.New("simulation clock moved backwards")
	}
	s.last = now
	return nil
}
func (s *PolicySimulation) replace(now time.Time) error {
	items := []policy.Policy{}
	for _, effect := range s.effects {
		if effect.State == "active" && now.Before(effect.Entry.ActionExpires) {
			items = append(items, simulationPolicy(effect.Entry))
		}
	}
	s.version++
	return s.replica.Replace(policy.Sign(policy.Snapshot{Epoch: s.id, Version: s.version, Generated: now, Policies: items}, s.key), s.key, now)
}
func (s *PolicySimulation) apply(e Entry, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ready(now); err != nil {
		return err
	}
	if e.Simulation == nil || e.Simulation.SimulatorID != s.id || !now.Before(e.ActionExpires) || policy.ValidateScoped(simulationPolicy(e), now) != nil {
		return errors.New("fresh exact simulation lease required")
	}
	if _, exists := s.effects[e.ID]; exists {
		return errors.New("simulation action already attempted")
	}
	if len(s.effects) >= MaxEntries {
		return errors.New("simulation capacity")
	}
	s.applyCalls++
	if s.beforeApply != nil {
		if err := s.beforeApply(e); err != nil {
			return err
		}
	}
	s.effects[e.ID] = simulationEffect{cloneEntry(e), "active"}
	if err := s.replace(now); err != nil {
		return err
	}
	if s.afterApply != nil {
		return s.afterApply(e)
	}
	return nil
}
func (s *PolicySimulation) release(e Entry, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ready(now); err != nil {
		return err
	}
	effect, exists := s.effects[e.ID]
	if !exists || effect.State != "active" {
		return errors.New("no confirmed active simulation to release")
	}
	s.releaseCalls++
	effect.State = "released"
	s.effects[e.ID] = effect
	if err := s.replace(now); err != nil {
		return err
	}
	if s.afterRelease != nil {
		return s.afterRelease(e)
	}
	return nil
}
func (s *PolicySimulation) observe(e Entry, now time.Time) (SimulationObservation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ready(now); err != nil {
		return SimulationObservation{}, err
	}
	if e.Simulation == nil || e.Simulation.SimulatorID != s.id || e.Simulation.Version != simulationVersion {
		return SimulationObservation{}, errors.New("simulation identity lost or changed; state remains unknown")
	}
	o := SimulationObservation{Schema: "action-simulation-observation/1", SimulatorID: s.id, Version: simulationVersion, AttemptID: e.Simulation.ID,
		EntryID: e.ID, ProposalSHA: decisions.Hash(e.Proposal), TargetSHA: decisions.Hash(e.Proposal.Target), Issued: e.Consumed, Expires: e.ActionExpires, Observed: now, State: "not_applied", Reason: "absent_in_same_simulator"}
	if effect, exists := s.effects[e.ID]; exists {
		if decisions.Hash(effect.Entry.Proposal) != o.ProposalSHA || !effect.Entry.ActionExpires.Equal(e.ActionExpires) {
			return SimulationObservation{}, errors.New("simulation binding mismatch")
		}
		o.State, o.Reason = effect.State, "replica_checked"
		if effect.State == "active" {
			if !now.Before(e.ActionExpires) {
				o.State, o.Reason = "released", "ttl_expired"
				effect.State = "released"
				s.effects[e.ID] = effect
			}
		}
	}
	matched, ok := s.replica.Match(e.Proposal.Target.Tenant, e.Proposal.Target.Asset, e.Proposal.Target.Principal, e.Proposal.Target.Session, e.Proposal.Target.Route, now)
	thisEffect := ok && matched.ID == simulationPolicy(e).ID
	if o.State == "active" && (!thisEffect || !matched.Expires.Equal(e.ActionExpires)) {
		return SimulationObservation{}, errors.New("simulation effect not confirmed by replica")
	}
	if o.State != "active" && thisEffect {
		return SimulationObservation{}, errors.New("simulation absence contradicted by replica")
	}
	o.EvidenceSHA = decisions.Hash(o)
	return o, nil
}

// Probe inspects only the private replica; it never sends a request or changes
// real traffic. An error means unknown, not an allow/deny decision.
func (s *PolicySimulation) Probe(target actionproposal.Target, now time.Time) (bool, error) {
	if s == nil {
		return false, errors.New("simulation required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ready(now); err != nil {
		return false, err
	}
	_, denied := s.replica.Match(target.Tenant, target.Asset, target.Principal, target.Session, target.Route, now)
	return denied, nil
}
