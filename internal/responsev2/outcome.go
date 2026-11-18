package responsev2

import (
	"crypto/rand"
	"encoding/hex"
	"reverse-artex/internal/decisions"
	"reverse-artex/internal/protection"
	"time"
)

type ResponseAttempt struct {
	Schema           string    `json:"schema"`
	ID               string    `json:"attempt_id"`
	EvidenceID       string    `json:"evidence_id"`
	CaseID           string    `json:"case_id"`
	CaseSHA          string    `json:"case_sha256"`
	Scope            Scope     `json:"scope"`
	PolicyID         string    `json:"policy_id,omitempty"`
	Episode          string    `json:"episode_id,omitempty"`
	Generation       int       `json:"generation,omitempty"`
	SDKStatus        int       `json:"sdk_status"`
	PlannedStatus    int       `json:"planned_status"`
	BootID           string    `json:"enforcer_boot_id"`
	PreparedAt       time.Time `json:"prepared_at"`
	PreparedSequence int       `json:"prepared_sequence"`
}
type ResponseObservation struct {
	Schema   string                   `json:"schema"`
	Write    protection.ResponseWrite `json:"write"`
	Sequence int                      `json:"sequence"`
}
type ReleaseFrame struct {
	Sequence int       `json:"sequence"`
	At       time.Time `json:"at"`
	State    string    `json:"state"`
	Intent   string    `json:"intent_id"`
}
type PolicyHistory struct {
	Binding           PolicyBinding  `json:"binding"`
	InstalledSequence int            `json:"installed_sequence"`
	InstalledAt       time.Time      `json:"installed_at"`
	Latest            Lease          `json:"latest"`
	Releases          []ReleaseFrame `json:"releases"`
}
type OutcomeAxis struct {
	State string   `json:"state"`
	Count int      `json:"count"`
	Refs  []string `json:"observation_refs"`
}
type Outcome struct {
	Schema           string      `json:"schema"`
	PolicyID         string      `json:"policy_id"`
	Episode          string      `json:"episode_id"`
	Generation       int         `json:"generation"`
	ScopeID          string      `json:"scope_id"`
	Enforcer         string      `json:"enforcer_id"`
	Registry         string      `json:"registry_digest"`
	AsOfSequence     int         `json:"as_of_sequence"`
	Installation     string      `json:"installation"`
	Target           OutcomeAxis `json:"target"`
	PolicyEffect     string      `json:"policy_effect"`
	Benign           OutcomeAxis `json:"benign_impact"`
	Release          OutcomeAxis `json:"release"`
	Recovery         OutcomeAxis `json:"recovery"`
	RecoveryReason   string      `json:"recovery_reason"`
	UnknownResponses int         `json:"unknown_or_partial_responses"`
	Source           string      `json:"source"`
	ClientReceipt    string      `json:"client_receipt"`
}

func historyKey(id, episode string) string { return decisions.Hash([]string{id, episode}) }
func newBootID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}
func (s *Store) PrepareResponse(tenant, evidenceID string, now time.Time) (protection.GateDecision, error) {
	started := s.timingStart()
	s.mu.Lock()
	s.timingEnd(timingPrepareWait, started)
	defer s.mu.Unlock()
	return s.prepareResponseLocked(tenant, evidenceID, now)
}

// PrepareResponseCurrent keeps live time sampling in the same critical
// section as the current policy snapshot and durable response preparation.
func (s *Store) PrepareResponseCurrent(tenant, evidenceID string) (protection.GateDecision, error) {
	started := s.timingStart()
	s.mu.Lock()
	s.timingEnd(timingPrepareWait, started)
	defer s.mu.Unlock()
	return s.prepareResponseLocked(tenant, evidenceID, time.Now())
}

func (s *Store) prepareResponseLocked(tenant, evidenceID string, now time.Time) (protection.GateDecision, error) {
	if err := s.check(now); err != nil {
		return protection.GateDecision{}, err
	}
	e, ok := s.events[evidenceID]
	if !ok {
		return protection.GateDecision{}, ErrStale
	}
	a, err := s.responseAttemptLocked(tenant, e, s.cases[caseID(e.Scope)], now)
	if err != nil {
		return protection.GateDecision{}, err
	}
	if err = s.commit(record{Operation: "response-prepared", At: now.UTC(), Attempt: &a}); err != nil {
		return protection.GateDecision{}, err
	}
	return decisionFor(a), nil
}

func (s *Store) responseAttemptLocked(tenant string, e Evidence, c Case, now time.Time) (ResponseAttempt, error) {
	if err := s.check(now); err != nil {
		return ResponseAttempt{}, err
	}
	if e.Scope.Tenant != tenant || c.ID != caseID(e.Scope) || now.Before(e.At) || now.Sub(e.Binding.Started) >= protection.ProofLifetime {
		return ResponseAttempt{}, ErrStale
	}
	verifyStarted := s.timingStart()
	_, verifyErr := s.registry.VerifyRecorded(e.Proof, e.Binding, e.Status, e.BodyLength, e.BodySHA, now)
	s.timingEnd(timingAttemptVerify, verifyStarted)
	if verifyErr != nil {
		return ResponseAttempt{}, verifyErr
	}
	g := s.gateEvidence(c, e, now)
	a := ResponseAttempt{Schema: "response-attempt/1", EvidenceID: e.ID, CaseID: c.ID, CaseSHA: c.SHA, Scope: e.Scope, SDKStatus: e.Status, PlannedStatus: e.Status, BootID: s.bootID, PreparedAt: now.UTC(), PreparedSequence: s.sequence + 1}
	if g.Deny {
		l := s.leases[g.PolicyID]
		a.PolicyID = l.ID
		a.Episode = l.Episode
		a.Generation = l.Generation
		a.PlannedStatus = 429
	}
	a.ID = decisions.Hash([]any{e.ID, a.PolicyID, a.Episode, a.Generation, a.BootID})
	if old, exists := s.attempts[a.ID]; exists {
		if old.EvidenceID != e.ID {
			return ResponseAttempt{}, ErrStale
		}
		return ResponseAttempt{}, ErrStale
	}
	if err := s.ensureHotCapacity(false, true); err != nil {
		return ResponseAttempt{}, err
	}
	if len(s.attempts) >= 8192 {
		return ResponseAttempt{}, ErrLimit
	}
	return a, nil
}
func decisionFor(a ResponseAttempt) protection.GateDecision {
	return protection.GateDecision{CaseID: a.CaseID, CaseSHA: a.CaseSHA, PolicyID: a.PolicyID, Deny: a.PlannedStatus == 429, AttemptID: a.ID}
}
func (s *Store) CompleteResponse(write protection.ResponseWrite) error {
	started := s.timingStart()
	s.mu.Lock()
	s.timingEnd(timingCompleteWait, started)
	defer s.mu.Unlock()
	return s.completeResponseLocked(write)
}

func (s *Store) completeResponseLocked(write protection.ResponseWrite) error {
	return s.completeResponseUsingClockLocked(write, time.Now)
}

// The live wrapper samples its original wall clock at the original commit
// point; deterministic fixtures can supply time without changing host clocks.
func (s *Store) completeResponseUsingClockLocked(write protection.ResponseWrite, clock func() time.Time) error {
	a, ok := s.attempts[write.AttemptID]
	if !ok && s.retained != nil {
		old, found, err := s.archivedCompletion(write.AttemptID)
		if err != nil {
			s.outcomeFailed = true
			return err
		}
		if found {
			if old.BootID == s.bootID && old.WriteSHA == decisions.Hash(write) {
				return nil
			}
			s.outcomeFailed = true
			return ErrStale
		}
	}
	if !ok || a.BootID != s.bootID || !validResponseWrite(a, write) {
		if ok {
			s.outcomeFailed = true
		}
		return ErrStale
	}
	if old, exists := s.observations[write.AttemptID]; exists {
		if decisions.Hash(old.Write) == decisions.Hash(write) {
			return nil
		}
		s.outcomeFailed = true
		return ErrStale
	}
	observation := ResponseObservation{Schema: "response-observation/1", Write: write, Sequence: s.sequence + 1}
	r := record{Operation: "response-observed", At: clock().UTC(), Observation: &observation}
	// A signed allowed representation denied by a policy is collateral, not a
	// successful attack block. Stop new automatic admissions atomically.
	e := s.events[a.EvidenceID]
	if write.Complete && ((a.PolicyID != "" && a.SDKStatus == 200 && write.Status == 429) || (write.Status == 200 && a.SDKStatus == 200 && (write.Bytes != e.BodyLength || write.BodySHA != e.BodySHA))) {
		pause := true
		epoch := s.epoch + 1
		r.Paused = &pause
		r.Epoch = &epoch
	}
	if err := s.commit(r); err != nil {
		s.outcomeFailed = true
		return err
	}
	return nil
}
func addRef(axis *OutcomeAxis, id string) {
	axis.Count++
	if len(axis.Refs) < 8 {
		axis.Refs = append(axis.Refs, id)
	}
}
func (s *Store) Outcome(tenant, id, episode string) (Outcome, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.outcomeLocked(tenant, id, episode, time.Now())
}
func (s *Store) outcomeLocked(tenant, id, episode string, now time.Time) (Outcome, error) {
	if episode == "" {
		if current, ok := s.leases[id]; ok {
			episode = current.Episode
		}
	}
	h, ok := s.histories[historyKey(id, episode)]
	if !ok || h.Binding.Scope.Tenant != tenant {
		return Outcome{}, ErrStale
	}
	unknown := func() OutcomeAxis { return OutcomeAxis{State: "unknown", Refs: []string{}} }
	out := Outcome{Schema: "defense-outcome/1", PolicyID: id, Episode: episode, Generation: h.Latest.Generation, ScopeID: scopeID(h.Binding.Scope), Enforcer: h.Binding.Scope.Enforcer, Registry: h.Binding.Scope.Registry, AsOfSequence: s.sequence, Installation: "installed_locally", Target: unknown(), PolicyEffect: "unknown", Benign: unknown(), Release: unknown(), Recovery: unknown(), Source: "trusted in-process edge server-write observations", ClientReceipt: "not_observed"}
	reason := ""
	for _, release := range h.Releases {
		out.Release.State = release.State
		addRef(&out.Release, release.Intent)
		if release.State == "no_effective_policy" {
			reason = "explicit_last_claim_release"
		}
	}
	if reason == "" && !now.Before(h.Latest.Expires) {
		reason = "natural_expiry"
	}
	if reason == "" && out.Release.State == "retained_by_other_owner" {
		out.Recovery.State = "retained_by_other_owner"
	}
	facts := cloneOutcomeFacts(s.outcomeFacts[historyKey(id, episode)])
	window := s.outcomeWindowLocked(h, now)
	for _, a := range s.attempts {
		var observation *ResponseObservation
		if observed, exists := s.observations[a.ID]; exists {
			copy := observed
			observation = &copy
		}
		facts.include(h, window, a, s.events[a.EvidenceID], observation)
	}
	out.Target = facts.Target.axis("unknown")
	if facts.Target.Count > 0 {
		out.Target.State = "observed_denied"
		out.PolicyEffect = "masked_by_sdk"
	}
	out.Benign = facts.Benign.axis("unknown")
	if facts.BenignObserved {
		out.Benign.State = "no_observed_collateral"
	}
	if facts.Collateral {
		out.Benign.State = "observed_collateral"
		out.PolicyEffect = "observed_collateral"
	}
	out.UnknownResponses = facts.Unknown
	out.Recovery = facts.Recovery.axis(out.Recovery.State)
	out.RecoveryReason = reason
	if reason != "" {
		out.Recovery.State = "unobserved"
		if facts.TargetRecovered {
			out.Recovery.State = "policy_absence_observed_benign_unverified"
		}
		if facts.TargetRecovered && facts.BenignRecovered {
			out.Recovery.State = "observed_guard_baseline_restored"
		}
	}
	return out, nil
}
func (s *Store) OutcomeHealth() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	pending := 0
	for id := range s.attempts {
		if _, ok := s.observations[id]; !ok {
			pending++
		}
	}
	return map[string]any{"response_attempts": s.totalAttempts, "response_observations": s.totalObservations, "active_response_attempts": len(s.attempts), "active_response_observations": len(s.observations), "retention": s.retainedStatusLocked(), "pending_unknown": pending, "audit_available": s.check(time.Now()) == nil, "enforcer_boot_id": s.bootID, "client_receipts": "not_observed",
		"policy_command_budget": map[string]any{"recorded": len(s.intents), "install_limit": policyInstallCommandLimit, "new_installs_at_limit": len(s.intents) >= policyInstallCommandLimit}}
}

// validResponseWrite also validates records during replay. "complete" means the
// server accepted the entire write, never that the remote client received it.
func validResponseWrite(a ResponseAttempt, w protection.ResponseWrite) bool {
	if w.CompletedAt.IsZero() || w.CompletedAt.Before(a.PreparedAt) || w.Bytes < 0 || w.Bytes > 1<<20 || !decisions.ValidHash(w.BodySHA) || w.Status < 0 || w.Status > 599 || (w.Status > 0 && w.Status < 200) {
		return false
	}
	if w.Complete && (w.Error || w.Status == 0) {
		return false
	}
	if w.Status == 0 && w.Bytes != 0 {
		return false
	}
	if (w.Bytes == 0 && w.BodySHA != protection.BodyHash(nil)) || (a.Scope.Method == "HEAD" && w.Bytes != 0) {
		return false
	}
	return true
}
