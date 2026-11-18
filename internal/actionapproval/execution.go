package actionapproval

import (
	"context"
	"errors"
	"time"

	"reverse-artex/internal/actionproposal"
	"reverse-artex/internal/control"
	"reverse-artex/internal/decisions"
	"reverse-artex/internal/policy"
)

type ExecutionAttempt struct {
	Schema         string                 `json:"schema"`
	ID             string                 `json:"attempt_id"`
	ServicesSHA    string                 `json:"services_sha256"`
	AuthoritySHA   string                 `json:"authority_sha256"`
	CaseSHA        string                 `json:"case_context_sha256"`
	RequestSHA     string                 `json:"request_sha256"`
	Started        time.Time              `json:"started_at"`
	ReleaseStarted *time.Time             `json:"release_started_at,omitempty"`
	Command        control.ApprovedPolicy `json:"command"`
}
type ExecutionReceipt struct {
	Schema         string                  `json:"schema"`
	Scope          string                  `json:"scope"`
	Entry          Entry                   `json:"entry"`
	Observation    *control.ApprovedStatus `json:"observation,omitempty"`
	ApplyInvoked   bool                    `json:"apply_invoked"`
	ReleaseInvoked bool                    `json:"release_invoked"`
}

func executionReceipt(e Entry) ExecutionReceipt {
	return ExecutionReceipt{Schema: "action-execution-receipt/1", Scope: "policy_control_command_state_only", Entry: cloneEntry(e)}
}
func (s *ExecutionServices) binding() string {
	return decisions.Hash([]string{s.caseOrigin, s.controlOrigin})
}
func executionCommand(e Entry, adapter string) control.ApprovedPolicy {
	p := e.Proposal
	return control.ApprovedPolicy{Key: e.ID, AdapterID: adapter, ApprovalSHA: e.ApprovalSHA, ProposalSHA: decisions.Hash(p), DispatchBefore: p.Expires,
		Policy: policy.Policy{ID: "approved-" + e.ID, CaseID: p.CaseID, Tenant: p.Target.Tenant, Asset: p.Target.Asset, Principal: p.Target.Principal, Session: p.Target.Session, Route: p.Target.Route, RuleVersion: "approved-session-route-1", Issued: e.Consumed, Expires: e.ActionExpires}}
}
func (l *Ledger) executionAuthority(e Entry, s *ExecutionServices, at time.Time) (ExecutionAuthority, error) {
	a, err := s.authority()
	if err != nil {
		return a, err
	}
	auth, ok := l.approvals[e.ApprovalSHA]
	if !ok || a.Epoch != e.Proposal.Epoch || a.Trust.Domain != l.trust.Domain || verifySignature(a.Trust, l.state.ID, auth, at) != nil || verifyApproval(auth.Command, e.Proposal) != nil {
		return a, errors.New("current operator grant revoked, changed or expired")
	}
	return a, nil
}

// RunExecution is explicit opt-in to the configured real policy-control writer.
// The local ledger lock serializes stop/cancel and records an attempt before
// the POST. Remote reads are point-in-time admissions, not a distributed lock.
// Any ambiguous result stays unknown and is never retried automatically.
func (l *Ledger) RunExecution(ctx context.Context, req actionproposal.Request, auth Signed, s *ExecutionServices) (ExecutionReceipt, error) {
	if s == nil {
		return ExecutionReceipt{}, errors.New("explicit execution services required")
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return ExecutionReceipt{}, err
	}
	e, err := l.consumeLocked(req, auth, time.Now().UTC())
	if err != nil {
		return ExecutionReceipt{}, err
	}
	r := executionReceipt(e)
	if e.Phase != "intent_recorded" || e.Execution != nil || e.Simulation != nil {
		return r, errors.New("intent already attempted, observed or recovered; no replay")
	}
	fail := func(cause error) (ExecutionReceipt, error) {
		err := l.unknownExecution(e.ID, time.Now().UTC(), cause)
		r.Entry = cloneEntry(l.state.Entries[e.ID])
		return r, err
	}
	if err = l.freshSimulation(e, req, time.Now().UTC()); err != nil {
		return fail(err)
	}
	a, err := l.executionAuthority(e, s, time.Now().UTC())
	if err != nil {
		return fail(err)
	}
	c, err := s.currentCase(ctx, req)
	if err != nil {
		return fail(err)
	}
	command := executionCommand(e, a.AdapterID)
	command.DispatchBefore = auth.Command.Expires
	if e.Proposal.Expires.Before(command.DispatchBefore) {
		command.DispatchBefore = e.Proposal.Expires
	}
	command.EvidenceID = req.SubjectRef
	for _, event := range req.Events {
		if event.EventID == req.SubjectRef {
			command.EvidenceSHA = decisions.Hash(event)
		}
	}
	status, err := s.status(ctx, command, false)
	if err != nil || status.State != "not_applied" {
		return fail(errors.Join(errors.New("adapter preflight did not confirm unused command"), err))
	}
	at := time.Now().UTC()
	if ctx.Err() != nil {
		return fail(ctx.Err())
	}
	if err = l.freshSimulation(e, req, at); err != nil {
		return fail(err)
	}
	attempt := &ExecutionAttempt{Schema: "action-execution-attempt/1", ID: decisions.Hash([]string{l.state.ID, e.ID, "policy-control-execution"}), ServicesSHA: s.binding(), AuthoritySHA: decisions.Hash(a), CaseSHA: decisions.Hash(c), RequestSHA: decisions.Hash(req), Started: at, Command: command}
	if err = l.append(record{Kind: "execution_dispatch", Time: at, EntryID: e.ID, Execution: attempt, Request: &req}); err != nil {
		return fail(err)
	}
	e = cloneEntry(l.state.Entries[e.ID])
	r.Entry = e
	// Reauthorize after durable Sync; it may have taken most of the remaining
	// lease. A stale case or revoked key cannot reuse the pre-Sync admission.
	a2, err := l.executionAuthority(e, s, time.Now().UTC())
	if err != nil || decisions.Hash(a2) != attempt.AuthoritySHA {
		return fail(errors.Join(errors.New("execution authority changed during admission"), err))
	}
	c2, err := s.currentCase(ctx, req)
	if err != nil || decisions.Hash(c2) != attempt.CaseSHA {
		return fail(errors.Join(errors.New("case changed during admission"), err))
	}
	a3, err := l.executionAuthority(e, s, time.Now().UTC())
	if err != nil || decisions.Hash(a3) != attempt.AuthoritySHA {
		return fail(errors.Join(errors.New("execution authority changed during case read"), err))
	}
	if err = l.freshSimulation(e, req, time.Now().UTC()); err != nil {
		return fail(err)
	}
	if err = ctx.Err(); err != nil {
		return fail(err)
	}
	r.ApplyInvoked = true
	status, err = s.status(ctx, command, true)
	if err != nil {
		return fail(err)
	}
	r.Observation = &status
	if status.State != "active" {
		return fail(errors.New("policy control did not confirm active command"))
	}
	// This is a controller observation. It is not edge effect proof or a
	// response-observer signature, and cannot make the ledger phase active.
	return r, nil
}
func (l *Ledger) unknownExecution(id string, at time.Time, cause error) error {
	e, ok := l.state.Entries[id]
	if !ok || terminal(e.Phase) || e.Phase == "unknown" {
		return cause
	}
	if err := l.append(record{Kind: "execution_unknown", Time: at, EntryID: id}); err != nil {
		return errors.Join(cause, err)
	}
	return cause
}
func (l *Ledger) ObserveExecution(ctx context.Context, id string, s *ExecutionServices) (ExecutionReceipt, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.state.Entries[id]
	if !ok {
		return ExecutionReceipt{}, errors.New("unknown execution entry")
	}
	r := executionReceipt(e)
	if err := l.ready(time.Now().UTC()); err != nil {
		return r, err
	}
	if s == nil || e.Execution == nil || s.binding() != e.Execution.ServicesSHA {
		return r, errors.New("original execution services required")
	}
	status, err := s.status(ctx, e.Execution.Command, false)
	if err != nil {
		err = l.unknownExecution(id, time.Now().UTC(), err)
		r.Entry = cloneEntry(l.state.Entries[id])
		return r, err
	}
	r.Observation = &status
	return r, nil
}
func (l *Ledger) ReleaseExecution(ctx context.Context, id string, s *ExecutionServices) (ExecutionReceipt, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.state.Entries[id]
	if !ok {
		return ExecutionReceipt{}, errors.New("unknown execution entry")
	}
	r := executionReceipt(e)
	if err := l.ready(time.Now().UTC()); err != nil {
		return r, err
	}
	if s == nil || e.Execution == nil || !e.CancelRequested || s.binding() != e.Execution.ServicesSHA {
		return r, errors.New("signed cancellation and original execution services required")
	}
	status, err := s.status(ctx, e.Execution.Command, false)
	if err != nil {
		err = l.unknownExecution(id, time.Now().UTC(), err)
		r.Entry = cloneEntry(l.state.Entries[id])
		return r, err
	}
	r.Observation = &status
	if status.State != "active" || terminal(e.Phase) || e.Execution.ReleaseStarted != nil {
		return r, nil
	}
	currentGrant := func() error {
		a, err := s.authority()
		cancel, ok := l.cancellations[id]
		if err != nil || !ok || a.Trust.Domain != l.trust.Domain || a.AdapterID != e.Execution.Command.AdapterID || verifySignature(a.Trust, l.state.ID, cancel, time.Now().UTC()) != nil {
			return errors.New("fresh current cancellation authority required")
		}
		return nil
	}
	if err = currentGrant(); err != nil {
		return r, err
	}
	if err = l.append(record{Kind: "execution_release", Time: time.Now().UTC(), EntryID: id}); err != nil {
		return r, err
	}
	r.Entry = cloneEntry(l.state.Entries[id])
	if err = currentGrant(); err != nil {
		err = l.unknownExecution(id, time.Now().UTC(), err)
		r.Entry = cloneEntry(l.state.Entries[id])
		return r, err
	}
	r.ReleaseInvoked = true
	var receipt control.Receipt
	err = s.exchange(ctx, s.controlOrigin, "/v1/revoke", s.adminToken, control.Revoke{Key: "release-" + id, ID: e.Execution.Command.Policy.ID, Reason: "operator_verified"}, &receipt, 8<<10)
	if err == nil {
		status, err = s.status(ctx, e.Execution.Command, false)
	}
	if err != nil || status.State != "released" {
		err = l.unknownExecution(id, time.Now().UTC(), errors.Join(errors.New("release outcome unconfirmed"), err))
		r.Entry = cloneEntry(l.state.Entries[id])
		return r, err
	}
	r.Observation = &status
	return r, nil
}

func (l *Ledger) executionTransition(next *state, r record) error {
	bad := errors.New("invalid policy-control execution transition")
	if l.state.Sequence == 0 || r.Authorization != nil || r.Simulation != nil || !decisions.ValidHash(r.EntryID) {
		return bad
	}
	e, ok := next.Entries[r.EntryID]
	if !ok || terminal(e.Phase) {
		return bad
	}
	switch r.Kind {
	case "execution_dispatch":
		if e.Phase != "intent_recorded" || e.Execution != nil || e.Simulation != nil || r.Execution == nil || r.Request == nil || l.freshSimulation(e, *r.Request, r.Time) != nil {
			return bad
		}
		a := *r.Execution
		want := executionCommand(e, a.Command.AdapterID)
		original, ok := l.approvals[e.ApprovalSHA]
		if !ok {
			return bad
		}
		want.DispatchBefore = original.Command.Expires
		if e.Proposal.Expires.Before(want.DispatchBefore) {
			want.DispatchBefore = e.Proposal.Expires
		}
		want.EvidenceID = r.Request.SubjectRef
		for _, v := range r.Request.Events {
			if v.EventID == want.EvidenceID {
				want.EvidenceSHA = decisions.Hash(v)
			}
		}
		if a.Schema != "action-execution-attempt/1" || a.ID != decisions.Hash([]string{next.ID, e.ID, "policy-control-execution"}) || !identifier.MatchString(a.Command.AdapterID) || decisions.Hash(want) != decisions.Hash(a.Command) || !decisions.ValidHash(a.ServicesSHA) || !decisions.ValidHash(a.AuthoritySHA) || !decisions.ValidHash(a.CaseSHA) || a.RequestSHA != decisions.Hash(r.Request) || !a.Started.Equal(r.Time) || a.ReleaseStarted != nil {
			return bad
		}
		e.Execution = &a
		e.Phase = "dispatching"
	case "execution_unknown":
		if r.Request != nil || r.Execution != nil || e.Phase == "unknown" {
			return bad
		}
		e.Phase = "unknown"
	case "execution_release":
		if r.Request != nil || r.Execution != nil || !e.CancelRequested || e.Execution == nil || e.Execution.ReleaseStarted != nil {
			return bad
		}
		a := *e.Execution
		at := r.Time
		a.ReleaseStarted = &at
		e.Execution = &a
		e.Phase = "release_pending"
	default:
		return bad
	}
	next.Entries[e.ID] = e
	return nil
}
