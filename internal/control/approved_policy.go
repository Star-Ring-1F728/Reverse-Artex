package control

import (
	"context"
	"errors"
	"reverse-artex/internal/decisions"
	"reverse-artex/internal/policy"
	"time"
)

// ApprovedPolicy is admitted only by the separately authenticated coordinator.
// Unlike Approve it binds an absolute expiry and an exact persisted subject.
// This endpoint never accepts an event to insert into the evidence ledger.
type ApprovedPolicy struct {
	Key            string        `json:"idempotency_key"`
	AdapterID      string        `json:"adapter_id"`
	ApprovalSHA    string        `json:"authorization_sha256"`
	ProposalSHA    string        `json:"proposal_sha256"`
	EvidenceID     string        `json:"subject_evidence_id"`
	EvidenceSHA    string        `json:"subject_evidence_sha256"`
	DispatchBefore time.Time     `json:"dispatch_before"`
	Policy         policy.Policy `json:"policy"`
}

type ApprovedStatus struct {
	Schema     string    `json:"schema"`
	AdapterID  string    `json:"adapter_id"`
	CommandSHA string    `json:"command_sha256"`
	PolicyID   string    `json:"policy_id"`
	State      string    `json:"state"`
	Observed   time.Time `json:"observed_at"`
}

func (a ApprovedPolicy) valid() bool {
	p := a.Policy
	return policy.ID.MatchString(a.Key) && policy.ID.MatchString(a.AdapterID) &&
		decisions.ValidHash(a.ApprovalSHA) && decisions.ValidHash(a.ProposalSHA) && decisions.ValidHash(a.EvidenceSHA) &&
		policy.ID.MatchString(a.EvidenceID) && p.ID == "approved-"+a.Key && p.Version == 0 && p.RuleVersion == "approved-session-route-1" &&
		!p.Issued.IsZero() && p.Expires.Sub(p.Issued) == 10*time.Second && !a.DispatchBefore.IsZero() &&
		a.DispatchBefore.After(p.Issued) && !a.DispatchBefore.After(p.Issued.Add(30*time.Second))
}

func (m *Manager) ApplyApprovedContext(ctx context.Context, a ApprovedPolicy) (ApprovedStatus, error) {
	if err := m.mu.LockContext(ctx); err != nil {
		return ApprovedStatus{}, err
	}
	defer m.mu.Unlock()
	now := time.Now().UTC()
	if !a.valid() || a.AdapterID != m.epoch || a.Policy.Issued.After(now) || !now.Before(a.DispatchBefore) || policy.ValidateScoped(a.Policy, now) != nil {
		return ApprovedStatus{}, errors.New("fresh exact approved policy required")
	}
	if _, exists, err := m.existing(a.Key, hash(a)); exists || err != nil {
		if err != nil {
			return ApprovedStatus{}, err
		}
		return m.approvedStatusLocked(a, now)
	}
	e, ok := m.events[a.EvidenceID]
	p := a.Policy
	if !ok || hash(e) != a.EvidenceSHA || e.Identity != "authenticated" || e.DataQuality != "complete" || e.EventTime.Before(now.Add(-time.Minute)) ||
		e.TenantID != p.Tenant || e.AssetID != p.Asset || e.Principal != p.Principal || e.SessionHMAC != p.Session || e.Route != p.Route {
		return ApprovedStatus{}, errors.New("approved target differs from persisted subject")
	}
	if m.dead[p.ID] {
		return ApprovedStatus{}, errors.New("retired approved policy")
	}
	if err := m.expire(now); err != nil {
		return ApprovedStatus{}, err
	}
	if len(m.active) >= 1024 {
		return ApprovedStatus{}, errors.New("active policy budget exceeded")
	}
	p.Version = m.version + 1
	if _, err := m.commit(record{Time: now, Operation: "approve", Actor: "signed-coordinator:" + a.ApprovalSHA, Key: a.Key, Hash: hash(a), Policy: &p, Auto: m.auto, Refs: []string{e.EventID, a.ProposalSHA}}); err != nil {
		return ApprovedStatus{}, err
	}
	return m.approvedStatusLocked(a, time.Now().UTC())
}

// Status never applies, expires, releases or retries a policy. Missing commands
// are meaningful only in the same pinned persistent control epoch.
func (m *Manager) ApprovedStatusContext(ctx context.Context, a ApprovedPolicy) (ApprovedStatus, error) {
	if err := m.mu.LockContext(ctx); err != nil {
		return ApprovedStatus{}, err
	}
	defer m.mu.Unlock()
	return m.approvedStatusLocked(a, time.Now().UTC())
}
func (m *Manager) approvedStatusLocked(a ApprovedPolicy, now time.Time) (ApprovedStatus, error) {
	if m.closed || m.auditFailed || !a.valid() || a.AdapterID != m.epoch {
		return ApprovedStatus{}, errors.New("approved adapter unavailable or identity changed")
	}
	s := ApprovedStatus{Schema: "approved-policy-status/1", AdapterID: m.epoch, CommandSHA: hash(a), PolicyID: a.Policy.ID, State: "not_applied", Observed: now}
	r, ok := m.keys[a.Key]
	if !ok {
		return s, nil
	}
	if r.Hash != hash(a) || r.PolicyID != a.Policy.ID {
		return ApprovedStatus{}, errors.New("approved command binding conflict")
	}
	s.State = "released"
	if p, ok := m.active[a.Policy.ID]; ok && now.Before(p.Expires) {
		want := a.Policy
		want.Version = p.Version
		if hash(want) != hash(p) {
			return ApprovedStatus{}, errors.New("approved policy changed")
		}
		s.State = "active"
	}
	return s, nil
}
