package localassistant

import (
	"context"
	"errors"
	"reverse-artex/internal/casememory"
	"reverse-artex/internal/control"
	"reverse-artex/internal/decisions"
	"reverse-artex/internal/event"
	"reverse-artex/internal/policy"
	"time"
)

func (s *Service) snapshot(ctx context.Context) (policy.Snapshot, error) {
	var snap policy.Snapshot
	c := client(2 * time.Second)
	defer c.CloseIdleConnections()
	if err := exchange(ctx, c, s.cfg.ControlOrigin, "/v1/snapshot", s.cfg.ReaderToken, nil, &snap, 1<<20); err != nil {
		return snap, err
	}
	if err := policy.NewReplica().Replace(snap, []byte(s.cfg.SnapshotKey), time.Now().UTC()); err != nil {
		return snap, errors.New("controller snapshot signature or freshness rejected")
	}
	return snap, nil
}
func (s *Service) contain(ctx context.Context, id string, bound BoundCase, eventID string) (any, error) {
	if !s.cfg.AllowDefense {
		return nil, errors.New("defense disabled")
	}
	current, err := s.read(ctx, bound.View.Current.Case.Tenant, bound.View.Current.Case.ID)
	if err != nil {
		return nil, err
	}
	if current.View.Current.SHA != bound.View.Current.SHA {
		return nil, casememory.ErrConflict
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	eligible := responseCandidate(current, time.Now().UTC())
	if len(eligible) != 1 || eligible[0] != eventID {
		return nil, errors.New("only the current newest eligible event can authorize containment")
	}
	var selected event.Event
	for _, e := range current.Events {
		if e.EventID == eventID && candidate(e, current.View.Current.Case) {
			selected = e
		}
	}
	if selected.EventID == "" || selected.EventTime.Before(time.Now().Add(-time.Minute)) {
		return nil, errors.New("fresh complete denied subject evidence required")
	}
	command := control.Approve{Key: id, CaseID: "ai-" + id[5:], EvidenceID: selected.EventID, Route: selected.Route, TTL: 60, Reason: "operator_verified"}
	expectedID := "p-" + decisions.Hash(command)[:32]
	// This exact intent is synced before transmission. Ambiguous writes are not
	// retried automatically. Controller idempotency and TTL remain authoritative.
	if err = s.update(id, func(d *diskRun) { d.Run.PolicyID = expectedID }); err != nil {
		return nil, err
	}
	c := client(2 * time.Second)
	defer c.CloseIdleConnections()
	var receipt control.Receipt
	if err = exchange(ctx, c, s.cfg.ControlOrigin, "/v1/policies", s.cfg.AdminToken, command, &receipt, 8192); err != nil {
		return nil, errors.New("policy apply outcome unconfirmed; inspect controller and TTL")
	}
	if receipt.PolicyID != expectedID || receipt.Operation != "approve" {
		return nil, errors.New("controller receipt differs from exact intent")
	}
	snap, err := s.snapshot(ctx)
	if err != nil {
		return nil, err
	}
	for _, p := range snap.Policies {
		if p.ID != expectedID {
			continue
		}
		if p.CaseID != command.CaseID || p.Tenant != selected.TenantID || p.Asset != selected.AssetID || p.Principal != selected.Principal || p.Session != selected.SessionHMAC || p.Route != selected.Route || p.Expires.Sub(p.Issued) != 60*time.Second {
			return nil, errors.New("controller applied a different scope")
		}
		if err = s.update(id, func(d *diskRun) { d.Owned = &p; d.Run.PolicyExpires = p.Expires }); err != nil {
			return nil, err
		}
		return map[string]any{"policy_id": p.ID, "controller_state": "active", "ttl_seconds": 60, "route_template": p.Route, "edge_effect_verified": false, "scope": "one observed subject/session/route"}, nil
	}
	return nil, errors.New("exact policy not active in verified controller snapshot")
}
func (s *Service) release(ctx context.Context, id, sourceID string) (any, error) {
	s.mu.Lock()
	source, ok := s.runs[sourceID]
	s.mu.Unlock()
	if !ok || source.Owned == nil {
		return nil, casememory.ErrNotFound
	}
	p := *source.Owned
	snap, err := s.snapshot(ctx)
	if err != nil {
		return nil, err
	}
	active := false
	for _, current := range snap.Policies {
		if current.ID == p.ID {
			if decisions.Hash(current) != decisions.Hash(p) {
				return nil, errors.New("owned policy binding changed")
			}
			active = true
		}
	}
	if !active {
		return nil, errors.New("owned policy is no longer active; expiry is not explicit release")
	}
	c := client(2 * time.Second)
	defer c.CloseIdleConnections()
	var receipt control.Receipt
	command := control.Revoke{Key: id, ID: p.ID, Reason: "operator_verified"}
	if err = exchange(ctx, c, s.cfg.ControlOrigin, "/v1/revoke", s.cfg.AdminToken, command, &receipt, 8192); err != nil {
		return nil, errors.New("policy release outcome unconfirmed; inspect controller")
	}
	if receipt.Operation != "revoke" {
		return nil, errors.New("unexpected release receipt")
	}
	snap, err = s.snapshot(ctx)
	if err != nil {
		return nil, err
	}
	for _, current := range snap.Policies {
		if current.ID == p.ID {
			return nil, errors.New("owned policy remains active")
		}
	}
	if err = s.update(id, func(d *diskRun) { d.Run.PolicyID = p.ID }); err != nil {
		return nil, err
	}
	return map[string]any{"policy_id": p.ID, "controller_state": "released", "edge_recovery_verified": false}, nil
}
