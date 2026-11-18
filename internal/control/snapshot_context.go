package control

import (
	"context"
	"reverse-artex/internal/policy"
	"time"
)

// One expiry worker per manager, even when Sync cannot be cancelled. A caller
// timeout only abandons its wait; it never cancels or duplicates an audit write.
type expiryFlight struct {
	done chan struct{}
	err  error
}

func (m *Manager) SnapshotContext(ctx context.Context, key []byte) (policy.Snapshot, error) {
	for {
		if err := ctx.Err(); err != nil {
			return policy.Snapshot{}, err
		}
		now := time.Now().UTC()
		if view := m.view.Load(); view != nil && (view.expires.IsZero() || view.expires.After(now)) {
			ps := append([]policy.Policy{}, view.policies...)
			return policy.Sign(policy.Snapshot{Epoch: view.epoch, Version: view.version, Generated: now, Policies: ps}, key), nil
		}
		m.refreshMu.Lock()
		if m.refresh == nil {
			flight := &expiryFlight{done: make(chan struct{})}
			m.refresh = flight
			go func() {
				started := time.Now()
				m.mu.Lock()
				m.recordIO("expiry_lock_wait", started)
				held := time.Now()
				// Evaluate at lock acquisition: a queued request's old clock must
				// not extend a policy's lifetime while waiting behind audit Sync.
				flight.err = m.expire(time.Now().UTC())
				m.mu.Unlock()
				m.recordIO("expiry_lock_held", held)
				m.refreshMu.Lock()
				// Failed expiry stays latched for this process. An uncertain write
				// is never retried by an HTTP polling storm. Preserve the audit.
				if flight.err == nil {
					m.refresh = nil
				}
				close(flight.done)
				m.refreshMu.Unlock()
			}()
		}
		flight := m.refresh
		m.refreshMu.Unlock()
		select {
		case <-ctx.Done():
			return policy.Snapshot{}, ctx.Err()
		case <-flight.done:
			if flight.err != nil {
				return policy.Snapshot{}, flight.err
			}
			// Sign the current view and clock, never a pre-wait snapshot.
		}
	}
}
