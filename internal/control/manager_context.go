package control

import (
	"context"
	"reverse-artex/internal/event"
	"time"
)

// HTTP mutations can abandon admission while queued. After acquiring the writer
// and checking cancellation, the existing complete operation (including Sync)
// runs to its normal outcome. Disconnecting cannot interrupt an admitted commit.
// Use the clock after admission so a queued request cannot reuse a stale TTL or
// evidence-window check. Direct APIs retain their explicit test/replay clocks.
func (m *Manager) EvidenceContext(ctx context.Context, e event.Event) (*Receipt, error) {
	if err := m.mu.LockContext(ctx); err != nil {
		return nil, err
	}
	defer m.mu.Unlock()
	return m.evidenceLocked(e, time.Now().UTC())
}
func (m *Manager) ApproveContext(ctx context.Context, a Approve) (Receipt, error) {
	if err := m.mu.LockContext(ctx); err != nil {
		return Receipt{}, err
	}
	defer m.mu.Unlock()
	return m.approveLocked(a, time.Now().UTC())
}
func (m *Manager) RevokeContext(ctx context.Context, a Revoke) (Receipt, error) {
	if err := m.mu.LockContext(ctx); err != nil {
		return Receipt{}, err
	}
	defer m.mu.Unlock()
	return m.revokeLocked(a, time.Now().UTC())
}
func (m *Manager) RollbackContext(ctx context.Context, a Rollback) (Receipt, error) {
	if err := m.mu.LockContext(ctx); err != nil {
		return Receipt{}, err
	}
	defer m.mu.Unlock()
	return m.rollbackLocked(a, time.Now().UTC())
}
func (m *Manager) SetAutoContext(ctx context.Context, key string, enabled bool) (Receipt, error) {
	if err := m.mu.LockContext(ctx); err != nil {
		return Receipt{}, err
	}
	defer m.mu.Unlock()
	return m.setAutoLocked(key, enabled, time.Now().UTC())
}
