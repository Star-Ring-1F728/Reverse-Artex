package control

import (
	"context"
	"sync"
)

// A zero-value, non-copyable mutex shared by direct calls, HTTP mutations and
// the existing single expiry worker. Context waiters need no polling or helper
// goroutine and cannot consume the writer after their request is cancelled.
type mutationLock struct {
	once  sync.Once
	token chan struct{}
}

func (m *mutationLock) init() {
	m.once.Do(func() {
		m.token = make(chan struct{}, 1)
		m.token <- struct{}{}
	})
}
func (m *mutationLock) Lock() {
	m.init()
	<-m.token
}
func (m *mutationLock) Unlock() {
	m.init()
	select {
	case m.token <- struct{}{}:
	default:
		panic("control: unlock of unlocked mutation lock")
	}
}
func (m *mutationLock) LockContext(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.init()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-m.token:
		// Cancellation and token release may both be ready. Recheck before
		// the caller starts validation, expiry or any durable state change.
		if err := ctx.Err(); err != nil {
			m.Unlock()
			return err
		}
		return nil
	}
}
