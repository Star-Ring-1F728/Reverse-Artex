package casememory

import (
	"context"
	"sync"
	"time"
)

type ObserverStatus struct {
	Running         bool      `json:"running"`
	IntervalSeconds int       `json:"interval_seconds"`
	Attempts        int       `json:"attempts"`
	Failures        int       `json:"failures"`
	LastAttempt     time.Time `json:"last_attempt,omitempty"`
	LastSuccess     time.Time `json:"last_success,omitempty"`
	Error           string    `json:"error,omitempty"`
}

type Observer struct {
	mu     sync.Mutex
	status ObserverStatus
	cancel context.CancelFunc
	done   chan struct{}
}

// One owned worker verifies the collector projection only while a run is armed.
// It never calls a model or changes policies. Failures are visible, not retried
// by replacing journals or modifying the source evidence.
func StartObserver(memory *Store, syncCases func(context.Context) (int, error)) *Observer {
	ctx, cancel := context.WithCancel(context.Background())
	o := &Observer{cancel: cancel, done: make(chan struct{}), status: ObserverStatus{Running: true, IntervalSeconds: 2}}
	go func() {
		defer close(o.done)
		defer func() { o.mu.Lock(); o.status.Running = false; o.mu.Unlock() }()
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			if !memory.NeedsAutomaticSync() {
				continue
			}
			o.mu.Lock()
			o.status.Attempts++
			o.status.LastAttempt = time.Now().UTC()
			o.mu.Unlock()
			attempt, cancelAttempt := context.WithTimeout(ctx, 2*time.Second)
			_, err := syncCases(attempt)
			cancelAttempt()
			o.mu.Lock()
			if err != nil {
				o.status.Failures++
				o.status.Error = err.Error()
			} else {
				o.status.LastSuccess = time.Now().UTC()
				o.status.Error = ""
			}
			o.mu.Unlock()
		}
	}()
	return o
}

func (o *Observer) Status() ObserverStatus { o.mu.Lock(); defer o.mu.Unlock(); return o.status }
func (o *Observer) Close()                 { o.cancel(); <-o.done }
