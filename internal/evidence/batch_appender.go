package evidence

import (
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

var ErrBatchBusy = errors.New("evidence batch admission full")
var ErrBatchClosed = errors.New("evidence batch appender closed")

const batchRecords = 64

type appendRequest struct {
	value any
	done  chan error
}

// BatchAppender coalesces concurrent records through AppendBatch. Every caller
// waits for its entire batch's synchronous write/Sync/rollback result. A store
// failure latches the appender shut; no uncertain batch is acknowledged/retried.
// Close this appender before closing its single-writer Store.
type BatchAppender struct {
	mu      sync.Mutex
	store   *Store
	stream  string
	window  time.Duration
	queue   chan appendRequest
	done    chan struct{}
	closed  bool
	failure error

	accepted, durable, failed, rejected, batches, maxBatch atomic.Uint64
	pending, highWater                                     atomic.Int64
}

func NewBatchAppender(store *Store, stream string, window time.Duration) (*BatchAppender, error) {
	if store == nil || !validStream(stream) || window < time.Millisecond || window > 25*time.Millisecond {
		return nil, errors.New("invalid synchronous evidence batch configuration")
	}
	store.mu.Lock()
	valid := !store.closed && (store.ownedStream == "" || store.ownedStream == stream)
	store.mu.Unlock()
	if !valid {
		return nil, errors.New("evidence batch store/stream unavailable")
	}
	b := &BatchAppender{store: store, stream: stream, window: window,
		queue: make(chan appendRequest, batchRecords), done: make(chan struct{})}
	go b.run()
	return b, nil
}

func (b *BatchAppender) Append(value any) error {
	request := appendRequest{value: value, done: make(chan error, 1)}
	b.mu.Lock()
	if b.closed || b.failure != nil {
		err := b.failure
		if err == nil {
			err = ErrBatchClosed
		}
		b.mu.Unlock()
		return err
	}
	if b.pending.Load() >= 2*batchRecords {
		b.rejected.Add(1)
		b.mu.Unlock()
		return ErrBatchBusy
	}
	pending := b.pending.Add(1)
	select {
	case b.queue <- request:
		b.accepted.Add(1)
		for old := b.highWater.Load(); pending > old; old = b.highWater.Load() {
			if b.highWater.CompareAndSwap(old, pending) {
				break
			}
		}
		b.mu.Unlock()
		return <-request.done
	default:
		b.pending.Add(-1)
		b.rejected.Add(1)
		b.mu.Unlock()
		return ErrBatchBusy
	}
}

func (b *BatchAppender) run() {
	defer close(b.done)
	for first := range b.queue {
		batch := []appendRequest{first}
		timer := time.NewTimer(b.window)
	collect:
		for len(batch) < batchRecords {
			select {
			case next, open := <-b.queue:
				if !open {
					break collect
				}
				batch = append(batch, next)
			case <-timer.C:
				break collect
			}
		}
		timer.Stop()
		b.mu.Lock()
		err := b.failure
		b.mu.Unlock()
		if err == nil {
			values := make([]any, len(batch))
			for index := range batch {
				values[index] = batch[index].value
			}
			b.batches.Add(1)
			for old := b.maxBatch.Load(); uint64(len(batch)) > old; old = b.maxBatch.Load() {
				if b.maxBatch.CompareAndSwap(old, uint64(len(batch))) {
					break
				}
			}
			err = b.store.AppendBatch(b.stream, values)
			if err != nil {
				b.mu.Lock()
				b.failure = err
				b.mu.Unlock()
			}
		}
		if err == nil {
			b.durable.Add(uint64(len(batch)))
		} else {
			b.failed.Add(uint64(len(batch)))
		}
		for _, request := range batch {
			b.pending.Add(-1)
			request.done <- err
		}
	}
}

func (b *BatchAppender) Close() error {
	b.mu.Lock()
	if !b.closed {
		b.closed = true
		close(b.queue)
	}
	b.mu.Unlock()
	<-b.done
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.failure
}

// Stats has fixed counters only; concurrent snapshots are approximate. Counts
// of batches/Syncs are not the request denominator. The source rows remain it.
func (b *BatchAppender) Stats() map[string]any {
	b.mu.Lock()
	closed, failed := b.closed, b.failure != nil
	b.mu.Unlock()
	return map[string]any{"schema": "synchronous-evidence-batch/1", "enabled": true,
		"window_ms":         float64(b.window) / float64(time.Millisecond),
		"max_batch_records": batchRecords, "queue_capacity": batchRecords,
		"max_pending": 2 * batchRecords, "pending": b.pending.Load(), "high_water": b.highWater.Load(),
		"accepted": b.accepted.Load(), "durable": b.durable.Load(), "failed": b.failed.Load(),
		"rejected": b.rejected.Load(), "batches": b.batches.Load(), "max_batch": b.maxBatch.Load(),
		"closed": closed, "unavailable": failed, "acknowledgement_after_sync": true}
}
