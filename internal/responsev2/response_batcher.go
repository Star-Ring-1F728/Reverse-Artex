package responsev2

import (
	"errors"
	"reverse-artex/internal/protection"
	"sync"
	"sync/atomic"
	"time"
)

const responseBatchRecords = 64

var ErrResponseBatchBusy = errors.New("V2 response batch admission full")
var ErrResponseBatchClosed = errors.New("V2 response batcher closed")

type responseBatchRequest struct {
	raw     string
	binding protection.RequestBinding
	status  int
	body    []byte
	write   *protection.ResponseWrite
	queued  time.Time
	done    chan responseBatchResult
}

type responseBatchResult struct {
	gate     protection.GateDecision
	err      error
	sequence int
}

// ResponseBatcher groups only live observation/preparation and server-write
// completion calls. Every successful caller waits for the full journal Sync.
// Store.mu excludes readers and policy mutations from the provisional view;
// failed writes restore that view before unlocking and leave the WAL untouched.
// One batcher may be registered per Store lifetime. Close drains accepted work,
// and Store.Close also drains this batcher before closing the journal.
// Input buffers must remain unchanged until the synchronous call returns.
type ResponseBatcher struct {
	mu      sync.Mutex
	store   *Store
	window  time.Duration
	queue   chan *responseBatchRequest
	done    chan struct{}
	closed  bool
	failure error

	accepted, acknowledged, failed, rejected atomic.Uint64
	batches, syncCalls, records, maxBatch    atomic.Uint64
	pending, highWater                       atomic.Int64
}

func NewResponseBatcher(store *Store, window time.Duration) (*ResponseBatcher, error) {
	if store == nil || window < time.Millisecond || window > 25*time.Millisecond {
		return nil, errors.New("invalid synchronous V2 batch configuration")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closed || store.failed || store.responseBatcher != nil {
		return nil, ErrUnavailable
	}
	b := &ResponseBatcher{store: store, window: window,
		queue: make(chan *responseBatchRequest, responseBatchRecords), done: make(chan struct{})}
	store.responseBatcher = b
	go b.run()
	return b, nil
}

func (b *ResponseBatcher) ObserveAndPrepareCurrent(raw string, binding protection.RequestBinding, status int, body []byte) (protection.GateDecision, error) {
	r := b.submit(&responseBatchRequest{raw: raw, binding: binding, status: status, body: body})
	return r.gate, r.err
}

func (b *ResponseBatcher) CompleteResponse(write protection.ResponseWrite) error {
	return b.submit(&responseBatchRequest{write: &write}).err
}

func (b *ResponseBatcher) submit(request *responseBatchRequest) responseBatchResult {
	request.done = make(chan responseBatchResult, 1)
	request.queued = b.store.timingStart()
	b.mu.Lock()
	if b.closed || b.failure != nil {
		err := b.failure
		if err == nil {
			err = ErrResponseBatchClosed
		}
		b.mu.Unlock()
		return responseBatchResult{err: err}
	}
	if b.pending.Load() >= 2*responseBatchRecords {
		b.rejected.Add(1)
		b.mu.Unlock()
		return responseBatchResult{err: ErrResponseBatchBusy}
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
		return responseBatchResult{err: ErrResponseBatchBusy}
	}
}

func (b *ResponseBatcher) run() {
	defer close(b.done)
	for first := range b.queue {
		batch := []*responseBatchRequest{first}
		timer := time.NewTimer(b.window)
	collect:
		for len(batch) < responseBatchRecords {
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
		results := b.process(batch)
		for i, request := range batch {
			if results[i].err == nil {
				b.acknowledged.Add(1)
			} else {
				b.failed.Add(1)
			}
			b.pending.Add(-1)
			request.done <- results[i]
		}
	}
}

func (b *ResponseBatcher) process(requests []*responseBatchRequest) []responseBatchResult {
	results := make([]responseBatchResult, len(requests))
	b.mu.Lock()
	failure := b.failure
	b.mu.Unlock()
	if failure != nil {
		for i := range results {
			results[i].err = failure
		}
		return results
	}

	s := b.store
	s.mu.Lock()
	transaction := &journalBatch{owner: b, durableSequence: s.sequence}
	s.commitBatch = transaction
	for i, request := range requests {
		s.timingEnd(timingBatchWait, request.queued)
		if s.closed || s.failed {
			results[i].err = ErrUnavailable
		} else if request.write != nil {
			results[i].err = s.completeResponseLocked(*request.write)
		} else {
			results[i].gate, results[i].err = s.observeAndPrepareCurrentLocked(request.raw, request.binding, request.status, request.body)
		}
		// Includes no-op duplicate completions that may depend on an earlier
		// provisional observation in this batch.
		results[i].sequence = s.sequence
	}
	_ = s.flushJournalBatch()
	durableSequence := transaction.durableSequence
	s.commitBatch = nil
	unavailable := s.closed || s.failed
	s.mu.Unlock()

	if unavailable {
		b.mu.Lock()
		b.failure = ErrUnavailable
		b.mu.Unlock()
	}
	for i := range results {
		if results[i].err == nil && results[i].sequence > durableSequence {
			results[i].err = ErrUnavailable
		}
		if results[i].err != nil {
			results[i].gate = protection.GateDecision{}
		}
	}
	return results
}

func (b *ResponseBatcher) Close() error {
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

// Stats is bounded diagnostics. Acknowledged calls can include idempotent
// completions; records_flushed and batches are not request denominators.
func (b *ResponseBatcher) Stats() map[string]any {
	b.mu.Lock()
	closed, failed := b.closed, b.failure != nil
	b.mu.Unlock()
	return map[string]any{"schema": "synchronous-response-v2-batch/1", "enabled": true,
		"window_ms":          float64(b.window) / float64(time.Millisecond),
		"max_batch_requests": responseBatchRecords, "max_batch_records": responseBatchRecords, "queue_capacity": responseBatchRecords,
		"max_pending": 2 * responseBatchRecords, "pending": b.pending.Load(), "high_water": b.highWater.Load(),
		"accepted": b.accepted.Load(), "durable": b.acknowledged.Load(), "failed": b.failed.Load(),
		"rejected": b.rejected.Load(), "batches": b.batches.Load(), "sync_calls": b.syncCalls.Load(), "records_flushed": b.records.Load(), "max_batch": b.maxBatch.Load(),
		"closed": closed, "unavailable": failed, "acknowledgement_after_sync": true}
}
