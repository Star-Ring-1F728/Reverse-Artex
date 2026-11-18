package responsev2

import (
	"errors"
	"fmt"
	"os"
	"reverse-artex/internal/decisions"
	"reverse-artex/internal/protection"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func responseBatchFixture(t *testing.T, s *Store) *ResponseBatcher {
	t.Helper()
	b, err := NewResponseBatcher(s, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.Close() })
	return b
}

func responseBatchProof(reg *protection.Registry, key []byte, id string) *responseBatchRequest {
	raw, binding, status, body := proofFixture(reg, key, id, "own", "alpha", "allow", time.Now())
	return &responseBatchRequest{raw: raw, binding: binding, status: status, body: body}
}

func responseBatchWrite(request *responseBatchRequest, gate protection.GateDecision) protection.ResponseWrite {
	return protection.ResponseWrite{AttemptID: gate.AttemptID, Status: request.status, Bytes: len(request.body),
		BodySHA: protection.BodyHash(request.body), Complete: true, CompletedAt: time.Now().UTC()}
}

func waitResponseBatch(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("bounded batch condition timed out")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestResponseBatcherSyncFenceReaderIsolationAndReplay(t *testing.T) {
	s, reg, key, path := storeFixture(t)
	b := responseBatchFixture(t, s)
	requests := []*responseBatchRequest{responseBatchProof(reg, key, "batch-a"), responseBatchProof(reg, key, "batch-b")}
	entered, release := make(chan struct{}), make(chan struct{})
	var block, unblock sync.Once
	defer unblock.Do(func() { close(release) })
	var syncs atomic.Int64
	s.syncFile = func(f *os.File) error {
		syncs.Add(1)
		block.Do(func() { close(entered); <-release })
		return f.Sync()
	}
	done := make(chan []responseBatchResult, 1)
	go func() { done <- b.process(requests) }()
	<-entered
	readerStarted := make(chan struct{})
	read := make(chan []Case, 1)
	go func() { close(readerStarted); read <- s.Cases("alpha") }()
	<-readerStarted
	select {
	case <-done:
		t.Fatal("prepared response escaped before Sync")
	case <-read:
		t.Fatal("reader observed speculative evidence before Sync")
	case <-time.After(20 * time.Millisecond):
	}
	unblock.Do(func() { close(release) })
	results := <-done
	cases := <-read
	if len(cases) != 1 || cases[0].Revision != 2 || syncs.Load() != 1 {
		t.Fatal("cohort did not share one durable fence", cases, syncs.Load())
	}
	completions := make([]*responseBatchRequest, len(results))
	for i, result := range results {
		if result.err != nil || result.gate.AttemptID == "" {
			t.Fatal(result)
		}
		write := responseBatchWrite(requests[i], result.gate)
		completions[i] = &responseBatchRequest{write: &write}
	}
	for _, result := range b.process(completions) {
		if result.err != nil {
			t.Fatal(result.err)
		}
	}
	if syncs.Load() != 2 || s.sequence != 4 || b.records.Load() != 4 {
		t.Fatal("separate completion durability fence lost", syncs.Load(), s.sequence)
	}
	head := s.head
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	replayed, err := Open(path, reg)
	if err != nil {
		t.Fatal(err)
	}
	defer replayed.Close()
	if replayed.head != head || replayed.sequence != 4 || replayed.OutcomeHealth()["audit_available"] != true {
		t.Fatal("batched evidence/response chain did not replay", replayed.OutcomeHealth())
	}
}

func TestResponseBatcherFailedSyncRestoresHotViewAndPreservesWAL(t *testing.T) {
	s, reg, key, path := storeFixture(t)
	pending := combinedResponseFixture(t, s, reg, key, "durable-before-batch", "own", "allow")
	// A contradictory complete body stages the existing collateral pause/epoch.
	pending.Bytes++
	before := s.retainedState()
	before.OutcomeFailed = true // Failed completion must preserve this latch.
	beforeSHA := decisions.Hash(before)
	sequence, head, high, size := s.sequence, s.head, s.high, s.size
	b := responseBatchFixture(t, s)
	s.syncFile = func(*os.File) error { return errors.New("injected batch Sync failure") }
	requests := []*responseBatchRequest{{write: &pending}, responseBatchProof(reg, key, "rollback-a"), responseBatchProof(reg, key, "rollback-b")}
	for _, result := range b.process(requests) {
		if !errors.Is(result.err, ErrUnavailable) || result.gate.AttemptID != "" {
			t.Fatal("uncertain result acknowledged", result)
		}
	}
	if decisions.Hash(s.retainedState()) != beforeSHA || s.sequence != sequence || s.head != head || !s.high.Equal(high) || s.size != size {
		t.Fatal("failed batch leaked evidence, case refs, pause, epoch, counters, or journal head")
	}
	if !s.failed || !s.outcomeFailed || b.Stats()["unavailable"] != true || b.records.Load() != 0 {
		t.Fatal("failure did not latch unavailable")
	}
	info, err := os.Stat(path)
	if err != nil || info.Size() <= size {
		t.Fatal("uncertain WAL bytes were discarded", info, err)
	}
	request := responseBatchProof(reg, key, "after-failed-batch")
	if _, err = b.ObserveAndPrepareCurrent(request.raw, request.binding, request.status, request.body); !errors.Is(err, ErrUnavailable) {
		t.Fatal("batcher admitted after uncertain Sync", err)
	}
}

func TestResponseBatcherValidationAndDuplicateResultsStayIndependent(t *testing.T) {
	s, reg, key, _ := storeFixture(t)
	b := responseBatchFixture(t, s)
	good := responseBatchProof(reg, key, "valid-in-mixed-batch")
	bad := responseBatchProof(reg, key, "invalid-in-mixed-batch")
	bad.body = []byte("substituted unsigned body")
	unknown := protection.ResponseWrite{AttemptID: decisions.Hash("unknown")}
	results := b.process([]*responseBatchRequest{bad, {write: &unknown}, good, good})
	if results[0].err == nil || !errors.Is(results[1].err, ErrStale) || results[2].err != nil || !errors.Is(results[3].err, ErrStale) {
		t.Fatal("validation errors leaked across requests", results)
	}
	write := responseBatchWrite(good, results[2].gate)
	for _, result := range b.process([]*responseBatchRequest{{write: &write}, {write: &write}}) {
		if result.err != nil {
			t.Fatal("idempotent same-batch completion rejected", result.err)
		}
	}
	if b.Stats()["unavailable"] != false || s.sequence != 2 || len(s.events) != 1 || len(s.observations) != 1 || b.records.Load() != 2 {
		t.Fatal("validation poisoned the durable writer", b.Stats())
	}
}

func TestResponseBatcherPreservesProofClockAndHotLimits(t *testing.T) {
	for _, kind := range []string{"expired", "future-high", "event-limit", "attempt-limit"} {
		t.Run(kind, func(t *testing.T) {
			s, reg, key, _ := storeFixture(t)
			b := responseBatchFixture(t, s)
			request := responseBatchProof(reg, key, "limited-"+kind)
			switch kind {
			case "expired":
				request.raw, request.binding, request.status, request.body = proofFixture(reg, key, "expired-batch", "own", "alpha", "allow", time.Now().Add(-10*time.Second))
			case "future-high":
				s.high = time.Now().Add(time.Minute)
			case "event-limit":
				for i := 0; i < 8192; i++ {
					s.events[fmt.Sprint(i)] = Evidence{}
				}
			case "attempt-limit":
				for i := 0; i < 8192; i++ {
					s.attempts[fmt.Sprint(i)] = ResponseAttempt{}
				}
			}
			if result := b.process([]*responseBatchRequest{request})[0]; result.err == nil || s.sequence != 0 || b.batches.Load() != 0 {
				t.Fatal("batching weakened original proof/high-water/hot limits", result)
			}
		})
	}
}

func TestResponseBatcherSamplesAuthorityTimeAfterQueue(t *testing.T) {
	s, reg, key, _ := storeFixture(t)
	s.EnableTimingMetrics()
	b := responseBatchFixture(t, s)
	request := responseBatchProof(reg, key, "queued-clock")
	s.mu.Lock()
	done := make(chan responseBatchResult, 1)
	go func() { done <- b.submit(request) }()
	waitResponseBatch(t, func() bool { return b.accepted.Load() == 1 })
	high := time.Now()
	s.high = high
	s.mu.Unlock()
	result := <-done
	if result.err != nil || s.attempts[result.gate.AttemptID].PreparedAt.Before(high) {
		t.Fatal("batch queue captured authority time before Store.mu", result)
	}
	if timingCount(t, s, "batch_queue_wait") != 1 {
		t.Fatal("batch queue wait was omitted from diagnostics")
	}
}

func TestResponseBatcherBoundedQueueAndStoreCloseDrain(t *testing.T) {
	s, reg, key, _ := storeFixture(t)
	b := responseBatchFixture(t, s)
	entered, release := make(chan struct{}), make(chan struct{})
	var block, unblock sync.Once
	defer unblock.Do(func() { close(release) })
	s.syncFile = func(f *os.File) error {
		block.Do(func() { close(entered); <-release })
		return f.Sync()
	}
	errs := make(chan error, responseBatchRecords+1)
	start := func(id string) {
		request := responseBatchProof(reg, key, id)
		go func() {
			_, err := b.ObserveAndPrepareCurrent(request.raw, request.binding, request.status, request.body)
			errs <- err
		}()
	}
	start("drain-active")
	<-entered
	for i := 0; i < responseBatchRecords; i++ {
		start(fmt.Sprintf("drain-queued-%d", i))
	}
	waitResponseBatch(t, func() bool { return b.pending.Load() == responseBatchRecords+1 })
	extra := responseBatchProof(reg, key, "over-capacity")
	if _, err := b.ObserveAndPrepareCurrent(extra.raw, extra.binding, extra.status, extra.body); !errors.Is(err, ErrResponseBatchBusy) {
		t.Fatal("full queue did not reject within its bound", err)
	}
	closed := make(chan error, 1)
	go func() { closed <- s.Close() }()
	select {
	case <-closed:
		t.Fatal("Store.Close passed an outstanding Sync")
	case <-time.After(20 * time.Millisecond):
	}
	unblock.Do(func() { close(release) })
	for i := 0; i < responseBatchRecords+1; i++ {
		if err := <-errs; err != nil {
			t.Fatal("Close failed accepted queued work", err)
		}
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	stats := b.Stats()
	if stats["pending"] != int64(0) || stats["durable"] != uint64(responseBatchRecords+1) || stats["rejected"] != uint64(1) || b.highWater.Load() > 2*responseBatchRecords {
		t.Fatal("drain/queue accounting", stats)
	}
	if _, err := b.ObserveAndPrepareCurrent(extra.raw, extra.binding, extra.status, extra.body); !errors.Is(err, ErrResponseBatchClosed) {
		t.Fatal("closed queue admitted work", err)
	}
	if _, err := NewResponseBatcher(s, time.Millisecond); !errors.Is(err, ErrUnavailable) {
		t.Fatal("closed Store registered another coordinator", err)
	}
}

func TestResponseBatcherSingleRegistrationAndConfiguration(t *testing.T) {
	s, _, _, _ := storeFixture(t)
	for _, duration := range []time.Duration{0, time.Microsecond, 26 * time.Millisecond} {
		if _, err := NewResponseBatcher(s, duration); err == nil {
			t.Fatal("invalid batch window accepted", duration)
		}
	}
	b := responseBatchFixture(t, s)
	if _, err := NewResponseBatcher(s, time.Millisecond); !errors.Is(err, ErrUnavailable) {
		t.Fatal("multiple coordinators registered", err)
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := NewResponseBatcher(s, time.Millisecond); !errors.Is(err, ErrUnavailable) {
		t.Fatal("Store re-registered a closed coordinator", err)
	}
}

func TestResponseBatcherUnknownOperationIsDurableBarrier(t *testing.T) {
	s, reg, key, _ := storeFixture(t)
	b := responseBatchFixture(t, s)
	request := responseBatchProof(reg, key, "before-policy-barrier")
	syncs := 0
	s.syncFile = func(f *os.File) error { syncs++; return f.Sync() }
	s.mu.Lock()
	transaction := &journalBatch{owner: b, durableSequence: s.sequence}
	s.commitBatch = transaction
	_, prepareErr := s.observeAndPrepareCurrentLocked(request.raw, request.binding, request.status, request.body)
	epoch, paused := s.epoch+1, true
	barrierErr := s.commit(record{Operation: "cancel-epoch", Epoch: &epoch, Paused: &paused})
	s.commitBatch = nil
	s.mu.Unlock()
	if prepareErr != nil || barrierErr != nil || syncs != 2 || transaction.durableSequence != s.sequence || len(transaction.undo) != 0 || !s.paused {
		t.Fatal("unbatched policy operation crossed provisional state", prepareErr, barrierErr, syncs)
	}
}

func TestResponseBatcherWhitelistRejectsEveryNonHotField(t *testing.T) {
	base := record{Schema: "response-journal/2", Sequence: 7, Previous: "previous", Registry: "registry",
		At: time.Now(), Operation: "response-observed", SHA: "hash", Observation: &ResponseObservation{}}
	if !batchableResponseRecord(base) {
		t.Fatal("allowed response observation was excluded")
	}
	for name, alter := range map[string]func(*record){
		"writer":      func(r *record) { r.WriterBoot = "boot" },
		"command":     func(r *record) { r.CommandID = "command" },
		"command-sha": func(r *record) { r.CommandSHA = "digest" },
		"lease":       func(r *record) { r.Lease = &Lease{} },
		"intent":      func(r *record) { r.Intent = &Intent{} },
		"receipt":     func(r *record) { r.Receipt = &Receipt{} },
		"job":         func(r *record) { r.Job = &Job{} },
		"l3":          func(r *record) { r.L3 = &L3Run{} },
		"event":       func(r *record) { r.Event = &Evidence{} },
		"case":        func(r *record) { r.Case = &Case{} },
		"attempt":     func(r *record) { r.Attempt = &ResponseAttempt{} },
		"operation":   func(r *record) { r.Operation = "future-operation" },
	} {
		r := base
		alter(&r)
		if batchableResponseRecord(r) {
			t.Fatal("unsupported response record field bypassed immediate Sync", name)
		}
	}
}
