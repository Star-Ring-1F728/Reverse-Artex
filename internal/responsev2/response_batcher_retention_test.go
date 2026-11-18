//go:build linux || windows

package responsev2

import (
	"errors"
	"fmt"
	"os"
	"reverse-artex/internal/protection"
	"testing"
)

func TestResponseBatcherRetainedRotationReplaysEverySignedRecord(t *testing.T) {
	cfg := RetentionConfig{64 << 10, 16 << 20, 64}
	s, reg, key, path := retainedFixture(t, cfg)
	b := responseBatchFixture(t, s)
	const count = 16
	requests := make([]*responseBatchRequest, count)
	for i := range requests {
		requests[i] = responseBatchProof(reg, key, fmt.Sprintf("retained-batch-%d", i))
	}
	results := b.process(requests)
	completions := make([]*responseBatchRequest, count)
	for i, result := range results {
		if result.err != nil {
			t.Fatal("bounded batch crossed unchanged completion reserve", i, result.err)
		}
		write := responseBatchWrite(requests[i], result.gate)
		completions[i] = &responseBatchRequest{write: &write}
	}
	for _, result := range b.process(completions) {
		if result.err != nil {
			t.Fatal(result.err)
		}
	}
	if s.retained.generation < 2 || b.records.Load() != count*2 || b.syncCalls.Load() >= count*2 {
		t.Fatal("fixture failed to exercise grouped Sync across retained rotation", s.retainedStatusLocked(), b.Stats())
	}
	if err := s.Checkpoint(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	verified := 0
	audit, err := VerifyJournal(path, reg, func(row VerifiedResponse) error {
		verified++
		if !row.Observation.Write.Complete || row.SDKStatus != 200 || row.Observation.Write.Status != 200 {
			t.Fatal("retained group changed signed representation or actual write", row)
		}
		return nil
	})
	if err != nil || !audit.Passed || !audit.AuditAvailable || audit.TotalEvents != count || audit.TotalAttempts != count || audit.TotalObservations != count || verified != count {
		t.Fatal("full signed retained verification failed", audit, err, verified)
	}
	replayed, err := OpenRetained(path, reg, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer replayed.Close()
	if replayed.OutcomeHealth()["audit_available"] != true || replayed.totalObservations != count {
		t.Fatal("retained reopen lost completed batch", replayed.OutcomeHealth())
	}
}

func TestResponseBatcherRetainedFailureAcknowledgesOnlyDurablePrefix(t *testing.T) {
	s, reg, key, _ := retainedFixture(t, RetentionConfig{64 << 10, 16 << 20, 64})
	b := responseBatchFixture(t, s)
	firstSequence, firstEvents, firstHead := 0, 0, ""
	groupSyncs := 0
	s.syncFile = func(f *os.File) error {
		// Rotation also Syncs metadata and the predecessor; only pending raw
		// records identify an actual coordinator durability boundary here.
		if f == s.file && s.commitBatch != nil && len(s.commitBatch.undo) != 0 {
			groupSyncs++
			if groupSyncs == 1 {
				firstSequence, firstEvents, firstHead = s.sequence, s.totalEvents, s.head
			} else {
				return errors.New("injected successor group Sync failure")
			}
		}
		return f.Sync()
	}
	requests := make([]*responseBatchRequest, 16)
	for i := range requests {
		requests[i] = responseBatchProof(reg, key, fmt.Sprintf("prefix-batch-%d", i))
	}
	results := b.process(requests)
	successes := 0
	for i, result := range results {
		if result.err == nil {
			successes++
			if result.sequence > firstSequence || result.gate.AttemptID == "" {
				t.Fatal("acknowledged successor before its failed Sync", i, result)
			}
		} else if !errors.Is(result.err, ErrUnavailable) || result.gate.AttemptID != "" {
			t.Fatal("unexpected successor failure", i, result)
		}
	}
	if groupSyncs != 2 || successes == 0 || successes >= len(requests) || successes != firstEvents || s.sequence != firstSequence || s.head != firstHead || len(s.events) != firstEvents || len(s.attempts) != firstEvents || !s.failed {
		t.Fatal("failed successor changed an already durable predecessor", groupSyncs, successes, firstSequence, s.sequence, s.retainedStatusLocked())
	}
	if b.records.Load() != uint64(successes) || b.Stats()["unavailable"] != true {
		t.Fatal("durable-prefix counters", b.Stats())
	}
}

func TestResponseBatcherRetentionCheckpointFailureKeepsFlushedPrefix(t *testing.T) {
	s, reg, key, _ := retainedFixture(t, RetentionConfig{64 << 10, 16 << 20, 64})
	b := responseBatchFixture(t, s)
	barrierSequence := 0
	s.retentionHook = func(stage string) error {
		if stage == "checkpoint-published" {
			if s.commitBatch == nil || len(s.commitBatch.undo) != 0 || s.commitBatch.durableSequence != s.sequence {
				t.Fatal("checkpoint published a provisional state")
			}
			barrierSequence = s.sequence
			return errors.New("injected checkpoint boundary failure")
		}
		return nil
	}
	requests := make([]*responseBatchRequest, 16)
	for i := range requests {
		requests[i] = responseBatchProof(reg, key, fmt.Sprintf("checkpoint-batch-%d", i))
	}
	successes := 0
	for _, result := range b.process(requests) {
		if result.err == nil {
			successes++
			if result.sequence > barrierSequence {
				t.Fatal("unflushed record acknowledged at checkpoint failure", result)
			}
		}
	}
	if barrierSequence == 0 || successes == 0 || successes == len(requests) || !s.failed || len(s.events) != successes {
		t.Fatal("checkpoint boundary did not preserve durable earlier results", barrierSequence, successes, s.sequence)
	}
}

func TestResponseBatcherRetainedReserveRejectsWithoutDiscardingDurableCalls(t *testing.T) {
	s, reg, key, _ := retainedFixture(t, RetentionConfig{64 << 10, 16 << 20, 128})
	b := responseBatchFixture(t, s)
	requests := make([]*responseBatchRequest, responseBatchRecords)
	for i := range requests {
		requests[i] = responseBatchProof(reg, key, fmt.Sprintf("reserve-batch-%d", i))
	}
	results := b.process(requests)
	accepted, limited := 0, 0
	var writes []protection.ResponseWrite
	for i, result := range results {
		switch {
		case result.err == nil:
			accepted++
			writes = append(writes, responseBatchWrite(requests[i], result.gate))
		case errors.Is(result.err, ErrLimit):
			limited++
		default:
			t.Fatal("unexpected completion reserve result", i, result.err)
		}
	}
	if accepted == 0 || limited == 0 || accepted+limited != len(requests) || accepted*completionReserve >= int(s.retained.config.SegmentBytes) || s.failed {
		t.Fatal("batching weakened the original completion reserve", accepted, limited)
	}
	completions := make([]*responseBatchRequest, len(writes))
	for i := range writes {
		completions[i] = &responseBatchRequest{write: &writes[i]}
	}
	for _, result := range b.process(completions) {
		if result.err != nil {
			t.Fatal("reserved completion space was unavailable", result.err)
		}
	}
}
