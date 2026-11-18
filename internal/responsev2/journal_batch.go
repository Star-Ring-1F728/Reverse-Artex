package responsev2

import "time"

// journalBatch exists only while ResponseBatcher holds Store.mu. All pending
// records and undo entries are bounded, and no caller receives a result until
// their sequence is durable. A retained rotation is a mandatory flush barrier.
type journalBatch struct {
	owner           *ResponseBatcher
	durableSequence int
	raw             []byte
	undo            []journalRecordUndo
	before          journalBatchState
}

type journalBatchState struct {
	sequence, epoch                               int
	head                                          string
	high                                          time.Time
	paused                                        bool
	totalEvents, totalAttempts, totalObservations int
	size, retainedBytes                           int64
}

type journalRecordUndo struct {
	event       *Evidence
	oldEvent    Evidence
	hadEvent    bool
	oldRequest  string
	hadRequest  bool
	caseValue   *Case
	oldCase     Case
	hadCase     bool
	retiredCase *Case
	attempt     *ResponseAttempt
	oldAttempt  ResponseAttempt
	hadAttempt  bool
	observation *ResponseObservation
	oldObserved ResponseObservation
	hadObserved bool
}

// This allowlist is deliberately narrower than commit. A new nonzero field
// falls back to immediate Sync; adding a non-comparable field makes this check
// fail compilation until its staging and rollback behavior is explicitly audited.
func batchableResponseRecord(r record) bool {
	allowed := record{Schema: r.Schema, Sequence: r.Sequence, Previous: r.Previous,
		Registry: r.Registry, At: r.At, Operation: r.Operation, SHA: r.SHA,
		Event: r.Event, Case: r.Case, RetiredCase: r.RetiredCase, Attempt: r.Attempt, Observation: r.Observation,
		Epoch: r.Epoch, Paused: r.Paused}
	if r != allowed {
		return false
	}
	switch r.Operation {
	case "adjudicate-and-prepare":
		return r.Event != nil && r.Case != nil && r.Attempt != nil && r.Observation == nil && r.Epoch == nil && r.Paused == nil
	case "response-prepared":
		return r.Event == nil && r.Case == nil && r.RetiredCase == nil && r.Attempt != nil && r.Observation == nil && r.Epoch == nil && r.Paused == nil
	case "response-observed":
		return r.Event == nil && r.Case == nil && r.RetiredCase == nil && r.Attempt == nil && r.Observation != nil
	}
	return false
}

func (s *Store) stageJournalRecord(r record, raw []byte) error {
	batch := s.commitBatch
	if len(batch.undo) >= responseBatchRecords || len(batch.raw)+len(raw) > responseBatchRecords*(64<<10) {
		if err := s.flushJournalBatch(); err != nil {
			return err
		}
	}
	if len(batch.undo) == 0 {
		batch.before = journalBatchState{sequence: s.sequence, epoch: s.epoch, head: s.head, high: s.high,
			paused: s.paused, totalEvents: s.totalEvents, totalAttempts: s.totalAttempts,
			totalObservations: s.totalObservations, size: s.size}
		if s.retained != nil {
			batch.before.retainedBytes = s.retained.bytes
		}
	}
	undo := journalRecordUndo{event: r.Event, caseValue: r.Case, attempt: r.Attempt, observation: r.Observation}
	if r.Event != nil {
		undo.oldEvent, undo.hadEvent = s.events[r.Event.ID]
		undo.oldRequest, undo.hadRequest = s.requests[r.Event.Request]
	}
	if r.Case != nil {
		// caseWithEvidence creates a fresh Refs slice; the previous value is
		// immutable, so restoring its slice header restores the complete case.
		undo.oldCase, undo.hadCase = s.cases[r.Case.ID]
	}
	if r.RetiredCase != nil {
		previous := s.cases[r.RetiredCase.ID]
		undo.retiredCase = &previous
	}
	if r.Attempt != nil {
		undo.oldAttempt, undo.hadAttempt = s.attempts[r.Attempt.ID]
	}
	if r.Observation != nil {
		undo.oldObserved, undo.hadObserved = s.observations[r.Observation.Write.AttemptID]
	}
	batch.undo = append(batch.undo, undo)
	batch.raw = append(batch.raw, raw...)
	s.apply(r)
	s.size += int64(len(raw))
	if s.retained != nil {
		s.retained.bytes += int64(len(raw))
	}
	return nil
}

func restoreJournalEntry[T any](entries map[string]T, key string, old T, exists bool) {
	if exists {
		entries[key] = old
	} else {
		delete(entries, key)
	}
}

func (s *Store) rollbackJournalBatch() {
	batch := s.commitBatch
	if batch == nil || len(batch.undo) == 0 {
		return
	}
	for i := len(batch.undo) - 1; i >= 0; i-- {
		undo := batch.undo[i]
		if undo.event != nil {
			restoreJournalEntry(s.events, undo.event.ID, undo.oldEvent, undo.hadEvent)
			restoreJournalEntry(s.requests, undo.event.Request, undo.oldRequest, undo.hadRequest)
		}
		if undo.caseValue != nil {
			restoreJournalEntry(s.cases, undo.caseValue.ID, undo.oldCase, undo.hadCase)
		}
		if undo.retiredCase != nil {
			s.cases[undo.retiredCase.ID] = *undo.retiredCase
		}
		if undo.attempt != nil {
			restoreJournalEntry(s.attempts, undo.attempt.ID, undo.oldAttempt, undo.hadAttempt)
		}
		if undo.observation != nil {
			s.outcomeFailed = true
			restoreJournalEntry(s.observations, undo.observation.Write.AttemptID, undo.oldObserved, undo.hadObserved)
		}
	}
	before := batch.before
	s.sequence, s.epoch, s.head, s.high = before.sequence, before.epoch, before.head, before.high
	s.paused = before.paused
	s.totalEvents, s.totalAttempts, s.totalObservations = before.totalEvents, before.totalAttempts, before.totalObservations
	s.rebuildPendingCases()
	s.size = before.size
	if s.retained != nil {
		s.retained.bytes = before.retainedBytes
	}
	// outcomeFailed is intentionally not restored: a contradictory completion
	// or failed completion commit must continue to fence automatic admission.
	batch.raw, batch.undo = nil, nil
}

func (s *Store) flushJournalBatch() error {
	batch := s.commitBatch
	if batch == nil || len(batch.undo) == 0 {
		return nil
	}
	if s.closed || s.failed {
		s.rollbackJournalBatch()
		return ErrUnavailable
	}
	count := uint64(len(batch.undo))
	batch.owner.batches.Add(1)
	for old := batch.owner.maxBatch.Load(); count > old; old = batch.owner.maxBatch.Load() {
		if batch.owner.maxBatch.CompareAndSwap(old, count) {
			break
		}
	}
	writeStarted := s.timingStart()
	n, err := s.file.Write(batch.raw)
	s.timingEnd(timingWrite, writeStarted)
	if err == nil && n == len(batch.raw) {
		syncStarted := s.timingStart()
		batch.owner.syncCalls.Add(1)
		err = s.syncFile(s.file)
		s.timingEnd(timingSync, syncStarted)
	} else {
		err = ErrUnavailable
	}
	if err != nil {
		s.failed = true
		s.rollbackJournalBatch()
		return ErrUnavailable
	}
	batch.owner.records.Add(count)
	batch.durableSequence = s.sequence
	batch.raw, batch.undo = nil, nil
	return nil
}
