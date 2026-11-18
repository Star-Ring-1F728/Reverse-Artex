package responsev2

import (
	"errors"
	"fmt"
	"reverse-artex/internal/decisions"
	"reverse-artex/internal/protection"
	"sync"
	"testing"
	"time"
)

func TestCurrentObserveAndPrepareUseTimeAfterLock(t *testing.T) {
	s, reg, key, _ := storeFixture(t)
	olderAt := time.Now().Add(-100 * time.Millisecond)
	newerAt := olderAt.Add(10 * time.Millisecond)

	newer, binding, status, body := proofFixture(reg, key, "clock-newer", "newer", "alpha", "allow", newerAt)
	if _, err := s.Observe(newer, binding, status, body, newerAt); err != nil {
		t.Fatal("commit newer captured event", err)
	}
	older, binding, status, body := proofFixture(reg, key, "clock-older", "older", "alpha", "allow", olderAt)
	if _, err := s.Observe(older, binding, status, body, olderAt); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("explicit older observation should retain strict high-water behavior: %v", err)
	}
	if _, err := s.ObserveCurrent(older, binding, status, body); err != nil {
		t.Fatalf("live observation should sample time after acquiring the lock: %v", err)
	}
	if _, err := s.PrepareResponse("alpha", decisions.Hash(older), olderAt); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("explicit older prepare should retain strict high-water behavior: %v", err)
	}
	prepared, err := s.PrepareResponseCurrent("alpha", decisions.Hash(older))
	if err != nil || prepared.Deny {
		t.Fatalf("live prepare of authorized evidence: decision=%+v err=%v", prepared, err)
	}
	write := protection.ResponseWrite{AttemptID: prepared.AttemptID, Status: 200, Bytes: len(body), BodySHA: protection.BodyHash(body), Complete: true, CompletedAt: time.Now().UTC()}
	if err := s.CompleteResponse(write); err != nil {
		t.Fatal("complete live prepared response", err)
	}
	if health := s.OutcomeHealth(); health["audit_available"] != true || health["pending_unknown"] != 0 {
		t.Fatal("current-time workflow left response audit unavailable", health)
	}
}

func TestCurrentTimeStillRejectsFutureHighWaterAndExpiredProof(t *testing.T) {
	futureStore, reg, key, _ := storeFixture(t)
	futureAt := time.Now().Add(time.Minute)
	future, binding, status, body := proofFixture(reg, key, "future-high", "future", "alpha", "allow", futureAt)
	if _, err := futureStore.Observe(future, binding, status, body, futureAt); err != nil {
		t.Fatal("install explicit future high-water fixture", err)
	}
	live, liveBinding, liveStatus, liveBody := proofFixture(reg, key, "after-future", "live", "alpha", "allow", time.Now())
	if _, err := futureStore.ObserveCurrent(live, liveBinding, liveStatus, liveBody); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("current observation must not bypass a future high-water mark: %v", err)
	}
	if _, err := futureStore.PrepareResponseCurrent("alpha", decisions.Hash(future)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("current prepare must not bypass a future high-water mark: %v", err)
	}
	if err := futureStore.Close(); err != nil {
		t.Fatal(err)
	}

	expiredStore, reg, key, _ := storeFixture(t)
	capturedAt := time.Now().Add(-10 * time.Second)
	expired, expiredBinding, expiredStatus, expiredBody := proofFixture(reg, key, "expired", "expired", "alpha", "allow", capturedAt)
	if _, err := expiredStore.ObserveCurrent(expired, expiredBinding, expiredStatus, expiredBody); err == nil {
		t.Fatal("current observation accepted an expired signed proof")
	}
	// The proof was valid when captured; storing it at that explicit time must
	// not make it usable for a response now that its original TTL has elapsed.
	if _, err := expiredStore.Observe(expired, expiredBinding, expiredStatus, expiredBody, capturedAt); err != nil {
		t.Fatal("store proof at its signed capture time", err)
	}
	if _, err := expiredStore.PrepareResponseCurrent("alpha", decisions.Hash(expired)); !errors.Is(err, ErrStale) {
		t.Fatalf("current prepare accepted expired signed evidence: %v", err)
	}
	if err := expiredStore.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentCurrentObservePrepareCompleteReplaysJournal(t *testing.T) {
	s, reg, key, path := storeFixture(t)
	const count = 32
	at := time.Now()
	type fixture struct {
		raw    string
		bind   protection.RequestBinding
		status int
		body   []byte
	}
	fixtures := make([]fixture, count)
	for n := range fixtures {
		id := fmt.Sprintf("concurrent-%02d", n)
		object := fmt.Sprintf("resource-%02d", n)
		fixtures[n].raw, fixtures[n].bind, fixtures[n].status, fixtures[n].body = proofFixture(reg, key, id, object, "alpha", "allow", at)
	}

	start := make(chan struct{})
	errs := make(chan error, count)
	attemptIDs := make([]string, count)
	writes := make([]protection.ResponseWrite, count)
	var group sync.WaitGroup
	group.Add(count)
	for n := range fixtures {
		go func(n int) {
			defer group.Done()
			<-start
			f := fixtures[n]
			if _, err := s.ObserveCurrent(f.raw, f.bind, f.status, f.body); err != nil {
				errs <- fmt.Errorf("observe %d: %w", n, err)
				return
			}
			prepared, err := s.PrepareResponseCurrent("alpha", decisions.Hash(f.raw))
			if err != nil {
				errs <- fmt.Errorf("prepare %d: %w", n, err)
				return
			}
			if prepared.Deny {
				errs <- fmt.Errorf("authorized response %d unexpectedly denied", n)
				return
			}
			attemptIDs[n] = prepared.AttemptID
			write := protection.ResponseWrite{AttemptID: prepared.AttemptID, Status: 200, Bytes: len(f.body), BodySHA: protection.BodyHash(f.body), Complete: true, CompletedAt: time.Now().UTC()}
			if err := s.CompleteResponse(write); err != nil {
				errs <- fmt.Errorf("complete %d: %w", n, err)
				return
			}
			writes[n] = write
			errs <- nil
		}(n)
	}
	close(start)
	group.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Error(err)
		}
	}
	if t.Failed() {
		return
	}

	s.mu.Lock()
	sequence, head, high := s.sequence, s.head, s.high
	events, attempts, observations := len(s.events), len(s.attempts), len(s.observations)
	s.mu.Unlock()
	if events != count || attempts != count || observations != count {
		t.Fatalf("incomplete live response workflow: events=%d attempts=%d observations=%d", events, attempts, observations)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	replayed, err := Open(path, reg)
	if err != nil {
		t.Fatal("reopen completed response journal", err)
	}
	defer replayed.Close()
	if replayed.sequence != sequence || replayed.head != head || !replayed.high.Equal(high) || len(replayed.events) != count || len(replayed.attempts) != count || len(replayed.observations) != count {
		t.Fatalf("journal replay count/head mismatch: sequence=%d/%d events=%d attempts=%d observations=%d", replayed.sequence, sequence, len(replayed.events), len(replayed.attempts), len(replayed.observations))
	}
	for n, f := range fixtures {
		evidenceID := decisions.Hash(f.raw)
		evidence, ok := replayed.events[evidenceID]
		if !ok || evidence.Request != f.bind.RequestID {
			t.Fatalf("missing replayed evidence %d", n)
		}
		attempt, ok := replayed.attempts[attemptIDs[n]]
		observation, observed := replayed.observations[attemptIDs[n]]
		if !ok || !observed || attempt.EvidenceID != evidenceID || decisions.Hash(observation.Write) != decisions.Hash(writes[n]) {
			t.Fatalf("missing or changed replayed response %d", n)
		}
	}
	if health := replayed.OutcomeHealth(); health["pending_unknown"] != 0 || health["audit_available"] != true {
		t.Fatal("replayed journal has unknown or unavailable responses", health)
	}
}
