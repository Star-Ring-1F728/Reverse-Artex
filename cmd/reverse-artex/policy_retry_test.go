package main

import (
	"context"
	"encoding/json"
	"net/http"
	"reverse-artex/internal/delivery"
	"reverse-artex/internal/detect"
	"reverse-artex/internal/event"
	"reverse-artex/internal/hostguard"
	"sync/atomic"
	"testing"
	"time"
)

func TestPolicyTransientExhaustionRecoversWithoutRestartOrEarlyAck(t *testing.T) {
	s := recoveryStore(t, t.TempDir())
	q := newPolicyOutbox(s, nil)
	i := &ingester{store: s, engine: detect.New(), hostEngine: hostguard.New(nil), forward: q.enqueue, forwardReady: q.ready}
	for _, id := range []string{"one", "two"} {
		if _, err := i.process(recoveryHTTP(id, "s", id, time.Now().UTC())); err != nil {
			t.Fatal(err)
		}
	}
	var calls atomic.Int64
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var e event.Event
		json.NewDecoder(r.Body).Decode(&e)
		if call := calls.Add(1); call <= 4 {
			w.WriteHeader([]int{429, 503, 504, 500}[call-1])
			return
		}
		w.WriteHeader(202)
	})
	go q.run(&http.Client{Transport: outboxTransport{h}}, "http://controller.test", "token")
	defer close(q.wake)
	deadline := time.Now().Add(3 * time.Second)
	for {
		retrying, rounds := q.retryStats()
		if retrying && rounds > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no retry round")
		}
		time.Sleep(time.Millisecond)
	}
	if _, _, _, failed := q.stats(); failed {
		t.Fatal("temporary failure latched permanent")
	}
	if err := q.ready(); err != nil {
		t.Fatal("temporary downstream outage blocked durable admission", err)
	}
	if pending, err := loadPolicyPending(s); err != nil || len(pending) != 2 {
		t.Fatalf("early ACK: %v %d", err, len(pending))
	}
	for {
		pending, _, failures, failed := q.stats()
		if pending == 0 {
			if failed || failures != 0 {
				t.Fatal("did not recover")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("outbox never drained")
		}
		time.Sleep(time.Millisecond)
	}
	if pending, err := loadPolicyPending(s); err != nil || len(pending) != 0 {
		t.Fatalf("durable ACK missing %v %d", err, len(pending))
	}
	// A successful last response must not hide intermediate capacity, server
	// and timeout responses. These counters cover both retry rounds and events.
	var health struct {
		Attempts delivery.AttemptStats `json:"http_attempts"`
	}
	raw, err := json.Marshal(q.flowStats())
	if err != nil || json.Unmarshal(raw, &health) != nil {
		t.Fatal("invalid delivery health", err)
	}
	want := delivery.AttemptStats{Requests: 6, HTTP202: 2, HTTP429: 1, HTTP500: 1, HTTP503: 1, HTTP504: 1}
	if health.Attempts != want {
		t.Fatalf("delivery health lost attempts: %+v want %+v", health.Attempts, want)
	}
}

func TestCancelledBatchWaiterDoesNotWriteOrAdvanceDetector(t *testing.T) {
	s := recoveryStore(t, t.TempDir())
	d := detect.New()
	i := &ingester{store: s, engine: d, hostEngine: hostguard.New(nil)}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := i.processBatchContext(ctx, []event.Event{recoveryHTTP("cancelled", "s", "r", time.Now().UTC())}, 16)
	if err != context.Canceled {
		t.Fatal(err)
	}
	if d.Stats()["dedup_keys"] != 0 {
		t.Fatal("cancelled waiter mutated detector")
	}
}

func TestPolicyRetryObservationsSurviveAckWriteFailure(t *testing.T) {
	s := recoveryStore(t, t.TempDir())
	q := newPolicyOutbox(s, nil)
	i := &ingester{store: s, engine: detect.New(), hostEngine: hostguard.New(nil), forward: q.enqueue}
	if _, err := i.process(recoveryHTTP("ack-write-failure", "s", "r", time.Now().UTC())); err != nil {
		t.Fatal(err)
	}
	calls := 0
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls <= 3 {
			w.WriteHeader(503)
			return
		}
		if err := s.Close(); err != nil {
			t.Error(err)
		}
		w.WriteHeader(202)
	})
	done := make(chan struct{})
	go func() {
		q.run(&http.Client{Transport: outboxTransport{h}}, "http://controller.test", "token")
		close(done)
	}()
	defer func() { close(q.wake); <-done }()
	deadline := time.Now().Add(3 * time.Second)
	for {
		pending, retries, failures, failed := q.stats()
		if failed {
			if pending != 1 || retries != 3 || failures != 1 {
				t.Fatalf("ACK failure observations: %d %d %d", pending, retries, failures)
			}
			health := q.flowStats()
			if health["acked"] != uint64(0) || health["retrying"] != false || health["http_attempts"] != (delivery.AttemptStats{Requests: 4, HTTP503: 3, HTTP202: 1}) {
				t.Fatalf("lost attempts or early ACK: %+v", health)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("ACK write failure did not stop worker")
		}
		time.Sleep(time.Millisecond)
	}
}
