package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reverse-artex/internal/delivery"
	"reverse-artex/internal/event"
	"reverse-artex/internal/evidence"
	"sync"
	"time"
)

const maxPolicyPending = 16384

var errPolicyDeliveryUnavailable = errors.New("policy delivery unavailable")

type policyAck struct {
	EventID string `json:"event_id"`
	Hash    string `json:"event_hash"`
}

func ackFor(e event.Event) policyAck {
	b, _ := json.Marshal(e)
	h := sha256.Sum256(b)
	return policyAck{EventID: e.EventID, Hash: fmt.Sprintf("%x", h[:])}
}

// The evaluation's policy_delivery bit is the durable outbox commit. The ack
// stream is an ordered prefix; a missing response or ack leaves the event
// pending for an explicit operator resume after restart.
func loadPolicyPending(store *evidence.Store) ([]event.Event, error) {
	evals, err := readEvaluations(store, "evaluations")
	if err != nil {
		return nil, err
	}
	all := make([]event.Event, 0)
	index := 0
	err = store.VisitRecords("events", func(line []byte) error {
		if index >= len(evals) {
			return errors.New("policy outbox event without evaluation")
		}
		var e event.Event
		if err := json.Unmarshal(line, &e); err != nil {
			return err
		}
		ev := evals[index]
		index++
		if ev.EventID != e.EventID || (ev.PolicyDelivery && ev.Result != "accepted") {
			return errors.New("invalid policy outbox evaluation")
		}
		if ev.PolicyDelivery {
			all = append(all, e)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if index != len(evals) {
		return nil, errors.New("policy outbox orphan evaluation")
	}
	acked := 0
	err = store.VisitRecords("policy-delivery-acks", func(line []byte) error {
		if acked >= len(all) {
			return errors.New("policy ack exceeds outbox")
		}
		var got policyAck
		if err := json.Unmarshal(line, &got); err != nil {
			return err
		}
		if got != ackFor(all[acked]) {
			return errors.New("policy ack does not match ordered outbox")
		}
		acked++
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(all)-acked > maxPolicyPending {
		return nil, errors.New("policy pending budget exceeded")
	}
	return all[acked:], nil
}

type policyOutbox struct {
	mu          sync.Mutex
	store       *evidence.Store
	pending     []event.Event
	wake        chan struct{}
	failed      bool
	failures    uint64
	retries     uint64
	retrying    bool
	retryRounds uint64
	highWater   int
	acked       uint64
	attempts    delivery.AttemptStats
}

func newPolicyOutbox(store *evidence.Store, pending []event.Event) *policyOutbox {
	return &policyOutbox{store: store, pending: pending, highWater: len(pending), wake: make(chan struct{}, 1)}
}

func (q *policyOutbox) ready() error {
	return q.readyBatch(1)
}
func (q *policyOutbox) readyBatch(n int) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.failed {
		return errPolicyDeliveryUnavailable
	}
	if n < 1 || len(q.pending)+n > maxPolicyPending {
		return errors.New("policy pending budget exceeded")
	}
	return nil
}

func (q *policyOutbox) enqueue(e event.Event) {
	q.mu.Lock()
	q.pending = append(q.pending, e)
	q.highWater = max(q.highWater, len(q.pending))
	q.mu.Unlock()
	select {
	case q.wake <- struct{}{}:
	default:
	}
}

func (q *policyOutbox) stats() (pending int, retries, failures uint64, failed bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.pending), q.retries, q.failures, q.failed
}

func (q *policyOutbox) retryStats() (bool, uint64) {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.retrying, q.retryRounds
}

func (q *policyOutbox) flowStats() map[string]any {
	q.mu.Lock()
	defer q.mu.Unlock()
	var oldest float64
	if len(q.pending) > 0 {
		oldest = max(0, time.Since(q.pending[0].IngestTime).Seconds())
	}
	return map[string]any{"depth": len(q.pending), "capacity": maxPolicyPending,
		"high_water": q.highWater, "oldest_seconds": oldest, "acked": q.acked,
		"retrying": q.retrying, "retry_rounds": q.retryRounds, "degraded": q.failed,
		"http_attempts":     q.attempts,
		"drain_batch_limit": 16, "drain_min_interval_ms": 20}
}

func (q *policyOutbox) run(client *http.Client, endpoint, token string) {
	var retrySince time.Time
	backoff := 100 * time.Millisecond
	for range q.wake {
		for {
			select {
			case _, open := <-q.wake:
				if !open {
					return
				}
			default:
			}
			q.mu.Lock()
			if q.failed || len(q.pending) == 0 {
				q.mu.Unlock()
				break
			}
			q.mu.Unlock()
			// Bound additional delivery latency while collecting a short ordered
			// ACK prefix. Each controller receipt remains durable per event.
			time.Sleep(20 * time.Millisecond)
			q.mu.Lock()
			n := min(len(q.pending), 16)
			batch := append([]event.Event(nil), q.pending[:n]...)
			q.mu.Unlock()
			acks := make([]any, 0, n)
			ok := true
			retryable := false
			for _, e := range batch {
				b, _ := json.Marshal(e)
				outcome := delivery.PostDetailed(client, endpoint+"/v1/evidence", token, b)
				q.mu.Lock()
				q.attempts.Add(outcome.Attempts)
				q.retries += outcome.Retries
				q.mu.Unlock()
				if !outcome.Accepted {
					retryable = outcome.Retryable
					ok = false
					break
				}
				acks = append(acks, ackFor(e))
			}
			// Persist every confirmed prefix before retrying a later failed item.
			// Never hold q.mu during a potentially non-cancellable file Sync.
			if len(acks) > 0 {
				if err := q.store.AppendBatch("policy-delivery-acks", acks); err != nil {
					q.mu.Lock()
					q.failed = true
					q.retrying = false
					q.failures++
					q.mu.Unlock()
					break
				}
				q.mu.Lock()
				clear(q.pending[:len(acks)])
				q.pending = q.pending[len(acks):]
				q.acked += uint64(len(acks))
				q.mu.Unlock()
			}
			q.mu.Lock()
			if !ok {
				if retrySince.IsZero() {
					retrySince = time.Now()
				}
				if retryable && time.Since(retrySince) < time.Minute {
					q.retrying = true
					q.retryRounds++
					q.retries++
					q.mu.Unlock()
					time.Sleep(backoff)
					backoff = min(2*backoff, time.Second)
					continue
				}
				q.retrying = false
				q.failed = true
				q.failures++
				q.mu.Unlock()
				break
			}
			q.mu.Unlock()
			q.mu.Lock()
			q.retrying = false
			q.mu.Unlock()
			retrySince = time.Time{}
			backoff = 100 * time.Millisecond
		}
	}
}
