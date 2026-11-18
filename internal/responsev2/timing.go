package responsev2

import (
	"sync/atomic"
	"time"
)

const (
	timingObserveWait = iota
	timingPrepareWait
	timingCompleteWait
	timingObservationVerify
	timingAttemptVerify
	timingMarshal
	timingWrite
	timingSync
	timingRotation
	timingRotationRead
	timingRotationBuild
	timingRotationMarshal
	timingRotationPublish
	timingBatchWait
	timingPhaseCount
)

var timingNames = [timingPhaseCount]string{"observe_lock_wait", "prepare_lock_wait", "complete_lock_wait", "observation_verify", "attempt_verify", "journal_marshal", "journal_write", "journal_sync", "retention_rotation", "retention_read_and_hash", "retention_build_checkpoint", "retention_marshal", "retention_publish", "batch_queue_wait"}
var timingBounds = [...]time.Duration{100 * time.Microsecond, 500 * time.Microsecond, time.Millisecond, 2 * time.Millisecond, 5 * time.Millisecond, 10 * time.Millisecond, 25 * time.Millisecond, 50 * time.Millisecond, 100 * time.Millisecond, 250 * time.Millisecond, 500 * time.Millisecond, time.Second, 2 * time.Second, 5 * time.Second}

type timingHistogram struct {
	count, sum, max atomic.Uint64
	buckets         [len(timingBounds) + 1]atomic.Uint64
}

type timingMetrics struct {
	phases [timingPhaseCount]timingHistogram
}

// EnableTimingMetrics enables bounded, identity-free diagnostic counters. It
// does not change journal records, admission, durability, or authority time.
func (s *Store) EnableTimingMetrics() { s.timings.CompareAndSwap(nil, &timingMetrics{}) }

func (s *Store) timingStart() time.Time {
	if s.timings.Load() == nil {
		return time.Time{}
	}
	return time.Now()
}

func (s *Store) timingEnd(phase int, started time.Time) {
	if started.IsZero() {
		return
	}
	m := s.timings.Load()
	if m == nil {
		return
	}
	ns := uint64(max(time.Duration(0), time.Since(started)))
	h := &m.phases[phase]
	h.count.Add(1)
	h.sum.Add(ns)
	for old := h.max.Load(); ns > old; old = h.max.Load() {
		if h.max.CompareAndSwap(old, ns) {
			break
		}
	}
	bucket := len(timingBounds)
	for i, bound := range timingBounds {
		if ns <= uint64(bound) {
			bucket = i
			break
		}
	}
	h.buckets[bucket].Add(1)
}

// TimingSnapshot is nonblocking with respect to the journal lock. Counters may
// advance during a snapshot; they are diagnostics, never authorization evidence.
func (s *Store) TimingSnapshot() map[string]any {
	m := s.timings.Load()
	if m == nil {
		return map[string]any{"enabled": false}
	}
	stages := map[string]any{}
	for i, name := range timingNames {
		h := &m.phases[i]
		bounds := make([]float64, len(timingBounds))
		counts := make([]uint64, len(h.buckets))
		var cumulative uint64
		for j := range h.buckets {
			cumulative += h.buckets[j].Load()
			counts[j] = cumulative
			if j < len(timingBounds) {
				bounds[j] = float64(timingBounds[j]) / float64(time.Millisecond)
			}
		}
		stages[name] = map[string]any{"count": h.count.Load(), "total_ns": h.sum.Load(), "max_ms": float64(h.max.Load()) / 1e6, "upper_bounds_ms": bounds, "cumulative_counts": counts}
	}
	return map[string]any{"enabled": true, "schema": "response-v2-timings/1", "diagnostic_only": true, "stages": stages}
}
