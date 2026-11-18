package evidence

import (
	"sync/atomic"
	"time"
)

const (
	appendTimingTotal = iota
	appendTimingLockWait
	appendTimingRecordAdmission
	appendTimingSerialize
	appendTimingBudgetEnter
	appendTimingBudgetExit
	appendTimingBudgetCheck
	appendTimingStreamState
	appendTimingSeal
	appendTimingFilePrepare
	appendTimingLeaseAllow
	appendTimingWrite
	appendTimingSync
	appendTimingRollback
	appendTimingStatsLockWait
	appendTimingStatsInventory
	appendTimingPhaseCount
)

var appendTimingNames = [appendTimingPhaseCount]string{
	"append_total", "store_lock_wait", "record_admission", "serialize",
	"budget_enter", "budget_exit", "legacy_budget_check", "stream_state", "seal",
	"file_prepare", "lease_allow", "write", "sync", "rollback", "stats_lock_wait", "stats_inventory",
}
var appendTimingBounds = [...]time.Duration{
	100 * time.Microsecond, 500 * time.Microsecond, time.Millisecond, 2 * time.Millisecond,
	5 * time.Millisecond, 10 * time.Millisecond, 25 * time.Millisecond, 50 * time.Millisecond,
	100 * time.Millisecond, 250 * time.Millisecond, 500 * time.Millisecond, time.Second,
	2 * time.Second, 5 * time.Second,
}

type appendTimingHistogram struct {
	count, sum, max atomic.Uint64
	buckets         [len(appendTimingBounds) + 1]atomic.Uint64
}

type appendTimingMetrics struct {
	phases [appendTimingPhaseCount]appendTimingHistogram
}

// EnableTimingMetrics opts in to fixed atomic diagnostics. No record contents,
// paths, request IDs or authority times enter these counters. Existing group
// diagnostics and all write, reservation, Sync and rollback semantics remain.
func (s *Store) EnableTimingMetrics() { s.appendTimings.CompareAndSwap(nil, &appendTimingMetrics{}) }

func (s *Store) appendTimingStart() time.Time {
	if s.appendTimings.Load() == nil {
		return time.Time{}
	}
	return time.Now()
}

func (s *Store) appendTimingEnd(phase int, started time.Time) {
	if started.IsZero() {
		return
	}
	m := s.appendTimings.Load()
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
	bucket := len(appendTimingBounds)
	for i, bound := range appendTimingBounds {
		if ns <= uint64(bound) {
			bucket = i
			break
		}
	}
	h.buckets[bucket].Add(1)
}

// TimingSnapshot never takes Store.mu or scans files. A concurrent snapshot is
// approximate. Stages can overlap: append_total includes its nested phases;
// budget_enter ends at the write callback, while budget_exit starts when that
// callback exits and includes configured budget postchecks and unlocks. With no
// shared budget these phases cover only the existing nil-budget dispatch.
// seal includes compression and its existing Sync; sync covers appendLine's
// immediate Sync only, not AppendGroup's deferred Sync or seal's Sync.
func (s *Store) TimingSnapshot() map[string]any {
	m := s.appendTimings.Load()
	if m == nil {
		return map[string]any{"enabled": false}
	}
	stages := make(map[string]any, appendTimingPhaseCount)
	for i, name := range appendTimingNames {
		h := &m.phases[i]
		bounds := make([]float64, len(appendTimingBounds))
		counts := make([]uint64, len(h.buckets))
		var cumulative uint64
		for j := range h.buckets {
			cumulative += h.buckets[j].Load()
			counts[j] = cumulative
			if j < len(appendTimingBounds) {
				bounds[j] = float64(appendTimingBounds[j]) / float64(time.Millisecond)
			}
		}
		stages[name] = map[string]any{"count": h.count.Load(), "total_ns": h.sum.Load(),
			"max_ms": float64(h.max.Load()) / 1e6, "upper_bounds_ms": bounds, "cumulative_counts": counts}
	}
	return map[string]any{"enabled": true, "schema": "evidence-append-timings/1",
		"diagnostic_only": true, "stages_overlap": true, "stages": stages}
}
