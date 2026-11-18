package edge

import (
	"sync/atomic"
	"time"
)

const (
	protectionTotal = iota
	protectionHeaders
	protectionBody
	protectionVerify
	protectionAudit
	protectionGate
	protectionWrite
	protectionReport
	protectionConnection
	protectionFirstByte
	protectionHandlerTotal
	protectionCoverage
	protectionPhaseCount
)

var protectionPhaseNames = [protectionPhaseCount]string{"total", "upstream_headers", "body_read_and_buffer", "proof_verify", "durable_audit", "v2_gate", "server_write", "postwrite_report", "connection_wait", "first_response_byte", "handler_total", "coverage_admission"}
var protectionBounds = [...]time.Duration{100 * time.Microsecond, 500 * time.Microsecond, time.Millisecond, 2 * time.Millisecond, 5 * time.Millisecond, 10 * time.Millisecond, 25 * time.Millisecond, 50 * time.Millisecond, 100 * time.Millisecond, 250 * time.Millisecond, 500 * time.Millisecond, time.Second, 2 * time.Second, 5 * time.Second}

type protectionHistogram struct {
	count, sum, max atomic.Uint64
	buckets         [len(protectionBounds) + 1]atomic.Uint64
}

// ProtectionMetrics has fixed stages/buckets and contains no identity, payload,
// URL, token, or policy evidence. Timing is diagnostic, never an authorization.
type ProtectionMetrics struct {
	phases           [protectionPhaseCount]protectionHistogram
	upstreamFailures upstreamFailureCounters
}

func protectionStart(metrics *ProtectionMetrics) time.Time {
	if metrics == nil {
		return time.Time{}
	}
	return time.Now()
}
func protectionElapsed(metrics *ProtectionMetrics, phase int, start time.Time) {
	if metrics != nil {
		metrics.observe(phase, time.Since(start))
	}
}
func (m *ProtectionMetrics) observe(phase int, elapsed time.Duration) {
	if m == nil {
		return
	}
	if elapsed < 0 {
		elapsed = 0
	}
	h := &m.phases[phase]
	ns := uint64(elapsed)
	h.count.Add(1)
	h.sum.Add(ns)
	for old := h.max.Load(); ns > old; old = h.max.Load() {
		if h.max.CompareAndSwap(old, ns) {
			break
		}
	}
	bucket := len(protectionBounds)
	for i, bound := range protectionBounds {
		if elapsed <= bound {
			bucket = i
			break
		}
	}
	h.buckets[bucket].Add(1)
}
func (m *ProtectionMetrics) Snapshot() map[string]any {
	if m == nil {
		return map[string]any{"enabled": false}
	}
	phases := map[string]any{}
	for index, name := range protectionPhaseNames {
		h := &m.phases[index]
		counts := []uint64{}
		bounds := []float64{}
		cumulative := uint64(0)
		for i := range h.buckets {
			cumulative += h.buckets[i].Load()
			counts = append(counts, cumulative)
			if i < len(protectionBounds) {
				bounds = append(bounds, float64(protectionBounds[i])/float64(time.Millisecond))
			}
		}
		phases[name] = map[string]any{"count": h.count.Load(), "total_ns": h.sum.Load(), "max_ms": float64(h.max.Load()) / 1e6, "upper_bounds_ms": bounds, "cumulative_counts": counts}
	}
	return map[string]any{"enabled": true, "schema": "protected-path-timings/1", "stages": phases, "upstream_failures": m.upstreamFailureSnapshot(), "diagnostic_only": true}
}
