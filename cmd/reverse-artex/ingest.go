package main

import (
	"context"
	"errors"
	"reverse-artex/internal/actioncontext"
	"reverse-artex/internal/detect"
	"reverse-artex/internal/event"
	"reverse-artex/internal/hostguard"
	"sync"
	"sync/atomic"
	"time"
)

type evidenceAppender interface {
	Append(string, any) error
}

// ingester fails closed after any ambiguous evidence write. A partial batch is
// explicitly left for operator recovery; no later request can mutate detector
// state or receive an ACK in this process.
type ingester struct {
	contextTrust      *actioncontext.Trust
	mu                sync.Mutex
	timingMu          sync.Mutex
	timing            map[string]ingestDuration
	store             evidenceAppender
	engine            *detect.Engine
	hostEngine        *hostguard.Engine
	forward           func(event.Event)
	forwardReady      func() error
	forwardBatchReady func(int) error
	clock             func() time.Time
	failed            error
	failedFlag        atomic.Bool
}

type ingestDuration struct {
	Calls   uint64    `json:"calls"`
	TotalMS float64   `json:"total_ms"`
	MaxMS   float64   `json:"max_ms"`
	Buckets [9]uint64 `json:"buckets_le_1_5_20_100_500_1000_5000_60000_inf_ms"`
}

func (i *ingester) timeBatch(phase string, started time.Time) {
	i.timingMu.Lock()
	defer i.timingMu.Unlock()
	if i.timing == nil {
		i.timing = make(map[string]ingestDuration)
	}
	value := i.timing[phase]
	duration := float64(time.Since(started)) / float64(time.Millisecond)
	value.Calls++
	value.TotalMS += duration
	value.MaxMS = max(value.MaxMS, duration)
	index := 8
	for j, limit := range [...]float64{1, 5, 20, 100, 500, 1000, 5000, 60000} {
		if duration <= limit {
			index = j
			break
		}
	}
	value.Buckets[index]++
	i.timing[phase] = value
}

func (i *ingester) batchTiming() map[string]ingestDuration {
	i.timingMu.Lock()
	defer i.timingMu.Unlock()
	result := make(map[string]ingestDuration, len(i.timing))
	for phase, value := range i.timing {
		result[phase] = value
	}
	return result
}

func (i *ingester) now() time.Time {
	if i.clock != nil {
		return i.clock().UTC()
	}
	return time.Now().UTC()
}

func (i *ingester) degraded() bool {
	return i.failedFlag.Load()
}

func (i *ingester) fail(err error) { i.failed = err; i.failedFlag.Store(true) }

func (i *ingester) append(name string, value any) error {
	if err := i.store.Append(name, value); err != nil {
		i.fail(errors.New("evidence write failed; ingestion requires recovery: " + err.Error()))
		return i.failed
	}
	return nil
}

func (i *ingester) process(e event.Event) (string, error) {
	started := time.Now()
	i.mu.Lock()
	defer i.mu.Unlock()
	i.timeBatch("single_wait", started)
	defer i.timeBatch("single_held", time.Now())
	if writer, ok := i.store.(budgetGroupWriter); ok && writer.BudgetEnabled() {
		return i.processBudgetLocked(func() (string, error) { return i.processLocked(e) }, writer)
	}
	return i.processLocked(e)
}

func (i *ingester) processLocked(e event.Event) (string, error) {
	if err := i.contextTrust.Verify(e.Context, e.ContextBinding()); err != nil {
		return "", err
	}
	if i.failed != nil {
		return "", i.failed
	}
	if i.forwardReady != nil {
		if err := i.forwardReady(); err != nil {
			return "", err
		}
	}
	e.IngestTime = i.now()
	if err := i.append("events", e); err != nil {
		return "", err
	}
	processTime := i.now()
	if processTime.Before(e.IngestTime) {
		processTime = e.IngestTime
	}
	alerts, result := i.engine.Process(e, processTime)
	availability := i.engine.EvaluabilityForResult(e, result)
	for _, a := range alerts {
		if err := i.append("alerts", a); err != nil {
			return "", err
		}
	}
	// Evaluation is the last local record and the replay commit marker.
	if err := i.append("evaluations", evaluationRecord{EventID: e.EventID, Result: result, Rules: availability, ProcessTime: processTime, PolicyDelivery: i.forward != nil && result == "accepted"}); err != nil {
		return "", err
	}
	if i.forward != nil && result == "accepted" {
		i.forward(e)
	}
	return result, nil
}

type stagedEvidence map[string][]any

func (s stagedEvidence) Append(name string, v any) error { s[name] = append(s[name], v); return nil }

// A successful batch ACK covers every event, alert and final evaluation Sync.
// Any ambiguous write latches ingestion closed, just as single-event ingest.
func (i *ingester) processBatch(events []event.Event) ([]string, error) {
	return i.processBatchLimit(events, 16)
}

func (i *ingester) processBatchLimit(events []event.Event, limit int) ([]string, error) {
	return i.processBatchContext(context.Background(), events, limit)
}

func (i *ingester) processBatchContext(ctx context.Context, events []event.Event, limit int) ([]string, error) {
	started := time.Now()
	i.mu.Lock()
	defer i.mu.Unlock()
	i.timeBatch("batch_wait", started)
	defer i.timeBatch("batch_held", time.Now())
	defer i.timeBatch("batch_total", started)
	// A cancelled waiter must not begin another commit. Once staging starts,
	// finish every existing Sync boundary even if the caller disconnects.
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	prepareStarted := time.Now()
	for _, e := range events {
		if err := i.contextTrust.Verify(e.Context, e.ContextBinding()); err != nil {
			return nil, err
		}
	}
	if (limit != 16 && limit != 64) || len(events) == 0 || len(events) > limit {
		return nil, errors.New("invalid ingest batch")
	}
	if i.failed != nil {
		return nil, i.failed
	}
	writer, ok := i.store.(interface{ AppendBatch(string, []any) error })
	if !ok {
		return nil, errors.New("batch writer required")
	}
	if i.forwardBatchReady != nil {
		if err := i.forwardBatchReady(len(events)); err != nil {
			return nil, err
		}
	} else if i.forwardReady != nil {
		if err := i.forwardReady(); err != nil {
			return nil, err
		}
	}
	original, forward, ready := i.store, i.forward, i.forwardReady
	staged := stagedEvidence{}
	pending := []event.Event{}
	i.store, i.forwardReady = staged, nil
	if forward != nil {
		i.forward = func(e event.Event) { pending = append(pending, e) }
	}
	defer func() { i.store, i.forward, i.forwardReady = original, forward, ready }()
	results := make([]string, 0, len(events))
	for _, e := range events {
		result, err := i.processLocked(e)
		if err != nil {
			i.fail(errors.New("staged ingestion requires recovery"))
			return nil, i.failed
		}
		results = append(results, result)
	}
	// Evaluations remain last: recovery must not see a commit before alerts.
	i.timeBatch("batch_prepare", prepareStarted)
	if group, ok := original.(budgetGroupWriter); ok && group.BudgetEnabled() {
		if err := group.AppendGroup(map[string][]any(staged)); err != nil {
			i.fail(errors.New("group evidence write failed; ingestion requires recovery: " + err.Error()))
			return nil, i.failed
		}
	} else {
		for _, name := range []string{"events", "alerts", "evaluations"} {
			values := staged[name]
			for len(values) > 0 {
				n := min(len(values), 64)
				if err := writer.AppendBatch(name, values[:n]); err != nil {
					i.fail(errors.New("batch evidence write failed; ingestion requires recovery: " + err.Error()))
					return nil, i.failed
				}
				values = values[n:]
			}
		}
	}
	if forward != nil {
		for _, e := range pending {
			forward(e)
		}
	}
	return results, nil
}

func (i *ingester) processHost(e hostguard.Event) (string, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if writer, ok := i.store.(budgetGroupWriter); ok && writer.BudgetEnabled() {
		return i.processBudgetLocked(func() (string, error) { return i.processHostLocked(e) }, writer)
	}
	return i.processHostLocked(e)
}
func (i *ingester) processHostLocked(e hostguard.Event) (string, error) {
	if i.failed != nil {
		return "", i.failed
	}
	e.IngestTime = i.now()
	if err := i.append("host-events", e); err != nil {
		return "", err
	}
	processTime := i.now()
	if processTime.Before(e.IngestTime) {
		processTime = e.IngestTime
	}
	alerts, status, rules := i.hostEngine.Process(e, processTime)
	if status == "capacity_rejected" {
		for rule := range rules {
			rules[rule] = "not_evaluable_capacity_rejected"
		}
	}
	for _, a := range alerts {
		if err := i.append("host-alerts", a); err != nil {
			return "", err
		}
	}
	if err := i.append("host-evaluations", evaluationRecord{EventID: e.EventID, Result: status, Rules: rules, ProcessTime: processTime}); err != nil {
		return "", err
	}
	return status, nil
}

// Staging lets quota admission cover event, alert and replay commit together.
// The detector has advanced in memory on refusal, so ingestion stays closed
// until restart replays the unchanged durable boundary.
type budgetGroupWriter interface {
	BudgetEnabled() bool
	AppendGroup(map[string][]any) error
}

func (i *ingester) processBudgetLocked(run func() (string, error), writer budgetGroupWriter) (string, error) {
	original, forward := i.store, i.forward
	staged := stagedEvidence{}
	var pending []event.Event
	i.store = staged
	if forward != nil {
		i.forward = func(e event.Event) { pending = append(pending, e) }
	}
	defer func() { i.store = original; i.forward = forward }()
	result, err := run()
	if err != nil {
		return "", err
	}
	if err = writer.AppendGroup(map[string][]any(staged)); err != nil {
		i.fail(errors.New("group evidence write failed; ingestion requires recovery: " + err.Error()))
		return "", i.failed
	}
	if forward != nil {
		for _, e := range pending {
			forward(e)
		}
	}
	return result, nil
}
