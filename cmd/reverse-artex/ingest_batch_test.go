package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"reverse-artex/internal/detect"
	"reverse-artex/internal/event"
	"reverse-artex/internal/evidence"
	"reverse-artex/internal/hostguard"
	"strings"
	"testing"
	"time"
)

type batchFailureStore struct {
	*evidence.Store
	fail string
}

func (s batchFailureStore) AppendBatch(name string, values []any) error {
	if name == s.fail {
		return errors.New("injected batch failure")
	}
	return s.Store.AppendBatch(name, values)
}

func TestBatchIngestCommitsBeforeForwardAndStopsAfterAnyStreamFailure(t *testing.T) {
	for _, failure := range []string{"", "events", "alerts", "evaluations"} {
		t.Run("failure-"+failure, func(t *testing.T) {
			dir := t.TempDir()
			s := recoveryStore(t, dir)
			if err := restoreState(s, dir, "session", nil, detect.New(), hostguard.New(nil)); err != nil {
				t.Fatal(err)
			}
			i := &ingester{store: batchFailureStore{s, failure}, engine: detect.New(), hostEngine: hostguard.New(nil)}
			forwarded := 0
			i.forward = func(event.Event) {
				pending, err := loadPolicyPending(s)
				if err != nil || len(pending) != 2 {
					t.Fatalf("forward before all durable evaluations: %v %d", err, len(pending))
				}
				forwarded++
			}
			es := []event.Event{recoveryHTTP("one", "s", "r1", time.Now().UTC()), recoveryHTTP("two", "s", "r2", time.Now().UTC())}
			es[0].UAHint = "norma-unverified"
			results, err := i.processBatch(es)
			if failure != "" {
				if err == nil || forwarded != 0 || !i.degraded() {
					t.Fatal("failed batch was acknowledged/forwarded", err, forwarded)
				}
				if _, err = i.process(es[0]); err == nil {
					t.Fatal("ingestion continued after ambiguous batch")
				}
				return
			}
			if err != nil || len(results) != 2 || forwarded != 2 {
				t.Fatal(results, err, forwarded)
			}
			if _, err = i.processBatch(es); err != nil || forwarded != 2 {
				t.Fatal("batch retry forwarded duplicate", err, forwarded)
			}
			if err := restoreState(s, dir, "session", nil, detect.New(), hostguard.New(nil)); err != nil {
				t.Fatal("batch recovery:", err)
			}
		})
	}
}

func TestAppBatchHandlerValidatesEntireBatchBeforeMutation(t *testing.T) {
	for _, variant := range []string{"valid", "unauthorized", "scope", "missing-required", "oversized-count", "trailing"} {
		t.Run(variant, func(t *testing.T) {
			s := recoveryStore(t, t.TempDir())
			i := &ingester{store: s, engine: detect.New(), hostEngine: hostguard.New(nil)}
			e := recoveryHTTP("one", "s", "r", time.Now().UTC())
			raw, _ := json.Marshal([]event.Event{e, e})
			expected := 202
			token := strings.Repeat("t", 32)
			credential := token
			switch variant {
			case "unauthorized":
				credential = "wrong"
				expected = 401
			case "scope":
				e.SensorID = "lab-waf"
				raw, _ = json.Marshal([]event.Event{recoveryHTTP("valid", "s", "r", time.Now().UTC()), e})
				expected = 403
			case "missing-required":
				raw = []byte(`[{"schema_version":"1.0"}]`)
				expected = 400
			case "oversized-count":
				raw, _ = json.Marshal(make([]event.Event, 17))
				expected = 400
			case "trailing":
				raw = append(raw, []byte(` []`)...)
				expected = 400
			}
			r := httptest.NewRequest("POST", "/v1/events/batch", bytes.NewReader(raw))
			r.Header.Set("Authorization", "Bearer "+credential)
			w := httptest.NewRecorder()
			appBatchHandler(i, token, "lab-app", "lab-api", map[string]bool{"alpha": true}, make(chan struct{}, 32))(w, r)
			if w.Code != expected {
				t.Fatalf("status %d: %s; ingest=%v", w.Code, w.Body.String(), i.failed)
			}
			if variant != "valid" && i.engine.Stats()["dedup_keys"] != 0 {
				t.Fatal("invalid batch mutated detector")
			}
		})
	}
}

func TestBatchReservationCannotExceedPolicyOutboxBudget(t *testing.T) {
	q := newPolicyOutbox(nil, make([]event.Event, maxPolicyPending-1))
	if q.readyBatch(1) != nil {
		t.Fatal("one remaining slot rejected")
	}
	if q.readyBatch(2) == nil {
		t.Fatal("batch exceeded pending budget")
	}
}

func groupTestStore(t *testing.T, dir string) *evidence.Store {
	t.Helper()
	s, err := evidence.NewPersistentRotating(dir, 4<<20, 256<<10)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if err := restoreState(s, dir, "session", nil, detect.New(), hostguard.New(nil)); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestAppGroupBoundScopeAndDurableDedup(t *testing.T) {
	for _, variant := range []string{"valid64", "default16", "count65", "scope", "unauthorized", "body-overflow", "trailing"} {
		t.Run(variant, func(t *testing.T) {
			dir := t.TempDir()
			s := groupTestStore(t, dir)
			i := &ingester{store: s, engine: detect.New(), hostEngine: hostguard.New(nil)}
			es := make([]event.Event, 64)
			for n := range es {
				es[n] = recoveryHTTP(fmt.Sprintf("group-%d", n), "s", fmt.Sprintf("r-%d", n), time.Now().UTC())
			}
			expected, limit := 202, 64
			token := strings.Repeat("t", 32)
			credential := token
			switch variant {
			case "default16":
				limit = 16
				expected = 400
			case "count65":
				es = append(es, es[0])
				expected = 400
			case "scope":
				es[63].TenantID = "other"
				expected = 403
			case "unauthorized":
				credential = "wrong"
				expected = 401
			}
			raw, _ := json.Marshal(es)
			if variant == "body-overflow" {
				raw = []byte("[" + strings.Repeat(" ", 256<<10) + "]")
				expected = 400
			}
			if variant == "trailing" {
				raw = append(raw, []byte("{}")...)
				expected = 400
			}
			send := func() *httptest.ResponseRecorder {
				r := httptest.NewRequest("POST", "/v1/events/group", bytes.NewReader(raw))
				r.Header.Set("Authorization", "Bearer "+credential)
				w := httptest.NewRecorder()
				appBatchHandlerLimit(i, token, "lab-app", "lab-api", map[string]bool{"alpha": true}, make(chan struct{}, 32), limit)(w, r)
				return w
			}
			w := send()
			if w.Code != expected {
				t.Fatalf("status %d: %s; ingest=%v", w.Code, w.Body.String(), i.failed)
			}
			if expected != 202 {
				if i.engine.Stats()["dedup_keys"] != 0 {
					t.Fatal("invalid group mutated detector")
				}
				return
			}
			if err := restoreState(s, dir, "session", nil, detect.New(), hostguard.New(nil)); err != nil {
				t.Fatal("ACK before durable recovery", err)
			}
			w = send()
			var ack struct {
				Results []string `json:"results"`
			}
			if w.Code != 202 || json.Unmarshal(w.Body.Bytes(), &ack) != nil || len(ack.Results) != 64 {
				t.Fatal("invalid repeated group ACK")
			}
			for _, result := range ack.Results {
				if result != "duplicate" {
					t.Fatal("group replay was not duplicate")
				}
			}
		})
	}
}

func TestGroupWriteFailureCannotAcknowledgeOrContinue(t *testing.T) {
	s := groupTestStore(t, t.TempDir())
	i := &ingester{store: batchFailureStore{s, "evaluations"}, engine: detect.New(), hostEngine: hostguard.New(nil)}
	es := make([]event.Event, 64)
	for n := range es {
		es[n] = recoveryHTTP(fmt.Sprintf("failed-%d", n), "s", fmt.Sprintf("r-%d", n), time.Now().UTC())
	}
	if _, err := i.processBatchLimit(es, 64); err == nil || !i.degraded() {
		t.Fatal("ambiguous group acknowledged")
	}
	if _, err := i.processBatchLimit(es, 64); err == nil {
		t.Fatal("continued after uncertain group")
	}
}
