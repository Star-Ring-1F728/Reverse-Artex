package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"reverse-artex/internal/control"
	"reverse-artex/internal/delivery"
	"reverse-artex/internal/detect"
	"reverse-artex/internal/event"
	"reverse-artex/internal/evidence"
	"reverse-artex/internal/hostguard"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func quotaWait(t *testing.T, what string, ready func() bool) {
	t.Helper()
	for deadline := time.Now().Add(3 * time.Second); ; {
		if ready() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("timeout:", what)
		}
		time.Sleep(time.Millisecond)
	}
}
func quotaWorker(t *testing.T, q *policyOutbox, client *http.Client, url, token string) func() {
	t.Helper()
	done := make(chan struct{})
	go func() { defer close(done); q.run(client, url, token) }()
	q.wake <- struct{}{}
	var once sync.Once
	stop := func() {
		once.Do(func() {
			close(q.wake)
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Error("quota worker did not stop")
			}
		})
	}
	t.Cleanup(stop)
	return stop
}
func quotaRecords(t *testing.T, s *evidence.Store, name string) [][]byte {
	t.Helper()
	var rows [][]byte
	if err := s.VisitRecords(name, func(line []byte) error { rows = append(rows, bytes.Clone(line)); return nil }); err != nil {
		t.Fatal(err)
	}
	return rows
}

func TestPolicyStorageSaturationRecoversExactOrderedOutboxOverHTTP(t *testing.T) {
	for _, fault := range []string{"controller-full", "confirmed-prefix", "ack-full"} {
		t.Run(fault, func(t *testing.T) {
			t.Setenv("RA_STORAGE_ROOT", "")
			t.Setenv("RA_STORAGE_LIMIT", "")
			controlDir, collectorDir := t.TempDir(), t.TempDir()
			m, err := control.OpenPersistent(controlDir)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { m.Close() }()
			if _, err := m.SetAuto("quota-auto", true, time.Now().UTC()); err != nil {
				t.Fatal(err)
			}
			tokens := control.Tokens{Evidence: strings.Repeat("e", 32), Reader: strings.Repeat("r", 32), SnapshotKey: []byte(strings.Repeat("k", 32))}
			type handlerSlot struct{ http.Handler }
			var current atomic.Value
			current.Store(handlerSlot{control.Handler(m, tokens)})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { current.Load().(handlerSlot).ServeHTTP(w, r) }))
			defer server.Close()
			t.Setenv("RA_POLICY_CONTROL_URL", server.URL)
			client := &http.Client{Timeout: time.Second}
			defer client.CloseIdleConnections()
			post := func(e event.Event) int {
				body, _ := json.Marshal(e)
				r, _ := http.NewRequest("POST", server.URL+"/v1/evidence", bytes.NewReader(body))
				r.Header.Set("Authorization", "Bearer "+tokens.Evidence)
				res, err := client.Do(r)
				if err != nil {
					t.Fatal(err)
				}
				defer res.Body.Close()
				if _, err := io.Copy(io.Discard, res.Body); err != nil {
					t.Fatal(err)
				}
				return res.StatusCode
			}
			s := recoveryStore(t, collectorDir)
			defer func() { s.Close() }()
			d, h := detect.New(), hostguard.New(nil)
			if err := restoreState(s, collectorDir, "session", nil, d, h); err != nil {
				t.Fatal(err)
			}
			i := &ingester{store: s, engine: d, hostEngine: h, forward: func(event.Event) {}}
			for n := 0; n < 4; n++ {
				e := recoveryHTTP(fmt.Sprintf("quota-%s-%d", fault, n), "quota-session", fmt.Sprint("object-", n), time.Now().UTC())
				e.Route = "/api/objects/{id}"
				if n < 2 {
					e.SensorID = "lab-waf"
					e.Route = "/api/search"
					e.Authorization = "unknown"
					e.DetectorFamily = "waf-local-denial"
				}
				if status, err := i.process(e); err != nil || status != "accepted" {
					t.Fatal("fixture not committed", status, err)
				}
			}
			canonical, err := loadPolicyPending(s)
			if err != nil || len(canonical) != 4 {
				t.Fatal("fixture outbox", len(canonical), err)
			}
			if fault == "confirmed-prefix" {
				for _, e := range canonical[:2] {
					if code := post(e); code != 202 {
						t.Fatal("prefix not accepted", code)
					}
				}
			}
			beforeControl, err := os.ReadFile(filepath.Join(controlDir, "actions.jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			ackStore := s
			if fault == "ack-full" {
				// An ACK-only writer with a test cap below one complete ACK row.
				// Source/evaluation records retain their original admission budget.
				ackStore, err = evidence.New(collectorDir, 64)
				if err != nil {
					t.Fatal(err)
				}
				defer ackStore.Close()
			} else {
				m.Budget = int64(len(beforeControl))
			}
			// The worker clears its acknowledged prefix in place. Preserve an
			// independent expected ledger for the final exact-ID/hash comparison.
			q := newPolicyOutbox(ackStore, append([]event.Event(nil), canonical...))
			i.forward, i.forwardReady = q.enqueue, q.ready
			stop := quotaWorker(t, q, client, server.URL, tokens.Evidence)
			quotaWait(t, "permanent quota failure", func() bool { _, _, _, failed := q.stats(); return failed })
			stop()
			wantPending, wantAcked := 4, uint64(0)
			if fault == "confirmed-prefix" {
				wantPending, wantAcked = 2, 2
			}
			pending, _, failures, failed := q.stats()
			if !failed || failures != 1 || pending != wantPending {
				t.Fatal("quota state", pending, failures, failed)
			}
			flow := q.flowStats()
			if flow["acked"] != wantAcked {
				t.Fatal("accepted HTTP was confused with durable local ACK", flow)
			}
			wantAttempts := delivery.AttemptStats{Requests: 1, HTTP503: 1}
			if fault == "confirmed-prefix" {
				wantAttempts = delivery.AttemptStats{Requests: 3, HTTP202: 2, HTTP503: 1}
			}
			if fault == "ack-full" {
				wantAttempts = delivery.AttemptStats{Requests: 4, HTTP202: 4}
			}
			if flow["http_attempts"] != wantAttempts {
				t.Fatal("quota attempt counters lost failure or early success", flow["http_attempts"], wantAttempts)
			}
			durablePending, err := loadPolicyPending(s)
			if err != nil || !reflect.DeepEqual(durablePending, canonical[int(wantAcked):]) {
				t.Fatal("pending suffix was lost or reordered", err)
			}
			beforeRows := map[string][][]byte{}
			for _, stream := range []string{"events", "evaluations", "alerts", "policy-delivery-acks"} {
				beforeRows[stream] = quotaRecords(t, s, stream)
			}
			beforeDetector := d.Stats()
			if _, err := i.process(recoveryHTTP("after-failure", "blocked", "blocked", time.Now().UTC())); err == nil {
				t.Fatal("failed delivery accepted new ingress")
			}
			for stream, rows := range beforeRows {
				if !reflect.DeepEqual(rows, quotaRecords(t, s, stream)) {
					t.Fatal("rejected ingress changed", stream)
				}
			}
			if !reflect.DeepEqual(beforeDetector, d.Stats()) {
				t.Fatal("rejected ingress changed detector")
			}
			failedControl, err := os.ReadFile(filepath.Join(controlDir, "actions.jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			if fault != "ack-full" && !bytes.Equal(beforeControl, failedControl) {
				t.Fatal("full controller wrote unacknowledged evidence")
			}
			// Stop the failed worker and reconstruct controller, store, detector and
			// outbox against the unchanged directory and endpoint fingerprint.
			if err := m.Close(); err != nil {
				t.Fatal(err)
			}
			m, err = control.OpenPersistent(controlDir)
			if err != nil {
				t.Fatal(err)
			}
			current.Store(handlerSlot{control.Handler(m, tokens)})
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			s = recoveryStore(t, collectorDir)
			d, h = detect.New(), hostguard.New(nil)
			if err := restoreState(s, collectorDir, "session", nil, d, h); err != nil {
				t.Fatal(err)
			}
			pendingEvents, err := loadPolicyPending(s)
			if err != nil || len(pendingEvents) != wantPending {
				t.Fatal("restart lost pending", err)
			}
			resumed := newPolicyOutbox(s, pendingEvents)
			stopResumed := quotaWorker(t, resumed, client, server.URL, tokens.Evidence)
			quotaWait(t, "recovery drain", func() bool {
				depth, _, _, failed := resumed.stats()
				if failed {
					t.Fatal("recovery delivery failed")
				}
				return depth == 0
			})
			stopResumed()
			acks := quotaRecords(t, s, "policy-delivery-acks")
			if len(acks) != 4 {
				t.Fatal("wrong durable ACK cardinality", len(acks))
			}
			for index, row := range acks {
				var got policyAck
				if json.Unmarshal(row, &got) != nil || got != ackFor(canonical[index]) {
					t.Fatal("incorrect ordered ACK", index)
				}
			}
			if pending, err := loadPolicyPending(s); err != nil || len(pending) != 0 {
				t.Fatal("final pending", len(pending), err)
			}
			snapshot, err := m.Snapshot(time.Now().UTC(), tokens.SnapshotKey)
			if err != nil || snapshot.Version != 6 || len(snapshot.Policies) != 1 {
				t.Fatal("policy duplicated or omitted", snapshot, err)
			}
			p := snapshot.Policies[0]
			if p.Session != "quota-session" || p.Principal != "user-a" || p.Tenant != "alpha" || p.Route != "/api/objects/{id}" {
				t.Fatal("recovery broadened policy")
			}
			finalControl, err := os.ReadFile(filepath.Join(controlDir, "actions.jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			if fault == "ack-full" && !bytes.Equal(failedControl, finalControl) {
				t.Fatal("ACK retry duplicated controller mutations")
			}
			for _, e := range canonical {
				if code := post(e); code != 202 {
					t.Fatal("duplicate ACK failed", code)
				}
			}
			afterDuplicates, err := os.ReadFile(filepath.Join(controlDir, "actions.jsonl"))
			if err != nil || !bytes.Equal(finalControl, afterDuplicates) {
				t.Fatal("duplicate delivery changed policy audit", err)
			}
			seen := map[string]bool{}
			for _, line := range bytes.Split(bytes.TrimSpace(finalControl), []byte{'\n'}) {
				var row struct {
					Evidence *event.Event `json:"evidence"`
				}
				if err := json.Unmarshal(line, &row); err != nil {
					t.Fatal(err)
				}
				if row.Evidence != nil {
					if seen[row.Evidence.EventID] {
						t.Fatal("controller duplicate evidence")
					}
					seen[row.Evidence.EventID] = true
				}
			}
			if len(seen) != 4 {
				t.Fatal("controller evidence mismatch", seen)
			}
			for _, e := range canonical {
				if !seen[e.EventID] {
					t.Fatal("controller lost event", e.EventID)
				}
			}
			// Reopen the collector once more after all durable ACKs were synced.
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			s = recoveryStore(t, collectorDir)
			if err := restoreState(s, collectorDir, "session", nil, detect.New(), hostguard.New(nil)); err != nil {
				t.Fatal(err)
			}
			if pending, err := loadPolicyPending(s); err != nil || len(pending) != 0 {
				t.Fatal("final restart lost ACK prefix", err)
			}
			t.Logf("fault=%s quota_pending=%d durable_prefix=%d controller_unique=4 final_ack=4 final_pending=0 policies=1 controller_version=6", fault, wantPending, wantAcked)
		})
	}
}
