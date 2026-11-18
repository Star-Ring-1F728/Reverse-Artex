package main

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"reverse-artex/internal/detect"
	"reverse-artex/internal/event"
	"reverse-artex/internal/evidence"
	"reverse-artex/internal/hostguard"
	"strings"
	"testing"
	"time"
)

func reservedHTTP(id string, canary bool, at time.Time) event.Event {
	e := recoveryHTTP(id, "session", "resource", at)
	e.Method = "GET"
	if canary {
		e.Route, e.ResourceClass, e.CanaryID, e.Status = "/internal/canary/{id}", "canary", "fixture", 404
	} else {
		e.Route, e.Status = "/api/export", 429
		e.Budget = &event.Budget{Measurement: "exact", Decision: "deny", RequestedRows: 1, RequestedBytes: 20, UsedRows: 2, UsedBytes: 40, LimitRows: 2, LimitBytes: 100, WindowSeconds: 60, PreResponse: true}
	}
	return e
}

func reservedEngine(principal bool) *detect.Engine {
	d := detect.NewWithCriticalReserve(principal)
	d.MaxHistory = 0
	d.Canaries = map[string]bool{"fixture": true}
	return d
}

func TestCriticalReserveEvidenceRecoveryAndForwardingBoundary(t *testing.T) {
	for _, scope := range []string{"session", "principal"} {
		t.Run(scope, func(t *testing.T) {
			dir, at := t.TempDir(), time.Now().UTC()
			store := recoveryStore(t, dir)
			defer store.Close()
			d, h := reservedEngine(scope == "principal"), hostguard.New([]string{"fixture"})
			if err := restoreState(store, dir, scope, []string{"fixture"}, d, h); err != nil {
				t.Fatal(err)
			}
			forwarded := 0
			i := &ingester{store: store, engine: d, hostEngine: h, clock: func() time.Time { return at }, forward: func(event.Event) { forwarded++ }}
			e := reservedHTTP("reserved", false, at)
			if result, err := i.process(e); result != "signal_only" || err != nil {
				t.Fatal(result, err)
			}
			if result, err := i.process(e); result != "duplicate" || err != nil {
				t.Fatal(result, err)
			}
			evals, err := readEvaluations(store, "evaluations")
			if err != nil || len(evals) != 2 || evals[0].PolicyDelivery || evals[0].Rules["RA-007"] != "evaluable_reserved_signal" || evals[0].Rules["RA-002"] != "not_evaluable_capacity_rejected" {
				t.Fatal("misleading partial evaluation", evals, err)
			}
			if rules := alertRules(t, store, "alerts"); len(rules) != 1 || rules[0] != "RA-007" {
				t.Fatal(rules)
			}
			pending, err := loadPolicyPending(store)
			if err != nil || len(pending) != 0 || forwarded != 0 {
				t.Fatal("reserved evidence gained policy admission", pending, err, forwarded)
			}
			if err = restoreState(store, dir, scope, []string{"fixture"}, recoveryEngine(scope), hostguard.New([]string{"fixture"})); err == nil {
				t.Fatal("reserve configuration downgrade accepted")
			}
			d = reservedEngine(scope == "principal")
			if err = restoreState(store, dir, scope, []string{"fixture"}, d, hostguard.New([]string{"fixture"})); err != nil {
				t.Fatal("reserved replay refused", err)
			}
			if d.CriticalReserveStats()["dedup_keys"] != 1 || d.CriticalReserveStats()["cooldown_keys"] != 1 {
				t.Fatal("reserve accounting not restored")
			}
			i.engine = d
			if result, err := i.process(e); result != "duplicate" || err != nil {
				t.Fatal("restored duplicate lost", result, err)
			}
			e.EventID, e.RequestID = "after-recovery", "after-recovery"
			if result, err := i.process(e); result != "signal_only" || err != nil {
				t.Fatal(result, err)
			}
			if rules := alertRules(t, store, "alerts"); len(rules) != 1 {
				t.Fatal("cooldown lost on recovery", rules)
			}
		})
	}
}

func TestCriticalReserveCannotUpgradeExistingEvidenceProfile(t *testing.T) {
	dir := t.TempDir()
	s := recoveryStore(t, dir)
	defer s.Close()
	if err := restoreState(s, dir, "session", nil, detect.New(), hostguard.New(nil)); err != nil {
		t.Fatal(err)
	}
	if err := restoreState(s, dir, "session", nil, reservedEngine(false), hostguard.New(nil)); err == nil {
		t.Fatal("old recovery profile silently upgraded")
	}
}

func TestCriticalReserveBatchACKRequiresEveryEvidenceStream(t *testing.T) {
	for _, failure := range []string{"", "events", "alerts", "evaluations"} {
		t.Run("failure-"+failure, func(t *testing.T) {
			s := recoveryStore(t, t.TempDir())
			defer s.Close()
			i := &ingester{store: batchFailureStore{s, failure}, engine: reservedEngine(false)}
			forwarded := 0
			i.forward = func(event.Event) { forwarded++ }
			token := strings.Repeat("t", 32)
			h := appBatchHandler(i, token, "lab-app", "lab-api", map[string]bool{"alpha": true}, make(chan struct{}, 32))
			at := time.Now().UTC()
			es := []event.Event{reservedHTTP("budget", false, at), reservedHTTP("canary", true, at)}
			raw, err := json.Marshal(es)
			if err != nil {
				t.Fatal(err)
			}
			request := func() *httptest.ResponseRecorder {
				r := httptest.NewRequest("POST", "/v1/events/batch", bytes.NewReader(raw))
				r.Header.Set("Authorization", "Bearer "+token)
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				return w
			}
			w := request()
			if failure != "" {
				if w.Code != 503 || !i.degraded() || w.Header().Get("X-RA-Delivery-Permanent") != "1" {
					t.Fatal("failed evidence acknowledged", w.Code, i.degraded())
				}
				if request().Code != 503 {
					t.Fatal("uncertain evidence resumed without recovery")
				}
			} else {
				if w.Code != 202 || strings.Count(w.Body.String(), "signal_only") != 2 {
					t.Fatal("reserved receipt missing", w.Code, w.Body.String())
				}
				if n := len(alertRules(t, s, "alerts")); n != 2 {
					t.Fatal("ACK before alerts", n)
				}
				if evals, err := readEvaluations(s, "evaluations"); err != nil || len(evals) != 2 {
					t.Fatal("ACK before evaluations", err, len(evals))
				}
				if w = request(); w.Code != 202 || strings.Count(w.Body.String(), "duplicate") != 2 {
					t.Fatal("lost ACK retry duplicated signals", w.Code, w.Body.String())
				}
				if n := len(alertRules(t, s, "alerts")); n != 2 {
					t.Fatal("retry emitted again", n)
				}
			}
			if forwarded != 0 {
				t.Fatal("partial correlation admitted policy evidence")
			}
		})
	}
}

func TestCriticalReserveStorageQuotaDoesNotACK(t *testing.T) {
	s, err := evidence.NewRotating(t.TempDir(), 256, 64)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	i := &ingester{store: s, engine: reservedEngine(false)}
	if result, err := i.process(reservedHTTP("quota", false, time.Now().UTC())); err == nil || result != "" || !i.degraded() {
		t.Fatal("storage quota acknowledged", result, err)
	}
}
