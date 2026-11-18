package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reverse-artex/internal/detect"
	"reverse-artex/internal/event"
	"reverse-artex/internal/evidence"
	"reverse-artex/internal/hostguard"
	"testing"
	"time"
)

func recoveryHTTP(id, session, resource string, at time.Time) event.Event {
	return event.Event{
		SchemaVersion: "1.0", EventID: id, EventTime: at, IngestTime: at,
		SensorID: "lab-app", TenantID: "alpha", AssetID: "lab-api", EventType: "http",
		RequestID: "request-" + id, Method: "GET", Route: "/api/{id}", Status: 403,
		Principal: "user-a", SessionHMAC: session, Identity: "authenticated",
		Authorization: "deny", ResourceHMAC: resource, KnownRoute: true,
		UAHint: "none", DataQuality: "complete",
	}
}

func recoveryHost(id, kind string, at time.Time) hostguard.Event {
	class := "unexpected_child"
	if kind == "network_connect" {
		class = "unapproved_destination"
	}
	return hostguard.Event{
		SchemaVersion: "host/1.0", EventID: id, EventTime: at, IngestTime: at,
		SensorID: "lab-host", TenantID: "alpha", AssetID: "lab-api", EventType: kind,
		ServiceID: "lab-web", WorkloadID: "lab-workload", ProcessKey: "boot:2:20",
		ParentKey: "boot:1:10", Lineage: "verified", DataQuality: "complete", Classification: class,
	}
}

func recoveryStore(t *testing.T, dir string) *evidence.Store {
	t.Helper()
	s, err := evidence.NewRotating(dir, 1<<20, 4096)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func recoveryEngine(scope string) *detect.Engine {
	if scope == "principal" {
		return detect.NewPrincipal()
	}
	return detect.New()
}

func alertRules(t *testing.T, s *evidence.Store, stream string) []string {
	t.Helper()
	var rules []string
	if err := s.VisitRecords(stream, func(line []byte) error {
		var a struct {
			Rule string `json:"rule_id"`
		}
		if err := json.Unmarshal(line, &a); err != nil {
			return err
		}
		rules = append(rules, a.Rule)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return rules
}

func TestRecoveryRestoresSessionPrincipalAndHostState(t *testing.T) {
	for _, scope := range []string{"session", "principal"} {
		t.Run(scope, func(t *testing.T) {
			dir := t.TempDir()
			s := recoveryStore(t, dir)
			h := hostguard.New(nil)
			d := recoveryEngine(scope)
			if err := restoreState(s, dir, scope, nil, d, h); err != nil {
				t.Fatal(err)
			}
			i := &ingester{store: s, engine: d, hostEngine: h}
			base := time.Now().UTC().Add(-10 * time.Second)
			for n := 0; n < 3; n++ {
				at := base.Add(time.Duration(n) * time.Second)
				if n == 1 {
					at = base.Add(-time.Second) // arrival order need not be event-time order
				}
				e := recoveryHTTP(fmt.Sprint("event-", n), fmt.Sprint("session-", n), fmt.Sprint("resource-", n), at)
				if status, err := i.process(e); status != "accepted" || err != nil {
					t.Fatal(status, err)
				}
			}
			if status, err := i.processHost(recoveryHost("start", "process_start", base.Add(4*time.Second))); status != "accepted" || err != nil {
				t.Fatal(status, err)
			}
			// Recreate every in-memory engine while retaining only the evidence directory.
			s = recoveryStore(t, dir)
			d, h = recoveryEngine(scope), hostguard.New(nil)
			if err := restoreState(s, dir, scope, nil, d, h); err != nil {
				t.Fatal(err)
			}
			i = &ingester{store: s, engine: d, hostEngine: h}
			fourth := recoveryHTTP("event-3", "session-3", "resource-0", base.Add(3*time.Second))
			if status, err := i.process(fourth); status != "accepted" || err != nil {
				t.Fatal(status, err)
			}
			if status, err := i.processHost(recoveryHost("network", "network_connect", base.Add(5*time.Second))); status != "accepted" || err != nil {
				t.Fatal(status, err)
			}
			if status, err := i.process(fourth); status != "duplicate" || err != nil {
				t.Fatal("duplicate state lost", status, err)
			}
			rules := alertRules(t, s, "alerts")
			if scope == "principal" {
				if len(rules) != 1 || rules[0] != "RA-004" {
					t.Fatal("principal correlation not restored", rules)
				}
			} else if len(rules) != 0 {
				t.Fatal("session boundaries merged", rules)
			}
			hostRules := alertRules(t, s, "host-alerts")
			if len(hostRules) != 1 || hostRules[0] != "RA-006" {
				t.Fatal("host process chain not restored", hostRules)
			}
		})
	}
}

func TestRecoveryExpiresOldCorrelationWindows(t *testing.T) {
	dir := t.TempDir()
	s := recoveryStore(t, dir)
	base := time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)
	d := detect.NewPrincipal()
	h := hostguard.New(nil)
	if err := restoreState(s, dir, "principal", nil, d, h); err != nil {
		t.Fatal(err)
	}
	i := &ingester{store: s, engine: d, hostEngine: h, clock: func() time.Time { return base }}
	for n := 0; n < 3; n++ {
		e := recoveryHTTP(fmt.Sprint("old-", n), fmt.Sprint("session-", n), fmt.Sprint("resource-", n), base)
		if _, err := i.process(e); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := i.processHost(recoveryHost("old-start", "process_start", base)); err != nil {
		t.Fatal(err)
	}
	s = recoveryStore(t, dir)
	d, h = detect.NewPrincipal(), hostguard.New(nil)
	if err := restoreState(s, dir, "principal", nil, d, h); err != nil {
		t.Fatal(err)
	}
	later := base.Add(time.Hour + time.Minute)
	i = &ingester{store: s, engine: d, hostEngine: h, clock: func() time.Time { return later }}
	if _, err := i.process(recoveryHTTP("fresh", "new-session", "fresh-resource", later)); err != nil {
		t.Fatal(err)
	}
	if _, err := i.processHost(recoveryHost("late-network", "network_connect", later)); err != nil {
		t.Fatal(err)
	}
	if got := alertRules(t, s, "alerts"); len(got) != 0 {
		t.Fatal("expired HTTP window emitted alert", got)
	}
	if got := alertRules(t, s, "host-alerts"); len(got) != 0 {
		t.Fatal("expired host process chain emitted alert", got)
	}
}

func TestRecoveryRejectsIncompleteAndChangedEvidence(t *testing.T) {
	for _, variant := range []string{"uncommitted", "torn-line", "missing-alert", "changed-evaluation", "configuration", "canary", "ruleset", "oversized-meta", "unversioned"} {
		t.Run(variant, func(t *testing.T) {
			dir := t.TempDir()
			s := recoveryStore(t, dir)
			if err := restoreState(s, dir, "session", nil, detect.New(), hostguard.New(nil)); err != nil {
				t.Fatal(err)
			}
			e := recoveryHTTP("initial", "session", "resource", time.Now().UTC().Add(-time.Second))
			if variant == "missing-alert" {
				e.UAHint = "norma-unverified"
			}
			i := &ingester{store: s, engine: detect.New(), hostEngine: hostguard.New(nil)}
			if _, err := i.process(e); err != nil {
				t.Fatal(err)
			}
			switch variant {
			case "uncommitted":
				e.EventID = "orphan"
				if err := s.Append("events", e); err != nil {
					t.Fatal(err)
				}
			case "torn-line":
				f, err := os.OpenFile(filepath.Join(dir, "evaluations.jsonl"), os.O_APPEND|os.O_WRONLY, 0600)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := f.Write([]byte(`{"event_id":"torn"`)); err != nil {
					t.Fatal(err)
				}
				f.Close()
			case "missing-alert":
				if err := os.Truncate(filepath.Join(dir, "alerts.jsonl"), 0); err != nil {
					t.Fatal(err)
				}
			case "changed-evaluation":
				path := filepath.Join(dir, "evaluations.jsonl")
				b, _ := os.ReadFile(path)
				var eval evaluationRecord
				json.Unmarshal(b, &eval)
				eval.Result = "duplicate"
				b, _ = json.Marshal(eval)
				if err := os.WriteFile(path, append(b, '\n'), 0600); err != nil {
					t.Fatal(err)
				}
			case "ruleset":
				path := filepath.Join(dir, "recovery.meta.json")
				b, _ := os.ReadFile(path)
				var meta recoveryMeta
				json.Unmarshal(b, &meta)
				meta.Ruleset = "other"
				b, _ = json.Marshal(meta)
				if err := os.WriteFile(path, b, 0600); err != nil {
					t.Fatal(err)
				}
			case "oversized-meta":
				if err := os.WriteFile(filepath.Join(dir, "recovery.meta.json"), make([]byte, 4097), 0600); err != nil {
					t.Fatal(err)
				}
			case "unversioned":
				if err := os.Remove(filepath.Join(dir, "recovery.meta.json")); err != nil {
					t.Fatal(err)
				}
			}
			s = recoveryStore(t, dir)
			scope := "session"
			if variant == "configuration" {
				scope = "principal"
			}
			var canaries []string
			if variant == "canary" {
				canaries = []string{"fixture"}
			}
			if err := restoreState(s, dir, scope, canaries, recoveryEngine(scope), hostguard.New(canaries)); err == nil {
				t.Fatal("unsafe recovery accepted", variant)
			}
		})
	}
}

func TestOfflineReplayCannotWriteLiveRecoveryDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := checkOfflineOutput(dir); err != nil {
		t.Fatal(err)
	}
	s := recoveryStore(t, dir)
	if err := restoreState(s, dir, "session", nil, detect.New(), hostguard.New(nil)); err != nil {
		t.Fatal(err)
	}
	if err := checkOfflineOutput(dir); err == nil {
		t.Fatal("offline replay could alter live detector state")
	}
}

func TestIngestClockStepCannotCreateUnrecoverableCommit(t *testing.T) {
	dir := t.TempDir()
	s := recoveryStore(t, dir)
	if err := restoreState(s, dir, "session", nil, detect.New(), hostguard.New(nil)); err != nil {
		t.Fatal(err)
	}
	base := time.Now().UTC().Add(-time.Second)
	calls := 0
	i := &ingester{store: s, engine: detect.New(), hostEngine: hostguard.New(nil), clock: func() time.Time {
		calls++
		if calls == 1 {
			return base
		}
		return base.Add(-time.Second)
	}}
	if _, err := i.process(recoveryHTTP("clock-step", "session", "resource", base)); err != nil {
		t.Fatal(err)
	}
	s = recoveryStore(t, dir)
	if err := restoreState(s, dir, "session", nil, detect.New(), hostguard.New(nil)); err != nil {
		t.Fatal("clock step created a commit that cannot be restored", err)
	}
}
