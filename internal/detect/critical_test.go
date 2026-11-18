package detect

import (
	"fmt"
	"reflect"
	"reverse-artex/internal/event"
	"testing"
	"time"
)

func criticalEvent(id, rule string) event.Event {
	e := detectEvent(id, id, detectTestNow)
	if rule == "RA-007" {
		e.Route, e.Status, e.Authorization = "/api/export", 429, "deny"
		e.Budget = &event.Budget{Measurement: "exact", Decision: "deny", RequestedRows: 1, RequestedBytes: 20, UsedRows: 2, UsedBytes: 40, LimitRows: 2, LimitBytes: 100, WindowSeconds: 60, PreResponse: true}
	} else {
		e.Route, e.ResourceClass, e.CanaryID, e.Authorization, e.Status = "/internal/canary/{id}", "canary", "fixture", "deny", 404
	}
	return e
}

func TestCriticalSignalsSurviveCorrelationCaps(t *testing.T) {
	for _, mode := range []bool{false, true} {
		for _, cap := range []string{"subjects", "events", "history", "seen"} {
			for _, rule := range []string{"RA-007", "RA-008"} {
				t.Run(fmt.Sprintf("principal=%t/%s/%s", mode, cap, rule), func(t *testing.T) {
					d := NewWithCriticalReserve(mode)
					d.Canaries = map[string]bool{"fixture": true}
					switch cap {
					case "subjects":
						d.MaxSubjects = 0
					case "events":
						d.MaxEvents = 0
					case "history":
						d.MaxHistory = 0
					case "seen":
						d.MaxSeen = 0
					}
					alerts, result := d.Process(criticalEvent("critical", rule), detectTestNow)
					if result != "signal_only" || len(alerts) != 1 || alerts[0].RuleID != rule {
						t.Fatalf("critical signal lost at capacity: %s alerts=%v", result, alerts)
					}
					if a := alerts[0]; a.Version != "1.1" || a.Mode != "observe" || a.DataQuality != "complete" || len(a.Evidence) != 1 || a.Evidence[0] != "critical" {
						t.Fatal("invalid reserved proof", a)
					}
					if s := d.Stats(); s["dedup_keys"] != 0 || s["history_events"] != 0 || s["subjects"] != 0 {
						t.Fatal("reserved signal consumed correlation state", s)
					}
				})
			}
		}
	}
}

func saturatedCritical() *Engine {
	d := NewWithCriticalReserve(false)
	d.MaxHistory = 0
	d.Canaries = map[string]bool{"fixture": true}
	return d
}

func TestCriticalReserveIsOptInAndCannotInventSignals(t *testing.T) {
	e := criticalEvent("critical", "RA-007")
	d := New()
	d.MaxHistory = 0
	if a, s := d.Process(e, detectTestNow); s != "capacity_rejected" || len(a) != 0 || d.CriticalReserveEnabled() {
		t.Fatal("default behavior changed", s, a)
	}
	for _, variant := range []string{"partial", "anonymous-budget", "missing-identity", "invalid-budget", "unconfigured-canary", "invalid-route", "ordinary"} {
		t.Run(variant, func(t *testing.T) {
			d := saturatedCritical()
			x := criticalEvent("invalid", "RA-007")
			switch variant {
			case "partial":
				x.DataQuality = "partial"
			case "anonymous-budget":
				x.Identity, x.Principal, x.SessionHMAC = "anonymous", "", ""
			case "missing-identity":
				x.Principal = ""
			case "invalid-budget":
				x.Budget.PreResponse = false
			case "unconfigured-canary":
				x = criticalEvent("invalid", "RA-008")
				x.CanaryID = "unknown"
			case "invalid-route":
				x.Route = "/api/search"
			case "ordinary":
				x = detectEvent("ordinary", "ordinary", detectTestNow)
				x.UAHint = "enrich"
			}
			if a, s := d.Process(x, detectTestNow); s != "capacity_rejected" || len(a) != 0 {
				t.Fatal("unverified signal admitted", s, a)
			}
			if len(d.critical.seen) != 0 || len(d.critical.cooldowns) != 0 {
				t.Fatal("invalid signal charged reserve")
			}
		})
	}
}

func TestCriticalReplayAndCooldownCrossAdmissionPaths(t *testing.T) {
	for _, reserveFirst := range []bool{true, false} {
		t.Run(fmt.Sprint(reserveFirst), func(t *testing.T) {
			d := saturatedCritical()
			if !reserveFirst {
				d.MaxHistory = 1
			}
			e := criticalEvent("first", "RA-007")
			if a, s := d.Process(e, detectTestNow); len(a) != 1 || (s != "accepted" && s != "signal_only") {
				t.Fatal(s, a)
			}
			// Free ordinary capacity after a reserved receipt. Replays must not
			// gain correlation or policy admission on the second attempt.
			if reserveFirst {
				d.MaxHistory = 1
			}
			if a, s := d.Process(e, detectTestNow); s != "duplicate" || len(a) != 0 {
				t.Fatal(s, a)
			}
			e.EventID, e.RequestID = "second", "second"
			if a, s := d.Process(e, detectTestNow.Add(10*time.Second)); len(a) != 0 || (s != "accepted" && s != "signal_only") {
				t.Fatal("cross-path cooldown lost", s, a)
			}
			e.EventID, e.RequestID = "third", "third"
			if a, s := d.Process(e, detectTestNow.Add(time.Minute)); s != "signal_only" || len(a) != 1 {
				t.Fatal("inclusive cooldown boundary", s, a)
			}
		})
	}
}

func TestCriticalReserveQuotasLeaveOtherScopesCapacity(t *testing.T) {
	for reason := 0; reason < 6; reason++ {
		t.Run(fmt.Sprint(reason), func(t *testing.T) {
			d := saturatedCritical()
			d.critical.limits = criticalLimits{8, 8, 8, 8, 8, 8}
			switch reason {
			case 0:
				d.critical.limits.seen = 1
			case 1:
				d.critical.limits.tenantSeen = 1
			case 2:
				d.critical.limits.sensorSeen = 1
			case 3:
				d.critical.limits.keys = 1
			case 4:
				d.critical.limits.tenantKeys = 1
			case 5:
				d.critical.limits.sensorKeys = 1
			}
			first := criticalEvent("first", "RA-007")
			if _, s := d.Process(first, detectTestNow); s != "signal_only" {
				t.Fatal(s)
			}
			x := criticalEvent("overflow", "RA-007")
			if reason >= 3 {
				x.SessionHMAC = "other-session"
			}
			if a, s := d.Process(x, detectTestNow); s != "capacity_rejected" || len(a) != 0 {
				t.Fatal("reserve cap bypassed", s, a)
			}
			if d.critical.rejected[reason] != 1 || len(d.critical.seen) != 1 {
				t.Fatal("refusal not atomic or uncounted")
			}
			if _, s := d.Process(first, detectTestNow); s != "duplicate" {
				t.Fatal("full reserve lost dedup", s)
			}
			if reason == 0 || reason == 3 {
				return
			} // The global budget is finite.
			x.EventID, x.RequestID = "other-scope", "other-scope"
			if reason == 1 || reason == 4 {
				x.TenantID = "tenant-b"
			} else {
				x.SensorID = "sensor-b"
			}
			if _, s := d.Process(x, detectTestNow); s != "signal_only" {
				t.Fatal("one scope exhausted unrelated reserve", s)
			}
		})
	}
}

func TestCriticalAnonymousAndPrincipalScopeStayWeakAndBounded(t *testing.T) {
	for _, principal := range []bool{false, true} {
		d := NewWithCriticalReserve(principal)
		d.MaxHistory = 0
		d.Canaries = map[string]bool{"fixture": true}
		e := criticalEvent("anonymous", "RA-008")
		e.Identity, e.Principal, e.SessionHMAC = "anonymous", "", ""
		a, s := d.Process(e, detectTestNow)
		if s != "signal_only" || len(a) != 1 || a[0].CorrelationScope != "asset" || a[0].Principal != "" || a[0].SessionHMAC != "" {
			t.Fatal("anonymous attribution widened", s, a)
		}
		e = criticalEvent("session-one", "RA-007")
		if _, s := d.Process(e, detectTestNow); s != "signal_only" {
			t.Fatal(s)
		}
		e.EventID, e.RequestID, e.SessionHMAC = "session-two", "session-two", "other-session"
		a, s = d.Process(e, detectTestNow)
		want := 1
		if principal {
			want = 0
		}
		if s != "signal_only" || len(a) != want {
			t.Fatal("session/principal cooldown boundary", s, a)
		}
	}
}

func TestCriticalReserveReclaimsAllQuotaAccountingAfterHour(t *testing.T) {
	d := saturatedCritical()
	e := criticalEvent("same-id", "RA-007")
	if _, s := d.Process(e, detectTestNow); s != "signal_only" {
		t.Fatal(s)
	}
	if _, s := d.Process(e, detectTestNow.Add(time.Hour)); s != "duplicate" {
		t.Fatal("inclusive replay boundary lost", s)
	}
	at := detectTestNow.Add(time.Hour + time.Second)
	ordinary := detectEvent("tick", "tick", at)
	ordinary.IngestTime = at
	d.Process(ordinary, at)
	if r := d.critical; len(r.seen) != 0 || len(r.cooldowns) != 0 || len(r.tenants) != 0 || len(r.sensors) != 0 {
		t.Fatal("expired accounting retained")
	}
	e.EventTime, e.IngestTime = at, at
	if a, s := d.Process(e, at); s != "signal_only" || len(a) != 1 {
		t.Fatal("reclaimed quota unusable", s, a)
	}
}

func TestCriticalReserveDefaultReplayBudgetsAreFiniteAcrossTenants(t *testing.T) {
	d := saturatedCritical()
	for tenant := 0; tenant < 4; tenant++ {
		for sensor := 0; sensor < 2; sensor++ {
			for n := 0; n < 512; n++ {
				e := criticalEvent(fmt.Sprintf("%d-%d-%d", tenant, sensor, n), "RA-007")
				e.TenantID, e.SensorID = fmt.Sprint("tenant-", tenant), fmt.Sprint("sensor-", sensor)
				if _, s := d.Process(e, detectTestNow); s != "signal_only" {
					t.Fatal("default reserve rejected early", tenant, sensor, n, s)
				}
			}
		}
		if tenant == 0 {
			e := criticalEvent("tenant-overflow", "RA-007")
			e.TenantID, e.SensorID = "tenant-0", "third-sensor"
			if _, s := d.Process(e, detectTestNow); s != "capacity_rejected" {
				t.Fatal("tenant replay cap bypassed")
			}
		}
	}
	e := criticalEvent("global-overflow", "RA-007")
	e.TenantID = "another-tenant"
	if _, s := d.Process(e, detectTestNow); s != "capacity_rejected" {
		t.Fatal("global replay cap bypassed")
	}
	stats := d.CriticalReserveStats()
	if stats["dedup_keys"] != 4096 || stats["tenant_scopes"] != 4 || stats["sensor_scopes"] != 8 || stats["refused_tenant_dedup"] != uint64(1) || stats["refused_global_dedup"] != uint64(1) {
		t.Fatal("unbounded default reserve", stats)
	}
}

func TestCriticalReserveKeepsUnsaturatedCorrelationResults(t *testing.T) {
	for _, principal := range []bool{false, true} {
		for _, profile := range []string{"normal", "recon", "validation", "mixed"} {
			t.Run(fmt.Sprintf("principal=%t/%s", principal, profile), func(t *testing.T) {
				legacy := New()
				if principal {
					legacy = NewPrincipal()
				}
				candidate := NewWithCriticalReserve(principal)
				legacy.Canaries, candidate.Canaries = map[string]bool{"fixture-canary": true}, map[string]bool{"fixture-canary": true}
				for _, e := range windowFixtureEvents(profile) {
					want, wantStatus := legacy.Process(e, e.IngestTime)
					got, status := candidate.Process(e, e.IngestTime)
					if status != wantStatus || !reflect.DeepEqual(got, want) {
						t.Fatal("unsaturated rules changed", e.EventID, status, wantStatus, got, want)
					}
				}
				if !reflect.DeepEqual(candidate.Stats(), legacy.Stats()) || candidate.CriticalReserveStats()["dedup_keys"] != 0 {
					t.Fatal("unsaturated input consumed reserve")
				}
			})
		}
	}
}
