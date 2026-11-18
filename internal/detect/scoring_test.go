package detect

import (
	"fmt"
	"reflect"
	"testing"
	"time"

	"reverse-artex/internal/event"
)

func TestCooldownSkipsScoringButRetainsHistoryAndSingleEventSignals(t *testing.T) {
	for _, factory := range []struct {
		name string
		new  func() *Engine
	}{{"session", New}, {"principal", NewPrincipal}} {
		t.Run(factory.name, func(t *testing.T) {
			d := factory.new()
			d.Canaries = map[string]bool{"private": true}
			var seed []event.Event
			for i := 0; i < 8; i++ {
				e := detectEvent(fmt.Sprint("recon-", i), fmt.Sprint("recon-request-", i), detectTestNow.Add(-20*time.Second))
				e.KnownRoute, e.Status, e.PathHMAC = false, 404, fmt.Sprint("path-", i)
				seed = append(seed, e)
			}
			for i := 0; i < 4; i++ {
				e := detectEvent(fmt.Sprint("validation-", i), fmt.Sprint("validation-request-", i), detectTestNow.Add(-10*time.Second))
				e.Route, e.DetectorFamily, e.Status = "/api/z", []string{"schema", "type"}[i%2], 400
				seed = append(seed, e)
			}
			for i := 0; i < 4; i++ {
				e := detectEvent(fmt.Sprint("deny-", i), fmt.Sprint("deny-request-", i), detectTestNow.Add(-5*time.Second))
				e.Authorization, e.ResourceHMAC = "deny", fmt.Sprint("resource-", i)
				seed = append(seed, e)
			}
			initial := processAccepted(t, d, seed)
			var rules []string
			for _, a := range initial {
				rules = append(rules, a.RuleID)
			}
			if !reflect.DeepEqual(rules, []string{"RA-002", "RA-005", "RA-003", "RA-004"}) {
				t.Fatalf("seed must cool down all correlation rules: %v", rules)
			}
			var fresh []event.Event
			for i := 0; i < 4; i++ {
				e := detectEvent(fmt.Sprint("fresh-", i), fmt.Sprint("fresh-request-", i), detectTestNow.Add(15*time.Second))
				e.Route, e.DetectorFamily, e.Status = "/api/a", []string{"schema", "type"}[i%2], 400
				fresh = append(fresh, e)
				if alerts, status := d.Process(e, detectTestNow.Add(30*time.Second)); status != "accepted" || len(alerts) != 0 {
					t.Fatalf("cooldown event: %s %+v", status, alerts)
				}
			}
			if stats := d.Stats(); stats["history_events"] != len(seed)+len(fresh) || stats["dedup_keys"] != len(seed)+len(fresh) {
				t.Fatalf("cooldown dropped state: %v", stats)
			}
			if _, status := d.Process(fresh[0], detectTestNow.Add(31*time.Second)); status != "duplicate" {
				t.Fatalf("cooldown lost replay protection: %s", status)
			}
			signal := detectEvent("signal", "signal-request", detectTestNow.Add(32*time.Second))
			signal.UAHint, signal.CanaryID, signal.ResourceClass, signal.Authorization = "tool", "private", "canary", "deny"
			alerts, status := d.Process(signal, detectTestNow.Add(32*time.Second))
			if status != "accepted" || len(alerts) != 2 || alerts[0].RuleID != "RA-008" || alerts[1].RuleID != "RA-001" {
				t.Fatalf("single-event signals suppressed: %s %+v", status, alerts)
			}
			for _, offset := range []time.Duration{time.Minute - time.Nanosecond, time.Minute} {
				tick := detectEvent(fmt.Sprint("tick-", offset), fmt.Sprint("tick-request-", offset), detectTestNow.Add(offset))
				alerts, status := d.Process(tick, detectTestNow.Add(offset))
				if status != "accepted" {
					t.Fatal(status)
				}
				if offset < time.Minute {
					if len(alerts) != 0 {
						t.Fatalf("cooldown ended early: %+v", alerts)
					}
					continue
				}
				found := false
				for _, a := range alerts {
					if a.RuleID == "RA-005" {
						found = true
						if a.Window != "1m0s" || !reflect.DeepEqual(a.Evidence, []string{"fresh-0", "fresh-1", "fresh-2", "fresh-3"}) {
							t.Fatalf("cooldown history witness changed: %+v", a)
						}
					}
				}
				if !found {
					t.Fatalf("fresh history missing after cooldown: %+v", alerts)
				}
			}
		})
	}
}

func TestWiderWindowRescoresWhenRequestWitnessChanges(t *testing.T) {
	for _, d := range []*Engine{New(), NewPrincipal()} {
		old := detectEvent("old", "shared", detectTestNow.Add(-61*time.Second))
		old.DetectorFamily, old.DataQuality = "type", "partial"
		newer := detectEvent("newer", "shared", detectTestNow.Add(-30*time.Second))
		newer.DetectorFamily = "schema"
		events := []event.Event{old, newer}
		for i := 0; i < 3; i++ {
			e := detectEvent(fmt.Sprint("unique-", i), fmt.Sprint("request-", i), detectTestNow.Add(-20*time.Second))
			e.DetectorFamily = "schema"
			events = append(events, e)
		}
		a := requireOnlyAlert(t, processAccepted(t, d, events), "RA-005", "medium")
		if a.Window != "10m0s" || a.DataQuality != "partial" || !reflect.DeepEqual(a.Evidence, []string{"old", "unique-0", "unique-1", "unique-2"}) {
			t.Fatalf("wider window must select its own first request: %+v", a)
		}
	}
}
