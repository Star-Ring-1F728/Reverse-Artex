package detect

import (
	"fmt"
	"reflect"
	"testing"
	"time"

	"reverse-artex/internal/event"
)

func TestValidationWindowBoundariesRemainInclusive(t *testing.T) {
	for _, factory := range []struct {
		name string
		new  func() *Engine
	}{{"session", New}, {"principal", NewPrincipal}} {
		for _, window := range []struct {
			age  time.Duration
			next string
		}{
			{time.Minute, "10m0s"},
			{10 * time.Minute, "1h0m0s"},
			{time.Hour, ""},
		} {
			for _, outside := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/outside=%v", factory.name, window.age, outside), func(t *testing.T) {
					at := detectTestNow.Add(-window.age)
					wantWindow := window.age.String()
					if outside {
						at = at.Add(-time.Nanosecond)
						wantWindow = window.next
					}
					var events []event.Event
					for i := 0; i < 4; i++ {
						e := detectEvent(fmt.Sprint("validation-", i), fmt.Sprint("request-", i), at)
						e.DetectorFamily = []string{"schema", "type"}[i%2]
						e.Status = 400
						events = append(events, e)
					}
					alerts := processAccepted(t, factory.new(), events)
					if wantWindow == "" {
						if len(alerts) != 0 {
							t.Fatalf("expired history emitted alerts: %+v", alerts)
						}
						return
					}
					a := requireOnlyAlert(t, alerts, "RA-005", "medium")
					if a.Window != wantWindow {
						t.Fatalf("window = %q, want %q", a.Window, wantWindow)
					}
					if !reflect.DeepEqual(a.Evidence, []string{"validation-0", "validation-1", "validation-2", "validation-3"}) {
						t.Fatalf("boundary evidence changed: %v", a.Evidence)
					}
				})
			}
		}
	}
}

func TestWindowDedupChoosesFirstRequestInsideEachWindow(t *testing.T) {
	old := detectEvent("old-partial", "shared-request", detectTestNow.Add(-61*time.Second))
	old.Route, old.DetectorFamily, old.DataQuality = "/api/a", "schema", "partial"
	recent := detectEvent("recent-complete", "shared-request", detectTestNow.Add(-time.Minute))
	recent.Route, recent.DetectorFamily = "/api/b", "type"
	var arrival = []event.Event{old}
	for i := 0; i < 3; i++ {
		e := detectEvent(fmt.Sprint("unique-", i), fmt.Sprint("request-", i), detectTestNow.Add(time.Duration(i-59)*time.Second))
		e.Route, e.DetectorFamily = "/api/b", "schema"
		arrival = append(arrival, e)
	}
	arrival = append(arrival, recent) // Late arrival exactly at the inclusive cutoff.
	for _, engine := range []*Engine{New(), NewPrincipal()} {
		a := requireOnlyAlert(t, processAccepted(t, engine, arrival), "RA-005", "medium")
		want := []string{"recent-complete", "unique-0", "unique-1", "unique-2"}
		if a.Window != "1m0s" || a.DataQuality != "complete" || !reflect.DeepEqual(a.Evidence, want) {
			t.Fatalf("window-local request witness changed: %+v", a)
		}
	}
}

func TestValidationCooldownKeepsLexicalRouteWitness(t *testing.T) {
	for _, engine := range []*Engine{New(), NewPrincipal()} {
		var arrivals []event.Event
		for _, route := range []string{"/api/b", "/api/a"} {
			for i := 0; i < 4; i++ {
				e := detectEvent(fmt.Sprintf("%s-%d", route, i), fmt.Sprintf("request-%s-%d", route, i), detectTestNow.Add(-2*time.Minute))
				e.Route, e.DetectorFamily = route, []string{"schema", "type"}[i%2]
				arrivals = append(arrivals, e)
			}
		}
		first := requireOnlyAlert(t, processAccepted(t, engine, arrivals), "RA-005", "medium")
		if first.Window != "10m0s" || first.Evidence[0] != "/api/b-0" {
			t.Fatalf("initial witness changed: %+v", first)
		}
		for _, offset := range []time.Duration{time.Minute - time.Nanosecond, time.Minute} {
			now := detectTestNow.Add(offset)
			e := detectEvent(fmt.Sprint("tick-", offset), fmt.Sprint("tick-request-", offset), now)
			alerts, status := engine.Process(e, now)
			if status != "accepted" {
				t.Fatal(status)
			}
			if offset < time.Minute {
				if len(alerts) != 0 {
					t.Fatalf("cooldown ended early: %+v", alerts)
				}
				continue
			}
			a := requireOnlyAlert(t, alerts, "RA-005", "medium")
			if a.Window != "10m0s" || !reflect.DeepEqual(a.Evidence, []string{"/api/a-0", "/api/a-1", "/api/a-2", "/api/a-3"}) {
				t.Fatalf("lexical witness after cooldown changed: %+v", a)
			}
		}
	}
}

func BenchmarkProcessWindowAccounting(b *testing.B) {
	for _, profile := range []string{"normal", "recon", "validation"} {
		b.Run(profile, func(b *testing.B) {
			fixture := make([]event.Event, 128)
			for i := range fixture {
				e := detectEvent(fmt.Sprint("event-", i), fmt.Sprint("request-", i), detectTestNow.Add(-50*time.Second+time.Duration(i)*250*time.Millisecond))
				e.PathHMAC = fmt.Sprint("path-", i)
				switch profile {
				case "recon":
					e.KnownRoute, e.Status = false, 404
				case "validation":
					e.Route = fmt.Sprint("/api/", i%4)
					e.DetectorFamily = []string{"schema", "type"}[(i/4)%2]
					e.Status = 400
				}
				fixture[i] = e
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				engine := New()
				for _, e := range fixture {
					if _, status := engine.Process(e, detectTestNow); status != "accepted" {
						b.Fatal(status)
					}
				}
			}
		})
	}
}

// Each batch retains non-benign history across all three windows. This exposes
// the cost of scanning old history for the shorter windows without storage I/O.
func BenchmarkProcessWindowAges(b *testing.B) {
	for _, age := range []time.Duration{0, 5 * time.Minute, 30 * time.Minute} {
		b.Run(age.String(), func(b *testing.B) {
			fixture := windowFixtureEvents("recon")
			for i := range fixture {
				fixture[i].EventTime = fixture[i].EventTime.Add(-age)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				engine := New()
				for _, e := range fixture {
					if _, status := engine.Process(e, detectTestNow); status != "accepted" {
						b.Fatal(status)
					}
				}
			}
		})
	}
}
