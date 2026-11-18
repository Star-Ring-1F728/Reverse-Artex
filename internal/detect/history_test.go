package detect

import (
	"reflect"
	"testing"
	"time"

	"reverse-artex/internal/event"
)

func TestLateEqualTimeEventsKeepRequestWitnessAndQuality(t *testing.T) {
	for _, mode := range []struct {
		name string
		new  func() *Engine
	}{{"session", New}, {"principal", NewPrincipal}} {
		for _, tc := range []struct {
			name    string
			order   []int
			witness string
			quality string
		}{
			{"chronological", []int{0, 1, 2, 3, 4}, "validation-first", "complete"},
			{"late-equal", []int{0, 1, 3, 2, 4}, "validation-first", "complete"},
			{"late-recon", []int{1, 3, 2, 0, 4}, "validation-first", "complete"},
			{"reversed-equal-arrival", []int{0, 2, 3, 1, 4}, "validation-second", "partial"},
		} {
			t.Run(mode.name+"/"+tc.name, func(t *testing.T) {
				recon := detectEvent("recon", "request-recon", detectTestNow.Add(-30*time.Second))
				recon.KnownRoute = false
				first := detectEvent("validation-first", "same-request", detectTestNow.Add(-20*time.Second))
				first.DetectorFamily = "json-schema"
				second := first
				second.EventID, second.DataQuality = "validation-second", "partial"
				noise := detectEvent("noise", "request-noise", detectTestNow.Add(-10*time.Second))
				denial := detectEvent("denial", "request-denial", detectTestNow.Add(-5*time.Second))
				denial.Authorization = "deny"
				fixtures := []event.Event{recon, first, second, noise, denial}
				var arrival []event.Event
				for _, i := range tc.order {
					arrival = append(arrival, fixtures[i])
				}
				alert := requireOnlyAlert(t, processAccepted(t, mode.new(), arrival), "RA-003", "medium")
				want := []string{"recon", tc.witness, "denial"}
				if !reflect.DeepEqual(alert.Evidence, want) {
					t.Fatalf("evidence = %v, want %v", alert.Evidence, want)
				}
				if alert.DataQuality != tc.quality {
					t.Fatalf("quality = %q, want %q", alert.DataQuality, tc.quality)
				}
			})
		}
	}
}
