package detect

import (
	"fmt"
	"reverse-artex/internal/event"
	"testing"
	"time"
)

func TestRA003RequiresThreeStrictlyOrderedRequests(t *testing.T) {
	for _, mode := range []string{"single", "two", "equal-time"} {
		t.Run(mode, func(t *testing.T) {
			recon := detectEvent("r", "req-r", detectTestNow.Add(-3*time.Second))
			recon.KnownRoute = false
			validation := detectEvent("v", "req-v", detectTestNow.Add(-2*time.Second))
			validation.DetectorFamily = "schema-type"
			deny := detectEvent("d", "req-d", detectTestNow.Add(-time.Second))
			deny.Authorization = "deny"
			es := []event.Event{recon, validation, deny}
			switch mode {
			case "single":
				recon.DetectorFamily, recon.Authorization = "schema-type", "deny"
				es = []event.Event{recon}
			case "two":
				validation.Authorization = "deny"
				es = []event.Event{recon, validation}
			case "equal-time":
				for i := range es {
					es[i].EventTime = detectTestNow
				}
			}
			for _, a := range processAccepted(t, New(), es) {
				if a.RuleID == "RA-003" {
					t.Fatalf("ambiguous chain emitted: %+v", a)
				}
			}
		})
	}
}

func TestRA005UnknownRouteIsNotACommonEndpoint(t *testing.T) {
	d := New()
	for i := 0; i < 4; i++ {
		e := detectEvent(fmt.Sprint(i), fmt.Sprint(i), detectTestNow.Add(time.Duration(i-4)*time.Second))
		e.Route, e.KnownRoute = "/unknown", false
		e.PathHMAC, e.DetectorFamily = fmt.Sprint("path-", i), fmt.Sprint("family-", i%2)
		for _, a := range processAccepted(t, d, []event.Event{e}) {
			if a.RuleID == "RA-005" {
				t.Fatal("unrelated unknown paths merged")
			}
		}
		if EvaluabilityFor(e)["RA-005"] == "evaluable" {
			t.Fatal("missing route classification hidden")
		}
	}
}

func TestAlertEvidenceRetainsThresholdWitnesses(t *testing.T) {
	// Four violations with a long unrelated interlude must reference only the
	// classified endpoint and preserve the minority validation family.
	d := New()
	all := map[string]event.Event{}
	var alerts []Alert
	for i := 0; i < 60; i++ {
		e := detectEvent(fmt.Sprint(i), fmt.Sprint(i), detectTestNow.Add(time.Duration(i-60)*time.Second))
		e.PathHMAC = fmt.Sprint("path-", i)
		if i < 3 || i == 59 {
			e.Route, e.DetectorFamily = "/api/search", "schema-type"
			if i == 0 {
				e.DetectorFamily = "schema-method"
			}
		} else {
			e.Route = "/api/export"
		}
		all[e.EventID] = e
		alerts = append(alerts, processAccepted(t, d, []event.Event{e})...)
	}
	a := requireOnlyAlert(t, alerts, "RA-005", "medium")
	families := map[string]bool{}
	for _, id := range a.Evidence {
		e := all[id]
		if e.Route != "/api/search" || e.DetectorFamily == "" {
			t.Fatal("unrelated evidence")
		}
		families[e.DetectorFamily] = true
	}
	if len(a.Evidence) != 4 || len(families) != 2 {
		t.Fatalf("lost threshold proof: %+v", a)
	}
}
