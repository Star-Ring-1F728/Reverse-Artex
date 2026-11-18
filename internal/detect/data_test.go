package detect

import (
	"reverse-artex/internal/event"
	"testing"
)

func TestExportBudgetAlertRequiresPreResponseAccountEvidence(t *testing.T) {
	e := detectEvent("budget", "budget", detectTestNow)
	e.Route = "/api/export"
	e.Status = 429
	e.Authorization = "deny"
	e.Budget = &event.Budget{Decision: "deny", Measurement: "exact", RequestedRows: 1, RequestedBytes: 20, UsedRows: 2, UsedBytes: 40, LimitRows: 2, LimitBytes: 100, WindowSeconds: 60, PreResponse: true}
	a := requireOnlyAlert(t, processAccepted(t, New(), []event.Event{e}), "RA-007", "medium")
	if a.Version != "1.0" || len(a.Evidence) != 1 {
		t.Fatal(a)
	}
	for _, variant := range []string{"partial", "anonymous", "not-preflight", "allow"} {
		x := e
		b := *e.Budget
		x.Budget = &b
		switch variant {
		case "partial":
			x.DataQuality = "partial"
		case "anonymous":
			x.Identity = "anonymous"
		case "not-preflight":
			x.Budget.PreResponse = false
		case "allow":
			x.Budget.Decision = "allow"
			x.Budget.RequestedRows = 0
			x.Budget.RequestedBytes = 0
		}
		for _, a := range processAccepted(t, New(), []event.Event{x}) {
			if a.RuleID == "RA-007" {
				t.Fatal("unverified data budget alert", variant)
			}
		}
	}
}
func TestCanaryRequiresConfigurationAndKeepsAnonymousWeak(t *testing.T) {
	e := detectEvent("canary", "canary", detectTestNow)
	e.CanaryID = "private-fixture"
	e.Route = "/internal/canary/{id}"
	e.ResourceClass = "canary"
	e.Authorization = "deny"
	e.Status = 404
	e.Identity = "anonymous"
	e.Principal, e.SessionHMAC = "", ""
	if a := processAccepted(t, New(), []event.Event{e}); len(a) != 0 {
		t.Fatal("unconfigured canary", a)
	}
	d := New()
	d.Canaries = map[string]bool{"private-fixture": true}
	a := requireOnlyAlert(t, processAccepted(t, d, []event.Event{e}), "RA-008", "medium")
	if a.CorrelationScope != "asset" || a.Principal != "" {
		t.Fatal("canary attributed an anonymous actor", a)
	}
	if EvaluabilityFor(detectEvent("plain", "plain", detectTestNow))["RA-007"] == "evaluable" {
		t.Fatal("invented export telemetry")
	}
}
