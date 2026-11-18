package detect

import (
	"fmt"
	"testing"
	"time"

	"reverse-artex/internal/event"
)

var detectTestNow = time.Date(2025, time.January, 2, 3, 4, 5, 0, time.UTC)

func detectEvent(eventID, requestID string, eventTime time.Time) event.Event {
	return event.Event{
		SchemaVersion: "1.0",
		EventID:       eventID,
		EventTime:     eventTime,
		IngestTime:    detectTestNow,
		SensorID:      "sensor-a",
		TenantID:      "tenant-a",
		AssetID:       "asset-a",
		EventType:     "http",
		RequestID:     requestID,
		Method:        "GET",
		Route:         "/api/{id}",
		Status:        200,
		Principal:     "user-a",
		SessionHMAC:   "session-a",
		Identity:      "authenticated",
		Authorization: "allow",
		KnownRoute:    true,
		UAHint:        "none",
		DataQuality:   "complete",
	}
}

func detectEventAt(eventID, requestID string, minutesBeforeNow int) event.Event {
	return detectEvent(eventID, requestID, detectTestNow.Add(-time.Duration(minutesBeforeNow)*time.Minute))
}

func processAccepted(t *testing.T, engine *Engine, events []event.Event) []Alert {
	t.Helper()
	var alerts []Alert
	for _, e := range events {
		out, status := engine.Process(e, detectTestNow)
		if status != "accepted" {
			t.Fatalf("Process(%q) status = %q, want accepted", e.EventID, status)
		}
		alerts = append(alerts, out...)
	}
	return alerts
}

func requireOnlyAlert(t *testing.T, alerts []Alert, rule, confidence string) Alert {
	t.Helper()
	if len(alerts) != 1 {
		t.Fatalf("got %d alerts (%+v), want exactly one %s alert", len(alerts), alerts, rule)
	}
	a := alerts[0]
	if a.RuleID != rule {
		t.Fatalf("alert rule = %q, want %q", a.RuleID, rule)
	}
	if a.Mode != "observe" {
		t.Errorf("alert mode = %q, want observe", a.Mode)
	}
	if a.Confidence != confidence {
		t.Errorf("alert confidence = %q, want %q", a.Confidence, confidence)
	}
	return a
}

func TestRA001UAAloneIsInformationalObserve(t *testing.T) {
	e := detectEventAt("ua-event", "ua-request", 1)
	e.UAHint = "norma-unverified"

	alerts := processAccepted(t, New(), []event.Event{e})
	a := requireOnlyAlert(t, alerts, "RA-001", "informational")
	if a.Mode != "observe" {
		t.Fatalf("UA-only alert mode = %q, want observe", a.Mode)
	}
	if len(a.Families) != 1 || a.Families[0] != "ua" {
		t.Errorf("UA-only evidence families = %v, want [ua]", a.Families)
	}
}

func TestRA002PathErrorsAndUnknownRoutesWithoutUA(t *testing.T) {
	var events []event.Event
	for i := 0; i < 8; i++ {
		e := detectEventAt(fmt.Sprintf("ra002-event-%d", i), fmt.Sprintf("ra002-request-%d", i), 8-i)
		e.PathHMAC = fmt.Sprintf("path-%d", i)
		e.UAHint = "none"
		if i < 6 {
			e.Status = 500
		}
		if i < 4 {
			e.KnownRoute = false
		}
		events = append(events, e)
	}

	alerts := processAccepted(t, New(), events)
	a := requireOnlyAlert(t, alerts, "RA-002", "medium")
	for _, e := range events {
		if e.UAHint != "none" {
			t.Fatalf("test event %q unexpectedly has a UA hint", e.EventID)
		}
	}
	if len(a.Families) != 3 {
		t.Errorf("RA-002 evidence families = %v, want three independent families", a.Families)
	}
}

func TestRA003UsesChronologicalReconValidationDenyOrder(t *testing.T) {
	recon := detectEventAt("recon", "recon-request", 3)
	recon.KnownRoute = false
	recon.Status = 404

	validation := detectEventAt("validation", "validation-request", 2)
	validation.DetectorFamily = "json-schema"
	validation.Status = 400

	denial := detectEventAt("denial", "denial-request", 1)
	denial.Authorization = "deny"
	denial.ResourceHMAC = "resource-a"

	// Ingest order differs from event-time order; the chain should follow time.
	alerts := processAccepted(t, New(), []event.Event{denial, validation, recon})
	a := requireOnlyAlert(t, alerts, "RA-003", "medium")
	wantEvidence := []string{"recon", "validation", "denial"}
	if len(a.Evidence) != len(wantEvidence) {
		t.Fatalf("RA-003 evidence = %v, want %v", a.Evidence, wantEvidence)
	}
	for i := range wantEvidence {
		if a.Evidence[i] != wantEvidence[i] {
			t.Errorf("RA-003 evidence[%d] = %q, want %q", i, a.Evidence[i], wantEvidence[i])
		}
	}
}

func TestRA004FourVerifiedDenialsAcrossThreeResources(t *testing.T) {
	var events []event.Event
	resources := []string{"resource-a", "resource-b", "resource-c", "resource-a"}
	for i, resource := range resources {
		e := detectEventAt(fmt.Sprintf("ra004-event-%d", i), fmt.Sprintf("ra004-request-%d", i), 4-i)
		e.Authorization = "deny"
		e.ResourceHMAC = resource
		e.Identity = "authenticated"
		e.Principal = "verified-user"
		e.SessionHMAC = "verified-session"
		events = append(events, e)
	}

	alerts := processAccepted(t, New(), events)
	a := requireOnlyAlert(t, alerts, "RA-004", "medium")
	if a.Subject != "verified-user:verified-session" {
		t.Errorf("RA-004 subject = %q, want the authenticated principal/session", a.Subject)
	}
}

func TestDuplicateEventDoesNotEmitAnotherAlert(t *testing.T) {
	e := detectEventAt("same-event", "same-request", 1)
	e.UAHint = "enrich"
	engine := New()

	first, status := engine.Process(e, detectTestNow)
	if status != "accepted" {
		t.Fatalf("first Process status = %q, want accepted", status)
	}
	requireOnlyAlert(t, first, "RA-001", "informational")

	second, status := engine.Process(e, detectTestNow)
	if status != "duplicate" {
		t.Errorf("replayed event status = %q, want duplicate", status)
	}
	if len(second) != 0 {
		t.Errorf("replayed event emitted alerts: %+v", second)
	}
}

func TestDifferentEventsForSameRequestAreScoredOnce(t *testing.T) {
	var events []event.Event
	for request := 0; request < 4; request++ {
		for feed := 0; feed < 2; feed++ {
			e := detectEventAt(
				fmt.Sprintf("same-request-%d-feed-%d", request, feed),
				fmt.Sprintf("request-%d", request),
				8-(request*2+feed),
			)
			e.PathHMAC = fmt.Sprintf("path-%d-%d", request, feed)
			e.Status = 500
			e.KnownRoute = false
			events = append(events, e)
		}
	}

	alerts := processAccepted(t, New(), events)
	if len(alerts) != 0 {
		t.Fatalf("duplicate feed events for four requests produced alerts: %+v", alerts)
	}
}

func TestRA004CorrelationIsSeparatedByTenantAndSession(t *testing.T) {
	t.Run("tenant", func(t *testing.T) {
		var events []event.Event
		for i, tenant := range []string{"tenant-a", "tenant-a", "tenant-b", "tenant-b"} {
			e := detectEventAt(fmt.Sprintf("tenant-event-%d", i), fmt.Sprintf("tenant-request-%d", i), 4-i)
			e.TenantID = tenant
			e.Authorization = "deny"
			e.ResourceHMAC = []string{"resource-a", "resource-b", "resource-c", "resource-a"}[i]
			events = append(events, e)
		}
		alerts := processAccepted(t, New(), events)
		if len(alerts) != 0 {
			t.Fatalf("RA-004 crossed tenant boundaries: %+v", alerts)
		}
	})

	t.Run("session", func(t *testing.T) {
		var events []event.Event
		for i, session := range []string{"session-a", "session-a", "session-b", "session-b"} {
			e := detectEventAt(fmt.Sprintf("session-event-%d", i), fmt.Sprintf("session-request-%d", i), 4-i)
			e.SessionHMAC = session
			e.Authorization = "deny"
			e.ResourceHMAC = []string{"resource-a", "resource-b", "resource-c", "resource-a"}[i]
			events = append(events, e)
		}
		alerts := processAccepted(t, New(), events)
		if len(alerts) != 0 {
			t.Fatalf("RA-004 crossed session boundaries: %+v", alerts)
		}
	})
}

func TestAnonymousDenialsCannotProduceRA004(t *testing.T) {
	var events []event.Event
	resources := []string{"resource-a", "resource-b", "resource-c", "resource-a"}
	for i, resource := range resources {
		e := detectEventAt(fmt.Sprintf("anonymous-event-%d", i), fmt.Sprintf("anonymous-request-%d", i), 4-i)
		e.Identity = "anonymous"
		e.Principal = ""
		e.SessionHMAC = ""
		e.Authorization = "deny"
		e.ResourceHMAC = resource
		events = append(events, e)
	}

	alerts := processAccepted(t, New(), events)
	for _, a := range alerts {
		if a.RuleID == "RA-004" {
			t.Fatalf("anonymous events emitted RA-004: %+v", a)
		}
	}
}

func TestCapacityRejectionIsExplicit(t *testing.T) {
	t.Run("event-limit", func(t *testing.T) {
		engine := New()
		engine.MaxEvents = 1
		first := detectEventAt("event-limit-first", "event-limit-request-1", 2)
		if alerts, status := engine.Process(first, detectTestNow); status != "accepted" || len(alerts) != 0 {
			t.Fatalf("first event: status=%q alerts=%+v, want accepted with no alert", status, alerts)
		}
		second := detectEventAt("event-limit-second", "event-limit-request-2", 1)
		if alerts, status := engine.Process(second, detectTestNow); status != "capacity_rejected" || len(alerts) != 0 {
			t.Errorf("second event: status=%q alerts=%+v, want explicit capacity_rejected with no alert", status, alerts)
		}
	})

	t.Run("subject-limit", func(t *testing.T) {
		engine := New()
		engine.MaxSubjects = 1
		first := detectEventAt("subject-limit-first", "subject-limit-request-1", 2)
		if alerts, status := engine.Process(first, detectTestNow); status != "accepted" || len(alerts) != 0 {
			t.Fatalf("first subject: status=%q alerts=%+v, want accepted with no alert", status, alerts)
		}
		second := detectEventAt("subject-limit-second", "subject-limit-request-2", 1)
		second.SessionHMAC = "different-session"
		if alerts, status := engine.Process(second, detectTestNow); status != "capacity_rejected" || len(alerts) != 0 {
			t.Errorf("second subject: status=%q alerts=%+v, want explicit capacity_rejected with no alert", status, alerts)
		}
	})
}

func TestRA005RequiresFourFailuresAndTwoFamiliesOnSameRoute(t *testing.T) {
	t.Run("same-route", func(t *testing.T) {
		var events []event.Event
		families := []string{"json-schema", "json-schema", "type-check", "type-check"}
		for i, family := range families {
			e := detectEventAt(fmt.Sprintf("ra005-same-route-%d", i), fmt.Sprintf("ra005-same-request-%d", i), 1)
			e.EventTime = detectTestNow.Add(-time.Duration(i+1) * 10 * time.Second)
			e.DetectorFamily = family
			e.Route = "/api/{id}"
			events = append(events, e)
		}

		alerts := processAccepted(t, New(), events)
		a := requireOnlyAlert(t, alerts, "RA-005", "medium")
		if a.Window != time.Minute.String() {
			t.Errorf("RA-005 window = %q, want %q", a.Window, time.Minute.String())
		}
	})

	t.Run("split-across-routes", func(t *testing.T) {
		var events []event.Event
		families := []string{"json-schema", "type-check", "json-schema", "type-check"}
		routes := []string{"/api/{id}", "/api/{id}", "/api/{other}", "/api/{other}"}
		for i, family := range families {
			e := detectEventAt(fmt.Sprintf("ra005-split-route-%d", i), fmt.Sprintf("ra005-split-request-%d", i), 1)
			e.EventTime = detectTestNow.Add(-time.Duration(i+1) * 10 * time.Second)
			e.DetectorFamily = family
			e.Route = routes[i]
			events = append(events, e)
		}

		alerts := processAccepted(t, New(), events)
		for _, a := range alerts {
			if a.RuleID == "RA-005" {
				t.Fatalf("validation failures split across routes emitted RA-005: %+v", a)
			}
		}
	})
}

func durationsOf(unit time.Duration, values ...int) []time.Duration {
	offsets := make([]time.Duration, len(values))
	for i, value := range values {
		offsets[i] = time.Duration(value) * unit
	}
	return offsets
}

func TestRA002EmitsOneAlertForTheNarrowestMatchingWindow(t *testing.T) {
	cases := []struct {
		name       string
		offsets    []time.Duration
		wantWindow string
	}{
		{
			name:       "one-minute",
			offsets:    durationsOf(time.Second, 5, 10, 15, 20, 25, 30, 35, 40),
			wantWindow: time.Minute.String(),
		},
		{
			name:       "ten-minute",
			offsets:    durationsOf(time.Second, 70, 140, 210, 280, 350, 420, 490, 560),
			wantWindow: (10 * time.Minute).String(),
		},
		{
			name:       "one-hour",
			offsets:    durationsOf(time.Minute, 8, 16, 24, 32, 40, 48, 56, 59),
			wantWindow: time.Hour.String(),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var events []event.Event
			for i, offset := range tc.offsets {
				e := detectEvent(
					fmt.Sprintf("ra002-%s-%d", tc.name, i),
					fmt.Sprintf("ra002-%s-request-%d", tc.name, i),
					detectTestNow.Add(-offset),
				)
				e.PathHMAC = fmt.Sprintf("ra002-%s-path-%d", tc.name, i)
				e.Status = 500
				e.KnownRoute = false
				events = append(events, e)
			}

			alerts := processAccepted(t, New(), events)
			a := requireOnlyAlert(t, alerts, "RA-002", "medium")
			if a.Window != tc.wantWindow {
				t.Errorf("RA-002 window = %q, want %q", a.Window, tc.wantWindow)
			}
		})
	}
}

func TestEvaluabilityForReportsUnknownAuthorizationResourceAndLinuxTelemetry(t *testing.T) {
	e := detectEventAt("evaluability-event", "evaluability-request", 1)
	e.Authorization = "unknown"
	e.ResourceHMAC = ""
	e.Identity = "anonymous"
	e.Principal = ""
	e.SessionHMAC = ""
	e.DetectorFamily = "unknown"

	got := EvaluabilityFor(e)
	want := map[string]string{
		"RA-003": "not_evaluable_missing_authorization_or_validation",
		"RA-004": "not_evaluable_missing_verified_resource_authorization",
		"RA-005": "not_evaluable_missing_validation",
		"RA-006": "not_evaluable_no_linux_sensor",
	}
	for rule, expected := range want {
		if got[rule] != expected {
			t.Errorf("EvaluabilityFor(%s) = %q, want %q", rule, got[rule], expected)
		}
	}
}
