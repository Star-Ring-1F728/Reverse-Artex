package detect

import (
	"reverse-artex/internal/event"
	"testing"
)

func TestApprovedExportsRetainDistinctEvidenceWithoutBudgetDenialAlert(t *testing.T) {
	e := detectEvent("approved-1", "same-export-path", detectTestNow)
	e.SensorID, e.AssetID, e.Method, e.Route = "lab-app", "lab-api", "GET", "/api/export"
	e.Status, e.Bytes, e.Authorization, e.Reason = 200, 19, "allow", "export-approval"
	e.DetectorFamily = ""
	e.ExportApproval = &event.ExportApproval{Schema: "export-approval/1", ApprovalID: "0123456789abcdef0123456789abcdef",
		JobID: "report", IssuedAt: detectTestNow.Unix() - 10, ExpiresAt: detectTestNow.Unix() + 50,
		ConsumedAt: detectTestNow.Unix(), LimitRows: 10, LimitBytes: 4096, Rows: 1, Bytes: 19,
		SingleUse: true, PreResponse: true}
	if err := e.Validate(detectTestNow); err != nil {
		t.Fatal(err)
	}
	second := e
	second.EventID, second.RequestID = "approved-2", "approved-request-2"
	a := *e.ExportApproval
	a.ApprovalID, a.JobID = "1123456789abcdef0123456789abcdef", "report2"
	second.ExportApproval = &a
	d := New()
	if alerts := processAccepted(t, d, []event.Event{e, second}); len(alerts) != 0 {
		t.Fatal("approved return invented a denial alert", alerts)
	}
	if d.Stats()["history_events"] != 2 {
		t.Fatal("separate approved returns compacted into one benign observation")
	}
}
