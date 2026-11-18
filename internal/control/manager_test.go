package control

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reverse-artex/internal/event"
	"strings"
	"testing"
	"time"
)

func specimen(id, sensor string, now time.Time) event.Event {
	return event.Event{SchemaVersion: "1.0", EventID: id, RequestID: "r-" + id, EventTime: now, IngestTime: now, SensorID: sensor, TenantID: "alpha", AssetID: "lab-api", EventType: "http", Method: "GET", Route: "/api/objects/{id}", Status: 200, Principal: "alice", SessionHMAC: "session-a", Identity: "authenticated", Authorization: "allow", KnownRoute: true, UAHint: "none", DataQuality: "complete"}
}
func approval(key, id string) Approve {
	return Approve{Key: key, CaseID: "case-1", EvidenceID: id, Route: "/api/objects/{id}", TTL: 10, Reason: "experiment"}
}
func manager(t *testing.T) *Manager {
	t.Helper()
	m, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return m
}
func TestDurableRevokeRollbackExpiryAndIdempotency(t *testing.T) {
	m := manager(t)
	now := time.Now().UTC()
	e := specimen("e1", "lab-app", now)
	if _, err := m.Evidence(e, now); err != nil {
		t.Fatal(err)
	}
	r, err := m.Approve(approval("approve-1", e.EventID), now)
	if err != nil {
		t.Fatal(err)
	}
	duplicate, err := m.Approve(approval("approve-1", e.EventID), now.Add(time.Second))
	if err != nil || duplicate.Version != r.Version {
		t.Fatal("idempotency failed", err)
	}
	changed := approval("approve-1", e.EventID)
	changed.TTL = 9
	if _, err := m.Approve(changed, now); err == nil {
		t.Fatal("changed command key accepted")
	}
	if _, err := m.Revoke(Revoke{"revoke-1", r.PolicyID, "false_positive"}, now); err != nil {
		t.Fatal(err)
	}
	restored, err := Open(m.dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(restored.active) != 0 {
		t.Fatal("revoke not persisted")
	}
	if _, err = restored.Approve(approval("approve-1", e.EventID), now); err != nil || len(restored.active) != 0 {
		t.Fatal("replayed command resurrected revoke")
	}
	_, _ = m.Evidence(specimen("e2", "lab-app", now), now)
	checkpoint := m.version
	r2, err := m.Approve(approval("approve-2", "e2"), now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.Rollback(Rollback{"rollback-1", checkpoint, "rollback"}, now); err != nil {
		t.Fatal(err)
	}
	if len(m.active) != 0 || m.auto {
		t.Fatal("rollback did not release policies/disable auto")
	}
	if _, err = m.Approve(approval("approve-2", "e2"), now); err != nil || len(m.active) != 0 {
		t.Fatal("rollback replay resurrected policy", r2)
	}
	_, _ = m.Evidence(specimen("e3", "lab-app", now), now)
	if _, err = m.Approve(approval("approve-3", "e3"), now); err != nil {
		t.Fatal(err)
	}
	if _, err = m.Snapshot(now.Add(11*time.Second), []byte(strings.Repeat("s", 32))); err != nil {
		t.Fatal(err)
	}
	restored, err = Open(m.dir)
	if err != nil || len(restored.active) != 0 {
		t.Fatal("expired policy resurrected on restart", err)
	}
}
func TestAuditFailureDoesNotCommitAndBadTailFailsClosed(t *testing.T) {
	m := manager(t)
	now := time.Now().UTC()
	_, _ = m.Evidence(specimen("e1", "lab-app", now), now)
	version := m.version
	m.Budget = 1
	if _, err := m.Approve(approval("a", "e1"), now); err == nil || m.version != version || len(m.active) != 0 {
		t.Fatal("unaudited command committed")
	}
	f, err := os.OpenFile(filepath.Join(m.dir, "actions.jsonl"), os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("{bad-tail")
	f.Close()
	if _, err = Open(m.dir); err == nil {
		t.Fatal("corrupt audit tail accepted")
	}
}

func TestAuditMissingFinalNewlineFailsClosed(t *testing.T) {
	m := manager(t)
	path := filepath.Join(m.dir, "actions.jsonl")
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// A complete JSON object with a lost delimiter must not become the prefix
	// of the next committed record on restart.
	truncated := contents[:len(contents)-1]
	if err := os.WriteFile(path, truncated, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(m.dir); err == nil {
		t.Fatal("unterminated audit record accepted")
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != string(truncated) {
		t.Fatal("failed recovery changed the audit evidence", err)
	}
}

func TestAutoRequiresIndependentQualityAndExplicitOptIn(t *testing.T) {
	now := time.Now().UTC()
	m := manager(t)
	es := []event.Event{}
	for _, id := range []string{"w1", "w2"} {
		e := specimen(id, "lab-waf", now)
		e.Status = 403
		e.Authorization = "unknown"
		e.DetectorFamily = "waf-local-denial"
		es = append(es, e)
	}
	for _, id := range []string{"a1", "a2"} {
		e := specimen(id, "lab-app", now)
		e.Status = 403
		e.Authorization = "deny"
		e.ResourceHMAC = "object-" + id
		es = append(es, e)
	}
	for _, e := range es {
		if r, err := m.Evidence(e, now); err != nil || r != nil {
			t.Fatal("observe created action")
		}
	}
	if _, err := m.SetAuto("enable-auto", true, now); err != nil {
		t.Fatal(err)
	}
	trigger := specimen("trigger", "lab-app", now)
	trigger.Status = 403
	trigger.Authorization = "deny"
	trigger.ResourceHMAC = "object-trigger"
	r, err := m.Evidence(trigger, now)
	if err != nil || r == nil || r.Operation != "auto-deny" || len(m.active) != 1 {
		t.Fatal("eligible evidence did not create action", err)
	}
	for _, p := range m.active {
		if p.Route != "/api/objects/{id}" || p.Expires.Sub(p.Issued) != time.Minute || p.Principal != "alice" {
			t.Fatal("unsafe automatic scope")
		}
	}
	version := m.version
	_, _ = m.Evidence(trigger, now)
	if m.version != version {
		t.Fatal("duplicate action")
	}
	// UA/IP alone, anonymous/partial telemetry, and overlapping requests cannot qualify.
	for _, variant := range []string{"anonymous", "partial", "shared-request", "single-family"} {
		x := manager(t)
		_, _ = x.SetAuto("enable", true, now)
		for _, orig := range es {
			e := orig
			switch variant {
			case "anonymous":
				e.Identity = "anonymous"
				e.Principal = ""
				e.SessionHMAC = ""
			case "partial":
				e.DataQuality = "partial"
			case "shared-request":
				e.RequestID = "same-request"
			case "single-family":
				e.SensorID = "lab-waf"
				e.Authorization = "unknown"
				e.DetectorFamily = "waf-local-denial"
			}
			e.UAHint = "enrich"
			_, _ = x.Evidence(e, now)
		}
		if len(x.active) != 0 {
			t.Fatalf("unsafe auto action for %s", variant)
		}
	}
}

func TestEvidenceReceiptAndAutoDecisionSurviveRestart(t *testing.T) {
	now := time.Now().UTC()
	m := manager(t)
	first := specimen("durable-first", "lab-app", now)
	if _, err := m.Evidence(first, now); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(m.dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.Approve(approval("approved-after-restart", first.EventID), now); err != nil {
		t.Fatal("accepted evidence was lost on restart", err)
	}
	changed := first
	changed.RequestID = "changed"
	if _, err := reopened.Evidence(changed, now); err == nil {
		t.Fatal("conflicting event ID accepted")
	}
	if _, err := reopened.SetAuto("enable-durable", true, now); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"w1", "w2"} {
		e := specimen(id, "lab-waf", now)
		e.Status, e.Authorization, e.DetectorFamily = 403, "unknown", "waf-local-denial"
		if _, err := reopened.Evidence(e, now); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []string{"a1", "a2"} {
		e := specimen(id, "lab-app", now)
		e.Status, e.Authorization, e.ResourceHMAC = 403, "deny", "resource-"+id
		if _, err := reopened.Evidence(e, now); err != nil {
			t.Fatal(err)
		}
	}
	if len(reopened.active) != 2 {
		t.Fatal("expected one manual and one automatic policy")
	}
	version := reopened.version
	reopened, err = Open(m.dir)
	if err != nil {
		t.Fatal(err)
	}
	duplicate := specimen("a2", "lab-app", now)
	duplicate.Status, duplicate.Authorization, duplicate.ResourceHMAC = 403, "deny", "resource-a2"
	if _, err := reopened.Evidence(duplicate, now); err != nil || reopened.version != version || len(reopened.active) != 2 {
		t.Fatal("lost 202 response created duplicate action", err)
	}
}

func TestEvidenceIDReuseAfterWindowReplaysConsistently(t *testing.T) {
	m := manager(t)
	now := time.Now().UTC()
	old := specimen("reused", "lab-app", now.Add(-2*time.Minute))
	if _, err := m.Evidence(old, old.EventTime); err != nil {
		t.Fatal(err)
	}
	fresh := specimen("reused", "lab-app", now)
	fresh.RequestID = "new-request"
	if _, err := m.Evidence(fresh, now); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(m.dir)
	if err != nil || reopened.events["reused"].RequestID != fresh.RequestID {
		t.Fatal("replayed inbox changed window semantics", err)
	}
}

func TestAutomaticEvidenceAndActionFailTogether(t *testing.T) {
	m := manager(t)
	now := time.Now().UTC()
	if _, err := m.SetAuto("enable-atomic", true, now); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"w1", "w2"} {
		e := specimen(id, "lab-waf", now)
		e.Status, e.Authorization, e.DetectorFamily = 403, "unknown", "waf-local-denial"
		if _, err := m.Evidence(e, now); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []string{"a1", "a2"} {
		e := specimen(id, "lab-app", now)
		e.Status, e.Authorization, e.ResourceHMAC = 403, "deny", "resource-"+id
		if id == "a2" {
			st, err := os.Stat(filepath.Join(m.dir, "actions.jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			m.Budget = st.Size() + 1
			if _, err := m.Evidence(e, now); err == nil || len(m.active) != 0 || m.events[e.EventID].EventID != "" {
				t.Fatal("failed policy audit consumed evidence", err)
			}
			m.Budget = defaultAuditBudget
			m, err = Open(m.dir)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := m.Evidence(e, now); err != nil || len(m.active) != 1 {
				t.Fatal("retry after recovery did not commit once", err)
			}
			continue
		}
		if _, err := m.Evidence(e, now); err != nil {
			t.Fatal(err)
		}
	}
}
func TestHTTPRoleSeparation(t *testing.T) {
	m := manager(t)
	tokens := Tokens{Admin: strings.Repeat("a", 32), Reader: strings.Repeat("r", 32), Evidence: strings.Repeat("e", 32), SnapshotKey: []byte(strings.Repeat("s", 32))}
	h := Handler(m, tokens)
	for _, tc := range []struct {
		method, path, key, body string
		want                    int
	}{{"POST", "/v1/policies", tokens.Reader, `{}`, 401}, {"POST", "/v1/policies", tokens.Evidence, `{}`, 401}, {"GET", "/v1/snapshot", tokens.Admin, "", 401}, {"GET", "/v1/snapshot", tokens.Reader, "", 200}, {"POST", "/v1/policies", tokens.Admin, `{"ttl_seconds":3600}`, 400}, {"POST", "/v1/auto", tokens.Admin, `{"idempotency_key":"k","enabled":true,"shell":"untrusted"}`, 400}} {
		r := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
		r.Header.Set("Authorization", "Bearer "+tc.key)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Fatalf("%s got %d want %d", tc.path, w.Code, tc.want)
		}
	}
	e := specimen("http-e", "lab-app", time.Now().UTC())
	b, _ := json.Marshal(e)
	r := httptest.NewRequest("POST", "/v1/evidence", strings.NewReader(string(b)))
	r.Header.Set("Authorization", "Bearer "+tokens.Evidence)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 202 {
		t.Fatal("valid evidence rejected", w.Code)
	}
}
