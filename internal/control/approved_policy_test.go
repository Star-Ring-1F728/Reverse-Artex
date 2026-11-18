package control

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"reverse-artex/internal/policy"
)

func exactCommand(t *testing.T, m *Manager) ApprovedPolicy {
	t.Helper()
	now := time.Now().UTC()
	e := specimen("approved-subject", "lab-app", now)
	if _, err := m.Evidence(e, now); err != nil {
		t.Fatal(err)
	}
	return ApprovedPolicy{Key: "exact-command", AdapterID: m.epoch, ApprovalSHA: strings.Repeat("a", 64), ProposalSHA: strings.Repeat("b", 64), EvidenceID: e.EventID, EvidenceSHA: hash(e), DispatchBefore: now.Add(5 * time.Second), Policy: policy.Policy{ID: "approved-exact-command", CaseID: "case-1", Tenant: e.TenantID, Asset: e.AssetID, Principal: e.Principal, Session: e.SessionHMAC, Route: e.Route, RuleVersion: "approved-session-route-1", Issued: now, Expires: now.Add(10 * time.Second)}}
}
func TestApprovedPolicyRejectsWideningDeadlineAndUnpersistedSubject(t *testing.T) {
	for _, mode := range []string{"tenant", "asset", "session", "route", "hash", "adapter", "expiry", "deadline", "subject"} {
		t.Run(mode, func(t *testing.T) {
			m := manager(t)
			a := exactCommand(t, m)
			switch mode {
			case "tenant":
				a.Policy.Tenant = "beta"
			case "asset":
				a.Policy.Asset = "other"
			case "session":
				a.Policy.Session = "other"
			case "route":
				a.Policy.Route = "/api/search"
			case "hash":
				a.EvidenceSHA = strings.Repeat("z", 64)
			case "adapter":
				a.AdapterID = "other"
			case "expiry":
				a.Policy.Expires = a.Policy.Expires.Add(time.Second)
			case "deadline":
				a.DispatchBefore = a.Policy.Issued.Add(-time.Second)
			case "subject":
				a.EvidenceID = "absent"
			}
			version := m.version
			if _, err := m.ApplyApprovedContext(context.Background(), a); err == nil || m.version != version || len(m.active) != 0 {
				t.Fatal("invalid lease admitted", err)
			}
		})
	}
}
func TestApprovedDeadlineRecheckedAfterWriterWaitAndStatusNeverWrites(t *testing.T) {
	m := manager(t)
	a := exactCommand(t, m)
	a.DispatchBefore = time.Now().Add(60 * time.Millisecond)
	m.mu.Lock()
	done := make(chan error, 1)
	go func() { _, err := m.ApplyApprovedContext(context.Background(), a); done <- err }()
	time.Sleep(90 * time.Millisecond)
	version := m.version
	m.mu.Unlock()
	if err := <-done; err == nil || m.version != version {
		t.Fatal("wait renewed deadline", err)
	}
	s, err := m.ApprovedStatusContext(context.Background(), a)
	if err != nil || s.State != "not_applied" || m.version != version {
		t.Fatal("status mutated", s, err)
	}
}
func TestApprovedHTTPReaderCannotWriteAndAmbiguousJSONRejected(t *testing.T) {
	m := manager(t)
	a := exactCommand(t, m)
	tokens := Tokens{Admin: strings.Repeat("a", 32), Reader: strings.Repeat("r", 32)}
	h := Handler(m, tokens)
	raw, _ := json.Marshal(a)
	for _, c := range []struct {
		path, token, body string
		status            int
	}{{"/v1/approved-policies", tokens.Reader, string(raw), 401}, {"/v1/approved-policies/status", tokens.Reader, string(raw), 200}, {"/v1/approved-policies", tokens.Admin, strings.TrimSuffix(string(raw), "}") + `,"idempotency_key":"other"}`, 400}} {
		r := httptest.NewRequest(http.MethodPost, c.path, strings.NewReader(c.body))
		r.Header.Set("Authorization", "Bearer "+c.token)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != c.status || len(m.active) != 0 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
}
