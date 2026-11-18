package control

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRecentEvidenceCapacityIsRetryableButAuditFailureIsPermanent(t *testing.T) {
	m := manager(t)
	now := time.Now().UTC()
	// Fill the bounded in-memory window without doing16,384 disk writes.
	for n := range 16384 {
		e := specimen(fmt.Sprint("cached-", n), "lab-app", now)
		m.retainEvidence(e)
	}
	token := strings.Repeat("e", 32)
	h := Handler(m, Tokens{Evidence: token})
	post := func(id string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(specimen(id, "lab-app", time.Now().UTC()))
		r := httptest.NewRequest(http.MethodPost, "/v1/evidence", bytes.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	version := m.version
	w := post("waiting")
	if w.Code != 429 || w.Header().Get("Retry-After") != "1" || w.Header().Get("X-RA-Delivery-Permanent") != "" || m.version != version {
		t.Fatal("temporary capacity stopped durable delivery permanently", w.Code, w.Header())
	}
	// Deterministic aging, not a one-minute sleep or a larger memory window.
	// Shift every fixture deadline equally so the heap ordering stays valid;
	// the HTTP call must still perform the actual expiration and recovery.
	for i := range m.evidenceExpiry {
		entry := &m.evidenceExpiry[i]
		entry.at = entry.at.Add(-2 * time.Minute)
		e := m.events[entry.id]
		e.EventTime = entry.at
		m.events[entry.id] = e
	}
	w = post("waiting")
	if w.Code != 202 || len(m.events) != 1 || m.version != version+1 {
		t.Fatal("capacity did not recover", w.Code, m.version)
	}
	m.Budget = 1
	w = post("audit-full")
	if w.Code != 503 || w.Header().Get("X-RA-Delivery-Permanent") != "1" || m.version != version+1 {
		t.Fatal("audit failure became retryable or committed", w.Code, w.Header())
	}
}
