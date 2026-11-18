package control

import (
	"fmt"
	"os"
	"reverse-artex/internal/event"
	"testing"
	"time"
)

func assertEvidenceIndexes(t *testing.T, m *Manager) {
	t.Helper()
	if len(m.events) != len(m.evidenceExpiry) {
		t.Fatalf("heap=%d events=%d", len(m.evidenceExpiry), len(m.events))
	}
	seen := map[string]bool{}
	for i, entry := range m.evidenceExpiry {
		e, ok := m.events[entry.id]
		if !ok || seen[entry.id] || !e.EventTime.Equal(entry.at) {
			t.Fatal("invalid heap entry", entry)
		}
		seen[entry.id] = true
		if i > 0 && m.evidenceExpiry.Less(i, (i-1)/2) {
			t.Fatal("broken expiry heap")
		}
	}
	count := 0
	for scope, ids := range m.evidenceScopes {
		if len(ids) == 0 {
			t.Fatal("empty retained scope")
		}
		for id := range ids {
			e, ok := m.events[id]
			if !ok || scopeOf(e) != scope {
				t.Fatal("invalid scope entry", id)
			}
			count++
		}
	}
	if count != len(m.events) {
		t.Fatal("scope cardinality mismatch", count, len(m.events))
	}
}

func TestEvidenceIndexExpiryMatchesFullScan(t *testing.T) {
	m := manager(t)
	now := time.Now().UTC()
	want := map[string]event.Event{}
	// Equal timestamps, reverse arrival order, future and already stale events.
	for i := 0; i < 200; i++ {
		e := specimen(fmt.Sprint("expiry-", i), "lab-app", now)
		e.EventTime = now.Add(time.Duration(30-i) * time.Second)
		e.SessionHMAC = fmt.Sprint("session-", i%17)
		m.retainEvidence(e)
		want[e.EventID] = e
	}
	for _, offset := range []time.Duration{0, -10 * time.Second, time.Nanosecond, 20 * time.Second, 2 * time.Minute, -time.Hour} {
		at := now.Add(offset)
		for id, e := range want {
			if e.EventTime.Before(at.Add(-time.Minute)) {
				delete(want, id)
			}
		}
		m.pruneEvidence(at)
		assertEvidenceIndexes(t, m)
		if len(m.events) != len(want) {
			t.Fatal("full-scan expiry mismatch")
		}
		for id := range want {
			if _, ok := m.events[id]; !ok {
				t.Fatal("wrongly expired", id)
			}
		}
	}
	if len(m.evidenceScopes) != 0 {
		t.Fatal("scope state leaked after expiry")
	}
	// Reuse after physical removal has only one fresh queue/scope entry.
	e := specimen("expiry-0", "lab-app", now)
	m.retainEvidence(e)
	assertEvidenceIndexes(t, m)
}

func TestEvidenceIndexScopeIsExact(t *testing.T) {
	m := manager(t)
	now := time.Now().UTC()
	base := specimen("base", "lab-app", now)
	for i := 0; i < 6; i++ {
		e := base
		e.EventID = fmt.Sprint("scope-", i)
		switch i {
		case 1:
			e.TenantID = "beta"
		case 2:
			e.AssetID = "other-api"
		case 3:
			e.Principal = "bob"
		case 4:
			e.SessionHMAC = "session-b"
		case 5:
			e.Route = "/api/search" // route is not part of the predicate scope
		}
		m.retainEvidence(e)
	}
	ids := m.evidenceScopes[scopeOf(base)]
	if len(ids) != 2 {
		t.Fatal("scope broadened or narrowed", ids)
	}
	for _, id := range []string{"scope-0", "scope-5"} {
		if _, ok := ids[id]; !ok {
			t.Fatal("missing scope member", id)
		}
	}
	assertEvidenceIndexes(t, m)
}

func TestEvidenceIndexChangesOnlyAfterSuccessfulSync(t *testing.T) {
	m := manager(t)
	now := time.Now().UTC()
	e := specimen("synced", "lab-app", now)
	if _, err := m.Evidence(e, now); err != nil {
		t.Fatal(err)
	}
	version := m.version
	if _, err := m.Evidence(e, now); err != nil || m.version != version {
		t.Fatal("duplicate changed state", err)
	}
	changed := e
	changed.SessionHMAC = "conflict"
	if _, err := m.Evidence(changed, now); err == nil {
		t.Fatal("conflict accepted")
	}
	assertEvidenceIndexes(t, m)
	m.syncFile = func(*os.File) error {
		if len(m.events) != 1 || len(m.evidenceExpiry) != 1 {
			t.Fatal("published before Sync")
		}
		return fmt.Errorf("injected Sync failure")
	}
	e.EventID = "failed"
	if _, err := m.Evidence(e, now); err == nil || m.version != version {
		t.Fatal("failed Sync committed")
	}
	assertEvidenceIndexes(t, m)
	if len(m.events) != 1 {
		t.Fatal("failed write entered index")
	}
	if _, err := m.Evidence(specimen("later", "lab-app", now), now); err == nil {
		t.Fatal("ambiguous writer reopened")
	}
}

func TestEvidenceIndexRecoveryAndReusedID(t *testing.T) {
	m := manager(t)
	now := time.Now().UTC()
	old := specimen("reused-index", "lab-app", now.Add(-2*time.Minute))
	if _, err := m.Evidence(old, old.EventTime); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 9; i++ {
		e := specimen(fmt.Sprint("recovery-", i), "lab-app", now)
		e.EventTime = now.Add(-time.Duration(8-i) * time.Second)
		e.SessionHMAC = fmt.Sprint("session-", i%3)
		if _, err := m.Evidence(e, now); err != nil {
			t.Fatal(err)
		}
	}
	fresh := specimen(old.EventID, "lab-app", now)
	fresh.SessionHMAC = "new-session"
	if _, err := m.Evidence(fresh, now); err != nil {
		t.Fatal(err)
	}
	restored, err := Open(m.dir)
	if err != nil {
		t.Fatal(err)
	}
	assertEvidenceIndexes(t, restored)
	if len(restored.events) != len(m.events) || len(restored.evidenceScopes) != len(m.evidenceScopes) {
		t.Fatal("recovery lost index state")
	}
	version := restored.version
	if _, err := restored.Evidence(fresh, now); err != nil || restored.version != version {
		t.Fatal("recovered duplicate changed audit")
	}
	if _, err := restored.Approve(approval("recovered-index-approve", fresh.EventID), now); err != nil {
		t.Fatal(err)
	}
	assertEvidenceIndexes(t, restored)
}
