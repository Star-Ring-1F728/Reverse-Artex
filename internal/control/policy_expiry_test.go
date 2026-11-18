package control

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"reverse-artex/internal/policy"
	"sort"
	"testing"
	"time"
)

func assertPolicyExpiry(t *testing.T, m *Manager) {
	t.Helper()
	q := &m.policyExpiry
	if len(q.entries) != len(m.active) || len(q.positions) != len(m.active) {
		t.Fatal("policy deadline cardinality mismatch")
	}
	for i, entry := range q.entries {
		p, ok := m.active[entry.id]
		position, indexed := q.positions[entry.id]
		if !ok || !indexed || position != i || !p.Expires.Equal(entry.at) {
			t.Fatal("deadline does not match policy", entry)
		}
		if i > 0 && q.Less(i, (i-1)/2) {
			t.Fatal("invalid policy expiry heap")
		}
	}
}

func TestPolicyExpirySelectionMatchesScanAcrossTransitions(t *testing.T) {
	m := manager(t)
	now := time.Now().UTC()
	for step := 0; step < 2048; step++ {
		id := fmt.Sprint("transition-", (step*17)%127)
		if step%5 == 0 {
			m.replay(record{Epoch: m.epoch, Version: m.version + 1, Removed: []string{id}})
		} else {
			p := policy.Policy{ID: id, Expires: now.Add(time.Duration((step*31)%181-90) * time.Second)}
			m.replay(record{Epoch: m.epoch, Version: m.version + 1, Policy: &p})
		}
		assertPolicyExpiry(t, m)
		for _, offset := range []time.Duration{-91 * time.Second, -time.Nanosecond, 0, time.Nanosecond, 91 * time.Second} {
			at := now.Add(offset)
			want := []string{}
			for id, p := range m.active {
				if !p.Expires.After(at) {
					want = append(want, id)
				}
			}
			sort.Strings(want)
			got := m.policyExpiry.expiredIDs(at)
			if len(got) != len(want) || (len(want) > 0 && !reflect.DeepEqual(got, want)) {
				t.Fatalf("step %d expiry mismatch: %v != %v", step, got, want)
			}
		}
		// Candidate queries, including future queries followed by clock rollback,
		// must not remove or reorder the indexed state.
		assertPolicyExpiry(t, m)
	}
}

func TestPolicyExpiryBudgetFailureKeepsCandidatesForRetry(t *testing.T) {
	m := manager(t)
	now := time.Now().UTC()
	if _, err := m.Evidence(specimen("expiry-subject", "lab-app", now), now); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"z-expiry", "a-expiry", "m-expiry"} {
		if _, err := m.Approve(approval(key, "expiry-subject"), now); err != nil {
			t.Fatal(err)
		}
	}
	assertPolicyExpiry(t, m)
	at := now.Add(10 * time.Second)
	want := m.policyExpiry.expiredIDs(at)
	version, budget := m.version, m.Budget
	m.Budget = 1
	if _, err := m.Snapshot(at, nil); err == nil {
		t.Fatal("unsaved expiry succeeded")
	}
	if m.version != version || len(m.active) != 3 || !reflect.DeepEqual(m.policyExpiry.expiredIDs(at), want) {
		t.Fatal("budget failure consumed candidates")
	}
	assertPolicyExpiry(t, m)
	m.Budget = budget
	m.syncFile = func(f *os.File) error {
		if m.version != version || len(m.active) != 3 || !reflect.DeepEqual(m.policyExpiry.expiredIDs(at), want) {
			t.Fatal("expiry published before Sync")
		}
		return f.Sync()
	}
	s, err := m.Snapshot(at, nil)
	if err != nil || len(s.Policies) != 0 || m.version != version+1 {
		t.Fatal("expiry retry failed", err)
	}
	assertPolicyExpiry(t, m)
	for _, id := range want {
		if !m.dead[id] {
			t.Fatal("missing durable tombstone", id)
		}
	}
	restored, err := Open(m.dir)
	if err != nil {
		t.Fatal(err)
	}
	assertPolicyExpiry(t, restored)
	if len(restored.active) != 0 {
		t.Fatal("expired policies resurrected")
	}
}

func TestPolicyExpiryAmbiguousSyncRetainsInMemoryState(t *testing.T) {
	m := manager(t)
	now := time.Now().UTC()
	if _, err := m.Evidence(specimen("unknown-expiry-subject", "lab-app", now), now); err != nil {
		t.Fatal(err)
	}
	r, err := m.Approve(approval("unknown-expiry", "unknown-expiry-subject"), now)
	if err != nil {
		t.Fatal(err)
	}
	at := m.active[r.PolicyID].Expires
	version := m.version
	m.syncFile = func(*os.File) error { return errors.New("injected expiry Sync failure") }
	if _, err := m.Snapshot(at, nil); err == nil {
		t.Fatal("unknown expiry returned success")
	}
	assertPolicyExpiry(t, m)
	if m.version != version || len(m.active) != 1 || m.dead[r.PolicyID] {
		t.Fatal("unknown Sync changed active policy")
	}
	if _, err := m.Snapshot(at, nil); err == nil {
		t.Fatal("ambiguous writer retried")
	}
	// The full unknown-outcome audit record remains available at restart.
	restored, err := Open(m.dir)
	if err != nil {
		t.Fatal(err)
	}
	assertPolicyExpiry(t, restored)
	if len(restored.active) != 0 || !restored.dead[r.PolicyID] || restored.version != version+1 {
		t.Fatal("restart lost durable expiry record")
	}
}

func TestPolicyExpiryRevokeRollbackAndRecovery(t *testing.T) {
	m := manager(t)
	now := time.Now().UTC()
	if _, err := m.Evidence(specimen("lifecycle-subject", "lab-app", now), now); err != nil {
		t.Fatal(err)
	}
	first, err := m.Approve(approval("lifecycle-first", "lifecycle-subject"), now)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint := m.version
	second, err := m.Approve(approval("lifecycle-second", "lifecycle-subject"), now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.Revoke(Revoke{"lifecycle-revoke", second.PolicyID, "experiment"}, now); err != nil {
		t.Fatal(err)
	}
	if _, err = m.Approve(approval("lifecycle-third", "lifecycle-subject"), now); err != nil {
		t.Fatal(err)
	}
	if _, err = m.Rollback(Rollback{"lifecycle-rollback", checkpoint, "rollback"}, now); err != nil {
		t.Fatal(err)
	}
	assertPolicyExpiry(t, m)
	if len(m.active) != 1 {
		t.Fatal("rollback retained extra policy")
	}
	restored, err := Open(m.dir)
	if err != nil {
		t.Fatal(err)
	}
	assertPolicyExpiry(t, restored)
	p := restored.active[first.PolicyID]
	if s, err := restored.Snapshot(p.Expires.Add(-time.Nanosecond), nil); err != nil || len(s.Policies) != 1 {
		t.Fatal("expired too early", err)
	}
	if s, err := restored.Snapshot(p.Expires, nil); err != nil || len(s.Policies) != 0 {
		t.Fatal("missed exact expiry", err)
	}
	assertPolicyExpiry(t, restored)
}
