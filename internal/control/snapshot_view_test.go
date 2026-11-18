package control

import (
	"os"
	"testing"
	"time"
)

func TestCommittedSnapshotIsIsolatedAndRevokePublishesAfterSync(t *testing.T) {
	m, err := OpenPersistent(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	now := time.Now().UTC()
	e := specimen("policy-evidence", "lab-app", now)
	if _, err = m.Evidence(e, now); err != nil {
		t.Fatal(err)
	}
	r, err := m.Approve(approval("view-approve", e.EventID), now)
	if err != nil {
		t.Fatal(err)
	}
	key := []byte("01234567890123456789012345678901")
	s, _ := m.Snapshot(now, key)
	s.Policies[0].ID = "caller-mutation"
	before, _ := m.Snapshot(now, key)
	if before.Policies[0].ID != r.PolicyID {
		t.Fatal("caller mutated published view")
	}
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	m.syncFile = func(f *os.File) error { close(entered); <-release; return f.Sync() }
	go func() { _, err := m.Revoke(Revoke{"view-revoke", r.PolicyID, "experiment"}, now); done <- err }()
	<-entered
	read := make(chan uint64, 1)
	go func() {
		snapshot, _ := m.Snapshot(now.Add(time.Millisecond), key)
		if len(snapshot.Policies) != 1 {
			t.Error("revoke published before Sync")
		}
		read <- snapshot.Version
	}()
	select {
	case v := <-read:
		if v != before.Version {
			t.Error("uncommitted version")
		}
	case <-time.After(200 * time.Millisecond):
		close(release)
		<-done
		t.Fatal("reader blocked behind Sync")
	}
	close(release)
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	after, _ := m.Snapshot(now.Add(2*time.Millisecond), key)
	if len(after.Policies) != 0 || after.Version != before.Version+1 {
		t.Fatal("committed revoke missing")
	}
}
