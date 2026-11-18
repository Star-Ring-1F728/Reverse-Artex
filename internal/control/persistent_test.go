package control

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPersistentAuditPreservesReplayBudgetAndClosedState(t *testing.T) {
	dir := t.TempDir()
	m, err := OpenPersistent(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.Close() })
	now := time.Now().UTC()
	if _, err := m.Evidence(specimen("persistent-e1", "lab-app", now), now); err != nil {
		t.Fatal(err)
	}
	first := m.audit
	if _, err := m.Evidence(specimen("persistent-e2", "lab-app", now), now); err != nil {
		t.Fatal(err)
	}
	if m.audit != first {
		t.Fatal("writer handle was reopened")
	}
	committedVersion := m.version
	path := filepath.Join(dir, "actions.jsonl")
	before, _ := os.ReadFile(path)
	m.Budget = int64(len(before))
	if _, err := m.Evidence(specimen("persistent-e3", "lab-app", now), now); err == nil {
		t.Fatal("budget bypass")
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("budget failure changed WAL")
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := m.SetAuto("closed-auto", true, now); err == nil {
		t.Fatal("closed manager committed")
	}
	reopened, err := OpenPersistent(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if len(reopened.events) != 2 || reopened.version != committedVersion {
		t.Fatal("persistent audit replay differs")
	}
}
