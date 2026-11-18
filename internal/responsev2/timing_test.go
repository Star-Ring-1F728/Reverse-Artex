package responsev2

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reverse-artex/internal/decisions"
	"testing"
	"time"
)

func timingCount(t *testing.T, s *Store, stage string) uint64 {
	t.Helper()
	return s.TimingSnapshot()["stages"].(map[string]any)[stage].(map[string]any)["count"].(uint64)
}

func TestTimingMetricsPreserveJournalBytesAndSyncFences(t *testing.T) {
	plain, registry, key, plainPath := storeFixture(t)
	measuredPath := filepath.Join(t.TempDir(), "measured.jsonl")
	measured, err := Open(measuredPath, registry)
	if err != nil {
		t.Fatal(err)
	}
	defer measured.Close()
	measured.bootID = plain.bootID
	measured.EnableTimingMetrics()
	if plain.TimingSnapshot()["enabled"] != false {
		t.Fatal("metrics must default off")
	}
	at := time.Now().UTC()
	raw, binding, status, body := proofFixture(registry, key, "measured", "own", "alpha", "allow", at)
	for _, s := range []*Store{plain, measured} {
		syncs := 0
		s.syncFile = func(f *os.File) error { syncs++; return f.Sync() }
		if _, err := s.Observe(raw, binding, status, body, at); err != nil {
			t.Fatal(err)
		}
		if _, err := s.PrepareResponse("alpha", decisions.Hash(raw), at); err != nil {
			t.Fatal(err)
		}
		if syncs != 2 {
			t.Fatal("metrics changed durable preparation fences", syncs)
		}
	}
	a, err := os.ReadFile(plainPath)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(measuredPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("diagnostics changed durable journal bytes")
	}
	for stage, want := range map[string]uint64{"observe_lock_wait": 1, "prepare_lock_wait": 1, "observation_verify": 1, "attempt_verify": 1, "journal_marshal": 2, "journal_write": 2, "journal_sync": 2} {
		if got := timingCount(t, measured, stage); got != want {
			t.Fatalf("%s count=%d want=%d", stage, got, want)
		}
	}
}

func TestTimingMetricsRecordFailedSyncWithoutPublishing(t *testing.T) {
	s, registry, key, _ := storeFixture(t)
	s.EnableTimingMetrics()
	s.syncFile = func(*os.File) error { return errors.New("injected sync failure") }
	raw, binding, status, body := proofFixture(registry, key, "failed-timed", "own", "alpha", "allow", time.Now())
	if _, err := s.ObserveAndPrepareCurrent(raw, binding, status, body); err == nil {
		t.Fatal("failed sync admitted response")
	}
	if !s.failed || s.sequence != 0 || len(s.events) != 0 || len(s.attempts) != 0 {
		t.Fatal("failed sync published partial state")
	}
	if timingCount(t, s, "journal_sync") != 1 {
		t.Fatal("failed sync missing from diagnostics")
	}
}

func TestTimingSnapshotDoesNotWaitForJournalLock(t *testing.T) {
	s, _, _, _ := storeFixture(t)
	s.EnableTimingMetrics()
	s.mu.Lock()
	defer s.mu.Unlock()
	done := make(chan struct{})
	go func() { s.TimingSnapshot(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("diagnostics blocked behind journal lock")
	}
}
