package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"reverse-artex/internal/casememory"
	"reverse-artex/internal/detect"
	"reverse-artex/internal/evidence"
	"reverse-artex/internal/hostguard"
)

func TestLiveCaseSyncVerifiesCommitAndPreservesRestart(t *testing.T) {
	dir := t.TempDir()
	store, err := evidence.NewPersistentRotating(dir, 8<<20, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	engine, host := detect.New(), hostguard.New(nil)
	if err = restoreState(store, dir, "session", nil, engine, host); err != nil {
		t.Fatal(err)
	}
	ingest := &ingester{store: store, engine: engine, hostEngine: host}
	path := filepath.Join(t.TempDir(), "journal.jsonl")
	memory, err := casememory.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer memory.Close()
	at := time.Now().UTC().Add(-time.Second)
	for i := 0; i < 4; i++ {
		e := recoveryHTTP(fmt.Sprint("case-event-", i), "same-session", fmt.Sprint("resource-", i), at)
		if _, err = ingest.process(e); err != nil {
			t.Fatal(err)
		}
	}
	changed, err := syncCases(context.Background(), ingest, dir, memory, map[string]bool{"alpha": true})
	if err != nil || changed == 0 {
		t.Fatal(changed, err)
	}
	list, err := memory.List("alpha")
	if err != nil || len(list) == 0 || len(list[0].Current.Case.Evidence) == 0 {
		t.Fatal(list, err)
	}
	current := list[0].Current
	if _, err = memory.SetLabel("alpha", current.Case.ID, casememory.LabelRequest{Expected: 0, CaseSHA: current.SHA, Value: "confirmed_attack", Reason: "synthetic integration scenario"}); err != nil {
		t.Fatal(err)
	}
	selection, err := memory.Select("alpha", true)
	if err != nil || selection.Eligible == 0 {
		t.Fatal(selection, err)
	}
	if n, err := syncCases(context.Background(), ingest, dir, memory, map[string]bool{"alpha": true}); n != 0 || err != nil {
		t.Fatal(n, err)
	}
	memory.Close()
	memory, err = casememory.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer memory.Close()
	if saved, err := memory.SavedSelection("alpha", selection.SHA); err != nil || saved.Reevaluation {
		t.Fatal(saved, err)
	}
	if _, err = syncCases(context.Background(), ingest, dir, memory, map[string]bool{"beta": true}); err == nil {
		t.Fatal("out-of-scope case imported")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = syncCases(ctx, ingest, dir, memory, map[string]bool{"alpha": true}); err == nil {
		t.Fatal("cancelled sync accepted")
	}
	// A complete but uncommitted source row must never enter case memory.
	f, err := os.OpenFile(filepath.Join(dir, "events.jsonl"), os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("{}\n")
	f.Close()
	if _, err = syncCases(context.Background(), ingest, dir, memory, map[string]bool{"alpha": true}); err == nil {
		t.Fatal("uncommitted source accepted")
	}
}
