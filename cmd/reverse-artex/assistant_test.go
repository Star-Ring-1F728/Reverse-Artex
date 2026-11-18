package main

import (
	"context"
	"fmt"
	"path/filepath"
	"reverse-artex/internal/casememory"
	"reverse-artex/internal/detect"
	"reverse-artex/internal/evidence"
	"reverse-artex/internal/hostguard"
	"testing"
	"time"
)

func TestAssistantCaseUsesExactCommittedTenantEvidence(t *testing.T) {
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
	i := &ingester{store: store, engine: engine, hostEngine: host}
	for n := 0; n < 4; n++ {
		e := recoveryHTTP(fmt.Sprint("assistant-event-", n), "assistant-session", fmt.Sprint("resource-", n), time.Now().UTC())
		if _, err = i.process(e); err != nil {
			t.Fatal(err)
		}
	}
	memory, err := casememory.Open(filepath.Join(t.TempDir(), "journal.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer memory.Close()
	if _, err = syncCases(context.Background(), i, dir, memory, map[string]bool{"alpha": true}); err != nil {
		t.Fatal(err)
	}
	cases, err := memory.List("alpha")
	if err != nil || len(cases) == 0 {
		t.Fatal(cases, err)
	}
	id := cases[0].Current.Case.ID
	b, err := assistantCase(context.Background(), i, dir, memory, map[string]bool{"alpha": true}, "alpha", id)
	if err != nil || len(b.Events) != len(b.View.Current.Case.Evidence) {
		t.Fatal(b, err)
	}
	for _, e := range b.Events {
		if e.TenantID != "alpha" || e.AssetID != "lab-api" {
			t.Fatal("foreign source event included")
		}
	}
	if _, err = assistantCase(context.Background(), i, dir, memory, map[string]bool{"alpha": true}, "beta", id); err == nil {
		t.Fatal("foreign tenant read")
	}
	i.fail(fmt.Errorf("injected ambiguous writer failure"))
	if _, err = assistantCase(context.Background(), i, dir, memory, map[string]bool{"alpha": true}, "alpha", id); err == nil {
		t.Fatal("degraded source reached model")
	}
}
