package main

import (
	"os"
	"path/filepath"
	"reverse-artex/internal/detect"
	"reverse-artex/internal/event"
	"reverse-artex/internal/evidence"
	"reverse-artex/internal/hostguard"
	"reverse-artex/internal/storagebudget"
	"testing"
)

func TestBudgetGroupRefusalLatchesWithoutOrphanReplay(t *testing.T) {
	for _, feed := range []string{"single", "batch", "host"} {
		t.Run(feed, func(t *testing.T) {
			root := t.TempDir()
			t.Setenv("RA_STORAGE_ROOT", root)
			t.Setenv("RA_STORAGE_LIMIT", "1048576")
			dir := filepath.Join(root, "collector")
			b, e := storagebudget.FromEnv(dir)
			if e != nil {
				t.Fatal(e)
			}
			store, e := evidence.NewPersistentRotating(dir, 8<<20, 8192)
			if e != nil {
				t.Fatal(e)
			}
			defer store.Close()
			status, _ := b.Stats()
			if e = b.WriteFile(filepath.Join(root, "fill"), make([]byte, status.Remaining-600)); e != nil {
				t.Fatal(e)
			}
			i := &ingester{store: store, engine: detect.New(), hostEngine: hostguard.New([]string{"fixture"})}
			forwarded := 0
			i.forward = func(event.Event) { forwarded++ }
			switch feed {
			case "single":
				_, e = i.process(sampleHTTP("quota"))
			case "batch":
				_, e = i.processBatch([]event.Event{sampleHTTP("quota")})
			case "host":
				_, e = i.processHost(sampleHost("quota"))
			}
			if e == nil || !i.degraded() || forwarded != 0 {
				t.Fatalf("err=%v degraded=%v forwarded=%d", e, i.degraded(), forwarded)
			}
			entries, _ := os.ReadDir(dir)
			if len(entries) != 0 {
				t.Fatal("quota refusal left orphan replay")
			}
			if e = os.Remove(filepath.Join(root, "fill")); e != nil {
				t.Fatal(e)
			}
			if _, e = i.process(sampleHTTP("retry")); e == nil {
				t.Fatal("mutated detector resumed without restart")
			}
			recovered := &ingester{store: store, engine: detect.New(), hostEngine: hostguard.New([]string{"fixture"})}
			if _, e = recovered.process(sampleHTTP("recovered")); e != nil {
				t.Fatal(e)
			}
		})
	}
}
