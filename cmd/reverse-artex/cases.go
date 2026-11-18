package main

import (
	"context"
	"errors"

	"reverse-artex/internal/casememory"
	"reverse-artex/internal/evidence"
	"reverse-artex/internal/incident"
	"reverse-artex/internal/recovery"
)

// Capture under the ingestion mutex: event/alert/evaluation writes have all
// committed or the failed ingester refuses the read. Replay the frozen bytes
// after releasing the mutex, so verification does not stall sensor writes.
func syncCases(ctx context.Context, ingest *ingester, directory string, memory *casememory.Store, allowed map[string]bool) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	ingest.mu.Lock()
	if ingest.failed != nil {
		ingest.mu.Unlock()
		return 0, errors.New("collector evidence requires recovery")
	}
	snapshot, err := evidence.Capture(directory)
	ingest.mu.Unlock()
	if err != nil {
		return 0, err
	}
	if err = ctx.Err(); err != nil {
		return 0, err
	}
	if err = recovery.VerifySnapshot(snapshot); err != nil {
		return 0, err
	}
	m, err := incident.Build(snapshot)
	if err != nil {
		return 0, err
	}
	for _, c := range m.Cases {
		if !allowed[c.Tenant] {
			return 0, errors.New("case tenant outside configured scope")
		}
	}
	if err = ctx.Err(); err != nil {
		return 0, err
	}
	return memory.Sync(m, snapshot.SHA256())
}
