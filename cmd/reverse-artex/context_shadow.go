package main

import (
	"context"
	"errors"
	"reverse-artex/internal/evidence"
	"time"
)

// Capture while holding the same mutex used by HTTP, batch and host commits.
// The returned immutable bytes are replayed only after unlocking ingestion.
func captureContextSnapshot(ctx context.Context, i *ingester, directory string) (*evidence.Snapshot, error) {
	waitStart := time.Now()
	for !i.mu.TryLock() {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(5 * time.Millisecond):
		}
	}
	i.timeBatch("context_snapshot_wait", waitStart)
	raw, err := func() (*evidence.FrozenSource, error) {
		heldStart := time.Now()
		defer func() { i.mu.Unlock(); i.timeBatch("context_snapshot_held", heldStart) }()
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if i.failed != nil {
			return nil, errors.New("collector evidence requires recovery")
		}
		return evidence.CaptureFilesLocked(directory)
	}()
	if err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	expandStart := time.Now()
	snapshot, err := raw.Snapshot()
	i.timeBatch("context_snapshot_expand", expandStart)
	if err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	return snapshot, nil
}
