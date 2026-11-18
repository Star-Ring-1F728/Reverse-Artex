package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reverse-artex/internal/casememory"
	"reverse-artex/internal/event"
	"reverse-artex/internal/evidence"
	"reverse-artex/internal/incident"
	"reverse-artex/internal/localassistant"
	"reverse-artex/internal/recovery"
)

func assistantCase(ctx context.Context, i *ingester, directory string, memory *casememory.Store, allowed map[string]bool, tenant, id string) (localassistant.BoundCase, error) {
	if !allowed[tenant] || memory == nil {
		return localassistant.BoundCase{}, casememory.ErrNotFound
	}
	if err := ctx.Err(); err != nil {
		return localassistant.BoundCase{}, err
	}
	i.mu.Lock()
	if i.failed != nil {
		i.mu.Unlock()
		return localassistant.BoundCase{}, errors.New("collector requires evidence recovery")
	}
	snapshot, err := evidence.Capture(directory)
	i.mu.Unlock()
	if err != nil {
		return localassistant.BoundCase{}, err
	}
	if err = recovery.VerifySnapshot(snapshot); err != nil {
		return localassistant.BoundCase{}, err
	}
	manifest, err := incident.Build(snapshot)
	if err != nil {
		return localassistant.BoundCase{}, err
	}
	for _, c := range manifest.Cases {
		if !allowed[c.Tenant] {
			return localassistant.BoundCase{}, errors.New("source case outside configured tenants")
		}
	}
	if _, err = memory.Sync(manifest, snapshot.SHA256()); err != nil {
		return localassistant.BoundCase{}, err
	}
	view, err := memory.Get(tenant, id)
	if err != nil {
		return localassistant.BoundCase{}, err
	}
	refs := map[string]string{}
	for _, ref := range view.Current.Case.Evidence {
		if ref.Stream == "events" {
			refs[ref.EventID] = ref.LineSHA
		}
	}
	result := localassistant.BoundCase{View: view, Events: []event.Event{}, SnapshotSHA: snapshot.SHA256()}
	err = snapshot.VisitRecords("events", func(raw []byte) error {
		var e event.Event
		if json.Unmarshal(raw, &e) != nil {
			return errors.New("source event decode failed")
		}
		expected, ok := refs[e.EventID]
		if !ok || e.TenantID != tenant || e.AssetID != view.Current.Case.Asset {
			return nil
		}
		sum := sha256.Sum256(raw)
		if hex.EncodeToString(sum[:]) != expected {
			return errors.New("case evidence hash differs from committed source")
		}
		for _, old := range result.Events {
			if old.EventID == e.EventID {
				return nil
			}
		}
		result.Events = append(result.Events, e)
		return nil
	})
	if err != nil {
		return localassistant.BoundCase{}, err
	}
	if len(result.Events) != len(refs) {
		return localassistant.BoundCase{}, errors.New("source evidence unavailable for exact case")
	}
	if err = ctx.Err(); err != nil {
		return localassistant.BoundCase{}, err
	}
	return result, nil
}
