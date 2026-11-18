//go:build linux

package responsev2

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"reverse-artex/internal/protection"
	"testing"
	"time"
)

func TestRetainedRotationPreservesCanonicalBytesAndPublicationFences(t *testing.T) {
	old, reg, key, path := storeFixture(t)
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	// Canonical-byte publication is independent of host wall-clock steps.
	// Seed the empty test writer in the past, then advance explicit authority
	// time through the unchanged signed-proof/window/commit paths.
	clock := time.Now().Add(-2 * protection.ProofLifetime).UTC()
	s, err := openRetainedUsingClock(path, reg, DefaultRetentionConfig(), nil, func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	complete := func(id string) {
		t.Helper()
		clock = clock.Add(time.Microsecond)
		raw, binding, status, body := proofFixture(reg, key, id, "own", "alpha", "allow", clock)
		s.mu.Lock()
		gate, prepareErr := s.observeAndPrepareAtLocked(raw, binding, status, body, clock)
		s.mu.Unlock()
		if prepareErr != nil {
			t.Fatal(prepareErr)
		}
		clock = clock.Add(time.Microsecond)
		write := protection.ResponseWrite{AttemptID: gate.AttemptID, Status: status, Bytes: len(body), BodySHA: protection.BodyHash(body), Complete: true, CompletedAt: clock}
		if err := retainedCompleteAtFixture(s, write, clock); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 4; i++ {
		complete(fmt.Sprintf("encoding-%d", i))
	}
	clock = clock.Add(protection.ProofLifetime + 20*time.Millisecond)
	complete("fresh-encoding")
	priorGeneration := s.retained.generation
	segmentPath := filepath.Join(s.retained.dir, segmentName(priorGeneration))
	segment, err := os.ReadFile(segmentPath)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := s.buildCheckpoint(priorGeneration+1, digestBytes(segment), int64(len(segment)))
	if err != nil {
		t.Fatal(err)
	}
	if len(expected.Completions) != 4 || len(expected.State.Attempts) != 1 {
		t.Fatal("fixture did not cover archived and hot response state")
	}
	raw, err := json.Marshal(expected)
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, '\n')
	syncs := 0
	s.syncFile = func(f *os.File) error { syncs++; return f.Sync() }
	var stages []string
	s.retentionHook = func(stage string) error {
		stages = append(stages, stage)
		wantSyncs := map[string]int{"predecessor-synced": 1, "checkpoint-published": 2, "successor-synced": 3, "current-published": 4, "state-installed": 4}[stage]
		if syncs != wantSyncs {
			t.Fatalf("%s file syncs=%d want=%d", stage, syncs, wantSyncs)
		}
		pointer, err := readPointer(s.retained)
		if err != nil {
			t.Fatal(err)
		}
		wantGeneration := priorGeneration
		if stage == "current-published" || stage == "state-installed" {
			wantGeneration++
		}
		if pointer.Generation != wantGeneration {
			t.Fatal("CURRENT advanced across the wrong durability boundary", stage)
		}
		if stage == "checkpoint-published" {
			published, err := os.ReadFile(filepath.Join(s.retained.dir, checkpointName(expected.Generation)))
			if err != nil || !bytes.Equal(published, raw) {
				t.Fatal("published checkpoint differs from canonical signed encoding", err)
			}
		}
		return nil
	}
	if err := s.Checkpoint(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(stages, []string{"predecessor-synced", "checkpoint-published", "successor-synced", "current-published", "state-installed"}) {
		t.Fatal("publication ordering changed", stages)
	}
	sealed, err := os.ReadFile(segmentPath)
	if err != nil || !bytes.Equal(sealed, segment) {
		t.Fatal("rotation changed the sealed signed journal", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	result, err := VerifyJournal(path, reg, nil)
	if err != nil || !result.Passed || result.TotalObservations != 5 || result.Pending != 0 {
		t.Fatal("full signed replay differs after checkpoint publication", result, err)
	}
}

func TestRetainedRotationEncodingKeepsEveryFileSyncFailureSticky(t *testing.T) {
	for failure := 1; failure <= 4; failure++ {
		t.Run(fmt.Sprint(failure), func(t *testing.T) {
			s, reg, key, path := retainedFixture(t, DefaultRetentionConfig())
			write := combinedResponseFixture(t, s, reg, key, "encoding-failure", "own", "allow")
			if err := s.CompleteResponse(write); err != nil {
				t.Fatal(err)
			}
			prior, err := readPointer(s.retained)
			if err != nil {
				t.Fatal(err)
			}
			injected := errors.New("injected rotation file sync failure")
			syncs := 0
			s.syncFile = func(f *os.File) error {
				syncs++
				if syncs == failure {
					return injected
				}
				return f.Sync()
			}
			if err := s.Checkpoint(); !errors.Is(err, injected) || !s.failed {
				t.Fatal("failed file sync did not fence rotation", err)
			}
			after, err := readPointer(s.retained)
			if err != nil || after != prior || s.retained.generation != prior.Generation {
				t.Fatal("failed sync advanced CURRENT or installed hot state", after, err)
			}
			if err := s.Checkpoint(); !errors.Is(err, ErrUnavailable) || syncs != failure {
				t.Fatal("failed writer retried or resumed", err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := OpenRetained(path, reg, DefaultRetentionConfig())
			if err != nil {
				t.Fatal("durable-prefix recovery failed", err)
			}
			defer reopened.Close()
			if reopened.totalObservations != 1 || reopened.totalAttempts != 1 || reopened.outcomeFailed {
				t.Fatal("recovery lost or doubled signed response facts")
			}
		})
	}
}
