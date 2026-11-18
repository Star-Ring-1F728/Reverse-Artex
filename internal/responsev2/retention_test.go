//go:build linux || windows

package responsev2

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reverse-artex/internal/decisions"
	"reverse-artex/internal/protection"
	"testing"
	"time"
)

func retainedFixture(t *testing.T, c RetentionConfig) (*Store, *protection.Registry, ed25519.PrivateKey, string) {
	t.Helper()
	old, reg, key, path := storeFixture(t)
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := OpenRetained(path, reg, c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, reg, key, path
}
func retainedEligibleFixture(t *testing.T, s *Store, reg *protection.Registry, key ed25519.PrivateKey) CaseView {
	t.Helper()
	observeFixture(t, s, reg, key, "fresh-deny-one", "one", "alpha", "deny", time.Now())
	gate := observeFixture(t, s, reg, key, "fresh-deny-two", "two", "alpha", "deny", time.Now())
	view, err := s.Case("alpha", gate.CaseID)
	if err != nil || len(view.Candidates) != 2 {
		t.Fatal(view, err)
	}
	return view
}
func agedPrepared(t *testing.T, s *Store, reg *protection.Registry, key ed25519.PrivateKey, n int) []protection.ResponseWrite {
	t.Helper()
	writes := make([]protection.ResponseWrite, 0, n)
	base := time.Now().Add(-10 * time.Second)
	for i := 0; i < n; i++ {
		at := base.Add(time.Duration(i) * time.Microsecond)
		raw, b, status, body := proofFixture(reg, key, fmt.Sprintf("aged-%d", i), "own", "alpha", "allow", at)
		if _, err := s.Observe(raw, b, status, body, at); err != nil {
			t.Fatal(err)
		}
		gate, err := s.PrepareResponse("alpha", decisions.Hash(raw), at)
		if err != nil {
			t.Fatal(err)
		}
		writes = append(writes, protection.ResponseWrite{AttemptID: gate.AttemptID, Status: status, Bytes: len(body), BodySHA: protection.BodyHash(body), Complete: true, CompletedAt: time.Now().UTC()})
	}
	return writes
}
func retainedCompleteAtFixture(s *Store, write protection.ResponseWrite, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.completeResponseUsingClockLocked(write, func() time.Time { return at })
}

func TestRetainedMigrationCrossesLifetimeCapAndReplaysBoundedState(t *testing.T) {
	old, reg, key, path := storeFixture(t)
	writes := agedPrepared(t, old, reg, key, 4000)
	// This is a persistence/compaction test, not a qualification of the host
	// wall clock. Use explicit increasing authority times through the same
	// validation and durable commit paths; never clamp the production clock.
	clock := old.high.Add(10 * time.Second)
	for _, write := range writes {
		clock = clock.Add(time.Microsecond)
		write.CompletedAt = clock
		if err := retainedCompleteAtFixture(old, write, clock); err != nil {
			t.Fatal(err)
		}
	}
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	old.Close()
	cfg := RetentionConfig{4 << 20, 512 << 20, 128}
	s, err := OpenRetained(path, reg, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.totalAttempts != 4000 || len(s.attempts) != 0 || len(s.events) != 32 {
		t.Fatal("initial hot state not compacted", s.totalAttempts, len(s.attempts), len(s.events))
	}
	prefix, err := os.ReadFile(filepath.Join(path+".retained", segmentName(0)))
	if err != nil || digestBytes(prefix) != digestBytes(original) {
		t.Fatal("legacy bytes changed", err)
	}
	clock = s.high
	for i := 0; i < 5000; i++ {
		clock = clock.Add(time.Microsecond)
		raw, binding, status, body := proofFixture(reg, key, fmt.Sprintf("current-%d", i), "own", "alpha", "allow", clock)
		s.mu.Lock()
		gate, prepareErr := s.observeAndPrepareAtLocked(raw, binding, status, body, clock)
		s.mu.Unlock()
		if prepareErr != nil {
			t.Fatal(prepareErr)
		}
		clock = clock.Add(time.Microsecond)
		w := protection.ResponseWrite{AttemptID: gate.AttemptID, Status: status, Bytes: len(body), BodySHA: protection.BodyHash(body), Complete: true, CompletedAt: clock}
		if err = retainedCompleteAtFixture(s, w, clock); err != nil {
			a, present := s.attempts[w.AttemptID]
			t.Fatalf("completion %d: %v; present=%v boot_match=%v valid=%v prepared=%s completed=%s delta=%s seq=%d high=%s outcome_failed=%v", i, err, present, a.BootID == s.bootID, validResponseWrite(a, w), a.PreparedAt.Format(time.RFC3339Nano), w.CompletedAt.Format(time.RFC3339Nano), w.CompletedAt.Sub(a.PreparedAt), s.sequence, s.high.Format(time.RFC3339Nano), s.outcomeFailed)
		}
	}
	if s.totalEvents != 9000 || s.totalAttempts != 9000 || s.totalObservations != 9000 || s.retained.generation < 2 || len(s.events) >= 8192 || len(s.attempts) >= 8192 {
		t.Fatal("lifetime/hot bound", s.retainedStatusLocked())
	}
	if err = s.Checkpoint(); err != nil {
		t.Fatal(err)
	}
	seq, head, events, attempts, obs := s.sequence, s.head, len(s.events), len(s.attempts), len(s.observations)
	s.Close()
	if wrong, err := Open(path, reg); err == nil {
		wrong.Close()
		t.Fatal("legacy reader silently reopened old prefix")
	}
	reopened, err := OpenRetained(path, reg, cfg)
	if err != nil {
		t.Fatal("retained replay", err)
	}
	defer reopened.Close()
	if reopened.sequence != seq+1 || reopened.head == head || len(reopened.events) != events || len(reopened.attempts) != attempts || len(reopened.observations) != obs || reopened.totalObservations != 9000 || reopened.OutcomeHealth()["audit_available"] != true {
		t.Fatal("replay lost hot state or totals", reopened.OutcomeHealth())
	}
}
func TestRetainedCheckpointKeepsPendingWriteAndOldBootFence(t *testing.T) {
	s, reg, key, path := retainedFixture(t, RetentionConfig{64 << 10, 64 << 20, 128})
	pending := combinedResponseFixture(t, s, reg, key, "pending", "own", "allow")
	if err := s.Checkpoint(); err != nil {
		t.Fatal(err)
	}
	s.Close()
	again, err := OpenRetained(path, reg, RetentionConfig{64 << 10, 64 << 20, 128})
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	if again.OutcomeHealth()["audit_available"] != false || again.OutcomeHealth()["pending_unknown"] != 1 {
		t.Fatal("in-flight write became success")
	}
	if err = again.CompleteResponse(pending); !errors.Is(err, ErrStale) {
		t.Fatal("old boot write admitted", err)
	}
	raw, b, status, body := proofFixture(reg, key, "next", "own", "alpha", "allow", time.Now())
	if _, err = again.ObserveAndPrepareCurrent(raw, b, status, body); err == nil {
		t.Fatal("pending unknown did not fence next response")
	}
}
func TestRetainedPartialWriteAndFoldedCompletionDedupeRemainExact(t *testing.T) {
	old, reg, key, path := storeFixture(t)
	writes := agedPrepared(t, old, reg, key, 40)
	for _, w := range writes {
		if err := old.CompleteResponse(w); err != nil {
			t.Fatal(err)
		}
	}
	boot := old.bootID
	old.Close()
	s, err := OpenRetained(path, reg, DefaultRetentionConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	// Simulate a late callback in the same writer identity, then verify that a
	// conflicting report still degrades the audit after the exact attempt folds.
	s.bootID = boot
	if len(s.attempts) != 0 {
		t.Fatal("expected archived completion")
	}
	if err = s.CompleteResponse(writes[0]); err != nil {
		t.Fatal("archived identical callback lost idempotency", err)
	}
	bad := writes[0]
	bad.Bytes--
	if err = s.CompleteResponse(bad); !errors.Is(err, ErrStale) || !s.outcomeFailed {
		t.Fatal("conflicting archived write was ignored", err)
	}
}
func TestRetainedArchivedRequestIDCannotBeReusedWithNewSignedProof(t *testing.T) {
	old, reg, key, path := storeFixture(t)
	writes := agedPrepared(t, old, reg, key, 40)
	for _, w := range writes {
		if err := old.CompleteResponse(w); err != nil {
			t.Fatal(err)
		}
	}
	old.Close()
	s, err := OpenRetained(path, reg, DefaultRetentionConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	raw, b, status, body := proofFixture(reg, key, "aged-0", "own", "alpha", "allow", time.Now())
	before := s.sequence
	if _, err = s.ObserveAndPrepareCurrent(raw, b, status, body); !errors.Is(err, ErrStale) || s.sequence != before {
		t.Fatal("archived request ID reused", err)
	}
}
func TestRetainedOutcomeFactsPreserveMaskOwnersReleaseRecoveryAndRefs(t *testing.T) {
	old, reg, key, path := storeFixture(t)
	base := time.Now().Add(-10 * time.Second)
	observeFixture(t, old, reg, key, "deny-one", "one", "alpha", "deny", base)
	initial := observeFixture(t, old, reg, key, "deny-two", "two", "alpha", "deny", base.Add(time.Millisecond))
	view, err := old.viewLocked("alpha", initial.CaseID, base.Add(2*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	installed, err := old.applyLocked(context.Background(), "alpha", intentFixture(old, view, "install", "operator", "run"), base.Add(3*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	policy := old.leases[installed.PolicyID]
	target := targetObject(view)
	prepare := func(id, object, decision string, offset time.Duration) protection.ResponseWrite {
		at := base.Add(offset)
		raw, b, status, body := proofFixture(reg, key, id, object, "alpha", decision, at)
		if _, err := old.Observe(raw, b, status, body, at); err != nil {
			t.Fatal(err)
		}
		gate, err := old.PrepareResponse("alpha", decisions.Hash(raw), at)
		if err != nil {
			t.Fatal(err)
		}
		if gate.Deny {
			status = 429
			body = []byte("Too Many Requests\n")
		}
		return protection.ResponseWrite{AttemptID: gate.AttemptID, Status: status, Bytes: len(body), BodySHA: protection.BodyHash(body), Complete: true, CompletedAt: time.Now().UTC()}
	}
	writes := []protection.ResponseWrite{prepare("target", target, "deny", 10*time.Millisecond), prepare("benign", "own", "allow", 20*time.Millisecond), prepare("inflight", target, "deny", 30*time.Millisecond)}
	if _, err = old.releaseLocked(context.Background(), "alpha", policy.ID, "operator", "run", "release", policy.Generation, base.Add(40*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	writes = append(writes, prepare("restored-target", target, "deny", 50*time.Millisecond), prepare("restored-normal", "own", "allow", 60*time.Millisecond))
	// Reverse write completion order must not change first-by-preparation refs.
	for i := len(writes) - 1; i >= 0; i-- {
		if err = old.CompleteResponse(writes[i]); err != nil {
			t.Fatal(err)
		}
	}
	expected, err := old.Outcome("alpha", policy.ID, policy.Episode)
	if err != nil {
		t.Fatal(err)
	}
	if expected.Target.Count != 2 || expected.Benign.Count != 1 || expected.Recovery.Count != 2 || expected.Recovery.State != "observed_guard_baseline_restored" {
		t.Fatal(expected)
	}
	old.Close()
	s, err := OpenRetained(path, reg, DefaultRetentionConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if len(s.attempts) != 0 {
		t.Fatal("old facts did not fold")
	}
	for i := 0; i < 3; i++ {
		if err = s.Checkpoint(); err != nil {
			t.Fatal(err)
		}
	}
	actual, err := s.Outcome("alpha", policy.ID, policy.Episode)
	if err != nil {
		t.Fatal(err)
	}
	expected.AsOfSequence = actual.AsOfSequence
	if decisions.Hash(actual) != decisions.Hash(expected) {
		t.Fatal("fold changed episode outcome", expected, actual)
	}
	s.Close()
	again, err := OpenRetained(path, reg, DefaultRetentionConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	after, err := again.Outcome("alpha", policy.ID, policy.Episode)
	if err != nil {
		t.Fatal(err)
	}
	expected.AsOfSequence = after.AsOfSequence
	if decisions.Hash(after) != decisions.Hash(expected) {
		t.Fatal("replay changed folded facts", expected, after)
	}
}
func TestRetainedRehashedCheckpointCannotAlterBudgetOrOutcome(t *testing.T) {
	for _, kind := range []string{"epoch", "total", "outcome", "pending"} {
		t.Run(kind, func(t *testing.T) {
			s, reg, key, path := retainedFixture(t, DefaultRetentionConfig())
			w := combinedResponseFixture(t, s, reg, key, "pending", "own", "allow")
			if kind != "pending" {
				if err := s.CompleteResponse(w); err != nil {
					t.Fatal(err)
				}
			}
			if err := s.Checkpoint(); err != nil {
				t.Fatal(err)
			}
			generation := s.retained.generation
			s.Close()
			file := filepath.Join(path+".retained", checkpointName(generation))
			raw, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			var c retainedCheckpoint
			if err = json.Unmarshal(raw, &c); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "epoch":
				c.State.Epoch++
			case "total":
				c.State.TotalObservations++
			case "outcome":
				c.State.Outcomes["forged"] = outcomeFacts{Target: outcomeTally{Count: 99}}
			case "pending":
				delete(c.State.Attempts, w.AttemptID)
			}
			c.SHA = checkpointSHA(c)
			raw, _ = json.Marshal(c)
			if err = os.WriteFile(file, append(raw, '\n'), 0600); err != nil {
				t.Fatal(err)
			}
			pointerPath := filepath.Join(path+".retained", "CURRENT")
			pointerRaw, _ := os.ReadFile(pointerPath)
			var p retentionPointer
			json.Unmarshal(pointerRaw, &p)
			p.CheckpointSHA = c.SHA
			p.SHA = pointerSHA(p)
			pointerRaw, _ = json.Marshal(p)
			os.WriteFile(pointerPath, append(pointerRaw, '\n'), 0600)
			if bad, err := OpenRetained(path, reg, DefaultRetentionConfig()); err == nil {
				bad.Close()
				t.Fatal("forged rehashed checkpoint accepted")
			}
		})
	}
}
func TestRetainedInterruptedPublicationRecoversWithoutLostOrDuplicateWrites(t *testing.T) {
	for _, stage := range []string{"predecessor-synced", "checkpoint-published", "successor-synced", "current-published", "state-installed"} {
		t.Run(stage, func(t *testing.T) {
			cfg := RetentionConfig{64 << 10, 64 << 20, 128}
			s, reg, key, path := retainedFixture(t, cfg)
			w := combinedResponseFixture(t, s, reg, key, "completed", "own", "allow")
			if err := s.CompleteResponse(w); err != nil {
				t.Fatal(err)
			}
			s.retentionHook = func(current string) error {
				if current == stage {
					return errors.New("simulated interruption")
				}
				return nil
			}
			if err := s.Checkpoint(); err == nil {
				t.Fatal("expected boundary interruption")
			}
			s.Close()
			next, err := OpenRetained(path, reg, cfg)
			if err != nil {
				t.Fatal(stage, err)
			}
			defer next.Close()
			if next.totalEvents != 1 || next.totalAttempts != 1 || next.totalObservations != 1 || next.outcomeFailed {
				t.Fatal("interrupted checkpoint lost/doubled completed facts", next.OutcomeHealth())
			}
			probe := combinedResponseFixture(t, next, reg, key, "after", "own", "allow")
			if err = next.CompleteResponse(probe); err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestRetainedInitialPublicationCanResumeAndNeverReinitializeAdvancedState(t *testing.T) {
	for _, stage := range []string{"initial-files-synced", "root-published"} {
		t.Run(stage, func(t *testing.T) {
			old, reg, key, path := storeFixture(t)
			w := responseFixture(t, old, reg, key, "prior", "own", "allow", true)
			_ = w
			old.Close()
			hook := func(current string) error {
				if current == stage {
					return errors.New("simulated initial interruption")
				}
				return nil
			}
			if s, err := openRetained(path, reg, DefaultRetentionConfig(), hook); err == nil {
				s.Close()
				t.Fatal("expected initial interruption")
			}
			s, err := OpenRetained(path, reg, DefaultRetentionConfig())
			if err != nil {
				t.Fatal(err)
			}
			if s.totalObservations != 1 {
				t.Fatal("migration lost prior response")
			}
			if err = s.Checkpoint(); err != nil {
				t.Fatal(err)
			}
			s.Close()
			// Losing the marker must not restart from the preserved initial generation.
			os.WriteFile(path, nil, 0600)
			if bad, err := OpenRetained(path, reg, DefaultRetentionConfig()); err == nil {
				bad.Close()
				t.Fatal("missing marker silently reset an advanced store")
			}
			if bad, err := Open(path, reg); err == nil {
				bad.Close()
				t.Fatal("legacy open silently reset an advanced retained store")
			}
			if result, err := VerifyJournal(path, reg, nil); err == nil || result.Passed {
				t.Fatal("read-only verification accepted a missing retention marker")
			}
		})
	}
}
func TestRetainedQuotaAndArchiveDamageFailClosed(t *testing.T) {
	cfg := RetentionConfig{64 << 10, 8 << 20, 2}
	s, reg, key, path := retainedFixture(t, cfg)
	w := combinedResponseFixture(t, s, reg, key, "one", "own", "allow")
	if err := s.CompleteResponse(w); err != nil {
		t.Fatal(err)
	}
	if err := s.Checkpoint(); err != nil {
		t.Fatal(err)
	}
	if err := s.Checkpoint(); !errors.Is(err, ErrLimit) || s.failed {
		t.Fatal("generation quota or existing completion availability changed", err)
	}
	s.Close()
	rawPath := filepath.Join(path+".retained", segmentName(1))
	raw, _ := os.ReadFile(rawPath)
	raw[len(raw)/2] ^= 1
	os.WriteFile(rawPath, raw, 0600)
	if bad, err := OpenRetained(path, reg, cfg); err == nil {
		bad.Close()
		t.Fatal("damaged archive accepted")
	}
}

func TestRetainedActiveFactsAndInFlightReleaseSurviveLaterCheckpoints(t *testing.T) {
	s, reg, key, path := retainedFixture(t, DefaultRetentionConfig())
	eligible := retainedEligibleFixture(t, s, reg, key)
	installed, err := s.Apply(context.Background(), "alpha", intentFixture(s, eligible, "install", "operator", "run"))
	if err != nil {
		t.Fatal(err)
	}
	policy := s.leases[installed.PolicyID]
	target := targetObject(eligible)
	targetWrite := responseFixture(t, s, reg, key, "target-before", target, "deny", true)
	normalWrite := responseFixture(t, s, reg, key, "normal-before", "own", "allow", true)
	inflight := responseFixture(t, s, reg, key, "pending-before-release", target, "deny", false)
	time.Sleep(protection.ProofLifetime + 20*time.Millisecond)
	// Move the committed authority clock with unrelated traffic; checkpoints
	// cannot invent an observation time merely because a process was idle.
	raw, b, status, body := proofFixture(reg, key, "unrelated-beta", "own", "beta", "allow", time.Now())
	gate, err := s.ObserveAndPrepareCurrent(raw, b, status, body)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.CompleteResponse(protection.ResponseWrite{AttemptID: gate.AttemptID, Status: status, Bytes: len(body), BodySHA: protection.BodyHash(body), Complete: true, CompletedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if err = s.Checkpoint(); err != nil {
		t.Fatal(err)
	}
	if _, kept := s.attempts[targetWrite.AttemptID]; kept {
		t.Fatal("completed old target was not folded")
	}
	if _, kept := s.attempts[normalWrite.AttemptID]; kept {
		t.Fatal("completed old baseline was not folded")
	}
	if _, kept := s.attempts[inflight.AttemptID]; !kept {
		t.Fatal("in-flight preparation was discarded")
	}
	if err = s.CompleteResponse(targetWrite); err != nil {
		t.Fatal("same-boot archived completion lost idempotency", err)
	}
	if _, err = s.Release(context.Background(), "alpha", policy.ID, "operator", "run", "release", policy.Generation); err != nil {
		t.Fatal(err)
	}
	inflight.CompletedAt = time.Now().UTC()
	if err = s.CompleteResponse(inflight); err != nil {
		t.Fatal(err)
	}
	outcome, err := s.Outcome("alpha", policy.ID, policy.Episode)
	if err != nil || outcome.Recovery.State != "unobserved" {
		t.Fatal("pre-release prepared write proved recovery", outcome, err)
	}
	responseFixture(t, s, reg, key, "after-target", target, "deny", true)
	responseFixture(t, s, reg, key, "after-normal", "own", "allow", true)
	before, err := s.Outcome("alpha", policy.ID, policy.Episode)
	if err != nil || before.Recovery.State != "observed_guard_baseline_restored" || before.Benign.Count != 1 || before.Target.Count != 2 {
		t.Fatal(before, err)
	}
	if err = s.Checkpoint(); err != nil {
		t.Fatal(err)
	}
	s.Close()
	afterStore, err := OpenRetained(path, reg, DefaultRetentionConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer afterStore.Close()
	after, err := afterStore.Outcome("alpha", policy.ID, policy.Episode)
	if err != nil {
		t.Fatal(err)
	}
	before.AsOfSequence = after.AsOfSequence
	if decisions.Hash(before) != decisions.Hash(after) {
		t.Fatal("later release or replay reclassified folded facts", before, after)
	}
}
func TestRetainedCrashProcessHelper(t *testing.T) {
	if os.Getenv("RA_RETENTION_CRASH_CHILD") != "1" {
		t.Skip("owned subprocess fixture only")
	}
	manifest, err := os.ReadFile(os.Getenv("RA_RETENTION_CRASH_REGISTRY"))
	if err != nil {
		t.Fatal(err)
	}
	reg, err := protection.Parse(manifest)
	if err != nil {
		t.Fatal(err)
	}
	s, err := OpenRetained(os.Getenv("RA_RETENTION_CRASH_PATH"), reg, DefaultRetentionConfig())
	if err != nil {
		t.Fatal(err)
	}
	s.retentionHook = func(stage string) error {
		if stage == os.Getenv("RA_RETENTION_CRASH_STAGE") {
			if err := os.WriteFile(os.Getenv("RA_RETENTION_CRASH_MARKER"), []byte(stage), 0600); err != nil {
				return err
			}
			select {}
		}
		return nil
	}
	if err = s.Checkpoint(); err != nil {
		t.Fatal(err)
	}
	t.Fatal("crash barrier was not reached")
}
func TestRetainedActualProcessKillAtPublicationBoundaries(t *testing.T) {
	for _, stage := range []string{"predecessor-synced", "checkpoint-published", "successor-synced", "current-published", "state-installed"} {
		t.Run(stage, func(t *testing.T) {
			s, reg, key, path := retainedFixture(t, DefaultRetentionConfig())
			responseFixture(t, s, reg, key, "completed-before-kill", "own", "allow", true)
			s.Close()
			dir := t.TempDir()
			registryPath := filepath.Join(dir, "registry.json")
			marker := filepath.Join(dir, "barrier")
			manifest := protection.Manifest{Schema: "protection-registry/1", Asset: reg.Asset(), Revision: "r1", TrustEpoch: reg.Epoch(), Enforcer: reg.Enforcer(), Tenants: []string{"alpha", "beta"}, Keys: map[string]string{"sdk": base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))}, Routes: reg.Routes()}
			raw, _ := json.Marshal(manifest)
			if err := os.WriteFile(registryPath, raw, 0600); err != nil {
				t.Fatal(err)
			}
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			command := exec.Command(executable, "-test.run=^TestRetainedCrashProcessHelper$", "-test.timeout=30s")
			command.Env = append(os.Environ(), "RA_RETENTION_CRASH_CHILD=1", "RA_RETENTION_CRASH_PATH="+path, "RA_RETENTION_CRASH_REGISTRY="+registryPath, "RA_RETENTION_CRASH_STAGE="+stage, "RA_RETENTION_CRASH_MARKER="+marker)
			log, err := os.Create(filepath.Join(dir, "child.log"))
			if err != nil {
				t.Fatal(err)
			}
			defer log.Close()
			command.Stdout = log
			command.Stderr = log
			if err = command.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if command.ProcessState == nil {
					_ = command.Process.Kill()
					_ = command.Wait()
				}
			})
			deadline := time.Now().Add(10 * time.Second)
			for {
				if _, err = os.Stat(marker); err == nil {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("child did not reach crash boundary; inspect", log.Name())
				}
				time.Sleep(10 * time.Millisecond)
			}
			if err = command.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			if err = command.Wait(); err == nil {
				t.Fatal("child was not actually killed")
			}
			again, err := OpenRetained(path, reg, DefaultRetentionConfig())
			if err != nil {
				t.Fatal("recover after actual kill", err)
			}
			defer again.Close()
			if again.totalEvents != 1 || again.totalAttempts != 1 || again.totalObservations != 1 || again.outcomeFailed {
				t.Fatal("kill lost or invented a completed response", again.OutcomeHealth())
			}
			responseFixture(t, again, reg, key, "after-actual-kill", "own", "allow", true)
		})
	}
}
