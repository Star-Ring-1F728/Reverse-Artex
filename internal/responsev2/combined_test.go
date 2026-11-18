package responsev2

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reverse-artex/internal/decisions"
	"reverse-artex/internal/protection"
	"sync"
	"testing"
	"time"
)

func combinedResponseFixture(t *testing.T, s *Store, reg *protection.Registry, key []byte, id, object, decision string) protection.ResponseWrite {
	t.Helper()
	raw, binding, status, body := proofFixture(reg, key, id, object, "alpha", decision, time.Now())
	gate, err := s.ObserveAndPrepareCurrent(raw, binding, status, body)
	if err != nil {
		t.Fatal(err)
	}
	if gate.Deny {
		status, body = 429, []byte("Too Many Requests\n")
	}
	return protection.ResponseWrite{AttemptID: gate.AttemptID, Status: status, Bytes: len(body), BodySHA: protection.BodyHash(body), Complete: true, CompletedAt: time.Now().UTC()}
}

func TestCombinedPreparationHasOnePreReleaseSyncAndReplaysWithPostWrite(t *testing.T) {
	s, reg, key, path := storeFixture(t)
	syncs := 0
	s.syncFile = func(f *os.File) error { syncs++; return f.Sync() }
	write := combinedResponseFixture(t, s, reg, key, "combined", "own", "allow")
	if syncs != 1 || s.sequence != 1 || len(s.events) != 1 || len(s.attempts) != 1 || len(s.observations) != 0 {
		t.Fatal("observation/preparation was not one durable pre-release fence", syncs, s.sequence)
	}
	if err := s.CompleteResponse(write); err != nil {
		t.Fatal(err)
	}
	if syncs != 2 || s.sequence != 2 || len(s.observations) != 1 {
		t.Fatal("server write lost separate commit", syncs, s.sequence)
	}
	head := s.head
	s.Close()
	reopened, err := Open(path, reg)
	if err != nil {
		t.Fatal("combined journal replay", err)
	}
	defer reopened.Close()
	if reopened.head != head || reopened.sequence != 2 || len(reopened.events) != 1 || len(reopened.attempts) != 1 || len(reopened.observations) != 1 || reopened.OutcomeHealth()["audit_available"] != true {
		t.Fatal("combined replay lost evidence, plan or observed write")
	}
}

func TestCombinedFailurePublishesNoPartialEvidenceOrAttempt(t *testing.T) {
	for _, kind := range []string{"sync", "proof", "event-limit", "attempt-limit", "expired", "future-high-water"} {
		t.Run(kind, func(t *testing.T) {
			s, reg, key, _ := storeFixture(t)
			at := time.Now()
			if kind == "expired" {
				at = at.Add(-10 * time.Second)
			}
			raw, binding, status, body := proofFixture(reg, key, "failed", "own", "alpha", "allow", at)
			switch kind {
			case "sync":
				s.syncFile = func(*os.File) error { return errors.New("injected durable write failure") }
			case "proof":
				body = []byte("untrusted substitution")
			case "event-limit":
				for i := 0; i < 8192; i++ {
					s.events[fmt.Sprint(i)] = Evidence{}
				}
			case "attempt-limit":
				for i := 0; i < 8192; i++ {
					s.attempts[fmt.Sprint(i)] = ResponseAttempt{}
				}
			case "future-high-water":
				s.high = at.Add(time.Minute)
			}
			events, attempts, cases, requests := len(s.events), len(s.attempts), len(s.cases), len(s.requests)
			if _, err := s.ObserveAndPrepareCurrent(raw, binding, status, body); err == nil {
				t.Fatal("failed combined fence accepted")
			}
			if len(s.events) != events || len(s.attempts) != attempts || len(s.cases) != cases || len(s.requests) != requests || s.sequence != 0 {
				t.Fatal("failed gate partially published state")
			}
		})
	}
}

func TestCombinedKeepsExistingObservedProofAndRejectsDuplicateAttempt(t *testing.T) {
	s, reg, key, _ := storeFixture(t)
	raw, binding, status, body := proofFixture(reg, key, "observed", "own", "alpha", "allow", time.Now())
	if _, err := s.ObserveCurrent(raw, binding, status, body); err != nil {
		t.Fatal(err)
	}
	gate, err := s.ObserveAndPrepareCurrent(raw, binding, status, body)
	if err != nil || gate.AttemptID == "" || s.sequence != 2 || len(s.events) != 1 {
		t.Fatal(gate, err)
	}
	before := s.sequence
	if _, err = s.ObserveAndPrepareCurrent(raw, binding, status, body); !errors.Is(err, ErrStale) || s.sequence != before {
		t.Fatal("combined gate replayed an already prepared response", err)
	}
}

func TestCombinedPolicyMaskReleaseAndRecoveryRemainBoundToServerWrites(t *testing.T) {
	s, reg, key, _ := storeFixture(t)
	v := eligibleFixture(t, s, reg, key)
	r, err := s.Apply(context.Background(), "alpha", intentFixture(s, v, "install", "operator", "run"))
	if err != nil {
		t.Fatal(err)
	}
	policy := s.Policies("alpha")[0]
	write := combinedResponseFixture(t, s, reg, key, "target", targetObject(v), "deny")
	if write.Status != 429 {
		t.Fatal("combined gate missed exact installed policy", write)
	}
	if err = s.CompleteResponse(write); err != nil {
		t.Fatal(err)
	}
	normal := combinedResponseFixture(t, s, reg, key, "normal", "own", "allow")
	if err = s.CompleteResponse(normal); err != nil {
		t.Fatal(err)
	}
	o, err := s.Outcome("alpha", r.PolicyID, policy.Episode)
	if err != nil || o.PolicyEffect != "masked_by_sdk" || o.Benign.State != "no_observed_collateral" || o.ClientReceipt != "not_observed" {
		t.Fatal(o, err)
	}
	inflight := combinedResponseFixture(t, s, reg, key, "before-release", targetObject(v), "deny")
	if _, err = s.Release(context.Background(), "alpha", policy.ID, "operator", "run", "release", policy.Generation); err != nil {
		t.Fatal(err)
	}
	if err = s.CompleteResponse(inflight); err != nil {
		t.Fatal(err)
	}
	o, _ = s.Outcome("alpha", r.PolicyID, policy.Episode)
	if o.Recovery.State != "unobserved" {
		t.Fatal("pre-release preparation was credited as recovery", o)
	}
	for _, args := range [][3]string{{"restored-target", targetObject(v), "deny"}, {"restored-normal", "own", "allow"}} {
		w := combinedResponseFixture(t, s, reg, key, args[0], args[1], args[2])
		if err = s.CompleteResponse(w); err != nil {
			t.Fatal(err)
		}
	}
	o, _ = s.Outcome("alpha", r.PolicyID, policy.Episode)
	if o.Recovery.State != "observed_guard_baseline_restored" {
		t.Fatal(o)
	}
}

func TestCombinedPendingWriteRestartStillBlocksAndRejectsOldBoot(t *testing.T) {
	s, reg, key, path := storeFixture(t)
	w := combinedResponseFixture(t, s, reg, key, "pending", "own", "allow")
	s.Close()
	reopened, err := Open(path, reg)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if reopened.OutcomeHealth()["audit_available"] != false {
		t.Fatal("missing server write became healthy")
	}
	if err = reopened.CompleteResponse(w); err == nil {
		t.Fatal("old-boot response accepted")
	}
	raw, b, status, body := proofFixture(reg, key, "next", "own", "alpha", "allow", time.Now())
	if _, err = reopened.ObserveAndPrepareCurrent(raw, b, status, body); err == nil {
		t.Fatal("unknown prior write did not fence new request")
	}
}

func TestCombinedReplayRejectsRehashedCrossBoundRecords(t *testing.T) {
	for _, kind := range []string{"case-revision", "evidence-id", "tenant", "timestamp", "preclaimed-write"} {
		t.Run(kind, func(t *testing.T) {
			s, reg, key, path := storeFixture(t)
			w := combinedResponseFixture(t, s, reg, key, "replay", "own", "allow")
			if err := s.CompleteResponse(w); err != nil {
				t.Fatal(err)
			}
			s.Close()
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			lines := bytes.Split(bytes.TrimSpace(raw), []byte{'\n'})
			records := make([]record, len(lines))
			for i, line := range lines {
				if err = json.Unmarshal(line, &records[i]); err != nil {
					t.Fatal(err)
				}
			}
			r := &records[0]
			switch kind {
			case "case-revision":
				r.Case.Revision++
				r.Case.SHA = caseSHA(*r.Case)
				r.Attempt.CaseSHA = r.Case.SHA
			case "evidence-id":
				r.Attempt.EvidenceID = decisions.Hash("another-proof")
			case "tenant":
				r.Attempt.Scope.Tenant = "beta"
			case "timestamp":
				r.Attempt.PreparedAt = r.At.Add(time.Nanosecond)
			case "preclaimed-write":
				r.Observation = records[1].Observation
			}
			var rewritten []byte
			previous := ""
			for i := range records {
				records[i].Previous = previous
				records[i].SHA = recordSHA(records[i])
				previous = records[i].SHA
				line, _ := json.Marshal(records[i])
				rewritten = append(rewritten, line...)
				rewritten = append(rewritten, '\n')
			}
			if err = os.WriteFile(path, rewritten, 0600); err != nil {
				t.Fatal(err)
			}
			bad, err := Open(path, reg)
			if err == nil {
				bad.Close()
				t.Fatal("rehashed invalid combined binding replayed", kind)
			}
		})
	}
}

func TestConcurrentCombinedPreparationSamplesClockUnderLockAndReplays(t *testing.T) {
	s, reg, key, path := storeFixture(t)
	const count = 32
	var group sync.WaitGroup
	errs := make(chan error, count)
	for i := 0; i < count; i++ {
		raw, b, status, body := proofFixture(reg, key, fmt.Sprint("parallel-", i), "own", "alpha", "allow", time.Now())
		group.Add(1)
		go func() {
			defer group.Done()
			g, err := s.ObserveAndPrepareCurrent(raw, b, status, body)
			if err == nil {
				err = s.CompleteResponse(protection.ResponseWrite{AttemptID: g.AttemptID, Status: status, Bytes: len(body), BodySHA: protection.BodyHash(body), Complete: true, CompletedAt: time.Now().UTC()})
			}
			errs <- err
		}()
	}
	group.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if s.sequence != count*2 {
		t.Fatal(s.sequence)
	}
	s.Close()
	reopened, err := Open(path, reg)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if len(reopened.events) != count || len(reopened.attempts) != count || len(reopened.observations) != count || reopened.OutcomeHealth()["audit_available"] != true {
		t.Fatal("concurrent combined replay incomplete")
	}
}
