package responsev2

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestL3PrefetchedObservationsKeepModelActionsAndOwnedRelease(t *testing.T) {
	s, reg, key, path := storeFixture(t)
	v := eligibleFixture(t, s, reg, key)
	m := newMockL3(t)
	cfg := l3Cfg(m)
	cfg.Prefetch = true
	if cfg.Validate() == nil {
		t.Fatal("prefetch without bounded bundled context was accepted")
	}
	cfg.BundleContext = true
	engine, err := NewL3(s, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	checkRun := func(id, mode, source string, calls int) L3Run {
		t.Helper()
		if _, err := engine.Enqueue(L3Request{ID: id, Tenant: "alpha", CaseID: v.Case.ID, CaseSHA: v.Case.SHA, Mode: mode, SourceRun: source}); err != nil {
			t.Fatal(err)
		}
		run := awaitL3(t, s, id)
		if run.Status != "completed" || run.Calls != calls || len(run.Steps) != calls*2 || run.Assessment == nil || len(run.Assessment.Evidence) != len(v.Evidence) {
			t.Fatalf("unexpected prefetched %s run: %+v", mode, run)
		}
		for i, step := range run.Steps {
			if step.Number != i+1 || step.State != "done" || step.ResultSHA == "" {
				t.Fatal("incomplete or misnumbered real observation", run.Steps)
			}
			if i%2 == 0 {
				if step.Executor != "server" || (step.Tool != "get_investigation_context" && step.Tool != "get_defense_outcome") {
					t.Fatal("server executed a model decision", step)
				}
			} else if step.Executor != "" {
				t.Fatal("model decision was not recorded as such", step)
			}
		}
		if run.Deadline.Sub(run.Started) != 30*time.Second {
			t.Fatal("prefetch changed the run deadline", run)
		}
		return run
	}
	checkRun("prefetch-analyze", "analyze", "", 1)
	contained := checkRun("prefetch-contain", "contain", "", 2)
	if contained.Binding == nil || contained.Steps[1].Tool != "apply_containment" {
		t.Fatal("model did not apply an exact candidate", contained)
	}
	assertCandidateLinks(t, m, "get_investigation_context", v, true)
	joined, err := s.Apply(context.Background(), "alpha", Intent{ID: "operator", CaseID: v.Case.ID, CaseSHA: v.Case.SHA, CandidateID: contained.ActionCandidate, Owner: "operator", Run: "human", Epoch: s.Epoch()})
	if err != nil || joined.PolicyID != contained.Binding.PolicyID {
		t.Fatal(joined, err)
	}
	released := checkRun("prefetch-release", "release", "prefetch-contain", 2)
	if released.Receipt == nil || released.Receipt.State != "retained_by_other_owner" || released.Steps[1].Tool != "release_owned_claim" {
		t.Fatal("release did not retain the other owner", released)
	}
	policies := s.Policies("alpha")
	if len(policies) != 1 || len(policies[0].Claims) != 1 || policies[0].Claims[0].Owner != "operator" {
		t.Fatal("prefetch altered ownership", policies)
	}
	if m.calls.Load() != 5 {
		t.Fatal("deterministic reads consumed model calls", m.calls.Load())
	}
	m.mu.Lock()
	messages := m.modelMessages
	m.mu.Unlock()
	for i, history := range messages {
		modelCalls, outcomes, hostContexts := 0, 0, 0
		for _, message := range history {
			modelCalls += len(message.Calls)
			if message.Role == "user" && strings.HasPrefix(message.Content, l3HostObservationPrefix) {
				tool, _, _ := mockL3Observation(message)
				if tool == "get_defense_outcome" {
					outcomes++
				}
				if tool == "get_investigation_context" {
					hostContexts++
				}
			}
		}
		expectedActions := 0
		if i == 2 || i == 4 {
			expectedActions = 1
		}
		if hostContexts != 1 || outcomes != expectedActions || modelCalls != expectedActions {
			t.Fatalf("model history faked a read or omitted the actual outcome: call=%d host=%d outcomes=%d calls=%d", i, hostContexts, outcomes, modelCalls)
		}
	}
	engine.Close()
	s.Close()
	reopened, err := Open(path, reg)
	if err != nil {
		t.Fatal("prefetched journal did not replay", err)
	}
	defer reopened.Close()
	restored, err := reopened.L3Run("alpha", "prefetch-release")
	if err != nil || restored.Status != "completed" || restored.Calls != 2 || len(restored.Steps) != 4 || restored.Steps[0].Executor != "server" || restored.Steps[2].Executor != "server" || restored.Assessment == nil {
		t.Fatal("replay lost model/server accounting or completed assessment", restored, err)
	}
	restoredEngine, err := NewL3(reopened, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer restoredEngine.Close()
	duplicate, err := restoredEngine.Enqueue(released.Request)
	if err != nil || duplicate.Status != "completed" || m.calls.Load() != 5 {
		t.Fatal("completed prefetched run redispatched after restart", duplicate, err)
	}
	policies = reopened.Policies("alpha")
	if len(policies) != 1 || len(policies[0].Claims) != 1 || policies[0].Claims[0].Owner != "operator" {
		t.Fatal("replay changed the retained owner", policies)
	}
}

func TestL3CompletionRechecksCancellationDeadlineEpochAndCaseAtomically(t *testing.T) {
	for _, change := range []string{"none", "cancel", "deadline", "epoch", "case", "terminal"} {
		t.Run(change, func(t *testing.T) {
			s, reg, key, _ := storeFixture(t)
			v := eligibleFixture(t, s, reg, key)
			m := newMockL3(t)
			if _, err := s.l3Start(L3Request{ID: "finish", Tenant: "alpha", CaseID: v.Case.ID, CaseSHA: v.Case.SHA, Mode: "analyze"}, l3Cfg(m)); err != nil {
				t.Fatal(err)
			}
			if err := s.l3Update("finish", func(r *L3Run) { r.Status = "running" }); err != nil {
				t.Fatal(err)
			}
			if _, _, err := s.l3Pin("finish", false); err != nil {
				t.Fatal(err)
			}
			switch change {
			case "cancel":
				s.l3Cancel("alpha", "finish")
			case "deadline":
				s.l3Update("finish", func(r *L3Run) { r.Deadline = time.Now().Add(-time.Second) })
			case "epoch":
				s.Pause(true)
			case "case":
				observeFixture(t, s, reg, key, "later", "three", "alpha", "allow", time.Now())
			case "terminal":
				s.l3Update("finish", func(r *L3Run) { r.Status = "failed" })
			}
			err := s.l3Complete("finish", L3Assessment{Classification: "needs_review", Summary: "Signed observation requires review.", Evidence: []string{v.Evidence[0].ID}}, false)
			run, readErr := s.L3Run("alpha", "finish")
			if readErr != nil {
				t.Fatal(readErr)
			}
			if change == "none" {
				if err != nil || run.Status != "completed" || run.Assessment == nil {
					t.Fatal(run, err)
				}
			} else if err == nil || run.Status == "completed" || run.Assessment != nil {
				t.Fatal("invalid run completed after final pin", run, err)
			}
		})
	}
}

func TestL3PrefetchStillRejectsForgedChoicesAndStaleRuns(t *testing.T) {
	for _, change := range []string{"candidate", "refs", "case", "cancel", "epoch"} {
		t.Run(change, func(t *testing.T) {
			s, reg, key, _ := storeFixture(t)
			v := eligibleFixture(t, s, reg, key)
			m := newMockL3(t)
			cfg := l3Cfg(m)
			cfg.BundleContext, cfg.Prefetch = true, true
			engine, err := NewL3(s, cfg, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer engine.Close()
			if change == "candidate" || change == "refs" {
				m.invalid = change
			} else {
				m.before = func(n int) {
					if n != 1 {
						return
					}
					switch change {
					case "case":
						observeFixture(t, s, reg, key, "later", "three", "alpha", "allow", time.Now())
					case "cancel":
						engine.Cancel("alpha", "prefetch")
					case "epoch":
						s.Pause(true)
					}
				}
			}
			engine.Enqueue(L3Request{ID: "prefetch", Tenant: "alpha", CaseID: v.Case.ID, CaseSHA: v.Case.SHA, Mode: "contain"})
			run := awaitL3(t, s, "prefetch")
			if run.Status == "completed" || run.Assessment != nil {
				t.Fatal(run)
			}
			if change != "refs" && len(s.Policies("alpha")) != 0 {
				t.Fatal("invalid selection installed a policy", run)
			}
		})
	}
}
