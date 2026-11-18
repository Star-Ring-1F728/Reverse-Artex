package responsev2

import (
	"context"
	"encoding/json"
	"fmt"
	"reverse-artex/internal/decisions"
	"testing"
	"time"
)

func TestStrategyUnderBurstUsesCompleteHistoryAndCurrentExactCandidates(t *testing.T) {
	for _, priorAllow := range []bool{false, true} {
		t.Run(fmt.Sprint(priorAllow), func(t *testing.T) {
			s, reg, key, _ := storeFixture(t)
			v := eligibleFixture(t, s, reg, key)
			if priorAllow {
				observeFixture(t, s, reg, key, "earlier-allowed", "one", "alpha", "allow", time.Now())
			}
			for i := 0; i < 40; i++ {
				object := "one"
				if i%2 != 0 {
					object = "two"
				}
				observeFixture(t, s, reg, key, fmt.Sprintf("burst-%d", i), object, "alpha", "deny", time.Now())
			}
			v, _ = s.Case("alpha", v.Case.ID)
			p := strategyFixture(t, s, v.Case.ID)
			want := 2
			if priorAllow {
				want = 1
			}
			if p.Next != "contain_exact" || len(p.Candidates) != want || len(v.Evidence) != 32 || v.Case.Revision <= 32 {
				t.Fatal("bounded context stopped complete verified history analysis", p)
			}
			var meta map[string]any
			json.Unmarshal(mustJSON(p), &meta)
			if meta["complete_case_history"] != true || meta["omitted_observations"].(float64) != float64(v.Case.Revision-32) {
				t.Fatal("missing sampled-window provenance", meta)
			}
			for _, c := range v.Candidates {
				if priorAllow && c.Scope.Resource == decisions.Hash("one") && strategyAllows(p, c.ID) {
					t.Fatal("discarded allow observation authorized containment")
				}
			}
		})
	}
}

func TestStrategyIncompleteHistoryStillHoldsAfterBurst(t *testing.T) {
	s, reg, key, _ := storeFixture(t)
	v := eligibleFixture(t, s, reg, key)
	for i := 0; i < 40; i++ {
		observeFixture(t, s, reg, key, fmt.Sprintf("burst-%d", i), "one", "alpha", "deny", time.Now())
	}
	// A detached cache projection models a missing retained event. This never
	// alters the authoritative journal or attempts a policy write.
	s.mu.Lock()
	view, err := s.viewLocked("alpha", v.Case.ID, time.Now())
	projection := &Store{sequence: s.sequence, epoch: s.epoch, histories: s.histories,
		leases: s.leases, deadlines: s.deadlines, events: make(map[string]Evidence, len(s.events))}
	for id, e := range s.events {
		projection.events[id] = e
	}
	delete(projection.events, v.Evidence[0].ID)
	p := projection.strategyLocked(view, time.Now())
	s.mu.Unlock()
	if err != nil || p.Next != "review_evidence" || len(p.Candidates) != 0 {
		t.Fatal("incomplete history gained action authority", p, err)
	}
}

func TestStrategyDoesNotRecommendScopesInReleaseCooldown(t *testing.T) {
	s, reg, key, _ := storeFixture(t)
	v := eligibleFixture(t, s, reg, key)
	for i, c := range v.Candidates {
		owner := fmt.Sprintf("operator-%d", i)
		r, err := s.Apply(context.Background(), "alpha", Intent{ID: "install-" + owner, CaseID: v.Case.ID, CaseSHA: v.Case.SHA, CandidateID: c.ID, Owner: "operator", Run: owner, Epoch: s.Epoch()})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = s.Release(context.Background(), "alpha", r.PolicyID, "operator", owner, "release-"+owner, r.Generation); err != nil {
			t.Fatal(err)
		}
	}
	responseFixture(t, s, reg, key, "restored-one", "one", "deny", true)
	responseFixture(t, s, reg, key, "restored-two", "two", "deny", true)
	responseFixture(t, s, reg, key, "restored-own", "own", "allow", true)
	p := strategyFixture(t, s, v.Case.ID)
	if p.Next != "wait_cooldown" || len(p.Candidates) != 0 {
		t.Fatal("strategy recommended an action the lease gate will reject", p)
	}
}
