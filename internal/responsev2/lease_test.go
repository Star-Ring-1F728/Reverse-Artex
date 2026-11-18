package responsev2

import (
	"context"
	"reverse-artex/internal/decisions"
	"testing"
	"time"
)

func TestLeaseOnlyNewIndependentViolationsRenewAndHardEndCaps(t *testing.T) {
	s, reg, key, _ := storeFixture(t)
	v := eligibleFixture(t, s, reg, key)
	// Choose a fixed resource scope from the first eligible candidate.
	selected := v.Candidates[0]
	originalResource := "one"
	if selected.Scope.Resource == decisions.Hash("two") {
		originalResource = "two"
	}
	receipt, err := s.Apply(context.Background(), "alpha", intentFixture(s, v, "first", "operator", "run"))
	if err != nil {
		t.Fatal(err)
	}
	initial := s.leases[receipt.PolicyID]
	// A different intent for the same owner's consumed evidence is a receipt,
	// not a policy update or renewal.
	again, err := s.Apply(context.Background(), "alpha", intentFixture(s, v, "same-proof", "operator", "run"))
	if err != nil || !again.Expires.Equal(initial.Expires) || s.leases[receipt.PolicyID].Generation != initial.Generation {
		t.Fatal("same evidence changed policy", again, err)
	}
	start := initial.Issued
	for n, offset := range []time.Duration{40 * time.Second, 80 * time.Second, 119 * time.Second} {
		at := start.Add(offset)
		// Keep independent corroboration fresh, and make the chosen exact scope
		// newest. This is a deterministic local time fixture, not real clock edits.
		other := "one"
		if originalResource == "one" {
			other = "two"
		}
		observeFixture(t, s, reg, key, "corroboration-"+string(rune('a'+n)), other, "alpha", "deny", at.Add(-time.Millisecond))
		g := observeFixture(t, s, reg, key, "renewal-"+string(rune('a'+n)), originalResource, "alpha", "deny", at)
		s.mu.Lock()
		next, err := s.viewLocked("alpha", g.CaseID, at)
		if err != nil {
			s.mu.Unlock()
			t.Fatal(err)
		}
		var candidate string
		for _, c := range next.Candidates {
			if c.Scope.Resource == selected.Scope.Resource {
				candidate = c.ID
			}
		}
		_, err = s.applyLocked(context.Background(), "alpha", Intent{ID: "renew-" + string(rune('a'+n)), CaseID: next.Case.ID, CaseSHA: next.Case.SHA, CandidateID: candidate, Owner: "operator", Run: "run", Epoch: s.epoch}, at)
		s.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
	}
	l := s.leases[receipt.PolicyID]
	if !l.Expires.Equal(l.HardEnd) || l.HardEnd.Sub(l.Issued) != 2*time.Minute || l.Cooldown.Sub(l.HardEnd) != time.Minute {
		t.Fatal("episode cap broken", l)
	}
	if s.gate(v.Case, l.Scope, l.HardEnd.Add(time.Millisecond)).Deny {
		t.Fatal("expired policy still enforced")
	}
	if s.check(start.Add(-time.Minute)) == nil {
		t.Fatal("clock rollback admitted mutation")
	}
}
