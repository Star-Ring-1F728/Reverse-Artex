package responsev2

import (
	"fmt"
	"testing"
	"time"
)

func TestNativeCoalescedRenewalHonorsHardEndAndKeepsScopeFences(t *testing.T) {
	s, reg, key, _ := storeFixture(t)
	v := eligibleFixture(t, s, reg, key)
	base := time.Now()
	s.mu.Lock()
	err := s.nativeLocked("alpha", v.Case.ID, v.Case.SHA, base)
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	for step := 1; step <= 19; step++ {
		at := base.Add(time.Duration(step) * 6 * time.Second)
		observeFixture(t, s, reg, key, fmt.Sprintf("renew-one-%d", step), "one", "alpha", "deny", at.Add(-time.Millisecond))
		g := observeFixture(t, s, reg, key, fmt.Sprintf("renew-two-%d", step), "two", "alpha", "deny", at)
		s.mu.Lock()
		err := s.nativeLocked("alpha", g.CaseID, g.CaseSHA, at)
		s.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, l := range s.leases {
		if l.Expires.After(l.HardEnd) || l.HardEnd.Sub(l.Expires) > nativeRenewalInterval || l.HardEnd.Sub(l.Issued) != 2*time.Minute || len(l.Consumed) >= 128 || s.gate(v.Case, l.Scope, l.HardEnd).Deny {
			t.Fatal("native hard end or renewal budget", l)
		}
	}
	before := s.sequence
	s.mu.Lock()
	err = s.nativeLocked("beta", v.Case.ID, v.Case.SHA, base.Add(115*time.Second))
	s.mu.Unlock()
	if err == nil || s.sequence != before {
		t.Fatal("wrong tenant gained a coalesced path", err)
	}
}

func TestCaseViewValueCopiesCannotMutateStoredEvidenceOrReferences(t *testing.T) {
	s, reg, key, _ := storeFixture(t)
	v := eligibleFixture(t, s, reg, key)
	first := v.Evidence[0]
	v.Evidence[0].Proof = "changed"
	v.Evidence[0].Scope.Tenant = "beta"
	v.Evidence[0].Binding.Nonce = "changed"
	v.Case.Refs[0] = "changed"
	again, err := s.Case("alpha", v.Case.ID)
	if err != nil || again.Evidence[0].Proof != first.Proof || again.Evidence[0].Scope.Tenant != first.Scope.Tenant || again.Evidence[0].Binding.Nonce != first.Binding.Nonce || again.Case.Refs[0] == "changed" {
		t.Fatal("case view aliases store", err)
	}
}

func TestNativeBurstDoesNotConsumePerEpisodeBudgetForRedundantRenewals(t *testing.T) {
	s, reg, key, _ := storeFixture(t)
	v := eligibleFixture(t, s, reg, key)
	if err := s.Native("alpha", v.Case.ID, v.Case.SHA); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 50; i++ {
		object := "one"
		if i%2 != 0 {
			object = "two"
		}
		g := observeFixture(t, s, reg, key, fmt.Sprintf("native-burst-%d", i), object, "alpha", "deny", time.Now())
		if err := s.Native("alpha", g.CaseID, g.CaseSHA); err != nil {
			t.Fatal(err)
		}
	}
	if len(s.intents) != 2 {
		t.Fatalf("burst created %d intents for two already covered scopes", len(s.intents))
	}
	for _, policy := range s.Policies("alpha") {
		if len(policy.Consumed) != 1 {
			t.Fatalf("burst consumed renewal budget: %d", len(policy.Consumed))
		}
	}
}
