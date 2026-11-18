package responsev2

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

func TestPolicyCommandCapacityPreservesOwnedRelease(t *testing.T) {
	s, reg, key, path := storeFixture(t)
	ctx := context.Background()
	v := eligibleFixture(t, s, reg, key)
	first, err := s.Apply(ctx, "alpha", intentFixture(s, v, "install-first", "operator", "first"))
	if err != nil {
		t.Fatal(err)
	}
	current, err := s.Apply(ctx, "alpha", intentFixture(s, v, "install-other", "operator", "other"))
	if err != nil {
		t.Fatal(err)
	}
	// Fill the admission counter without making the regression depend on the
	// host's ability to sync thousands of records before the lease expires.
	for n := len(s.intents); n < policyInstallCommandLimit; n++ {
		s.intents[fmt.Sprintf("occupied-%d", n)] = "historical receipt"
	}
	if _, err = s.Apply(ctx, "alpha", intentFixture(s, v, "new-install", "operator", "new")); !errors.Is(err, ErrStale) {
		t.Fatal("installation exceeded the budget", err)
	}
	for _, check := range []struct {
		tenant, run string
		generation  int
	}{
		{"beta", "first", current.Generation},
		{"alpha", "unowned", current.Generation},
		{"alpha", "first", first.Generation},
	} {
		if _, err = s.Release(ctx, check.tenant, current.PolicyID, "operator", check.run, "release-first", check.generation); !errors.Is(err, ErrStale) {
			t.Fatal("release authority fence changed", err)
		}
	}
	budget := s.OutcomeHealth()["policy_command_budget"].(map[string]any)
	if budget["recorded"] != policyInstallCommandLimit || budget["new_installs_at_limit"] != true {
		t.Fatal("rejected releases used capacity")
	}
	removed, err := s.Release(ctx, "alpha", current.PolicyID, "operator", "first", "release-first", current.Generation)
	if err != nil || removed.State != "retained_by_other_owner" {
		t.Fatal("first owner could not recover at capacity", removed, err)
	}
	last, err := s.Release(ctx, "alpha", current.PolicyID, "operator", "other", "release-other", removed.Generation)
	if err != nil || last.State != "no_effective_policy" || len(s.Policies("alpha")) != 0 {
		t.Fatal("last owner could not recover at capacity", last, err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path, reg)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	again, err := reopened.Release(ctx, "alpha", current.PolicyID, "operator", "other", "release-other", removed.Generation)
	if err != nil || again != last || len(reopened.Policies("alpha")) != 0 {
		t.Fatal("durable release replay changed", again, err)
	}
}
