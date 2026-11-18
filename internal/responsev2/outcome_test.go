package responsev2

import (
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"reverse-artex/internal/decisions"
	"reverse-artex/internal/protection"
	"testing"
	"time"
)

func responseFixture(t *testing.T, s *Store, reg *protection.Registry, key ed25519.PrivateKey, id, object, decision string, finish bool) protection.ResponseWrite {
	t.Helper()
	at := time.Now()
	raw, b, status, body := proofFixture(reg, key, id, object, "alpha", decision, at)
	if _, err := s.Observe(raw, b, status, body, at); err != nil {
		t.Fatal(err)
	}
	gate, err := s.PrepareResponse("alpha", decisions.Hash(raw), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if gate.Deny {
		status = 429
		body = []byte("Too Many Requests\n")
	}
	write := protection.ResponseWrite{AttemptID: gate.AttemptID, Status: status, Bytes: len(body), BodySHA: protection.BodyHash(body), Complete: true, CompletedAt: time.Now().UTC()}
	if finish {
		if err = s.CompleteResponse(write); err != nil {
			t.Fatal(err)
		}
	}
	return write
}
func targetObject(v CaseView) string {
	for _, object := range []string{"one", "two"} {
		if decisions.Hash(object) == v.Candidates[0].Scope.Resource {
			return object
		}
	}
	return ""
}
func TestOutcomeSeparatesInstallMaskReleaseAndBaselineRecovery(t *testing.T) {
	s, reg, key, path := storeFixture(t)
	v := eligibleFixture(t, s, reg, key)
	r, err := s.Apply(context.Background(), "alpha", intentFixture(s, v, "install", "operator", "run"))
	if err != nil {
		t.Fatal(err)
	}
	policy := s.Policies("alpha")[0]
	o, _ := s.Outcome("alpha", r.PolicyID, policy.Episode)
	if o.Installation != "installed_locally" || o.Target.State != "unknown" || o.Recovery.State != "unknown" {
		t.Fatal(o)
	}
	responseFixture(t, s, reg, key, "target", targetObject(v), "deny", true)
	responseFixture(t, s, reg, key, "normal", "own", "allow", true)
	o, _ = s.Outcome("alpha", r.PolicyID, policy.Episode)
	if o.Target.State != "observed_denied" || o.PolicyEffect != "masked_by_sdk" || o.Benign.State != "no_observed_collateral" || o.ClientReceipt != "not_observed" {
		t.Fatal(o)
	}
	// Prepare before removal; completion afterwards must not count as recovery.
	inflight := responseFixture(t, s, reg, key, "inflight", targetObject(v), "deny", false)
	released, err := s.Release(context.Background(), "alpha", r.PolicyID, "operator", "run", "remove", policy.Generation)
	if err != nil || released.State != "no_effective_policy" {
		t.Fatal(released, err)
	}
	inflight.CompletedAt = time.Now().UTC()
	if err = s.CompleteResponse(inflight); err != nil {
		t.Fatal(err)
	}
	o, _ = s.Outcome("alpha", r.PolicyID, policy.Episode)
	if o.Recovery.State != "unobserved" || o.RecoveryReason != "explicit_last_claim_release" {
		t.Fatal(o)
	}
	responseFixture(t, s, reg, key, "restored-target", targetObject(v), "deny", true)
	o, _ = s.Outcome("alpha", r.PolicyID, policy.Episode)
	if o.Recovery.State != "policy_absence_observed_benign_unverified" {
		t.Fatal(o)
	}
	responseFixture(t, s, reg, key, "restored-normal", "own", "allow", true)
	o, _ = s.Outcome("alpha", r.PolicyID, policy.Episode)
	if o.Recovery.State != "observed_guard_baseline_restored" {
		t.Fatal(o)
	}
	s.Close()
	reopened, err := Open(path, reg)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	again, err := reopened.Outcome("alpha", r.PolicyID, policy.Episode)
	if err != nil || decisions.Hash(again) != decisions.Hash(o) {
		t.Fatal("outcome changed on replay", again, err)
	}
	if _, err = reopened.Outcome("beta", r.PolicyID, policy.Episode); err == nil {
		t.Fatal("tenant leak")
	}
}
func TestOutcomePendingCrashAndSyncFailureFailClosed(t *testing.T) {
	for _, kind := range []string{"pending-restart", "sync-failure", "conflicting-report", "old-boot"} {
		t.Run(kind, func(t *testing.T) {
			s, reg, key, path := storeFixture(t)
			v := eligibleFixture(t, s, reg, key)
			r, err := s.Apply(context.Background(), "alpha", intentFixture(s, v, "install", "operator", "run"))
			if err != nil {
				t.Fatal(err)
			}
			w := responseFixture(t, s, reg, key, "pending", targetObject(v), "deny", false)
			switch kind {
			case "pending-restart", "old-boot":
				s.Close()
				s, err = Open(path, reg)
				if err != nil {
					t.Fatal(err)
				}
				defer s.Close()
				if err = s.CompleteResponse(w); err == nil {
					t.Fatal("old boot completion accepted")
				}
			case "sync-failure":
				s.syncFile = func(*os.File) error { return errors.New("disk failure") }
				if err = s.CompleteResponse(w); err == nil {
					t.Fatal("unsynced result accepted")
				}
				if _, ok := s.observations[w.AttemptID]; ok {
					t.Fatal("unsynced observation published")
				}
			case "conflicting-report":
				if err = s.CompleteResponse(w); err != nil {
					t.Fatal(err)
				}
				if err = s.CompleteResponse(w); err != nil {
					t.Fatal("exact retry not idempotent", err)
				}
				w.Bytes++
				if err = s.CompleteResponse(w); err == nil {
					t.Fatal("conflicting report accepted")
				}
			}
			if s.OutcomeHealth()["audit_available"] != false {
				t.Fatal("audit health stayed available")
			}
			if _, err = s.Apply(context.Background(), "alpha", intentFixture(s, v, "later", "operator", "other")); err == nil {
				t.Fatal("audit failure allowed action")
			}
			_ = r
		})
	}
}
func TestOutcomeCollateralPausesAndDominatesMaskedEvents(t *testing.T) {
	s, reg, key, _ := storeFixture(t)
	v := eligibleFixture(t, s, reg, key)
	r, _ := s.Apply(context.Background(), "alpha", intentFixture(s, v, "install", "operator", "run"))
	before := s.Epoch()
	responseFixture(t, s, reg, key, "authorized-now", targetObject(v), "allow", true)
	responseFixture(t, s, reg, key, "denied-later", targetObject(v), "deny", true)
	o, _ := s.Outcome("alpha", r.PolicyID, "")
	if !s.paused || s.Epoch() != before+1 || o.PolicyEffect != "observed_collateral" || o.Benign.State != "observed_collateral" {
		t.Fatal(o, s.paused, s.Epoch())
	}
}
func TestOutcomePartialMalformedAndRetainedClaimsNeverProveRecovery(t *testing.T) {
	s, reg, key, _ := storeFixture(t)
	v := eligibleFixture(t, s, reg, key)
	r, _ := s.Apply(context.Background(), "alpha", intentFixture(s, v, "install", "operator", "run"))
	_, err := s.Apply(context.Background(), "alpha", intentFixture(s, v, "join", "decisions", "other"))
	if err != nil {
		t.Fatal(err)
	}
	p := s.Policies("alpha")[0]
	released, err := s.Release(context.Background(), "alpha", r.PolicyID, "operator", "run", "remove", p.Generation)
	if err != nil || released.State != "retained_by_other_owner" {
		t.Fatal(err, released)
	}
	w := responseFixture(t, s, reg, key, "partial", targetObject(v), "deny", false)
	w.Complete = false
	w.Error = true
	w.Bytes = 0
	w.BodySHA = protection.BodyHash(nil)
	if err = s.CompleteResponse(w); err != nil {
		t.Fatal(err)
	}
	o, _ := s.Outcome("alpha", r.PolicyID, "")
	if o.UnknownResponses != 1 || o.Target.State != "unknown" || o.Recovery.State != "retained_by_other_owner" {
		t.Fatal(o)
	}
	w = responseFixture(t, s, reg, key, "invalid", targetObject(v), "deny", false)
	w.Complete = true
	w.Error = true
	if err = s.CompleteResponse(w); err == nil {
		t.Fatal("complete+error accepted")
	}
}
func TestNaturalExpiryIsDistinctAndEmptyTrafficIsUnobserved(t *testing.T) {
	s, reg, key, _ := storeFixture(t)
	v := eligibleFixture(t, s, reg, key)
	r, _ := s.Apply(context.Background(), "alpha", intentFixture(s, v, "install", "operator", "run"))
	s.mu.Lock()
	o, err := s.outcomeLocked("alpha", r.PolicyID, "", time.Now().Add(3*time.Minute))
	s.mu.Unlock()
	if err != nil || o.RecoveryReason != "natural_expiry" || o.Recovery.State != "unobserved" || o.Release.State != "unknown" {
		t.Fatal(o, err)
	}
}
