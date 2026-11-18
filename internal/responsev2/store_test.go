package responsev2

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reverse-artex/internal/decisions"
	"reverse-artex/internal/protection"
	"strings"
	"testing"
	"time"
)

func storeFixture(t *testing.T) (*Store, *protection.Registry, ed25519.PrivateKey, string) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	reg, err := protection.New(protection.Manifest{Schema: "protection-registry/1", Asset: "app", Revision: "r1", TrustEpoch: "e1", Enforcer: "edge1", Tenants: []string{"alpha", "beta"}, Keys: map[string]string{"sdk": base64.RawURLEncoding.EncodeToString(pub)}, Routes: []protection.Route{{ID: "object", Template: "/legacy/objects/{id}", Namespace: "objects", Mode: "enforce", MaxBody: 1024, AuthAdapter: "lab-hmac-v1", Resolver: "snapshot-v1"}}})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "v2.jsonl")
	s, err := Open(path, reg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, reg, key, path
}
func proofFixture(reg *protection.Registry, key ed25519.PrivateKey, id, object, tenant, decision string, at time.Time) (string, protection.RequestBinding, int, []byte) {
	b := protection.RequestBinding{RequestID: id, Nonce: "nonce-" + id, Method: "GET", Route: "object", Tenant: tenant, Principal: "principal", Session: "session", Resource: decisions.Hash(object), Started: at.Add(-time.Millisecond)}
	body := []byte("{\"error\":\"forbidden\"}")
	status := 403
	if decision == "allow" {
		body = []byte("{\"object\":\"own\"}")
		status = 200
	}
	p := protection.Proof{Schema: "release-proof/1", KeyID: "sdk", Asset: reg.Asset(), Registry: reg.Digest(), Epoch: reg.Epoch(), RequestID: b.RequestID, Nonce: b.Nonce, Method: b.Method, Route: b.Route, Tenant: b.Tenant, Principal: b.Principal, Session: b.Session, Resource: b.Resource, Action: "read", AuthzRevision: "acl1", ContentRevision: "v1", Decision: decision, Status: status, BodyLength: len(body), BodySHA: protection.BodyHash(body), Issued: at.UnixMilli(), Expires: at.Add(5 * time.Second).UnixMilli()}
	raw, _ := json.Marshal(p)
	wire, _ := json.Marshal(protection.Envelope{KeyID: "sdk", Payload: base64.RawURLEncoding.EncodeToString(raw), Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, raw))})
	return string(wire), b, status, body
}
func observeFixture(t *testing.T, s *Store, reg *protection.Registry, key ed25519.PrivateKey, id, object, tenant, decision string, at time.Time) GateResult {
	t.Helper()
	raw, b, status, body := proofFixture(reg, key, id, object, tenant, decision, at)
	g, err := s.Observe(raw, b, status, body, at)
	if err != nil {
		t.Fatal(err)
	}
	return g
}
func eligibleFixture(t *testing.T, s *Store, reg *protection.Registry, key ed25519.PrivateKey) CaseView {
	t.Helper()
	now := time.Now().Add(-100 * time.Millisecond)
	observeFixture(t, s, reg, key, "r1", "one", "alpha", "deny", now)
	g := observeFixture(t, s, reg, key, "r2", "two", "alpha", "deny", now.Add(time.Millisecond))
	v, err := s.Case("alpha", g.CaseID)
	if err != nil || len(v.Candidates) != 2 {
		t.Fatal(v, err)
	}
	return v
}
func intentFixture(s *Store, v CaseView, id, owner, run string) Intent {
	return Intent{ID: id, CaseID: v.Case.ID, CaseSHA: v.Case.SHA, CandidateID: v.Candidates[0].ID, Owner: owner, Run: run, Epoch: s.Epoch()}
}
func TestSignedEvidenceCaseCASAndStablePolicyAcrossRestart(t *testing.T) {
	s, reg, key, path := storeFixture(t)
	v := eligibleFixture(t, s, reg, key)
	i := intentFixture(s, v, "intent1", "operator", "run1")
	first, err := s.Apply(context.Background(), "alpha", i)
	if err != nil {
		t.Fatal(err)
	}
	duplicate, err := s.Apply(context.Background(), "alpha", i)
	if err != nil || duplicate != first {
		t.Fatal("intent not idempotent", duplicate, err)
	}
	other := intentFixture(s, v, "intent2", "decisions", "run2")
	joined, err := s.Apply(context.Background(), "alpha", other)
	if err != nil || joined.PolicyID != first.PolicyID || !joined.Expires.Equal(first.Expires) || len(s.Policies("alpha")) != 1 {
		t.Fatal("same evidence multiplied/extended policy", joined, err)
	}
	if _, err = s.Apply(context.Background(), "beta", intentFixture(s, v, "wrong-tenant", "operator", "run3")); err == nil {
		t.Fatal("cross tenant apply accepted")
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path, reg)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	again, err := reopened.Apply(context.Background(), "alpha", i)
	if err != nil || again != first {
		t.Fatal("restart replayed intent", again, err)
	}
	policies := reopened.Policies("alpha")
	if len(policies) != 1 || len(policies[0].Claims) != 2 || !policies[0].Expires.Equal(first.Expires) {
		t.Fatal(policies)
	}
	release, err := reopened.Release(context.Background(), "alpha", policies[0].ID, "operator", "run1", "release1", policies[0].Generation)
	if err != nil || release.State != "retained_by_other_owner" || len(reopened.Policies("alpha")[0].Claims) != 1 {
		t.Fatal("cross owner release", release, err)
	}
	remaining := reopened.Policies("alpha")[0]
	if _, err = reopened.Release(context.Background(), "alpha", remaining.ID, "operator", "run1", "release2", remaining.Generation); err == nil {
		t.Fatal("unowned claim released")
	}
}
func TestCaseChangesPauseAndProofTamperingCannotAuthorize(t *testing.T) {
	s, reg, key, _ := storeFixture(t)
	v := eligibleFixture(t, s, reg, key)
	original := intentFixture(s, v, "stale", "operator", "run")
	observeFixture(t, s, reg, key, "r3", "three", "alpha", "allow", time.Now().Add(-time.Millisecond))
	if _, err := s.Apply(context.Background(), "alpha", original); err == nil {
		t.Fatal("old case authorized")
	}
	v, _ = s.Case("alpha", v.Case.ID)
	current := intentFixture(s, v, "current", "operator", "run")
	s.Pause(true)
	if _, err := s.Apply(context.Background(), "alpha", current); err == nil {
		t.Fatal("cancel fence ignored")
	}
	s.Pause(false)
	if _, err := s.Apply(context.Background(), "alpha", current); err == nil {
		t.Fatal("old epoch survived resume")
	}
	raw, b, status, body := proofFixture(reg, key, "tampered", "one", "alpha", "deny", time.Now())
	if _, err := s.Observe(raw, b, status, []byte("substituted private body"), time.Now()); err == nil {
		t.Fatal("tampered body ingested")
	}
	if _, err := s.Observe(strings.Replace(raw, "sdk", "bad", 1), b, status, body, time.Now()); err == nil {
		t.Fatal("forged signature ingested")
	}
}
func TestNormal200AndRepeatedRequestNeverBecomeViolationCandidates(t *testing.T) {
	s, reg, key, _ := storeFixture(t)
	at := time.Now().Add(-100 * time.Millisecond)
	g := observeFixture(t, s, reg, key, "one", "own1", "alpha", "allow", at)
	observeFixture(t, s, reg, key, "two", "own2", "alpha", "allow", at.Add(time.Millisecond))
	v, err := s.Case("alpha", g.CaseID)
	if err != nil || len(v.Candidates) != 0 || v.PendingReview {
		t.Fatal("normal 200 promoted to violation", v, err)
	}
	raw, b, status, body := proofFixture(reg, key, "deny", "foreign", "alpha", "deny", at.Add(2*time.Millisecond))
	g, err = s.Observe(raw, b, status, body, at.Add(2*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	for n := 0; n < 3; n++ {
		if _, err = s.Observe(raw, b, status, body, at.Add(3*time.Millisecond)); err != nil {
			t.Fatal(err)
		}
	}
	v, _ = s.Case("alpha", g.CaseID)
	if v.Case.Revision != 3 || len(v.Candidates) != 0 {
		t.Fatal("duplicate request became independent evidence", v)
	}
}
func TestSyncFailureNeverPublishesMutationAndTornJournalIsPreserved(t *testing.T) {
	s, reg, key, path := storeFixture(t)
	v := eligibleFixture(t, s, reg, key)
	s.syncFile = func(*os.File) error { return errors.New("injected Sync failure") }
	if _, err := s.Apply(context.Background(), "alpha", intentFixture(s, v, "no-sync", "operator", "run")); err == nil {
		t.Fatal("unsynced accepted")
	}
	if len(s.leases) != 0 || !s.failed {
		t.Fatal("unsynced policy published")
	}
	s.Close()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("{torn")
	f.Close()
	before, _ := os.ReadFile(path)
	if other, err := Open(path, reg); err == nil {
		other.Close()
		t.Fatal("torn journal accepted")
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("corrupt journal modified")
	}
}
func TestOwnerLockAndRegistryDriftRefuseStartup(t *testing.T) {
	s, reg, key, path := storeFixture(t)
	eligibleFixture(t, s, reg, key)
	if second, err := Open(path, reg); err == nil {
		second.Close()
		t.Fatal("second writer opened")
	}
	s.Close()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	other, err := protection.New(protection.Manifest{Schema: "protection-registry/1", Asset: "app", Revision: "r2", TrustEpoch: "e1", Enforcer: "edge1", Tenants: []string{"alpha"}, Keys: map[string]string{"sdk": base64.RawURLEncoding.EncodeToString(pub)}, Routes: []protection.Route{{ID: "object", Template: "/legacy/objects/{id}", Namespace: "objects", Mode: "enforce", MaxBody: 1024, AuthAdapter: "lab-hmac-v1", Resolver: "snapshot-v1"}}})
	if err != nil {
		t.Fatal(err)
	}
	if opened, err := Open(path, other); err == nil {
		opened.Close()
		t.Fatal("registry drift accepted")
	}
}
