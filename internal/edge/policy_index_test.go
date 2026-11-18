package edge

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reverse-artex/internal/identity"
	"reverse-artex/internal/policy"
	"strings"
	"testing"
	"time"
)

func TestIndexedPolicyOverlapHeadersRevocationAndExpiry(t *testing.T) {
	now := time.Now()
	clock := now
	key, hmacKey, snapKey := []byte(strings.Repeat("k", 32)), []byte(strings.Repeat("h", 32)), []byte(strings.Repeat("s", 32))
	token := credential("alice", key, now)
	a := policy.Policy{ID: "a", CaseID: "case-a", Tenant: "alpha", Asset: "lab-api", Principal: "alice", Session: identity.Pseudonym(token, hmacKey), Route: "/api/objects/{id}", RuleVersion: "1.0", Issued: now.UTC(), Expires: now.Add(3 * time.Second).UTC(), Version: 1}
	z := a
	z.ID, z.CaseID = "z", "case-z"
	cache := policy.NewReplica()
	up, _ := url.Parse("http://127.0.0.1:9999")
	forwarded, actions := 0, []string{}
	h := Handler(Config{Upstream: up, Asset: "lab-api", IdentityKey: key, HMACKey: hmacKey, Cache: cache, Now: func() time.Time { return clock }, Emit: func(kind string, v any) {
		if kind == "actions" {
			actions = append(actions, v.(map[string]any)["policy_id"].(string))
		}
	}, Transport: transport(func(r *http.Request) (*http.Response, error) {
		forwarded++
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("{}")), Request: r}, nil
	})})
	update := func(version uint64, ps ...policy.Policy) {
		t.Helper()
		if err := cache.Replace(policy.Sign(policy.Snapshot{Epoch: "epoch", Version: version, Generated: clock.UTC(), Policies: ps}, snapKey), snapKey, clock); err != nil {
			t.Fatal(err)
		}
	}
	check := func(status int, id string) {
		t.Helper()
		r := httptest.NewRequest("GET", "/api/objects/1", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != status || w.Header().Get("X-RA-Policy-ID") != id {
			t.Fatalf("got HTTP %d policy %q want %d/%q", w.Code, w.Header().Get("X-RA-Policy-ID"), status, id)
		}
	}
	update(1, z, a)
	check(429, "a")
	update(2, z)
	check(429, "z")
	update(3)
	check(200, "")
	update(4, a, z)
	check(200, "")
	fresh := a
	fresh.ID = "fresh"
	update(5, fresh)
	check(429, "fresh")
	clock = now.Add(3 * time.Second)
	check(200, "")
	if forwarded != 3 || strings.Join(actions, ",") != "a,z,fresh" {
		t.Fatal("wrong forwarding or action evidence", forwarded, actions)
	}
}
