package protection

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"
)

func fixture(t *testing.T) (*Registry, ed25519.PrivateKey) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	r, err := New(Manifest{Schema: "protection-registry/1", Asset: "asset", Revision: "r1", TrustEpoch: "e1", Enforcer: "edge1", Tenants: []string{"alpha"}, Keys: map[string]string{"sdk1": base64.RawURLEncoding.EncodeToString(pub)}, Routes: []Route{{ID: "legacy", Template: "/legacy/objects/{id}", Namespace: "objects", Mode: "enforce", MaxBody: 1024, AuthAdapter: "lab-hmac-v1", Resolver: "snapshot-v1"}}})
	if err != nil {
		t.Fatal(err)
	}
	return r, key
}
func sign(p Proof, key ed25519.PrivateKey) string {
	raw, _ := json.Marshal(p)
	env := Envelope{KeyID: p.KeyID, Payload: base64.RawURLEncoding.EncodeToString(raw), Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, raw))}
	wire, _ := json.Marshal(env)
	return string(wire)
}
func TestRegistryRejectsAmbiguityAndReservedPathBypass(t *testing.T) {
	r, _ := fixture(t)
	for _, value := range []string{"/legacy/objects", "/legacy/objects/a/b", "/legacy/objects/a?owner=b", "/legacy/objects/a?", "/legacy/objects/a%2fb", "/legacy/objects/..", "/legacy/objects/"} {
		u, _ := url.Parse(value)
		if _, _, matched, err := r.Resolve(u, "GET"); !matched || err == nil {
			t.Fatal("accepted reserved invalid path", value)
		}
	}
	u, _ := url.Parse("/legacy/objects/a")
	if _, id, matched, err := r.Resolve(u, "GET"); err != nil || !matched || id != "a" {
		t.Fatal(id, matched, err)
	}
	if _, _, _, err := r.Resolve(u, "POST"); err == nil {
		t.Fatal("write treated as protected read")
	}
	for _, kind := range []string{"duplicate-route", "shadow-route", "unknown-mode", "bad-key", "empty-tenant", "oversize", "duplicate-json"} {
		t.Run(kind, func(t *testing.T) {
			raw, _ := json.Marshal(r.manifest)
			var m Manifest
			json.Unmarshal(raw, &m)
			switch kind {
			case "duplicate-route":
				m.Routes = append(m.Routes, m.Routes[0])
			case "shadow-route":
				x := m.Routes[0]
				x.ID = "shadow"
				x.Template = "/legacy/objects/nested/{id}"
				m.Routes = append(m.Routes, x)
			case "unknown-mode":
				m.Routes[0].Mode = "automatic"
			case "bad-key":
				m.Keys["sdk1"] = "bad"
			case "empty-tenant":
				m.Tenants = nil
			case "oversize":
				m.Routes[0].MaxBody = 1<<20 + 1
			case "duplicate-json":
				raw = []byte(strings.Replace(string(raw), "{", "{\"schema\":\"duplicate\",", 1))
				if _, err := Parse(raw); err == nil {
					t.Fatal("duplicate JSON accepted")
				}
				return
			}
			if _, err := New(m); err == nil {
				t.Fatal("invalid contract accepted")
			}
		})
	}
}
func TestReleaseProofBindsEveryRequestAndRepresentationField(t *testing.T) {
	r, key := fixture(t)
	now := time.Now()
	b := RequestBinding{RequestID: "request", Nonce: "nonce", Method: "GET", Route: "legacy", Tenant: "alpha", Principal: "alice", Session: "session", Resource: "resource", Started: now}
	body := []byte("{\"value\":\"private\"}")
	p := Proof{Schema: "release-proof/1", KeyID: "sdk1", Asset: r.Asset(), Registry: r.Digest(), Epoch: r.Epoch(), RequestID: b.RequestID, Nonce: b.Nonce, Method: b.Method, Route: b.Route, Tenant: b.Tenant, Principal: b.Principal, Session: b.Session, Resource: b.Resource, Action: "read", AuthzRevision: "acl1", ContentRevision: "content1", Decision: "allow", Status: 200, BodyLength: len(body), BodySHA: BodyHash(body), Issued: now.UnixMilli(), Expires: now.Add(5 * time.Second).UnixMilli()}
	if _, err := r.Verify(sign(p, key), b, 200, body, now); err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*Proof){
		"tenant": func(p *Proof) { p.Tenant = "beta" }, "actor": func(p *Proof) { p.Principal = "bob" },
		"session": func(p *Proof) { p.Session = "other" }, "resource": func(p *Proof) { p.Resource = "other" },
		"nonce": func(p *Proof) { p.Nonce = "replay" }, "request": func(p *Proof) { p.RequestID = "replay" },
		"method": func(p *Proof) { p.Method = "HEAD" }, "route": func(p *Proof) { p.Route = "api" },
		"registry": func(p *Proof) { p.Registry = "stale" }, "epoch": func(p *Proof) { p.Epoch = "stale" },
		"asset": func(p *Proof) { p.Asset = "other" }, "status": func(p *Proof) { p.Status = 403 },
		"decision": func(p *Proof) { p.Decision = "unknown" }, "length": func(p *Proof) { p.BodyLength++ },
		"body":     func(p *Proof) { p.BodySHA = BodyHash([]byte("other")) },
		"future":   func(p *Proof) { p.Issued = now.Add(time.Second).UnixMilli() },
		"expired":  func(p *Proof) { p.Expires = now.UnixMilli() },
		"long-ttl": func(p *Proof) { p.Expires = now.Add(6 * time.Second).UnixMilli() },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			x := p
			mutate(&x)
			if _, err := r.Verify(sign(x, key), b, 200, body, now); err == nil {
				t.Fatal("foreign proof accepted")
			}
		})
	}
	for _, delta := range []time.Duration{-2 * time.Millisecond, 2 * time.Millisecond} {
		adjusted := p
		adjusted.Issued = now.Add(delta).UnixMilli()
		adjusted.Expires = adjusted.Issued + ProofLifetime.Milliseconds()
		if _, err := r.Verify(sign(adjusted, key), b, 200, body, now); err != nil {
			t.Fatal("bounded same-host clock quantization rejected", delta, err)
		}
	}
	tooFar := p
	tooFar.Issued = now.Add(10 * time.Millisecond).UnixMilli()
	tooFar.Expires = tooFar.Issued + ProofLifetime.Milliseconds()
	if _, err := r.Verify(sign(tooFar, key), b, 200, body, now); err == nil {
		t.Fatal("clock skew beyond bound accepted")
	}
	wire := sign(p, key)
	if _, err := r.Verify(wire, b, 200, []byte("changed"), now); err == nil {
		t.Fatal("payload substitution accepted")
	}
	if _, err := r.Verify(wire, b, 200, body, now.Add(5*time.Second)); err == nil {
		t.Fatal("deadline ignored")
	}
	if _, err := r.Verify(wire, b, 200, body, now.Add(-time.Millisecond)); err == nil {
		t.Fatal("clock rollback ignored")
	}
	if _, err := r.Verify(strings.Replace(wire, "sdk1", "sdk2", 1), b, 200, body, now); err == nil {
		t.Fatal("wrong key accepted")
	}
}

func TestAcceptedRegistryIsDetachedFromCallerManifest(t *testing.T) {
	source, _ := fixture(t)
	m := source.manifest
	raw, _ := json.Marshal(m)
	var caller Manifest
	json.Unmarshal(raw, &caller)
	r, err := New(caller)
	if err != nil {
		t.Fatal(err)
	}
	digest := r.Digest()
	caller.Routes[0].Template = "/unregistered/{id}"
	caller.Routes[0].Mode = "observe"
	caller.Tenants[0] = "other"
	caller.Keys["sdk1"] = "invalid"
	u, _ := url.Parse("/legacy/objects/one")
	route, _, matched, err := r.Resolve(u, "GET")
	if err != nil || !matched || route.Mode != "enforce" || !r.TenantAllowed("alpha") || r.Digest() != digest {
		t.Fatal("caller changed accepted registry", route, err)
	}
}
