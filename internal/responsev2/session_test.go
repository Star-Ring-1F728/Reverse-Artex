package responsev2

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"reverse-artex/internal/decisions"
	"reverse-artex/internal/protection"
	"testing"
	"time"
)

func TestSessionFailuresPreserveStatusUnderActivePolicyAndReplay(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	reg, err := protection.New(protection.Manifest{Schema: "protection-registry/1", Asset: "app", Revision: "r1", TrustEpoch: "e1", Enforcer: "edge1", Tenants: []string{"alpha"}, Keys: map[string]string{"sdk": base64.RawURLEncoding.EncodeToString(pub)}, Routes: []protection.Route{{ID: "object", Template: "/legacy/objects/{id}", Namespace: "objects", Mode: "enforce", MaxBody: 1024, AuthAdapter: "lab-hmac-v1", Resolver: "session-snapshot-v1"}}})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "session.jsonl")
	s, err := Open(path, reg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { s.Close() }()
	v := eligibleFixture(t, s, reg, key)
	applied, err := s.Apply(context.Background(), "alpha", intentFixture(s, v, "apply", "operator", "run"))
	if err != nil {
		t.Fatal(err)
	}
	// Use exactly the installed scope; neither status may be masked as 429.
	target := s.leases[applied.PolicyID].Scope.Resource
	for _, decision := range []string{"unauthenticated", "not_found", "unknown"} {
		now := time.Now()
		raw, b, _, _ := proofFixture(reg, key, "session-"+decision, "one", "alpha", "deny", now)
		var env protection.Envelope
		json.Unmarshal([]byte(raw), &env)
		payload, _ := base64.RawURLEncoding.DecodeString(env.Payload)
		var p protection.Proof
		json.Unmarshal(payload, &p)
		p.Resource = target
		b.Resource = target
		status := 401
		if decision == "not_found" {
			status = 404
		}
		if decision == "unknown" {
			status = 503
		}
		body := []byte(`{"error":"rejected"}`)
		p.Decision, p.Status, p.AuthzRevision, p.ContentRevision = decision, status, "unknown", "unknown"
		if decision == "unknown" {
			// A DB/serialization failure after reading the ACL can retain the
			// exact active lease scope, unlike an unauthenticated snapshot.
			p.AuthzRevision, p.ContentRevision = "acl1", "v1"
		}
		p.BodyLength, p.BodySHA = len(body), protection.BodyHash(body)
		payload, _ = json.Marshal(p)
		wire, _ := json.Marshal(protection.Envelope{KeyID: "sdk", Payload: base64.RawURLEncoding.EncodeToString(payload), Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, payload))})
		gate, err := s.Observe(string(wire), b, status, body, now)
		if err != nil || gate.Deny || gate.PolicyID != "" {
			t.Fatal("session failure masked", gate, err)
		}
		again, err := s.Observe(string(wire), b, status, body, now)
		if err != nil || again != gate {
			t.Fatal("repeated observation changed gate", again, err)
		}
		prepared, err := s.PrepareResponse("alpha", decisions.Hash(string(wire)), now)
		if err != nil || prepared.Deny || prepared.PolicyID != "" {
			t.Fatal("response preparation masked failure", prepared, err)
		}
		if err = s.CompleteResponse(protection.ResponseWrite{AttemptID: prepared.AttemptID, Status: status, Bytes: len(body), BodySHA: protection.BodyHash(body), Complete: true, CompletedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path, reg)
	if err != nil {
		t.Fatal(err)
	}
	view, err := s.Case("alpha", v.Case.ID)
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, e := range view.Evidence {
		counts[e.Kind]++
	}
	if counts["authentication_rejected"] != 1 || counts["object_not_found"] != 1 || counts["unknown"] != 1 || counts["prevented_unauthorized_access"] != 2 {
		t.Fatal(counts)
	}
	if len(view.Candidates) != 2 {
		t.Fatal("session failures became policy candidates", len(view.Candidates))
	}
}
