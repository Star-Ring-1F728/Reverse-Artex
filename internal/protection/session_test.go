package protection

import (
	"testing"
	"time"
)

func TestSessionSnapshotStatusesRequireExplicitRouteContract(t *testing.T) {
	reg, key := fixture(t)
	for _, resolver := range []string{"snapshot-v1", "session-snapshot-v1"} {
		manifest := reg.manifest
		manifest.Routes = append([]Route(nil), manifest.Routes...)
		manifest.Routes[0].Resolver = resolver
		r, err := New(manifest)
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now()
		b := RequestBinding{RequestID: "req", Nonce: "nonce", Method: "GET", Route: "legacy", Tenant: "alpha", Principal: "alice", Session: "session", Resource: "resource", Started: now}
		for _, decision := range []string{"unauthenticated", "not_found"} {
			status := 401
			if decision == "not_found" {
				status = 404
			}
			body := []byte(`{"error":"rejected"}`)
			p := Proof{Schema: "release-proof/1", KeyID: "sdk1", Asset: r.Asset(), Registry: r.Digest(), Epoch: r.Epoch(), RequestID: b.RequestID, Nonce: b.Nonce, Method: b.Method, Route: b.Route, Tenant: b.Tenant, Principal: b.Principal, Session: b.Session, Resource: b.Resource, Action: "read", AuthzRevision: "unknown", ContentRevision: "unknown", Decision: decision, Status: status, BodyLength: len(body), BodySHA: BodyHash(body), Issued: now.UnixMilli(), Expires: now.Add(5 * time.Second).UnixMilli()}
			_, err := r.Verify(sign(p, key), b, status, body, now)
			if (err == nil) != (resolver == "session-snapshot-v1") {
				t.Fatalf("resolver=%s decision=%s err=%v", resolver, decision, err)
			}
			p.Status = 200
			if _, err := r.Verify(sign(p, key), b, 200, body, now); err == nil {
				t.Fatal("rejected session became allowed")
			}
			p.Status = status
			p.AuthzRevision = "acl1"
			if _, err := r.Verify(sign(p, key), b, status, body, now); err == nil {
				t.Fatal("authentication failure claimed an object snapshot")
			}
		}
	}
}
