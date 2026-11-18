package edge

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"reverse-artex/internal/protection"
	"reverse-artex/internal/responsev2"
	"strings"
	"testing"
	"time"
)

func TestSignedSDKToV2CaseNativePolicyAndProtectedHTTP(t *testing.T) {
	c, key := guardFixture(t)
	s, err := responsev2.Open(filepath.Join(t.TempDir(), "v2.jsonl"), c.Protection)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	c.ProtectionGate = func(raw string, b protection.RequestBinding, status int, body []byte, at time.Time) (protection.GateDecision, error) {
		g, err := s.Observe(raw, b, status, body, at)
		if err != nil {
			return protection.GateDecision{}, err
		}
		if status == 403 {
			if err = s.Native(b.Tenant, g.CaseID, g.CaseSHA); err != nil {
				t.Error("native admission", err)
			}
			g, err = s.Observe(raw, b, status, body, time.Now())
			if err != nil {
				return protection.GateDecision{}, err
			}
		}
		return protection.GateDecision{CaseID: g.CaseID, CaseSHA: g.CaseSHA, PolicyID: g.PolicyID, Deny: g.Deny}, nil
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		status := 403
		body := []byte("{\"error\":\"forbidden\"}")
		if strings.HasSuffix(r.URL.Path, "/own") {
			status = 200
			body = []byte("{\"value\":\"OWNED_PRIVATE\"}")
		}
		proof := sdkProof(c, key, r, body, func(p *protection.Proof) {
			p.Status = status
			if status == 403 {
				p.Decision = "deny"
			}
		})
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set(protection.ProofHeader, proof)
		w.WriteHeader(status)
		w.Write(body)
	}))
	defer upstream.Close()
	c.Upstream, _ = url.Parse(upstream.URL)
	h := Handler(c)
	authorization := guardRequest(c, "/legacy/objects/own", "GET").Header.Get("Authorization")
	request := func(object string, want int) string {
		t.Helper()
		w := httptest.NewRecorder()
		r := guardRequest(c, "/legacy/objects/"+object, "GET")
		r.Header.Set("Authorization", authorization)
		h.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("object=%s status=%d want=%d body=%s", object, w.Code, want, w.Body.String())
		}
		if want != 200 && strings.Contains(w.Body.String(), "PRIVATE") {
			t.Fatal("unauthorized payload escaped")
		}
		return w.Body.String()
	}
	request("foreign-one", 403)
	request("foreign-two", 429)
	policies := s.Policies("alpha")
	if len(policies) != 2 {
		t.Fatal("exact object policies missing", policies)
	}
	original, _ := json.Marshal(policies)
	if !strings.Contains(request("own", 200), "OWNED_PRIVATE") {
		t.Fatal("normal owner read blocked")
	}
	current, _ := json.Marshal(s.Policies("alpha"))
	if string(original) != string(current) {
		t.Fatal("normal 200 mutated native policies")
	}
	cases := s.Cases("alpha")
	if len(cases) != 1 || cases[0].Revision != 3 {
		t.Fatal("v2 case linkage missing", cases)
	}
	view, err := s.Case("alpha", cases[0].ID)
	if err != nil || !view.PendingReview || len(view.Evidence) != 3 {
		t.Fatal(view, err)
	}
	for _, e := range view.Evidence {
		if e.Kind != "prevented_unauthorized_access" && e.Kind != "authorized_representation" {
			t.Fatal("false leak/effect claim", e)
		}
	}
	// The same epoch cannot mutate after the persisted pause fence. Existing
	// policies remain finite; the ACL guard still returns owner responses.
	s.Pause(true)
	request("own", 200)
	if err = s.Native("alpha", view.Case.ID, view.Case.SHA); err == nil {
		t.Fatal("stale/paused native action accepted")
	}
}
