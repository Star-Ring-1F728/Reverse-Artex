package web

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"reverse-artex/internal/casememory"
	"reverse-artex/internal/incident"
)

func TestVerifiedLearningHTTPGuardsSyncAndStrictSignatures(t *testing.T) {
	memory, err := casememory.Open(filepath.Join(t.TempDir(), "journal.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer memory.Close()
	public, key, _ := ed25519.GenerateKey(rand.Reader)
	policy := casememory.LearningTrust{Schema: "case-learning-trust/1", Tenant: "alpha", Revision: 1, Keys: []casememory.LearningKey{{ID: "reviewer", Actor: "synthetic-reviewer", Role: "label_reviewer", PublicKey: base64.StdEncoding.EncodeToString(public)}}}
	trust, err := memory.SetLearningTrust(policy)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC()
	sha := strings.Repeat("a", 64)
	c := incident.Case{ID: "verified", Tenant: "alpha", Asset: "api", First: at, Last: at, Evidence: []incident.EvidenceRef{{Stream: "events", Tenant: "alpha", Asset: "api", EventID: "e", LineSHA: sha, Time: at}}, Alerts: []incident.AlertRef{{Stream: "alerts", LineSHA: sha, Time: at, Rule: "RA-004", Refs: []string{"e"}}}}
	if _, err = memory.Sync(incident.Manifest{Version: 1, Cases: []incident.Case{c}}, sha); err != nil {
		t.Fatal(err)
	}
	view, _ := memory.Get("alpha", c.ID)
	selection, _ := memory.Select("alpha", false)
	q := casememory.SignedLabel{TrustSHA: trust, Schema: "case-verified-label/1", Tenant: "alpha", CaseID: c.ID, CaseSHA: view.Current.SHA, SourceSHA: sha, EvidenceSHA: selection.Items[0].EvidenceSHA, Value: "confirmed_benign", Reason: "synthetic evidence review", Basis: "evidence_review", KeyID: "reviewer", IssuedAt: at, ExpiresAt: at.Add(time.Hour)}
	q.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, casememory.LabelSigningBytes(q)))
	raw, _ := json.Marshal(q)
	body := string(raw)
	calls := 0
	failSync := false
	token := strings.Repeat("k", 64)
	mux := http.NewServeMux()
	Register(mux, Options{Token: token, Listen: "127.0.0.1:9081", Cases: memory, Tenants: []string{"alpha", "beta"}, SyncCases: func(context.Context) (int, error) {
		calls++
		if failSync {
			return 0, errors.New("source unavailable")
		}
		return 0, nil
	}})
	call := func(method, path, body, key, origin string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "http://127.0.0.1:9081/console/api/"+path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+key)
		r.Header.Set("Content-Type", "application/json; charset=utf-8")
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}
	path := "cases/label/verified?tenant=alpha"
	if w := call("POST", path, body, "", ""); w.Code != 401 {
		t.Fatal(w.Code)
	}
	if w := call("POST", path, body, token, "https://other.invalid"); w.Code != 403 {
		t.Fatal(w.Code)
	}
	for _, bad := range []string{strings.Replace(body, `"value":"confirmed_benign"`, `"value":"confirmed_benign","value":"confirmed_attack"`, 1), strings.Replace(body, `"key_id"`, `"Key_ID"`, 1), body + " {}", strings.Replace(body, `"expected_label_revision":0`, `"expected_label_revision":null`, 1)} {
		before := calls
		if w := call("POST", path, bad, token, ""); w.Code != 400 || calls != before {
			t.Fatal("ambiguous input reached sync", w.Code, w.Body.String())
		}
	}
	if w := call("POST", path+"&tenant=beta", body, token, ""); w.Code != 400 {
		t.Fatal(w.Code)
	}
	before := calls
	if w := call("POST", "cases/label/verified?tenant=beta", body, token, ""); w.Code != 400 || calls != before {
		t.Fatal(w.Code)
	}
	failSync = true
	if w := call("POST", path, body, token, ""); w.Code != 503 {
		t.Fatal(w.Code)
	}
	current, _ := memory.Get("alpha", c.ID)
	if len(current.Labels) != 0 {
		t.Fatal("failed sync imported label")
	}
	failSync = false
	if w := call("POST", path, strings.Replace(body, "confirmed_benign", "confirmed_attack", 1), token, ""); w.Code != 400 {
		t.Fatal("forged label accepted", w.Code)
	}
	if w := call("POST", path, body, token, ""); w.Code != 200 || !strings.Contains(w.Body.String(), `"actor":"synthetic-reviewer"`) {
		t.Fatal(w.Code, w.Body.String())
	}
	for _, method := range []string{"GET", "POST"} {
		if w := call(method, "cases/selection/verified?tenant=alpha", "", token, ""); w.Code != 200 || !strings.Contains(w.Body.String(), `"eligible":1`) {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	if w := call("GET", "cases/learning/trust?tenant=alpha", "", token, ""); w.Code != 200 || !strings.Contains(w.Body.String(), trust) {
		t.Fatal(w.Code)
	}
	if w := call("GET", "cases/learning/trust?tenant=beta", "", token, ""); w.Code != 404 {
		t.Fatal(w.Code)
	}
	// The console bearer cannot install or replace the operator's trust policy.
	if w := call("POST", "cases/learning/trust?tenant=alpha", "{}", token, ""); w.Code == 200 {
		t.Fatal("console installed trust")
	}
	if w := call("POST", "cases/learning/advisory/verified?tenant=alpha", "{}", token, ""); w.Code != 400 {
		t.Fatal(w.Code)
	}
}
