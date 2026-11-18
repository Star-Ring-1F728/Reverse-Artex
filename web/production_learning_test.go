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
	"reverse-artex/internal/casememory"
	"reverse-artex/internal/incident"
	"strings"
	"testing"
	"time"
)

func TestProductionHTTPPreparesWithoutClaimingIndependenceAndStopsDuringSourceFailure(t *testing.T) {
	memory, err := casememory.Open(filepath.Join(t.TempDir(), "journal.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer memory.Close()
	public, key, _ := ed25519.GenerateKey(rand.Reader)
	trust := casememory.LearningTrust{Schema: "case-learning-trust/1", Tenant: "alpha", Revision: 1, Keys: []casememory.LearningKey{{ID: "reviewer", Actor: "reviewer", Role: "label_reviewer", PublicKey: base64.StdEncoding.EncodeToString(public)}}}
	trustSHA, err := memory.SetLearningTrust(trust)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	sha := strings.Repeat("a", 64)
	cases := []incident.Case{}
	for _, id := range []string{"a", "b", "c", "d"} {
		cases = append(cases, incident.Case{ID: id, Tenant: "alpha", Asset: "api", First: now, Last: now, Evidence: []incident.EvidenceRef{{Stream: "events", Tenant: "alpha", Asset: "api", EventID: id, LineSHA: sha, Time: now}}, Alerts: []incident.AlertRef{{Stream: "alerts", LineSHA: sha, Time: now, Rule: "RA-004", Refs: []string{id}}}})
	}
	if _, err = memory.Sync(incident.Manifest{Version: 1, Cases: cases}, sha); err != nil {
		t.Fatal(err)
	}
	for i, c := range cases {
		v, _ := memory.Get("alpha", c.ID)
		selected, _ := memory.Select("alpha", false)
		evidence := ""
		for _, b := range selected.Items {
			if b.CaseID == c.ID {
				evidence = b.EvidenceSHA
			}
		}
		value := "confirmed_attack"
		if i >= 2 {
			value = "confirmed_benign"
		}
		q := casememory.SignedLabel{TrustSHA: trustSHA, Schema: "case-verified-label/1", Tenant: "alpha", CaseID: c.ID, CaseSHA: v.Current.SHA, SourceSHA: v.Current.Source, EvidenceSHA: evidence, Value: value, Reason: "synthetic reviewer fixture", Basis: "evidence_review", KeyID: "reviewer", IssuedAt: now, ExpiresAt: now.Add(time.Hour)}
		q.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, casememory.LabelSigningBytes(q)))
		if _, err = memory.ImportVerifiedLabel("alpha", q); err != nil {
			t.Fatal(err)
		}
	}
	selected, _ := memory.SelectVerified("alpha", true)
	candidate, err := memory.CreateCandidate("alpha", selected.SHA)
	if err != nil {
		t.Fatal(err)
	}
	policy := casememory.DefaultProductionPolicy("alpha", trustSHA)
	if _, err = memory.SetProductionPolicy(policy); err != nil {
		t.Fatal(err)
	}
	// Disabled policy supports honest preparation without fabricated independent keys.
	token := strings.Repeat("k", 64)
	syncCalls := 0
	fail := false
	mux := http.NewServeMux()
	Register(mux, Options{Token: token, Listen: "127.0.0.1:9081", Cases: memory, Tenants: []string{"alpha", "beta"}, SyncCases: func(context.Context) (int, error) {
		syncCalls++
		if fail {
			return 0, errors.New("owned source unavailable")
		}
		return 0, nil
	}})
	call := func(method, path, body, auth string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "http://127.0.0.1:9081/console/api/cases/learning/"+path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+auth)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}
	body := `{"candidate_id":"` + candidate.Candidate.ID + `"}`
	if w := call("POST", "quality/prepare?tenant=alpha", body, ""); w.Code != 401 {
		t.Fatal(w.Code)
	}
	before := syncCalls
	if w := call("POST", "quality/prepare?tenant=alpha", strings.Replace(body, "}", `,"candidate_id":"other"}`, 1), token); w.Code != 400 || syncCalls != before {
		t.Fatal(w.Code)
	}
	if w := call("POST", "quality/prepare?tenant=beta", body, token); w.Code != 404 {
		t.Fatal(w.Code)
	}
	w := call("POST", "quality/prepare?tenant=alpha", body, token)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var prepared casememory.QualityView
	if err = json.Unmarshal(w.Body.Bytes(), &prepared); err != nil {
		t.Fatal(err)
	}
	if prepared.State != "PREPARED_NOT_READY" || prepared.Proof != nil {
		t.Fatal(prepared)
	}
	id := prepared.Capsule.Plan.ID
	if w := call("GET", "quality?tenant=alpha&plan_id="+id, "", token); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if w := call("GET", "quality?tenant=beta&plan_id="+id, "", token); w.Code != 404 {
		t.Fatal(w.Code)
	}
	for _, path := range []string{"quality/cohort", "quality/report", "production"} {
		before := syncCalls
		if w := call("POST", path+"?tenant=alpha", "{}", token); w.Code != 400 || syncCalls != before {
			t.Fatal("invalid signed body synchronized", w.Code)
		}
	}
	if w := call("GET", "production?tenant=alpha&plan_id="+id, "", token); w.Code != 400 {
		t.Fatal(w.Code)
	}
	fail = true
	before = syncCalls
	if w := call("POST", "production/stop?tenant=alpha", `{"expected_revision":0,"reason":"stop without source or signing key"}`, token); w.Code != 200 || syncCalls != before {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := call("POST", "production-policy?tenant=alpha", "{}", token); w.Code == 200 {
		t.Fatal("console installed deployment policy")
	}
}
