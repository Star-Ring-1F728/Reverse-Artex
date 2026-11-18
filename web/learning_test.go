package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"reverse-artex/internal/casememory"
	"reverse-artex/internal/incident"
)

func TestLearningHTTPExactSelectionScopeAndCorrection(t *testing.T) {
	memory, err := casememory.Open(filepath.Join(t.TempDir(), "journal.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer memory.Close()
	at := time.Now().UTC()
	sha := strings.Repeat("a", 64)
	cases := []incident.Case{}
	for i, id := range []string{"attack-a", "attack-b", "benign-a", "benign-b", "pending"} {
		rule := "RA-004"
		if i >= 2 {
			rule = "RA-002"
		}
		cases = append(cases, incident.Case{ID: id, Tenant: "alpha", Asset: "api", First: at, Last: at,
			Evidence: []incident.EvidenceRef{{Stream: "events", Tenant: "alpha", Asset: "api", EventID: id, LineSHA: sha, Time: at}},
			Alerts:   []incident.AlertRef{{Stream: "alerts", LineSHA: sha, Time: at, Rule: rule, Refs: []string{id}}}})
	}
	if _, err = memory.Sync(incident.Manifest{Version: 1, Cases: cases}, sha); err != nil {
		t.Fatal(err)
	}
	for i, c := range cases[:4] {
		v, _ := memory.Get("alpha", c.ID)
		value := "confirmed_attack"
		if i >= 2 {
			value = "confirmed_benign"
		}
		if _, err = memory.SetLabel("alpha", c.ID, casememory.LabelRequest{Expected: 0, CaseSHA: v.Current.SHA, Value: value, Reason: "reviewed source"}); err != nil {
			t.Fatal(err)
		}
	}
	selected, _ := memory.Select("alpha", true)
	key := strings.Repeat("k", 64)
	mux := http.NewServeMux()
	syncCalls := 0
	Register(mux, Options{Token: key, Listen: "127.0.0.1:9081", Cases: memory, Tenants: []string{"alpha", "beta"}, SyncCases: func(context.Context) (int, error) { syncCalls++; return 0, nil }})
	call := func(method, path, body, auth, origin string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "http://127.0.0.1:9081/console/api/"+path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+auth)
		r.Header.Set("Content-Type", "application/json")
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}
	body := `{"selection_sha256":"` + selected.SHA + `"}`
	if w := call("POST", "cases/learning?tenant=alpha", body, "", ""); w.Code != 401 {
		t.Fatal(w.Code)
	}
	if w := call("POST", "cases/learning?tenant=alpha", body, key, "http://foreign.invalid"); w.Code != 403 {
		t.Fatal(w.Code)
	}
	if w := call("POST", "cases/learning?tenant=beta", body, key, ""); w.Code != 404 {
		t.Fatal(w.Code)
	}
	for _, bad := range []string{
		`{"selection_sha256":null}`, `{"Selection_SHA256":"x"}`, body + " {}",
		`{"selection_sha256":"x","selection_sha256":"x"}`, `{"selection_sha256":"x","activate":true}`,
	} {
		if w := call("POST", "cases/learning?tenant=alpha", bad, key, ""); w.Code != 400 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	for _, path := range []string{"cases/learning?tenant=alpha&tenant=beta", "cases/learning?tenant=alpha&activate=true", "cases/learning?tenant=alpha;tenant=beta"} {
		if w := call("GET", path, "", key, ""); w.Code != 400 {
			t.Fatal(w.Code, path)
		}
	}
	w := call("POST", "cases/learning?tenant=alpha", body, key, "")
	if w.Code != 200 || syncCalls < 1 {
		t.Fatal(w.Code, w.Body.String())
	}
	var saved casememory.CandidateView
	if err := json.Unmarshal(w.Body.Bytes(), &saved); err != nil || saved.Candidate.TrainingStatus != "fit_complete" || saved.Candidate.Selection.Total != 5 || saved.Candidate.FitCount != 4 {
		t.Fatal(w.Body.String(), err)
	}
	if saved.Candidate.DeploymentAllowed || saved.Candidate.IndependentEvaluated || !saved.Candidate.ReviewRequired {
		t.Fatal("offline candidate gained authority")
	}
	if w = call("POST", "cases/learning?tenant=alpha", body, key, ""); w.Code != 200 || !strings.Contains(w.Body.String(), saved.Candidate.ID) {
		t.Fatal("idempotence", w.Code)
	}
	w = call("GET", "cases/learning?tenant=alpha", "", key, "")
	if w.Code != 200 || strings.Contains(w.Body.String(), `"rows"`) || !strings.Contains(w.Body.String(), saved.Candidate.ID) {
		t.Fatal("bounded summary missing", w.Body.String())
	}
	diagnosticPath := "cases/learning/diagnostics?tenant=alpha&candidate_id=" + saved.Candidate.ID
	if w = call("GET", diagnosticPath, "", "", ""); w.Code != 401 {
		t.Fatal("unauthenticated diagnostics", w.Code)
	}
	if w = call("GET", diagnosticPath, "", key, "http://foreign.invalid"); w.Code != 403 {
		t.Fatal("foreign diagnostics", w.Code)
	}
	if w = call("GET", strings.Replace(diagnosticPath, "tenant=alpha", "tenant=beta", 1), "", key, ""); w.Code != 404 {
		t.Fatal("diagnostic tenant leak", w.Code)
	}
	if w = call("GET", diagnosticPath+"&gold=x", "", key, ""); w.Code != 400 {
		t.Fatal("diagnostic extra input", w.Code)
	}
	w = call("GET", diagnosticPath, "", key, "")
	var diagnostic casememory.CandidateFeatureDiagnostics
	if err := json.Unmarshal(w.Body.Bytes(), &diagnostic); err != nil || w.Code != 200 || diagnostic.Fit.Cases != 4 || diagnostic.Fit.ProductionApproval || diagnostic.Fit.IndependentEvaluation {
		t.Fatal(w.Code, w.Body.String(), err)
	}
	for _, secret := range []string{`"features":`, `"rows":`, `"label":`, `"model":`} {
		if strings.Contains(w.Body.String(), secret) {
			t.Fatal("diagnostic row disclosure", w.Body.String())
		}
	}
	path := "cases/learning/detail?tenant=alpha&candidate_id=" + saved.Candidate.ID
	if w = call("GET", strings.Replace(path, "tenant=alpha", "tenant=beta", 1), "", key, ""); w.Code != 404 {
		t.Fatal("tenant leak", w.Code)
	}
	v, _ := memory.Get("alpha", "attack-a")
	if _, err := memory.SetLabel("alpha", "attack-a", casememory.LabelRequest{Expected: 1, CaseSHA: v.Current.SHA, Value: "uncertain", Reason: "new review"}); err != nil {
		t.Fatal(err)
	}
	w = call("GET", path, "", key, "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"reevaluation_required":true`) {
		t.Fatal(w.Code, w.Body.String())
	}
	if w = call("POST", "cases/learning?tenant=alpha", body, key, ""); w.Code != 409 {
		t.Fatal("stale cohort trained", w.Code)
	}
}

func TestLearningSynchronizesBeforeCreatingCandidate(t *testing.T) {
	memory, _ := casememory.Open(filepath.Join(t.TempDir(), "journal.jsonl"))
	defer memory.Close()
	selection, _ := memory.Select("alpha", true)
	mux := http.NewServeMux()
	key := strings.Repeat("k", 64)
	Register(mux, Options{Token: key, Listen: "127.0.0.1:9081", Cases: memory, Tenants: []string{"alpha"}, SyncCases: func(context.Context) (int, error) { return 0, casememory.ErrUnavailable }})
	r := httptest.NewRequest("POST", "http://127.0.0.1:9081/console/api/cases/learning?tenant=alpha", strings.NewReader(`{"selection_sha256":"`+selection.SHA+`"}`))
	r.Header.Set("Authorization", "Bearer "+key)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != 503 {
		t.Fatal(w.Code)
	}
	candidates, _ := memory.Candidates("alpha")
	if len(candidates) != 0 {
		t.Fatal("training continued after source failure")
	}
}
