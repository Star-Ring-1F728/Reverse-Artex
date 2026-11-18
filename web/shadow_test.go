package web

import (
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

func TestShadowHTTPProspectiveCaptureHistoryAndTrainingCorrection(t *testing.T) {
	memory, err := casememory.Open(filepath.Join(t.TempDir(), "journal.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer memory.Close()
	sha := strings.Repeat("a", 64)
	makeCase := func(id string, at time.Time) incident.Case {
		return incident.Case{ID: id, Tenant: "alpha", Asset: "api", First: at, Last: at,
			Evidence: []incident.EvidenceRef{{Stream: "events", Tenant: "alpha", Asset: "api", EventID: id, LineSHA: sha, Time: at}},
			Alerts:   []incident.AlertRef{{Stream: "alerts", LineSHA: sha, Time: at, Rule: "RA-004", Refs: []string{id}}}}
	}
	cases := []incident.Case{}
	for _, id := range []string{"attack-a", "attack-b", "benign-a", "benign-b"} {
		cases = append(cases, makeCase(id, time.Now().UTC()))
	}
	if _, err = memory.Sync(incident.Manifest{Version: 1, Cases: cases}, sha); err != nil {
		t.Fatal(err)
	}
	for i, c := range cases {
		view, _ := memory.Get("alpha", c.ID)
		value := "confirmed_attack"
		if i > 1 {
			value = "confirmed_benign"
		}
		if _, err = memory.SetLabel("alpha", c.ID, casememory.LabelRequest{Expected: 0, CaseSHA: view.Current.SHA, Value: value, Reason: "synthetic reviewed source"}); err != nil {
			t.Fatal(err)
		}
	}
	selection, _ := memory.Select("alpha", true)
	candidate, err := memory.CreateCandidate("alpha", selection.SHA)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	key := strings.Repeat("k", 64)
	Register(mux, Options{Token: key, Listen: "127.0.0.1:9081", Cases: memory, Tenants: []string{"alpha", "beta"}})
	call := func(method, path, body, auth string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "http://127.0.0.1:9081/console/api/cases/learning/shadow"+path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+auth)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}
	body := `{"candidate_id":"` + candidate.Candidate.ID + `"}`
	if w := call("POST", "?tenant=alpha", body, ""); w.Code != 401 {
		t.Fatal(w.Code)
	}
	if w := call("POST", "?tenant=beta", body, key); w.Code != 404 {
		t.Fatal(w.Code)
	}
	for _, bad := range []string{`{"candidate_id":null}`, `{"candidate_id":"x","activate":true}`, body + " {}", `{"candidate_id":"x","candidate_id":"x"}`} {
		if w := call("POST", "?tenant=alpha", bad, key); w.Code != 400 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	w := call("POST", "?tenant=alpha", body, key)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var started casememory.ShadowView
	if json.Unmarshal(w.Body.Bytes(), &started) != nil || started.Snapshot != nil || started.Plan.Baseline.Total != 4 {
		t.Fatal(w.Body.String())
	}
	runID := started.Plan.ID
	if w := call("GET", "/detail?tenant=beta&run_id="+runID, "", key); w.Code != 404 {
		t.Fatal("tenant leak", w.Code)
	}
	future := makeCase("later-case", time.Now().UTC())
	cases = append(cases, future)
	if _, err = memory.Sync(incident.Manifest{Version: 1, Cases: cases}, sha); err != nil {
		t.Fatal(err)
	}
	capture := `{"run_id":"` + runID + `"}`
	w = call("POST", "/capture?tenant=alpha", capture, key)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var first casememory.ShadowView
	json.Unmarshal(w.Body.Bytes(), &first)
	if first.Snapshot == nil || first.Snapshot.Total != 1 || first.Snapshot.Awaiting != 1 || first.Snapshot.Scored != 0 || first.Snapshot.Rows[0].Prediction == "" {
		t.Fatal(w.Body.String())
	}
	if first.Snapshot.IndependentEvaluation || first.Snapshot.DeploymentAllowed {
		t.Fatal("shadow gained deployment authority")
	}
	if w := call("POST", "/capture?tenant=alpha", capture, key); w.Code != 200 || !strings.Contains(w.Body.String(), first.Snapshot.SHA) {
		t.Fatal("duplicate observation changed snapshot", w.Code)
	}
	view, _ := memory.Get("alpha", future.ID)
	if _, err = memory.SetLabel("alpha", future.ID, casememory.LabelRequest{Expected: 0, CaseSHA: view.Current.SHA, Value: "confirmed_attack", Reason: "review after frozen prediction"}); err != nil {
		t.Fatal(err)
	}
	w = call("GET", "/detail?tenant=alpha&run_id="+runID, "", key)
	var pending casememory.ShadowView
	json.Unmarshal(w.Body.Bytes(), &pending)
	if !pending.RefreshRequired || pending.Snapshot.Scored != 0 {
		t.Fatal("GET silently rescored", w.Body.String())
	}
	w = call("POST", "/capture?tenant=alpha", capture, key)
	var second casememory.ShadowView
	json.Unmarshal(w.Body.Bytes(), &second)
	if w.Code != 200 || second.Snapshot == nil || second.Snapshot.Scored != 1 || second.Snapshot.Revision != 2 {
		t.Fatal(w.Code, w.Body.String())
	}
	if second.Snapshot.Rows[0].PredictionSequence != first.Snapshot.JournalSequence {
		t.Fatal("prediction sequence rewritten")
	}
	w = call("GET", "/detail?tenant=alpha&run_id="+runID+"&revision=1", "", key)
	var old casememory.ShadowView
	json.Unmarshal(w.Body.Bytes(), &old)
	if w.Code != 200 || old.Snapshot.SHA != first.Snapshot.SHA || old.Snapshot.Scored != 0 || !old.RefreshRequired {
		t.Fatal("history changed", w.Body.String())
	}
	for _, query := range []string{
		"&revision=0", "&revision=01", "&revision=1&revision=2", "&revision=1&unexpected=a;b", "&activate=true",
	} {
		if w := call("GET", "/detail?tenant=alpha&run_id="+runID+query, "", key); w.Code != 400 {
			t.Fatal("ambiguous query accepted", query, w.Code)
		}
	}
	if w := call("GET", "?tenant=alpha&tenant=beta", "", key); w.Code != 400 {
		t.Fatal(w.Code)
	}
	training, _ := memory.Get("alpha", "attack-a")
	if _, err = memory.SetLabel("alpha", "attack-a", casememory.LabelRequest{Expected: 1, CaseSHA: training.Current.SHA, Value: "uncertain", Reason: "corrected training review"}); err != nil {
		t.Fatal(err)
	}
	if w := call("POST", "/capture?tenant=alpha", capture, key); w.Code != 409 {
		t.Fatal("changed training base accepted", w.Code)
	}
	w = call("GET", "/detail?tenant=alpha&run_id="+runID, "", key)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"reevaluation_required":true`) {
		t.Fatal(w.Code, w.Body.String())
	}
	w = call("GET", "?tenant=alpha", "", key)
	if w.Code != 200 || strings.Contains(w.Body.String(), `"rows"`) || !strings.Contains(w.Body.String(), runID) {
		t.Fatal("summary list", w.Body.String())
	}
}
