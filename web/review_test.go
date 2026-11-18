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

func TestReviewHTTPPreregistrationCASAndLocalApproval(t *testing.T) {
	memory, err := casememory.Open(filepath.Join(t.TempDir(), "journal.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer memory.Close()
	sha := strings.Repeat("a", 64)
	makeCase := func(id string, at time.Time) incident.Case {
		return incident.Case{ID: id, Tenant: "alpha", Asset: "api", First: at, Last: at, Evidence: []incident.EvidenceRef{{Stream: "events", Tenant: "alpha", Asset: "api", EventID: id, LineSHA: sha, Time: at}}, Alerts: []incident.AlertRef{{Stream: "alerts", LineSHA: sha, Time: at, Rule: "RA-004", Refs: []string{id}}}}
	}
	cases := []incident.Case{}
	for _, id := range []string{"base-a", "base-b", "base-c", "base-d"} {
		cases = append(cases, makeCase(id, time.Now().UTC()))
	}
	if _, err = memory.Sync(incident.Manifest{Version: 1, Cases: cases}, sha); err != nil {
		t.Fatal(err)
	}
	label := func(c incident.Case, value string, expected int) {
		v, _ := memory.Get("alpha", c.ID)
		if _, err := memory.SetLabel("alpha", c.ID, casememory.LabelRequest{Expected: expected, CaseSHA: v.Current.SHA, Value: value, Reason: "synthetic operator review"}); err != nil {
			t.Fatal(err)
		}
	}
	for i, c := range cases {
		value := "confirmed_attack"
		if i > 1 {
			value = "confirmed_benign"
		}
		label(c, value, 0)
	}
	selection, _ := memory.Select("alpha", true)
	candidate, err := memory.CreateCandidate("alpha", selection.SHA)
	if err != nil {
		t.Fatal(err)
	}
	shadow, err := memory.StartShadow("alpha", candidate.Candidate.ID)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	key := strings.Repeat("k", 64)
	Register(mux, Options{Token: key, Listen: "127.0.0.1:9081", Cases: memory, Tenants: []string{"alpha", "beta"}})
	call := func(method, path, body, auth, origin string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "http://127.0.0.1:9081/console/api/cases/learning/review"+path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+auth)
		r.Header.Set("Content-Type", "application/json")
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}
	query := "?tenant=alpha&run_id=" + shadow.Plan.ID
	criteria := casememory.ReviewCriteria{MinimumAttack: 2, MinimumBenign: 2, MinimumCoverageBPS: 10000, MaximumFalseAttackBPS: 10000}
	b, _ := json.Marshal(criteria)
	if w := call("POST", "/plan"+query, string(b), "", ""); w.Code != 401 {
		t.Fatal(w.Code)
	}
	if w := call("POST", "/plan"+query, string(b), key, "http://foreign.invalid"); w.Code != 403 {
		t.Fatal(w.Code)
	}
	if w := call("POST", "/plan"+strings.Replace(query, "tenant=alpha", "tenant=beta", 1), string(b), key, ""); w.Code != 404 {
		t.Fatal(w.Code)
	}
	for _, bad := range []string{`{}`, string(b) + " {}", strings.Replace(string(b), `"minimum_confirmed_attack":2`, `"minimum_confirmed_attack":null`, 1), strings.TrimSuffix(string(b), "}") + `,"actor":"other"}`, strings.TrimSuffix(string(b), "}") + `,"minimum_confirmed_attack":2}`} {
		if w := call("POST", "/plan"+query, bad, key, ""); w.Code != 400 {
			t.Fatal("ambiguous criteria accepted", w.Code, w.Body.String())
		}
	}
	w := call("POST", "/plan"+query, string(b), key, "")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var registered casememory.ReviewView
	if json.Unmarshal(w.Body.Bytes(), &registered) != nil || registered.Plan == nil || registered.ApprovalAvailable {
		t.Fatal(w.Body.String())
	}
	criteria.MinimumAttack = 3
	changed, _ := json.Marshal(criteria)
	if w := call("POST", "/plan"+query, string(changed), key, ""); w.Code != 409 {
		t.Fatal("criteria changed", w.Code)
	}
	request := casememory.ReviewRequest{Expected: 0, PlanSHA: registered.Plan.SHA, Decision: "defer", Reason: "awaiting prospective cases"}
	b, _ = json.Marshal(request)
	w = call("POST", query, string(b), key, "")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := call("POST", query, string(b), key, ""); w.Code != 200 || !strings.Contains(w.Body.String(), `"expected_review_revision":1`) {
		t.Fatal("review retry duplicated record", w.Code, w.Body.String())
	}
	request.Decision = "approve_for_evaluation"
	b, _ = json.Marshal(request)
	if w := call("POST", query, string(b), key, ""); w.Code != 409 {
		t.Fatal("empty review approved", w.Code)
	}
	future := []incident.Case{}
	for _, id := range []string{"later-a", "later-b", "later-c", "later-d"} {
		future = append(future, makeCase(id, time.Now().UTC()))
	}
	cases = append(cases, future...)
	if _, err = memory.Sync(incident.Manifest{Version: 1, Cases: cases}, sha); err != nil {
		t.Fatal(err)
	}
	if _, err = memory.CaptureShadow("alpha", shadow.Plan.ID); err != nil {
		t.Fatal(err)
	}
	for i, c := range future {
		value := "confirmed_attack"
		if i > 1 {
			value = "confirmed_benign"
		}
		label(c, value, 0)
	}
	if _, err = memory.CaptureShadow("alpha", shadow.Plan.ID); err != nil {
		t.Fatal(err)
	}
	w = call("GET", query, "", key, "")
	var ready casememory.ReviewView
	json.Unmarshal(w.Body.Bytes(), &ready)
	if w.Code != 200 || !ready.ApprovalAvailable || ready.Assessment.Scored != 4 {
		t.Fatal(w.Code, w.Body.String())
	}
	request.Expected = ready.ExpectedRevision
	request.SnapshotSHA = ready.LatestSnapshotSHA
	request.Reason = "approve only the next local evaluation"
	b, _ = json.Marshal(request)
	w = call("POST", query, string(b), key, "")
	var approved casememory.ReviewView
	json.Unmarshal(w.Body.Bytes(), &approved)
	if w.Code != 200 || approved.State != "APPROVED_FOR_EVALUATION" || approved.DeploymentAllowed || approved.IndependentEvaluation {
		t.Fatal(w.Code, w.Body.String())
	}
	label(future[0], "uncertain", 1)
	w = call("GET", query, "", key, "")
	var stale casememory.ReviewView
	json.Unmarshal(w.Body.Bytes(), &stale)
	if w.Code != 200 || stale.ApprovalAvailable || !stale.ReviewStale || stale.State != "REVIEW_STALE" {
		t.Fatal(w.Code, w.Body.String())
	}
	request.Expected = stale.ExpectedRevision
	request.Reason = "attempting stale approval"
	b, _ = json.Marshal(request)
	if w := call("POST", query, string(b), key, ""); w.Code != 409 {
		t.Fatal("stale approval accepted", w.Code)
	}
	for _, suffix := range []string{"&run_id=duplicate", "&unexpected=x", "&bad=a;b"} {
		if w := call("GET", query+suffix, "", key, ""); w.Code != 400 {
			t.Fatal("ambiguous query accepted", w.Code)
		}
	}
}

func TestReviewJSONRejectsDecisionOverridesAndMissingFields(t *testing.T) {
	for _, raw := range []string{
		`{"expected_review_revision":0,"review_plan_sha256":"x","shadow_snapshot_sha256":"","decision":"defer"}`,
		`{"expected_review_revision":0,"review_plan_sha256":"x","shadow_snapshot_sha256":"","decision":"defer","reason":null}`,
		`{"expected_review_revision":0,"review_plan_sha256":"x","shadow_snapshot_sha256":"","decision":"defer","reason":"x","deployment_allowed":true}`,
		`{"expected_review_revision":0,"review_plan_sha256":"x","shadow_snapshot_sha256":"","Decision":"defer","reason":"x"}`,
	} {
		var q casememory.ReviewRequest
		if decodeReviewObject([]byte(raw), &q, "expected_review_revision", "review_plan_sha256", "shadow_snapshot_sha256", "decision", "reason") == nil {
			t.Fatal("non-canonical review accepted", raw)
		}
	}
}
