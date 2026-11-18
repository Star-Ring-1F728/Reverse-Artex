package web

import (
	"context"
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

func TestLearningLifecycleHTTPStrictScopeCASAndEmergencyStop(t *testing.T) {
	memory, err := casememory.Open(filepath.Join(t.TempDir(), "journal.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer memory.Close()
	sha := strings.Repeat("a", 64)
	at := time.Now().UTC()
	cases := []incident.Case{}
	for _, id := range []string{"a", "b", "c", "d"} {
		cases = append(cases, incident.Case{ID: id, Tenant: "alpha", Asset: "api", First: at, Last: at,
			Evidence: []incident.EvidenceRef{{Stream: "events", Tenant: "alpha", Asset: "api", EventID: id, LineSHA: sha, Time: at}},
			Alerts:   []incident.AlertRef{{Stream: "alerts", LineSHA: sha, Time: at, Rule: "RA-004", Refs: []string{id}}}})
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
		if _, err = memory.SetLabel("alpha", c.ID, casememory.LabelRequest{CaseSHA: view.Current.SHA, Value: value, Reason: "synthetic label"}); err != nil {
			t.Fatal(err)
		}
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
	run := shadow.Plan.ID
	if _, err = memory.RegisterReview("alpha", run, casememory.ReviewCriteria{MinimumAttack: 2, MinimumBenign: 2, MinimumCoverageBPS: 10000, MaximumFalseAttackBPS: 10000}); err != nil {
		t.Fatal(err)
	}
	failSync := false
	syncCalls := 0
	key := strings.Repeat("k", 64)
	mux := http.NewServeMux()
	Register(mux, Options{Token: key, Listen: "127.0.0.1:9081", Cases: memory, Tenants: []string{"alpha", "beta"},
		SyncCases: func(context.Context) (int, error) {
			syncCalls++
			if failSync {
				return 0, errors.New("source verification unavailable")
			}
			return 0, nil
		}})
	call := func(method, path, body, auth, origin string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "http://127.0.0.1:9081/console/api/cases/learning/"+path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+auth)
		r.Header.Set("Content-Type", "application/json")
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}
	path := "automatic?tenant=alpha&run_id=" + run
	body := `{"expected_revision":0,"enabled":true,"reason":"automatic observation"}`
	if w := call("POST", path, body, "", ""); w.Code != 401 {
		t.Fatal(w.Code)
	}
	if w := call("POST", path, body, key, "http://elsewhere.invalid"); w.Code != 403 {
		t.Fatal(w.Code)
	}
	if w := call("POST", strings.Replace(path, "alpha", "beta", 1), body, key, ""); w.Code != 404 {
		t.Fatal(w.Code)
	}
	for _, bad := range []string{`{}`, `{"expected_revision":0,"enabled":null,"reason":"x"}`, `{"expected_revision":0,"enabled":true,"reason":"x","activate":true}`, `{"expected_revision":0,"enabled":true,"enabled":false,"reason":"x"}`, body + " {}"} {
		before := syncCalls
		if w := call("POST", path, bad, key, ""); w.Code != 400 || syncCalls != before {
			t.Fatal("invalid mutation had side effects", w.Code, w.Body.String())
		}
	}
	for _, bad := range []string{path + "&run_id=" + run, path + "&tenant=beta", path + "&activate=true"} {
		if w := call("GET", bad, "", key, ""); w.Code != 400 {
			t.Fatal(w.Code)
		}
	}
	if w := call("POST", path, body, key, ""); w.Code != 200 || !strings.Contains(w.Body.String(), `"enabled":true`) {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := call("POST", path, `{"expected_revision":0,"enabled":false,"reason":"stale stop"}`, key, ""); w.Code != 409 {
		t.Fatal(w.Code)
	}
	failSync = true
	before := syncCalls
	if w := call("POST", path, `{"expected_revision":1,"enabled":false,"reason":"stop while evidence unavailable"}`, key, ""); w.Code != 200 || syncCalls != before {
		t.Fatal(w.Code, w.Body.String())
	}
	stop := casememory.AdvisoryRequest{Action: "stop", Reason: "emergency recommendation stop"}
	raw, _ := json.Marshal(stop)
	if w := call("POST", "advisory?tenant=alpha", string(raw), key, ""); w.Code != 200 || !strings.Contains(w.Body.String(), `"state":"stopped"`) || syncCalls != before {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := call("GET", "advisory?tenant=alpha&run_id="+run, "", key, ""); w.Code != 400 {
		t.Fatal(w.Code)
	}
}
