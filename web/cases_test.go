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

func TestCaseAPIAuthenticationScopeCorrectionAndSelection(t *testing.T) {
	memory, err := casememory.Open(filepath.Join(t.TempDir(), "journal.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer memory.Close()
	at := time.Now().UTC()
	sha := strings.Repeat("a", 64)
	c := incident.Case{ID: "case/one", Tenant: "alpha", Asset: "api", First: at, Last: at, Evidence: []incident.EvidenceRef{{Stream: "events", Tenant: "alpha", Asset: "api", EventID: "e", LineSHA: sha, Time: at}}, Alerts: []incident.AlertRef{{Stream: "alerts", LineSHA: sha, Time: at, Rule: "RA-004", Refs: []string{"e"}}}}
	if _, err = memory.Sync(incident.Manifest{Version: 1, Cases: []incident.Case{c}}, sha); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	key := strings.Repeat("k", 64)
	Register(mux, Options{Token: key, Listen: "127.0.0.1:9081", Cases: memory, Tenants: []string{"alpha", "beta"}})
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
	if w := call("GET", "cases?tenant=alpha", "", "", ""); w.Code != 401 {
		t.Fatal(w.Code)
	}
	if w := call("GET", "cases?tenant=unknown", "", key, ""); w.Code != 404 {
		t.Fatal(w.Code)
	}
	if w := call("GET", "cases/detail?tenant=beta&case_id=case%2Fone", "", key, ""); w.Code != 404 {
		t.Fatal(w.Code)
	}
	v, _ := memory.Get("alpha", c.ID)
	q := casememory.LabelRequest{Expected: 0, CaseSHA: v.Current.SHA, Value: "confirmed_attack", Reason: "reviewed"}
	b, _ := json.Marshal(q)
	path := "cases/label?tenant=alpha&case_id=case%2Fone"
	if w := call("POST", path, string(b), key, "http://foreign.invalid"); w.Code != 403 {
		t.Fatal(w.Code)
	}
	if w := call("POST", path, string(b), key, ""); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := call("POST", path, string(b), key, ""); w.Code != 409 {
		t.Fatal(w.Code)
	}
	if w := call("POST", path, string(b)+" {}", key, ""); w.Code != 400 {
		t.Fatal(w.Code)
	}
	w := call("POST", "cases/selection?tenant=alpha", "", key, "")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var selection casememory.Selection
	json.Unmarshal(w.Body.Bytes(), &selection)
	if selection.Eligible != 1 {
		t.Fatal(w.Body.String())
	}
	q.Expected = 1
	q.Value = "uncertain"
	b, _ = json.Marshal(q)
	if w = call("POST", path, string(b), key, ""); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	w = call("GET", "cases/selection/saved?tenant=alpha&sha256="+selection.SHA, "", key, "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"reevaluation_required":true`) {
		t.Fatal(w.Code, w.Body.String())
	}
	w = call("GET", "cases/selection/saved?tenant=beta&sha256="+selection.SHA, "", key, "")
	if w.Code != 404 {
		t.Fatal(w.Code)
	}
}

func TestLabelJSONRejectsAmbiguityAndAcceptsKoreanReason(t *testing.T) {
	for _, raw := range []string{
		`{"expected_label_revision":0,"case_sha256":"x","value":"uncertain","reason":"x","reason":"y"}`,
		`{"expected_label_revision":0,"case_sha256":"x","VALUE":"uncertain","reason":"x"}`,
		`{"expected_label_revision":0,"case_sha256":"x","value":null,"reason":"x"}`,
		`{"case_sha256":"x","value":"uncertain","reason":"x"}`,
		`{"expected_label_revision":0,"case_sha256":"x","value":"uncertain","reason":"x"} {}`,
	} {
		var q casememory.LabelRequest
		if decodeLabel([]byte(raw), &q) == nil {
			t.Fatal("ambiguous input accepted", raw)
		}
	}
	var q casememory.LabelRequest
	if decodeLabel([]byte(`{"expected_label_revision":0,"case_sha256":"x","value":"uncertain","reason":"증거를 검토했습니다"}`), &q) != nil {
		t.Fatal("valid Korean reason refused")
	}
}
