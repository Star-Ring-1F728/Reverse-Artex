package responsev2

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	api "reverse-artex/internal/decisions/openai"
	"strings"
	"testing"
)

func TestL3HTTPManagementBoundariesAndOutcome(t *testing.T) {
	s, reg, key, _ := storeFixture(t)
	v := eligibleFixture(t, s, reg, key)
	m := newMockL3(t)
	engine, _ := NewL3(s, l3Cfg(m), nil)
	defer engine.Close()
	runner, _ := NewRunner(s, api.Config{Mode: "off"}, []byte(strings.Repeat("s", 32)), nil)
	defer runner.Close()
	reader, operator := strings.Repeat("r", 32), strings.Repeat("o", 32)
	handler := Handler(s, runner, reader, operator, engine)
	request := func(method, path, token, origin string, c Command) (int, []byte) {
		raw, _ := json.Marshal(c)
		q := httptest.NewRequest(method, "http://127.0.0.1:9999"+path, bytes.NewReader(raw))
		q.Header.Set("Authorization", "Bearer "+token)
		if origin != "" {
			q.Header.Set("Origin", origin)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, q)
		return w.Code, w.Body.Bytes()
	}
	command := Command{Tenant: "alpha", CaseID: v.Case.ID, CaseSHA: v.Case.SHA, RequestID: "http-run", Mode: "contain"}
	if code, _ := request("POST", "/v2/l3", reader, "", command); code != 401 {
		t.Fatal("reader mutated", code)
	}
	if code, _ := request("POST", "/v2/l3", operator, "http://foreign.example", command); code != 403 {
		t.Fatal("cross origin", code)
	}
	if code, raw := request("POST", "/v2/l3", operator, "", command); code != 200 {
		t.Fatal(code, string(raw))
	}
	run := awaitL3(t, s, "http-run")
	if run.Binding == nil {
		t.Fatal(run)
	}
	if code, _ := request("GET", "/v2/l3-run?tenant=beta&id=http-run", reader, "", Command{}); code != 404 {
		t.Fatal("cross tenant run", code)
	}
	if code, raw := request("GET", "/v2/outcome?tenant=alpha&id="+run.Binding.PolicyID+"&episode="+run.Binding.Episode, reader, "", Command{}); code != 200 || !bytes.Contains(raw, []byte("installed_locally")) {
		t.Fatal(code, string(raw))
	}
	if code, raw := request("GET", "/v2/status", reader, "", Command{}); code != 200 || !bytes.Contains(raw, []byte("outcome_audit")) || !bytes.Contains(raw, []byte("\"enabled\":true")) {
		t.Fatal(code, string(raw))
	}
	command = Command{Tenant: "alpha", SourceRun: "http-run", CaseSHA: v.Case.SHA, RequestID: "direct-release", Epoch: s.Epoch(), Generation: run.Binding.Generation}
	if code, _ := request("POST", "/v2/l3-release", reader, "", command); code != 401 {
		t.Fatal(code)
	}
	if code, raw := request("POST", "/v2/l3-release", operator, "", command); code != 200 || !bytes.Contains(raw, []byte("no_effective_policy")) {
		t.Fatal(code, string(raw))
	}
	if code, _ := request("GET", "/v2/outcome?tenant=beta&id="+run.Binding.PolicyID, reader, "", Command{}); code != 404 {
		t.Fatal("cross tenant outcome", code)
	}
	_ = http.MethodGet
}
