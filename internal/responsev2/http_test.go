package responsev2

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestManagementRolesConsoleAndExactReleaseReplay(t *testing.T) {
	s, reg, key, _ := storeFixture(t)
	v := eligibleFixture(t, s, reg, key)
	runner, err := NewRunner(s, configFixture("fake"), []byte(strings.Repeat("p", 32)), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer runner.Close()
	reader, operator := strings.Repeat("r", 40), strings.Repeat("o", 40)
	server := httptest.NewServer(Handler(s, runner, reader, operator))
	defer server.Close()
	call := func(method, path, token, origin string, body any) (int, []byte) {
		t.Helper()
		var b []byte
		if body != nil {
			b, _ = json.Marshal(body)
		}
		req, _ := http.NewRequest(method, server.URL+path, bytes.NewReader(b))
		req.Header.Set("Authorization", "Bearer "+token)
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		res, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		raw, _ := io.ReadAll(res.Body)
		return res.StatusCode, raw
	}
	if status, _ := call("GET", "/v2/console", "", "", nil); status != 200 {
		t.Fatal("console unavailable", status)
	}
	if status, _ := call("GET", "/v2/status", reader, "", nil); status != 200 {
		t.Fatal(status)
	}
	if status, _ := call("POST", "/v2/pause", reader, "", Command{}); status != 401 {
		t.Fatal("reader mutated", status)
	}
	if status, _ := call("POST", "/v2/pause", operator, "http://malicious.invalid", Command{}); status != 403 {
		t.Fatal("foreign origin accepted", status)
	}
	if status, _ := call("GET", "/v2/case?tenant=beta&id="+v.Case.ID, reader, "", nil); status != 404 {
		t.Fatal("cross tenant read", status)
	}
	intent := intentFixture(s, v, "apply", "operator", "owned")
	first, err := s.Apply(context.Background(), "alpha", intent)
	if err != nil {
		t.Fatal(err)
	}
	policies := s.Policies("alpha")
	cmd := Command{Tenant: "alpha", PolicyID: first.PolicyID, Owner: "operator", Run: "owned", Generation: policies[0].Generation, RequestID: "release"}
	status, raw := call("POST", "/v2/release", operator, server.URL, cmd)
	if status != 200 {
		t.Fatal(status, string(raw))
	}
	var receipt Receipt
	json.Unmarshal(raw, &receipt)
	status, again := call("POST", "/v2/release", operator, server.URL, cmd)
	if status != 200 || string(raw) != string(again) {
		t.Fatal("release replay not exact", status, string(again))
	}
	// A release ID cannot overwrite a prior application receipt.
	cmd.RequestID = intent.ID
	if status, _ := call("POST", "/v2/release", operator, server.URL, cmd); status != 409 {
		t.Fatal("intent ID collision accepted", status)
	}
	if len(s.Policies("alpha")) != 0 {
		t.Fatal("released policy active")
	}
}
