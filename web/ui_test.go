package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConsoleAccessAndOfflineIsolation(t *testing.T) {
	dir := t.TempDir()
	key := strings.Repeat("a", 64)
	mux := http.NewServeMux()
	Register(mux, Options{Token: key, Listen: "127.0.0.1:9081", Directory: dir, Status: func() any { return map[string]bool{"ready": true} }})
	call := func(method, path, auth, origin string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "http://127.0.0.1:9081"+path, nil)
		if auth != "" {
			r.Header.Set("Authorization", "Bearer "+auth)
		}
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}
	if w := call("GET", "/console/api/status", "", ""); w.Code != 401 {
		t.Fatalf("anonymous status: %d", w.Code)
	}
	if w := call("POST", "/console/api/sample", key, "https://untrusted.invalid"); w.Code != 403 {
		t.Fatalf("cross-origin analysis: %d", w.Code)
	}
	r := httptest.NewRequest("GET", "http://untrusted.invalid:9081/console/api/status", nil)
	r.Header.Set("Authorization", "Bearer "+key)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatalf("foreign host: %d", w.Code)
	}
	w = call("POST", "/console/api/sample", key, "http://127.0.0.1:9081")
	if w.Code != 200 {
		t.Fatalf("sample: %d %s", w.Code, w.Body.String())
	}
	var result struct {
		Events int `json:"events"`
		Alerts []struct {
			Rule string `json:"rule_id"`
		} `json:"alerts"`
		Changed bool `json:"live_evidence_changed"`
		Actions int  `json:"policy_actions"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	foundRecon := false
	for _, alert := range result.Alerts {
		foundRecon = foundRecon || alert.Rule == "RA-002"
	}
	if result.Events != 12 || !foundRecon || result.Changed || result.Actions != 0 {
		t.Fatalf("unexpected analysis: %s", w.Body.String())
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatal("offline analysis modified live evidence")
	}
	if w = call("GET", "/console/api/stream?name=../../config", key, ""); w.Code != 400 {
		t.Fatalf("path selection: %d", w.Code)
	}
	if w = call("GET", "/", "", ""); w.Code != 200 || !strings.Contains(w.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Fatalf("page: %d", w.Code)
	}
}

func TestTailSkipsUncommittedRecordAndBoundsRows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	if err := os.WriteFile(path, []byte("{\"event_id\":\"complete\"}\n{\"event_id\":\"partial\"}"), 0600); err != nil {
		t.Fatal(err)
	}
	rows, _, err := tail(path)
	if err != nil || len(rows) != 1 || !strings.Contains(string(rows[0]), "complete") {
		t.Fatalf("tail: %s %v", rows, err)
	}
	if _, err := analyze(strings.NewReader("{}\n")); err == nil {
		t.Fatal("invalid event was accepted")
	}
}
