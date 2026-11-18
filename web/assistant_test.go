package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reverse-artex/internal/casememory"
	"reverse-artex/internal/localassistant"
	"strings"
	"sync/atomic"
	"testing"
)

func TestAIConsoleAuthenticationTenantAndRequestBinding(t *testing.T) {
	var modelCalls atomic.Int32
	model := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		modelCalls.Add(1)
		json.NewEncoder(w).Encode(map[string]any{"models": []any{}})
	}))
	defer model.Close()
	service, err := localassistant.Open(t.TempDir(), localassistant.Config{Origin: model.URL}, func(context.Context, string, string) (localassistant.BoundCase, error) {
		return localassistant.BoundCase{}, casememory.ErrNotFound
	})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	key := strings.Repeat("a", 64)
	mux := http.NewServeMux()
	Register(mux, Options{Token: key, Listen: "127.0.0.1:9081", Tenants: []string{"alpha", "beta"}, Assistant: service})
	call := func(method, path, body, auth, origin string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "http://127.0.0.1:9081/console/api/"+path, strings.NewReader(body))
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
	if w := call("GET", "ai/status", "", "", ""); w.Code != 401 {
		t.Fatal(w.Code)
	}
	if modelCalls.Load() != 0 {
		t.Fatal("unauthenticated caller reached local model")
	}
	if w := call("GET", "ai/status", "", key, "https://outside.invalid"); w.Code != 403 {
		t.Fatal(w.Code)
	}
	if w := call("GET", "ai/status", "", key, ""); w.Code != 200 || strings.Contains(w.Body.String(), key) {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := call("GET", "ai/runs?tenant=unregistered", "", key, ""); w.Code != 404 {
		t.Fatal(w.Code)
	}
	body := `{"tenant_id":"beta","case_id":"case-1","case_sha256":"` + strings.Repeat("a", 64) + `","model":"qwen:test","mode":"analyze"}`
	if w := call("POST", "ai/runs?tenant=alpha", body, key, ""); w.Code != 400 {
		t.Fatal(w.Code)
	}
	body = strings.Replace(body, `"beta"`, `"alpha"`, 1)
	if w := call("POST", "ai/runs?tenant=alpha", strings.TrimSuffix(body, "}")+`,"shell":"whoami"}`, key, ""); w.Code != 400 {
		t.Fatal(w.Code)
	}
	w := call("POST", "ai/runs?tenant=alpha", body, key, "")
	if w.Code != 202 {
		t.Fatal(w.Code, w.Body.String())
	}
	var run localassistant.Run
	json.Unmarshal(w.Body.Bytes(), &run)
	if w = call("GET", "ai/run?tenant=beta&id="+run.ID, "", key, ""); w.Code != 404 {
		t.Fatal(w.Code)
	}
	if w = call("POST", "ai/cancel?tenant=beta&id="+run.ID, "", key, ""); w.Code != 404 {
		t.Fatal(w.Code)
	}
	if w = call("POST", "ai/cancel?tenant=alpha&id="+run.ID, "", key, ""); w.Code != 200 {
		t.Fatal(w.Code)
	}
}
