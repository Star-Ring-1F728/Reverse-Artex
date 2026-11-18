package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestProductionTriageKeepsConsoleAndTenantBoundary(t *testing.T) {
	key := strings.Repeat("p", 64)
	mux := http.NewServeMux()
	Register(mux, Options{Token: key, Listen: "127.0.0.1:9081", Directory: t.TempDir(), Tenants: []string{"alpha"}, ContextProductionUnavailable: "preserve configured journal"})
	for _, tt := range []struct {
		name, method, path, auth, origin string
		code                             int
	}{
		{"anonymous", "GET", "status?tenant=alpha", "", "", 401},
		{"cross-origin", "POST", "stop?tenant=alpha", key, "https://untrusted.invalid", 403},
		{"duplicate-tenant", "GET", "status?tenant=alpha&tenant=alpha", key, "", 400},
		{"arbitrary-path", "GET", "status?tenant=alpha&profile=private", key, "", 400},
		{"other-tenant", "GET", "status?tenant=beta", key, "", 404},
		{"unavailable", "GET", "status?tenant=alpha", key, "", 200},
		{"no-web-approval", "POST", "approve?tenant=alpha", key, "", 405},
		{"stop-unavailable", "POST", "stop?tenant=alpha", key, "", 503},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(tt.method, "http://127.0.0.1:9081/console/api/cases/context-production/"+tt.path, strings.NewReader(`{}`))
			if tt.auth != "" {
				r.Header.Set("Authorization", "Bearer "+tt.auth)
			}
			if tt.origin != "" {
				r.Header.Set("Origin", tt.origin)
			}
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, r)
			if w.Code != tt.code {
				t.Fatal(w.Code, w.Body.String())
			}
			if tt.name == "unavailable" && !strings.Contains(w.Body.String(), `"deployment_allowed":false`) {
				t.Fatal(w.Body.String())
			}
		})
	}
}
