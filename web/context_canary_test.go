package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCanaryStatusAndStopKeepConsoleAccessBoundary(t *testing.T) {
	key := strings.Repeat("a", 64)
	mux := http.NewServeMux()
	Register(mux, Options{Token: key, Listen: "127.0.0.1:9081", Directory: t.TempDir(), Tenants: []string{"alpha"}, ContextCanaryUnavailable: "preserve configured journal"})
	for _, tt := range []struct {
		name, method, path, auth, origin, host string
		code                                   int
	}{
		{"anonymous", "GET", "/console/api/cases/context-canary/status?tenant=alpha", "", "", "", 401},
		{"cross-origin", "POST", "/console/api/cases/context-canary/stop?tenant=alpha", key, "https://untrusted.invalid", "", 403},
		{"foreign-host", "GET", "/console/api/cases/context-canary/status?tenant=alpha", key, "", "untrusted.invalid:9081", 403},
		{"missing-tenant", "GET", "/console/api/cases/context-canary/status", key, "", "", 400},
		{"duplicate-tenant", "GET", "/console/api/cases/context-canary/status?tenant=alpha&tenant=alpha", key, "", "", 400},
		{"path-injection", "GET", "/console/api/cases/context-canary/status?tenant=alpha&profile=private", key, "", "", 400},
		{"other-tenant", "GET", "/console/api/cases/context-canary/status?tenant=beta", key, "", "", 404},
		{"unavailable", "GET", "/console/api/cases/context-canary/status?tenant=alpha", key, "", "", 200},
		{"stop-unavailable", "POST", "/console/api/cases/context-canary/stop?tenant=alpha", key, "", "", 503},
		{"no-approve-api", "POST", "/console/api/cases/context-canary/approve?tenant=alpha", key, "", "", 405},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(tt.method, "http://127.0.0.1:9081"+tt.path, strings.NewReader(`{}`))
			if tt.auth != "" {
				r.Header.Set("Authorization", "Bearer "+tt.auth)
			}
			if tt.origin != "" {
				r.Header.Set("Origin", tt.origin)
			}
			if tt.host != "" {
				r.Host = tt.host
			}
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, r)
			if w.Code != tt.code {
				t.Fatal(w.Code, w.Body.String())
			}
			if tt.name == "unavailable" && (!strings.Contains(w.Body.String(), `"state":"UNAVAILABLE"`) || !strings.Contains(w.Body.String(), `"deployment_allowed":false`)) {
				t.Fatal(w.Body.String())
			}
		})
	}
}
