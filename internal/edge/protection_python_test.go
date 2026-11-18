package edge

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Opt in with a Python interpreter whose PYTHONPATH contains the SDK and its
// pinned dependency. Never installs packages or starts persistent services.
func TestPythonGuardToGoEdgeInteroperability(t *testing.T) {
	python := os.Getenv("RA_GUARD_TEST_PYTHON")
	if python == "" {
		t.Skip("opt-in Python SDK interoperability")
	}
	for _, kind := range []string{"owner", "foreign-owner", "foreign-tenant", "shared-grant", "revoked-grant", "head", "resolver-substitution"} {
		t.Run(kind, func(t *testing.T) {
			c, key := guardFixture(t)
			c.Transport = transport(func(r *http.Request) (*http.Response, error) {
				snapshot := map[string]any{"canonical_id": "one", "tenant": "alpha", "owner": "alice", "grants": []string{}, "authz_revision": "acl1", "content_revision": "v1", "payload": map[string]string{"secret": "PYTHON_PRIVATE"}}
				switch kind {
				case "foreign-owner", "revoked-grant":
					snapshot["owner"] = "bob"
				case "foreign-tenant":
					snapshot["tenant"] = "beta"
				case "shared-grant":
					snapshot["owner"] = "bob"
					snapshot["grants"] = []string{"alice"}
				case "resolver-substitution":
					snapshot["canonical_id"] = "other"
				}
				headers := map[string]string{}
				for k, v := range r.Header {
					headers[k] = v[0]
				}
				// Preserve the actual Go header spelling. Adding alternate spellings
				// would send duplicate fields to the SDK's case-insensitive reader.
				input := map[string]any{"config": map[string]any{"asset": c.Asset, "registry_digest": c.Protection.Digest(), "trust_epoch": c.Protection.Epoch(), "route_id": "legacy", "template": "/legacy/objects/{id}", "namespace": "objects", "tenants": []string{"alpha"}, "key_id": "sdk1", "private_key": base64.StdEncoding.EncodeToString(key.Seed()), "identity_key": base64.StdEncoding.EncodeToString(c.IdentityKey), "session_key": base64.StdEncoding.EncodeToString(c.HMACKey), "ingress_token": c.IngressToken, "max_body_bytes": 1024}, "snapshot": snapshot, "headers": headers, "method": r.Method, "target": r.URL.RequestURI()}
				raw, _ := json.Marshal(input)
				cmd := exec.CommandContext(r.Context(), python, filepath.Join("..", "..", "sdk", "python", "tests", "emit_fixture.py"))
				cmd.Stdin = bytes.NewReader(raw)
				output, err := cmd.Output()
				if err != nil {
					t.Errorf("Python fixture failed: %v", err)
					return nil, err
				}
				var result struct {
					Status  int
					Body    string
					Headers map[string]string
				}
				if err = json.Unmarshal(output, &result); err != nil {
					t.Fatal(err)
				}
				body, err := base64.StdEncoding.DecodeString(result.Body)
				if err != nil {
					t.Fatal(err)
				}
				h := make(http.Header)
				for k, v := range result.Headers {
					h.Set(k, v)
				}
				return &http.Response{StatusCode: result.Status, Header: h, Body: io.NopCloser(bytes.NewReader(body)), Request: r}, nil
			})
			method := "GET"
			want := 200
			switch kind {
			case "foreign-owner", "foreign-tenant", "revoked-grant":
				want = 403
			case "resolver-substitution":
				want = 503
			case "head":
				method = "HEAD"
			}
			w := httptest.NewRecorder()
			started := time.Now()
			Handler(c).ServeHTTP(w, guardRequest(c, "/legacy/objects/one", method))
			if w.Code != want {
				t.Fatalf("status=%d want=%d elapsed=%s body=%s", w.Code, want, time.Since(started), w.Body.String())
			}
			if want != 200 && strings.Contains(w.Body.String(), "PYTHON_PRIVATE") {
				t.Fatal("foreign payload escaped")
			}
			if method == "HEAD" && w.Body.Len() != 0 {
				t.Fatal("HEAD released bytes")
			}
		})
	}
}
