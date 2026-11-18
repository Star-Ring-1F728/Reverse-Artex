package edge

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"reverse-artex/internal/protection"
	"testing"
)

func TestProtectedRejectsAmbiguousRepresentationHeadersBeforeRelease(t *testing.T) {
	for _, tc := range []struct {
		name, header string
		values       []string
	}{
		{"encoding", "Content-Encoding", []string{"identity", "gzip"}},
		{"duplicate-identity", "Content-Encoding", []string{"identity", "identity"}},
		{"empty-encoding-first", "Content-Encoding", []string{"", "gzip"}},
		{"type", "Content-Type", []string{"application/json", "text/html"}},
		{"range-empty-first", "Content-Range", []string{"", "bytes 0-2/3"}},
		{"range-empty", "Content-Range", []string{""}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, key := protectedBufferConfig(t, 1024)
			body := []byte(`{"value":"SIGNED_REPRESENTATION_SENTINEL"}`)
			audits := 0
			c.ProtectionAudit = func(protection.Observation) error { audits++; return nil }
			c.Transport = transport(func(r *http.Request) (*http.Response, error) {
				resp := protectedBufferResponse(c, key, r, body, "alice")
				resp.Header[tc.header] = tc.values
				return resp, nil
			})
			w := httptest.NewRecorder()
			Handler(c).ServeHTTP(w, protectedBufferRequest(c, "alice", "GET"))
			if w.Code != 503 || bytes.Contains(w.Body.Bytes(), body) || audits != 0 || w.Header().Get(protection.ProofHeader) != "" {
				t.Fatalf("ambiguous metadata released: status=%d audits=%d", w.Code, audits)
			}
		})
	}
}
