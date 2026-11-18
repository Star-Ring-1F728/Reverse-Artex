package edge

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reverse-artex/internal/protection"
	"strings"
	"testing"
	"time"
)

type completionReader func([]byte) (int, error)

func (read completionReader) Read(p []byte) (int, error) { return read(p) }

func TestProtectedBodyRequiresCleanEOFWithinBound(t *testing.T) {
	for _, kind := range []string{"empty", "short", "exact", "fragmented", "data-and-eof", "oversize", "short-framing-error", "exact-framing-error", "no-progress"} {
		t.Run(kind, func(t *testing.T) {
			storage := []byte("PRIOR_PRIVATE_XX")
			want := "{}"
			var reader io.Reader
			switch kind {
			case "empty":
				want = ""
			case "exact":
				want = strings.Repeat("x", len(storage))
			case "fragmented":
				remaining := want
				reader = completionReader(func(p []byte) (int, error) {
					if remaining == "" {
						return 0, io.EOF
					}
					p[0] = remaining[0]
					remaining = remaining[1:]
					return 1, nil
				})
			case "data-and-eof", "short-framing-error", "exact-framing-error":
				if kind == "exact-framing-error" {
					want = strings.Repeat("x", len(storage))
				}
				reader = completionReader(func(p []byte) (int, error) {
					err := io.EOF
					if kind != "data-and-eof" {
						err = io.ErrUnexpectedEOF
					}
					return copy(p, want), err
				})
			case "oversize":
				want = strings.Repeat("x", len(storage)+1)
			case "no-progress":
				reader = completionReader(func([]byte) (int, error) { return 0, nil })
			}
			if reader == nil {
				reader = strings.NewReader(want)
			}
			body, err := readProtectedBody(reader, storage)
			switch kind {
			case "oversize":
				if err == nil || body != nil {
					t.Fatal("oversize response accepted", string(body), err)
				}
			case "short-framing-error", "exact-framing-error":
				if !errors.Is(err, io.ErrUnexpectedEOF) || body != nil {
					t.Fatal("framing error lost", string(body), err)
				}
			case "no-progress":
				if !errors.Is(err, io.ErrNoProgress) || body != nil {
					t.Fatal("non-progressing reader accepted", string(body), err)
				}
			default:
				if err != nil || string(body) != want {
					t.Fatalf("complete body changed: got=%q want=%q err=%v", body, want, err)
				}
			}
		})
	}
}

// A signed prefix is insufficient when HTTP framing says the representation
// was interrupted. Exercise a real transport, not a fabricated reader error.
func TestProtectedResponseRejectsTruncatedHTTPBody(t *testing.T) {
	for _, reuse := range []bool{false, true} {
		for _, framing := range []string{"content-length", "chunked", "complete"} {
			t.Run(fmt.Sprintf("reuse=%t/%s", reuse, framing), func(t *testing.T) {
				c, key := guardFixture(t)
				c.ReuseProtectedBuffers = reuse
				body := []byte(`{"secret":"TRUNCATED_PRIVATE"}`)
				upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					w.Header().Set(protection.ProofHeader, sdkProof(c, key, r, body, nil))
					switch framing {
					case "content-length":
						w.Header().Set("Content-Length", fmt.Sprint(len(body)+10))
						_, _ = w.Write(body)
					case "chunked":
						w.WriteHeader(200)
						w.(http.Flusher).Flush()
						_, _ = w.Write(body)
						w.(http.Flusher).Flush()
						conn, _, err := w.(http.Hijacker).Hijack()
						if err != nil {
							t.Error(err)
							return
						}
						_ = conn.Close() // No terminating zero-length chunk.
					default:
						_, _ = w.Write(body)
					}
				}))
				defer upstream.Close()
				c.Upstream, _ = url.Parse(upstream.URL)
				audits, gates := 0, 0
				c.ProtectionAudit = func(protection.Observation) error { audits++; return nil }
				c.ProtectionGate = func(string, protection.RequestBinding, int, []byte, time.Time) (protection.GateDecision, error) {
					gates++
					return protection.GateDecision{}, nil
				}
				w := httptest.NewRecorder()
				Handler(c).ServeHTTP(w, guardRequest(c, "/legacy/objects/one", "GET"))
				if framing == "complete" {
					if w.Code != 200 || w.Body.String() != string(body) || audits != 1 || gates != 1 {
						t.Fatalf("complete response changed: status=%d body=%q audit=%d gate=%d", w.Code, w.Body.String(), audits, gates)
					}
				} else if w.Code != 503 || strings.Contains(w.Body.String(), "PRIVATE") || audits != 0 || gates != 0 {
					t.Fatalf("interrupted HTTP response released: status=%d body=%q audit=%d gate=%d", w.Code, w.Body.String(), audits, gates)
				}
			})
		}
	}
}

func TestProtectedResponseCancellationDuringGateCannotRelease(t *testing.T) {
	for _, method := range []string{"GET", "HEAD"} {
		for _, deny := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/deny=%t", method, deny), func(t *testing.T) {
				c, key := guardFixture(t)
				body := []byte(`{"secret":"CANCELLED_PRIVATE"}`)
				if method == "HEAD" {
					body = nil
				}
				c.Transport = transport(func(r *http.Request) (*http.Response, error) {
					h := http.Header{"Content-Type": []string{"application/json"}}
					h.Set(protection.ProofHeader, sdkProof(c, key, r, body, nil))
					return &http.Response{StatusCode: 200, Header: h, Body: io.NopCloser(strings.NewReader(string(body))), Request: r}, nil
				})
				r := guardRequest(c, "/legacy/objects/one", method)
				ctx, cancel := context.WithCancel(r.Context())
				defer cancel()
				c.ProtectionGate = func(string, protection.RequestBinding, int, []byte, time.Time) (protection.GateDecision, error) {
					cancel()
					return protection.GateDecision{AttemptID: "cancelled-attempt", Deny: deny, PolicyID: "policy"}, nil
				}
				reports := []protection.ResponseWrite{}
				c.ProtectionReport = func(r protection.ResponseWrite) error { reports = append(reports, r); return nil }
				w := httptest.NewRecorder()
				Handler(c).ServeHTTP(w, r.WithContext(ctx))
				if w.Code != 503 || strings.Contains(w.Body.String(), "PRIVATE") {
					t.Fatalf("cancelled request released: status=%d body=%q", w.Code, w.Body.String())
				}
				if len(reports) != 1 || reports[0].Complete || !reports[0].Error || reports[0].Status != 503 {
					t.Fatalf("cancelled attempt misreported: %+v", reports)
				}
				if method == "HEAD" && w.Body.Len() != 0 {
					t.Fatal("cancelled HEAD wrote a body")
				}
			})
		}
	}
}
