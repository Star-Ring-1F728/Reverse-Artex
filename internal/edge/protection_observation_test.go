package edge

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reverse-artex/internal/protection"
	"strings"
	"testing"
	"time"
)

type brokenResponse struct {
	*httptest.ResponseRecorder
	mode string
}

func (w brokenResponse) Write(body []byte) (int, error) {
	if w.mode == "panic" {
		panic("synthetic disconnected writer")
	}
	n := len(body) / 2
	w.ResponseRecorder.Write(body[:n])
	return n, errors.New("synthetic short write")
}
func TestProtectedWriteObservationsGETHEADAndInterruptedWrites(t *testing.T) {
	for _, kind := range []string{"GET", "HEAD", "deny-GET", "deny-HEAD", "short", "panic"} {
		t.Run(kind, func(t *testing.T) {
			c, key := guardFixture(t)
			method := "GET"
			if strings.Contains(kind, "HEAD") {
				method = "HEAD"
			}
			deny := strings.HasPrefix(kind, "deny")
			c.Transport = transport(func(r *http.Request) (*http.Response, error) {
				body := []byte("{\"secret\":\"private\"}")
				if method == "HEAD" {
					body = nil
				}
				h := http.Header{"Content-Type": []string{"application/json"}}
				h.Set(protection.ProofHeader, sdkProof(c, key, r, body, nil))
				return &http.Response{StatusCode: 200, Header: h, Body: io.NopCloser(strings.NewReader(string(body))), Request: r}, nil
			})
			c.ProtectionGate = func(string, protection.RequestBinding, int, []byte, time.Time) (protection.GateDecision, error) {
				return protection.GateDecision{AttemptID: "trusted-attempt", Deny: deny, PolicyID: "policy"}, nil
			}
			reports := []protection.ResponseWrite{}
			c.ProtectionReport = func(w protection.ResponseWrite) error { reports = append(reports, w); return nil }
			recorder := httptest.NewRecorder()
			var writer http.ResponseWriter = recorder
			if kind == "short" || kind == "panic" {
				writer = brokenResponse{recorder, kind}
			}
			func() {
				defer func() {
					if caught := recover(); caught != nil && kind != "panic" {
						t.Fatal(caught)
					}
				}()
				Handler(c).ServeHTTP(writer, guardRequest(c, "/legacy/objects/one", method))
			}()
			if len(reports) != 1 {
				t.Fatal("missing completion callback", reports)
			}
			report := reports[0]
			expected := 200
			if deny {
				expected = 429
			}
			if report.AttemptID != "trusted-attempt" || report.Status != expected {
				t.Fatal(report)
			}
			if kind == "short" || kind == "panic" {
				if report.Complete {
					t.Fatal("partial response reported complete", report)
				}
				return
			}
			if !report.Complete || report.Error || report.Bytes != recorder.Body.Len() || report.BodySHA != protection.BodyHash(recorder.Body.Bytes()) {
				t.Fatal(report)
			}
			if method == "HEAD" && report.Bytes != 0 {
				t.Fatal("HEAD leaked body")
			}
			if deny && strings.Contains(recorder.Body.String(), "private") {
				t.Fatal("denial leaked payload")
			}
		})
	}
}
