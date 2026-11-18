package edge

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reverse-artex/internal/protection"
	"reverse-artex/internal/routecoverage"
	"strings"
	"testing"
	"time"
)

func TestCoverageAuditRunsBeforeEveryUpstreamAdmission(t *testing.T) {
	for _, failure := range []bool{false, true} {
		t.Run(map[bool]string{false: "healthy", true: "audit-failure"}[failure], func(t *testing.T) {
			c, _ := guardFixture(t)
			p, err := routecoverage.New(routecoverage.Manifest{Schema: "route-coverage/1", Asset: c.Asset, Revision: "c1", Registry: c.Protection.Digest(), Exceptions: []routecoverage.Exception{{ID: "search", Path: "/api/search", Methods: []string{"GET"}, Query: "allow", Reason: "Application owns search authorization."}}}, c.Protection)
			if err != nil {
				t.Fatal(err)
			}
			audits, calls := 0, 0
			c.Coverage = routecoverage.NewGate(p, func(o routecoverage.Observation) error {
				audits++
				if o.RequestID == "forged" || strings.Contains(o.PathHMAC, "private-value") {
					t.Fatal(o)
				}
				if failure {
					return errors.New("disk unavailable")
				}
				return nil
			})
			c.Transport = transport(func(r *http.Request) (*http.Response, error) {
				calls++
				if audits < calls {
					t.Fatal("request passed audit")
				}
				if r.Header.Get("X-RA-Request-ID") == "forged" {
					t.Fatal("client request id used")
				}
				return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{"results":[]}`)), Request: r}, nil
			})
			h := Handler(c)
			for _, path := range []string{"/api/search?q=private-value", "/api/export", "/v2/objects/one", "/legacy/objects/one/two", "/healthz"} {
				w := httptest.NewRecorder()
				r := httptest.NewRequest("GET", path, nil)
				r.Header.Set("X-RA-Request-ID", "forged")
				h.ServeHTTP(w, r)
				want := 404
				if path == "/api/search?q=private-value" || path == "/healthz" {
					want = 200
				}
				if path == "/legacy/objects/one/two" {
					want = 400
				}
				if failure {
					want = 503
				}
				if w.Code != want {
					t.Fatal(path, w.Code, w.Body.String())
				}
				if len(w.Header().Get("X-Request-ID")) != 32 {
					t.Fatal("trusted correlation missing")
				}
			}
			if failure && calls != 0 {
				t.Fatal("audit failure reached application")
			}
			if !failure && calls != 1 {
				t.Fatal("unregistered request reached application", calls)
			}
		})
	}
}
func TestCoverageHEADAndConfigurationMismatchFailClosed(t *testing.T) {
	c, _ := guardFixture(t)
	p, _ := routecoverage.New(routecoverage.Manifest{Schema: "route-coverage/1", Asset: c.Asset, Revision: "c1", Registry: c.Protection.Digest()}, c.Protection)
	c.Coverage = routecoverage.NewGate(p, func(routecoverage.Observation) error { return nil })
	c.Transport = transport(func(*http.Request) (*http.Response, error) { t.Fatal("unregistered HEAD forwarded"); return nil, nil })
	w := httptest.NewRecorder()
	Handler(c).ServeHTTP(w, httptest.NewRequest("HEAD", "/admin", nil))
	if w.Code != 404 || w.Body.Len() != 0 {
		t.Fatal(w.Code, w.Body.String())
	}
	c.Asset = "other"
	w = httptest.NewRecorder()
	Handler(c).ServeHTTP(w, httptest.NewRequest("GET", "/admin", nil))
	if w.Code != 503 {
		t.Fatal(w.Code)
	}
}

func TestCoverageAuditConsumesOriginalRequestBudget(t *testing.T) {
	for _, elapsed := range []time.Duration{4 * time.Second, 5 * time.Second} {
		t.Run(elapsed.String(), func(t *testing.T) {
			c, key := guardFixture(t)
			started := time.Now()
			clock := started
			c.Now = func() time.Time { return clock }
			p, _ := routecoverage.New(routecoverage.Manifest{Schema: "route-coverage/1", Asset: c.Asset, Revision: "c1", Registry: c.Protection.Digest()}, c.Protection)
			c.Coverage = routecoverage.NewGate(p, func(routecoverage.Observation) error { clock = clock.Add(elapsed); return nil })
			calls := 0
			c.Transport = transport(func(r *http.Request) (*http.Response, error) {
				calls++
				deadline, ok := r.Context().Deadline()
				if !ok || !deadline.Equal(started.Add(protection.ProofLifetime)) {
					t.Fatal("audit extended original deadline", deadline, started)
				}
				body := []byte(`{"value":"owned"}`)
				h := http.Header{}
				h.Set("Content-Type", "application/json")
				h.Set(protection.ProofHeader, sdkProof(c, key, r, body, nil))
				return &http.Response{StatusCode: 200, Header: h, Body: io.NopCloser(strings.NewReader(string(body))), Request: r}, nil
			})
			w := httptest.NewRecorder()
			Handler(c).ServeHTTP(w, guardRequest(c, "/legacy/objects/one", "GET"))
			if elapsed >= protection.ProofLifetime {
				if w.Code != 503 || calls != 0 {
					t.Fatal("expired admission reached SDK", w.Code, calls)
				}
			} else if w.Code != 200 || calls != 1 {
				t.Fatal(w.Code, calls, w.Body.String())
			}
		})
	}
}
