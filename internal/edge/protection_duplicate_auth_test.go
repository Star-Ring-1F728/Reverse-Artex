package edge

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Exercise the wire parser as well as Header.Values: differently cased field
// names must retain the same ambiguity boundary before protected forwarding.
func TestProtectedRawHTTPDuplicateAuthorization(t *testing.T) {
	for _, name := range []string{"valid-first", "invalid-first", "case-mixed", "no-header", "single-valid", "head-no-header", "head-single-valid"} {
		t.Run(name, func(t *testing.T) {
			c, key := guardFixture(t)
			var upstreamCalls atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				upstreamCalls.Add(1)
				body := []byte(`{"value":"OWNED_CONTROL"}`)
				if r.Method == "HEAD" {
					body = nil
				}
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("X-RA-Release-Proof", sdkProof(c, key, r, body, nil))
				w.Write(body)
			}))
			defer upstream.Close()
			c.Upstream, _ = url.Parse(upstream.URL)
			edge := httptest.NewServer(Handler(c))
			defer edge.Close()
			valid := "Bearer " + credential("alice", c.IdentityKey, time.Now())
			method, fields, wantStatus, wantBody, wantCalls := "GET", "", 400, "ambiguous authentication\n", int32(0)
			switch name {
			case "valid-first":
				fields = "Authorization: " + valid + "\r\nAuthorization: Bearer invalid\r\n"
			case "invalid-first":
				fields = "Authorization: Bearer invalid\r\nAuthorization: " + valid + "\r\n"
			case "case-mixed":
				fields = "authorization: " + valid + "\r\nAUTHORIZATION: Bearer invalid\r\n"
			case "no-header", "head-no-header":
				wantStatus, wantBody = 401, "Unauthorized\n"
			case "single-valid", "head-single-valid":
				fields = "Authorization: " + valid + "\r\n"
				wantStatus, wantBody, wantCalls = 200, `{"value":"OWNED_CONTROL"}`, 1
			}
			if strings.HasPrefix(name, "head-") {
				method, wantBody = "HEAD", ""
			}
			conn, err := net.DialTimeout("tcp", strings.TrimPrefix(edge.URL, "http://"), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err := fmt.Fprintf(conn, "%s /legacy/objects/one HTTP/1.1\r\nHost: owned.invalid\r\n%sConnection: close\r\n\r\n", method, fields); err != nil {
				t.Fatal("request write failed")
			}
			resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: method})
			if err != nil {
				t.Fatal("response read failed")
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal("body read failed")
			}
			if resp.StatusCode != wantStatus || string(body) != wantBody || upstreamCalls.Load() != wantCalls {
				t.Errorf("status=%d want=%d body=%q want=%q upstream_calls=%d want=%d", resp.StatusCode, wantStatus, body, wantBody, upstreamCalls.Load(), wantCalls)
			}
			if resp.Header.Get("X-RA-Release-Proof") != "" {
				t.Error("internal proof exposed")
			}
		})
	}
}
