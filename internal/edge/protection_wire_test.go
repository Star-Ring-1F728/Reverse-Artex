package edge

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reverse-artex/internal/protection"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestPythonSDKThroughRealHTTPProtectedEdge(t *testing.T) {
	python := os.Getenv("RA_GUARD_TEST_PYTHON")
	if python == "" {
		t.Skip("opt-in real Python SDK HTTP integration")
	}
	c, key := guardFixture(t)
	config := map[string]any{"asset": c.Asset, "registry_digest": c.Protection.Digest(), "trust_epoch": c.Protection.Epoch(), "route_id": "legacy", "template": "/legacy/objects/{id}", "namespace": "objects", "tenants": []string{"alpha"}, "key_id": "sdk1", "private_key": base64.StdEncoding.EncodeToString(key.Seed()), "identity_key": base64.StdEncoding.EncodeToString(c.IdentityKey), "session_key": base64.StdEncoding.EncodeToString(c.HMACKey), "ingress_token": c.IngressToken, "max_body_bytes": 1024}
	raw, _ := json.Marshal(config)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, python, "-u", filepath.Join("..", "..", "sdk", "python", "tests", "serve_fixture.py"))
	cmd.Stdin = bytes.NewReader(append(raw, '\n'))
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil {
		t.Fatal("Python fixture readiness", err)
	}
	c.Upstream, err = url.Parse(strings.TrimSpace(line))
	if err != nil || c.Upstream.Hostname() != "127.0.0.1" {
		t.Fatal("fixture not on owned loopback")
	}
	var audits atomic.Int32
	c.ProtectionAudit = func(o protection.Observation) error { audits.Add(1); return nil }
	var timing atomic.Value
	timing.Store("")
	wireTransport := http.DefaultTransport.(*http.Transport).Clone()
	wireTransport.Proxy = nil
	defer wireTransport.CloseIdleConnections()
	c.Transport = transport(func(req *http.Request) (*http.Response, error) {
		before := time.Now()
		resp, err := wireTransport.RoundTrip(req)
		after := time.Now()
		if err == nil {
			var envelope protection.Envelope
			var proof protection.Proof
			json.Unmarshal([]byte(resp.Header.Get(protection.ProofHeader)), &envelope)
			raw, _ := base64.RawURLEncoding.DecodeString(envelope.Payload)
			json.Unmarshal(raw, &proof)
			timing.Store(fmt.Sprintf("upstream_status=%d issued_minus_go_before_ms=%d go_headers_minus_issued_ms=%d remaining_ms=%d", resp.StatusCode, proof.Issued-before.UnixMilli(), after.UnixMilli()-proof.Issued, proof.Expires-after.UnixMilli()))
		}
		return resp, err
	})
	edgeServer := httptest.NewServer(Handler(c))
	defer edgeServer.Close()
	for _, test := range []struct {
		object, method string
		status         int
	}{
		{"self", "GET", 200}, {"foreign", "GET", 403}, {"other-tenant", "GET", 403},
		{"shared", "GET", 200}, {"revoked", "GET", 403}, {"self", "HEAD", 200}, {"broken", "GET", 503},
	} {
		t.Run(test.object+"-"+test.method, func(t *testing.T) {
			req := guardRequest(c, "/legacy/objects/"+test.object, test.method)
			req.RequestURI = ""
			req.URL, _ = url.Parse(edgeServer.URL + "/legacy/objects/" + test.object)
			resp, err := edgeServer.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != test.status {
				t.Fatal(resp.StatusCode, test.status, string(body), timing.Load())
			}
			if test.status != 200 && strings.Contains(string(body), "WIRE_PRIVATE") {
				t.Fatal("foreign/unsigned bytes escaped")
			}
			if test.method == http.MethodHead && len(body) != 0 {
				t.Fatal("HEAD released body")
			}
			if resp.Header.Get("X-RA-Release-Proof") != "" {
				t.Fatal("internal signature exposed")
			}
		})
	}
	if audits.Load() != 6 {
		t.Fatal("signed response audit count", audits.Load())
	}
}
