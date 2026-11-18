package openai_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"reverse-artex/internal/decisions"
	api "reverse-artex/internal/decisions/openai"
	"reverse-artex/internal/protection"
	"reverse-artex/internal/responsev2"
)

type virtualCase struct {
	store    *responsev2.Store
	registry *protection.Registry
	key      ed25519.PrivateKey
	path     string
	view     responsev2.CaseView
}

func newVirtualCase(t *testing.T, kinds ...string) *virtualCase {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := protection.New(protection.Manifest{Schema: "protection-registry/1", Asset: "app", Revision: "r1", TrustEpoch: "e1", Enforcer: "edge1", Tenants: []string{"alpha", "beta"}, Keys: map[string]string{"sdk": base64.RawURLEncoding.EncodeToString(pub)}, Routes: []protection.Route{{ID: "object", Template: "/legacy/objects/{id}", Namespace: "objects", Mode: "enforce", MaxBody: 1024, AuthAdapter: "lab-hmac-v1", Resolver: "session-snapshot-v1"}}})
	if err != nil {
		t.Fatal(err)
	}
	f := &virtualCase{registry: registry, key: key, path: filepath.Join(t.TempDir(), "response.jsonl")}
	f.store, err = responsev2.Open(f.path, registry)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.store.Close() })
	for n, kind := range kinds {
		f.observe(t, fmt.Sprintf("initial-%d", n), fmt.Sprintf("object-%d", n), kind)
	}
	return f
}

func (f *virtualCase) observe(t *testing.T, id, object, decision string) responsev2.GateResult {
	t.Helper()
	at := time.Now()
	binding := protection.RequestBinding{RequestID: id, Nonce: "nonce-" + id, Method: "GET", Route: "object", Tenant: "alpha", Principal: "fixture-principal", Session: "fixture-session", Resource: decisions.Hash(object), Started: at.Add(-time.Millisecond)}
	status, body := 403, []byte(`{"error":"forbidden"}`)
	authz, content := "acl1", "v1"
	switch decision {
	case "allow":
		status, body = 200, []byte(`{"object":"own"}`)
	case "unauthenticated":
		status, body, authz, content = 401, []byte(`{"error":"authentication"}`), "unknown", "unknown"
	case "not_found":
		status, body, authz, content = 404, []byte(`{"error":"missing"}`), "unknown", "unknown"
	case "unknown":
		status, body = 503, []byte(`{"error":"unavailable"}`)
	}
	p := protection.Proof{Schema: "release-proof/1", KeyID: "sdk", Asset: f.registry.Asset(), Registry: f.registry.Digest(), Epoch: f.registry.Epoch(), RequestID: binding.RequestID, Nonce: binding.Nonce, Method: binding.Method, Route: binding.Route, Tenant: binding.Tenant, Principal: binding.Principal, Session: binding.Session, Resource: binding.Resource, Action: "read", AuthzRevision: authz, ContentRevision: content, Decision: decision, Status: status, BodyLength: len(body), BodySHA: protection.BodyHash(body), Issued: at.UnixMilli(), Expires: at.Add(5 * time.Second).UnixMilli()}
	payload, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(protection.Envelope{KeyID: "sdk", Payload: base64.RawURLEncoding.EncodeToString(payload), Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(f.key, payload))})
	if err != nil {
		t.Fatal(err)
	}
	gate, err := f.store.Observe(string(wire), binding, status, body, at)
	if err != nil {
		t.Fatal(err)
	}
	f.view, err = f.store.Case("alpha", gate.CaseID)
	if err != nil {
		t.Fatal(err)
	}
	return gate
}

func virtualConfig(mode string) api.Config {
	return api.Config{Revision: "virtual-review-1", Mode: mode, KeyEnv: "RA_SYNTHETIC_TEST_KEY", DailyCalls: 100, DailyTokens: 1000000, ReserveTokens: 8192, Threshold: 0.95, GateSHA: strings.Repeat("a", 64)}
}

func awaitVirtualJob(t *testing.T, runner *responsev2.Runner, id string) responsev2.Job {
	t.Helper()
	deadline := time.NewTimer(7 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		job, err := runner.Job("alpha", id)
		if err != nil {
			t.Fatal(err)
		}
		if job.Status != "reserved" && job.Status != "dispatched" {
			return job
		}
		select {
		case <-tick.C:
		case <-deadline.C:
			t.Fatal("virtual Decisions job did not finish")
		}
	}
}

func TestVirtualDecisionsProtocolThroughManagementAndPolicy(t *testing.T) {
	tests := []struct {
		name, mode, status string
		kinds              []string
		policy             bool
	}{
		{name: "off", mode: "off", status: "off"},
		{name: "fake", mode: "fake", status: "ok"},
		{name: "shadow", mode: "shadow", status: "ok"},
		{name: "advisory", mode: "advisory", status: "ok"},
		{name: "fresh", mode: "enforce-gated", status: "ok", policy: true},
		{name: "mixed-authentication", mode: "enforce-gated", status: "ok", kinds: []string{"deny", "deny", "unauthenticated"}, policy: true},
		{name: "mixed-missing-object", mode: "enforce-gated", status: "ok", kinds: []string{"deny", "deny", "not_found"}, policy: true},
		{name: "mixed-unavailable", mode: "enforce-gated", status: "ok", kinds: []string{"deny", "deny", "unknown"}, policy: true},
		{name: "authorized-only", mode: "enforce-gated", status: "ok", kinds: []string{"allow", "allow"}},
		{name: "authentication-only", mode: "enforce-gated", status: "ok", kinds: []string{"unauthenticated", "unauthenticated"}},
		{name: "missing-object-only", mode: "enforce-gated", status: "ok", kinds: []string{"not_found", "not_found"}},
		{name: "refusal", mode: "enforce-gated", status: "partial_refusal"},
		{name: "wrong-model", mode: "enforce-gated", status: "invalid"},
		{name: "duplicate-answer", mode: "enforce-gated", status: "invalid"},
		{name: "missing-usage", mode: "enforce-gated", status: "invalid"},
		{name: "below-threshold", mode: "enforce-gated", status: "ok"},
		{name: "observe-advice", mode: "enforce-gated", status: "ok"},
		{name: "credential-error", mode: "enforce-gated", status: "credential_error"},
		{name: "rate-limited", mode: "enforce-gated", status: "rate_limited"},
		{name: "provider-error", mode: "enforce-gated", status: "provider_error"},
		{name: "redirect", mode: "enforce-gated", status: "invalid"},
		{name: "oversize", mode: "enforce-gated", status: "invalid"},
		{name: "usage-over-reservation", mode: "enforce-gated", status: "usage_over_reservation"},
		{name: "case-changed", mode: "enforce-gated", status: "stale_result"},
		{name: "paused", mode: "enforce-gated", status: "stale_result"},
		{name: "deadline", mode: "enforce-gated", status: "stale_result"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			kinds := test.kinds
			if len(kinds) == 0 {
				kinds = []string{"deny", "deny"}
			}
			fixture := newVirtualCase(t, kinds...)
			initial := fixture.view
			var calls, keys atomic.Int32
			seen, release := make(chan struct{}, 1), make(chan struct{})
			const secret = "synthetic-virtual-credential-only"
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.Method != "POST" || r.URL.Path != "/v1/decisions" || r.Host != "api.openai.com" || r.Header.Get("Authorization") != "Bearer "+secret {
					t.Error("fixed Decisions wire contract changed")
				}
				raw, err := io.ReadAll(io.LimitReader(r.Body, 16385))
				if err != nil || len(raw) > 16384 {
					t.Error("unbounded provider request")
				}
				for _, private := range []string{secret, "fixture-principal", "fixture-session", "signed_sdk_proof", "release-proof/1"} {
					if bytes.Contains(raw, []byte(private)) {
						t.Error("raw credential or signed identity on Decisions input")
					}
				}
				if test.name == "case-changed" || test.name == "paused" {
					seen <- struct{}{}
					select {
					case <-release:
					case <-r.Context().Done():
						return
					}
				}
				if test.name == "deadline" {
					<-r.Context().Done()
					return
				}
				value := api.ProtocolResponseFixture()
				answers := value["answers"].([]any)
				switch test.name {
				case "refusal":
					answers[0] = map[string]any{"name": "ongoing_abuse", "type": "refusal"}
				case "wrong-model":
					value["model"] = "wrong-model"
				case "duplicate-answer":
					answers[1] = answers[0]
				case "missing-usage":
					delete(value, "usage")
				case "below-threshold":
					answers[0].(map[string]any)["probability"] = 0.94
				case "observe-advice":
					answers[1].(map[string]any)["choice"] = "observe"
				case "credential-error":
					w.WriteHeader(401)
					return
				case "rate-limited":
					w.WriteHeader(429)
					return
				case "provider-error":
					w.WriteHeader(500)
					return
				case "redirect":
					w.Header().Set("Location", "http://127.0.0.1:1/no-dispatch")
					w.WriteHeader(302)
					return
				case "oversize":
					w.Write([]byte(strings.Repeat("x", 65537)))
					return
				case "usage-over-reservation":
					usage := value["usage"].(map[string]any)
					usage["input_tokens"], usage["total_tokens"] = 8300, 8300
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(value)
			}))
			t.Cleanup(server.Close)
			roots := x509.NewCertPool()
			roots.AddCert(server.Certificate())
			transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: server.Certificate().DNSNames[0]}, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				if address != "api.openai.com:443" {
					return nil, fmt.Errorf("unexpected virtual destination")
				}
				return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
			}}
			client := api.NewProtocolTestClient(transport, func() string { keys.Add(1); return secret })
			runner, err := responsev2.NewRunner(fixture.store, virtualConfig(test.mode), bytes.Repeat([]byte("p"), 32), client)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(runner.Close)
			reader, operator := strings.Repeat("r", 40), strings.Repeat("o", 40)
			management := httptest.NewServer(responsev2.Handler(fixture.store, runner, reader, operator))
			t.Cleanup(management.Close)
			command, _ := json.Marshal(responsev2.Command{Tenant: "alpha", CaseID: initial.Case.ID, CaseSHA: initial.Case.SHA, RequestID: "virtual-job"})
			req, _ := http.NewRequest("POST", management.URL+"/v2/decisions", bytes.NewReader(command))
			req.Header.Set("Authorization", "Bearer "+operator)
			response, err := management.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			var queued responsev2.Job
			if response.StatusCode != 200 || json.NewDecoder(response.Body).Decode(&queued) != nil {
				t.Fatalf("management did not accept valid signed-evidence case: HTTP %d", response.StatusCode)
			}
			if test.name == "case-changed" || test.name == "paused" {
				select {
				case <-seen:
				case <-time.After(2 * time.Second):
					t.Fatal("provider request did not arrive")
				}
				if test.name == "case-changed" {
					fixture.observe(t, "new-observation", "own", "allow")
				} else if err = fixture.store.Pause(true); err != nil {
					t.Fatal(err)
				}
				close(release)
			}
			job := queued
			if test.mode != "off" {
				job = awaitVirtualJob(t, runner, queued.ID)
			}
			policies := fixture.store.Policies("alpha")
			wantPolicies := 0
			if test.policy {
				wantPolicies = 1
			}
			if job.Status != test.status || !job.ReviewPreserved || len(policies) != wantPolicies || (job.Receipt != nil) != test.policy {
				t.Fatalf("unexpected disposition: status=%s policies=%d receipt=%t", job.Status, len(policies), job.Receipt != nil)
			}
			wantCalls := int32(1)
			if test.mode == "off" || test.mode == "fake" {
				wantCalls = 0
			}
			if calls.Load() != wantCalls || keys.Load() != wantCalls {
				t.Fatal("unexpected dispatch or key lookup count", calls.Load(), keys.Load())
			}
			if test.policy {
				lease := policies[0]
				if len(policies) != 1 || lease.Scope != initial.Candidates[0].Scope || len(lease.Claims) != 1 || lease.Claims[0].Owner != "decisions" || lease.Expires.After(lease.Issued.Add(time.Minute)) {
					t.Fatal("API expanded exact server scope or lease")
				}
				var target string
				for _, object := range []string{"object-0", "object-1"} {
					if decisions.Hash(object) == lease.Scope.Resource {
						target = object
					}
				}
				if target == "" || !fixture.observe(t, "target-after-install", target, "deny").Deny || fixture.observe(t, "normal-after-install", "own", "allow").Deny {
					t.Fatal("exact policy gate or normal-object isolation failed")
				}
				for _, kind := range []string{"unauthenticated", "not_found", "unknown"} {
					if fixture.observe(t, "status-after-"+kind, target, kind).Deny {
						t.Fatal("policy masked SDK failure", kind)
					}
				}
			}
			if test.name == "credential-error" || test.name == "usage-over-reservation" {
				if _, err = runner.Enqueue("alpha", initial.Case.ID, initial.Case.SHA, "blocked-next"); err == nil {
					t.Fatal("provider block did not reject next dispatch")
				}
				runner.Close()
				fixture.store.Close()
				fixture.store, err = responsev2.Open(fixture.path, fixture.registry)
				if err != nil {
					t.Fatal(err)
				}
				restarted, err := responsev2.NewRunner(fixture.store, virtualConfig(test.mode), bytes.Repeat([]byte("p"), 32), client)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(restarted.Close)
				if _, err = restarted.Enqueue("alpha", initial.Case.ID, initial.Case.SHA, "blocked-after-restart"); err == nil || calls.Load() != 1 {
					t.Fatal("restart cleared credential or usage block")
				}
			}
			journal, err := os.ReadFile(fixture.path)
			if err != nil || bytes.Contains(journal, []byte(secret)) || bytes.Contains(journal, []byte(operator)) || bytes.Contains(journal, []byte(reader)) {
				t.Fatal("virtual credential reached persisted journal")
			}
			t.Logf("virtual protocol only: mode=%s status=%s TLS requests=%d local policies=%d external API calls=0", test.mode, job.Status, calls.Load(), len(policies))
		})
	}
}
