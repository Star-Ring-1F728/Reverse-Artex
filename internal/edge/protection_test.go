package edge

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/textproto"
	"net/url"
	"reverse-artex/internal/identity"
	"reverse-artex/internal/protection"
	"strings"
	"sync"
	"testing"
	"time"
)

func guardFixture(t *testing.T) (Config, ed25519.PrivateKey) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := protection.New(protection.Manifest{Schema: "protection-registry/1", Asset: "asset", Revision: "r1", TrustEpoch: "e1", Enforcer: "edge1", Tenants: []string{"alpha"}, Keys: map[string]string{"sdk1": base64.RawURLEncoding.EncodeToString(pub)}, Routes: []protection.Route{{ID: "legacy", Template: "/legacy/objects/{id}", Namespace: "objects", Mode: "enforce", MaxBody: 1024, AuthAdapter: "lab-hmac-v1", Resolver: "snapshot-v1"}}})
	if err != nil {
		t.Fatal(err)
	}
	upstream, _ := url.Parse("http://127.0.0.1:1")
	return Config{Upstream: upstream, Asset: "asset", Protection: registry, ProtectionAudit: func(protection.Observation) error { return nil }, IdentityKey: []byte(strings.Repeat("i", 32)), HMACKey: []byte(strings.Repeat("h", 32)), IngressToken: strings.Repeat("g", 32)}, key
}
func sdkProof(c Config, key ed25519.PrivateKey, r *http.Request, body []byte, modify func(*protection.Proof)) string {
	object := strings.TrimPrefix(r.URL.Path, "/legacy/objects/")
	resource, _ := protection.ResourceID(c.HMACKey, "alpha", "objects", object)
	now := time.Now()
	p := protection.Proof{Schema: "release-proof/1", KeyID: "sdk1", Asset: c.Asset, Registry: c.Protection.Digest(), Epoch: c.Protection.Epoch(), RequestID: r.Header.Get("X-RA-Request-ID"), Nonce: r.Header.Get("X-RA-Nonce"), Method: r.Method, Route: "legacy", Tenant: "alpha", Principal: "alice", Session: identity.Pseudonym(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), c.HMACKey), Resource: resource, Action: "read", AuthzRevision: "acl1", ContentRevision: "v1", Decision: "allow", Status: 200, BodyLength: len(body), BodySHA: protection.BodyHash(body), Issued: now.UnixMilli(), Expires: now.Add(5 * time.Second).UnixMilli()}
	if modify != nil {
		modify(&p)
	}
	raw, _ := json.Marshal(p)
	wire, _ := json.Marshal(protection.Envelope{KeyID: "sdk1", Payload: base64.RawURLEncoding.EncodeToString(raw), Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, raw))})
	return string(wire)
}
func guardRequest(c Config, path, method string) *http.Request {
	r := httptest.NewRequest(method, path, nil)
	r.Header.Set("Authorization", "Bearer "+credential("alice", c.IdentityKey, time.Now()))
	r.Header.Set("X-RA-Nonce", "forged")
	r.Header.Set("X-Principal-ID", "bob")
	return r
}
func TestProtectedResponseRejectsUnboundBytesBeforeRelease(t *testing.T) {
	for _, kind := range []string{"valid", "missing", "body-swap", "nonce-replay", "cross-tenant", "other-resource", "expired", "compressed", "too-large", "audit-failure", "duplicate-proof", "upstream-header-leak"} {
		t.Run(kind, func(t *testing.T) {
			c, key := guardFixture(t)
			var audits int
			c.ProtectionAudit = func(o protection.Observation) error {
				audits++
				if kind == "audit-failure" {
					return errors.New("disk full")
				}
				if o.Decision != "allow" {
					t.Fatal(o)
				}
				return nil
			}
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("X-RA-Nonce") == "forged" || r.Header.Get("X-Principal-ID") != "" {
					t.Error("untrusted header forwarded")
				}
				body := []byte("{\"secret\":\"SENTINEL_PRIVATE\"}")
				wire := sdkProof(c, key, r, body, func(p *protection.Proof) {
					switch kind {
					case "nonce-replay":
						p.Nonce = "prior"
					case "cross-tenant":
						p.Tenant = "beta"
					case "other-resource":
						p.Resource = "foreign"
					case "expired":
						p.Expires = p.Issued
					}
				})
				if kind == "body-swap" {
					body = []byte("{\"secret\":\"SUBSTITUTED_PRIVATE\"}")
				}
				if kind == "too-large" {
					body = []byte(strings.Repeat("SENTINEL_PRIVATE", 100))
				}
				w.Header().Set("Content-Type", "application/json")
				if kind != "missing" {
					w.Header().Set(protection.ProofHeader, wire)
				}
				if kind == "duplicate-proof" {
					w.Header().Add(protection.ProofHeader, wire)
				}
				if kind == "compressed" {
					w.Header().Set("Content-Encoding", "gzip")
				}
				w.Header().Set("X-Upstream-Secret", "SENTINEL_PRIVATE")
				w.Write(body)
			}))
			defer upstream.Close()
			c.Upstream, _ = url.Parse(upstream.URL)
			edgeServer := httptest.NewServer(Handler(c))
			defer edgeServer.Close()
			req := guardRequest(c, edgeServer.URL+"/legacy/objects/one", "GET")
			// httptest request with absolute target must be converted to client form.
			req.RequestURI = ""
			req.URL, _ = url.Parse(edgeServer.URL + "/legacy/objects/one")
			res, err := edgeServer.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer res.Body.Close()
			raw, _ := io.ReadAll(res.Body)
			valid := kind == "valid" || kind == "upstream-header-leak"
			if valid {
				if res.StatusCode != 200 || !strings.Contains(string(raw), "SENTINEL_PRIVATE") || audits != 1 {
					t.Fatal(res.StatusCode, string(raw), audits)
				}
			} else if res.StatusCode != 503 || strings.Contains(string(raw), "PRIVATE") {
				t.Fatal("upstream bytes escaped", res.StatusCode, string(raw))
			}
			if res.Header.Get(protection.ProofHeader) != "" || res.Header.Get("X-Upstream-Secret") != "" {
				t.Fatal("internal upstream header escaped")
			}
		})
	}
}
func TestProtectedRouteCannotFallBackAndHEADBindsEmptyBody(t *testing.T) {
	c, key := guardFixture(t)
	calls := 0
	c.Transport = transport(func(r *http.Request) (*http.Response, error) {
		calls++
		body := []byte{}
		h := http.Header{"Content-Type": []string{"application/json"}}
		h.Set(protection.ProofHeader, sdkProof(c, key, r, body, nil))
		return &http.Response{StatusCode: 200, Header: h, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
	})
	h := Handler(c)
	for _, path := range []string{"/legacy/objects", "/legacy/objects/a/b", "/legacy/objects/a?owner=foreign", "/legacy/objects/a?", "/legacy/objects/.."} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, guardRequest(c, path, "GET"))
		if w.Code != 400 {
			t.Fatal(path, w.Code)
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, guardRequest(c, "/legacy/objects/a", "POST"))
	if w.Code != 400 {
		t.Fatal(w.Code)
	}
	if calls != 0 {
		t.Fatal("invalid route forwarded")
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, guardRequest(c, "/legacy/objects/a", "HEAD"))
	if w.Code != 200 || w.Body.Len() != 0 {
		t.Fatal(w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	r := guardRequest(c, "/legacy/objects/a", "GET")
	r.Header.Del("Authorization")
	h.ServeHTTP(w, r)
	if w.Code != 401 || calls != 1 {
		t.Fatal("anonymous forwarded", w.Code, calls)
	}
}
func TestProtectedAdmissionSaturationDoesNotForwardExtraRequest(t *testing.T) {
	c, key := guardFixture(t)
	entered := make(chan struct{}, 32)
	release := make(chan struct{})
	c.Transport = transport(func(r *http.Request) (*http.Response, error) {
		entered <- struct{}{}
		<-release
		body := []byte("{}")
		h := http.Header{"Content-Type": []string{"application/json"}}
		h.Set(protection.ProofHeader, sdkProof(c, key, r, body, nil))
		return &http.Response{StatusCode: 200, Header: h, Body: io.NopCloser(strings.NewReader("{}")), Request: r}, nil
	})
	h := Handler(c)
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h.ServeHTTP(httptest.NewRecorder(), guardRequest(c, "/legacy/objects/a", "GET"))
		}()
	}
	for i := 0; i < 32; i++ {
		select {
		case <-entered:
		case <-time.After(3 * time.Second):
			close(release)
			wg.Wait()
			t.Fatal("requests never admitted")
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, guardRequest(c, "/legacy/objects/a", "GET"))
	close(release)
	wg.Wait()
	if w.Code != 503 {
		t.Fatal("overflow forwarded", w.Code)
	}
}

func TestProtectedResponseDoesNotForwardInformationalHeaders(t *testing.T) {
	c, key := guardFixture(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Early-Secret", "EARLY_PRIVATE")
		w.WriteHeader(103)
		body := []byte("{}")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set(protection.ProofHeader, sdkProof(c, key, r, body, nil))
		w.Write(body)
	}))
	defer upstream.Close()
	c.Upstream, _ = url.Parse(upstream.URL)
	server := httptest.NewServer(Handler(c))
	defer server.Close()
	req := guardRequest(c, "/legacy/objects/one", "GET")
	req.RequestURI = ""
	req.URL, _ = url.Parse(server.URL + "/legacy/objects/one")
	early := 0
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{Got1xxResponse: func(int, textproto.MIMEHeader) error { early++; return nil }}))
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != 200 || early != 0 || resp.Header.Get("X-Early-Secret") != "" {
		t.Fatal("unverified informational header forwarded", resp.StatusCode, early)
	}
}
func TestProtectedSlowBodyHasWholeRequestDeadline(t *testing.T) {
	c, _ := guardFixture(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set(protection.ProofHeader, "not-a-proof")
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer upstream.Close()
	c.Upstream, _ = url.Parse(upstream.URL)
	w := httptest.NewRecorder()
	started := time.Now()
	Handler(c).ServeHTTP(w, guardRequest(c, "/legacy/objects/one", "GET"))
	if w.Code != 503 || time.Since(started) > 7*time.Second {
		t.Fatal("slow body deadline failed", w.Code, time.Since(started))
	}
}
