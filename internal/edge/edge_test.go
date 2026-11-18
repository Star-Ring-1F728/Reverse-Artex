package edge

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reverse-artex/internal/event"
	"reverse-artex/internal/identity"
	"reverse-artex/internal/policy"
	"strings"
	"testing"
	"time"
)

type transport func(*http.Request) (*http.Response, error)

func TestUpstreamFailureCarriesTrustedRequestIDAndUnknownOutcome(t *testing.T) {
	up, _ := url.Parse("http://127.0.0.1:9999")
	forwarded := ""
	h := Handler(Config{Upstream: up, Cache: policy.NewReplica(), Transport: transport(func(r *http.Request) (*http.Response, error) {
		forwarded = r.Header.Get("X-RA-Request-ID")
		return nil, errors.New("injected timeout after upstream may have committed")
	})})
	r := httptest.NewRequest("POST", "/api/upload", strings.NewReader("body"))
	r.Header.Set("X-RA-Request-ID", "forged")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 503 || len(forwarded) != 32 || w.Header().Get("X-Request-ID") != forwarded || forwarded == "forged" {
		t.Fatal("lost or trusted forged ID", w.Code, w.Header())
	}
	if w.Header().Get("X-RA-Upstream-Outcome") != "unknown" || w.Header().Get("X-RA-Evidence-State") != "" {
		t.Fatal("ambiguous commit mislabeled", w.Header())
	}
}

type countedBody struct {
	read int64
}

func (b *countedBody) Read(p []byte) (int, error) {
	b.read += int64(len(p))
	return len(p), nil
}
func (b *countedBody) Close() error { return nil }

func TestOversizedRequestDrainIsBoundedAndNeverForwarded(t *testing.T) {
	up, _ := url.Parse("http://127.0.0.1:9999")
	h := Handler(Config{Upstream: up, Cache: policy.NewReplica(), Transport: transport(func(*http.Request) (*http.Response, error) {
		t.Fatal("oversized body reached upstream")
		return nil, nil
	})})
	b := &countedBody{}
	r := httptest.NewRequest("POST", "/api/login", nil)
	r.ContentLength = 1 << 30
	r.Body = b
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusRequestEntityTooLarge || b.read != 16384 {
		t.Fatalf("status=%d consumed=%d", w.Code, b.read)
	}
}

func (f transport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func credential(name string, key []byte, now time.Time) string {
	b, _ := json.Marshal(identity.Claims{Principal: name, Tenant: "alpha", JTI: "jti-" + name, Issued: now.Unix(), Exp: now.Unix() + 600})
	p := base64.RawURLEncoding.EncodeToString(b)
	m := hmac.New(sha256.New, key)
	m.Write([]byte(p))
	return p + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}
func TestEnforcementScopeExpiryHeadersAndWAFAdapter(t *testing.T) {
	now := time.Now()
	clock := now
	key := []byte(strings.Repeat("k", 32))
	hmacKey := []byte(strings.Repeat("h", 32))
	snapkey := []byte(strings.Repeat("s", 32))
	alice := credential("alice", key, now)
	bob := credential("bob", key, now)
	cache := policy.NewReplica()
	p := policy.Policy{ID: "p1", CaseID: "case1", Tenant: "alpha", Asset: "lab-api", Principal: "alice", Session: identity.Pseudonym(alice, hmacKey), Route: "/api/objects/{id}", RuleVersion: "1.0", Issued: now.UTC(), Expires: now.Add(3 * time.Second).UTC(), Version: 1}
	if err := cache.Replace(policy.Sign(policy.Snapshot{Epoch: "epoch1", Version: 1, Generated: now.UTC(), Policies: []policy.Policy{p}}, snapkey), snapkey, now); err != nil {
		t.Fatal(err)
	}
	calls := 0
	emitted := []string{}
	var waf event.Event
	up, _ := url.Parse("http://127.0.0.1:9999")
	h := Handler(Config{Upstream: up, Asset: "lab-api", IngressToken: "trusted-ingress", IdentityKey: key, HMACKey: hmacKey, Cache: cache, Now: func() time.Time { return clock }, Emit: func(kind string, v any) {
		emitted = append(emitted, kind)
		if kind == "waf-events" {
			waf = v.(event.Event)
		}
	}, Transport: transport(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Header.Get("X-Lab-Ingress") != "trusted-ingress" || r.Header.Get("X-Principal-ID") != "" || r.Header.Get("X-RA-Request-ID") == "forged" {
			t.Fatal("untrusted identity/header forwarded")
		}
		status := 200
		headers := http.Header{}
		if r.URL.Path == "/waf-test" {
			status = 403
			headers.Set("X-RA-WAF-Blocked", "1")
		}
		if r.URL.Path == "/app-denial" {
			status = 403
		}
		return &http.Response{StatusCode: status, Header: headers, Body: io.NopCloser(strings.NewReader("{}")), Request: r}, nil
	})})
	call := func(path, token string, want int) {
		t.Helper()
		r := httptest.NewRequest("GET", path, nil)
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("X-RA-Request-ID", "forged")
		r.Header.Set("X-Principal-ID", "bob")
		r.Header.Set("X-Lab-Ingress", "forged")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("%s got %d want %d", path, w.Code, want)
		}
		if w.Header().Get("X-RA-WAF-Blocked") != "" {
			t.Fatal("internal marker leaked")
		}
	}
	call("/api/objects/1", alice, 429)
	if calls != 0 {
		t.Fatal("deny reached backend")
	}
	call("/api/objects/+1", alice, 429)
	call("/api/objects/0000000000000001", alice, 429)
	call("/api/objects/1", bob, 200)
	call("/api/search", alice, 200)
	call("/api/objects/1", alice+"tampered", 200)
	before := len(emitted)
	call("/app-denial", alice, 403)
	if len(emitted) != before {
		t.Fatal("app 403 mislabeled WAF")
	}
	call("/waf-test", alice, 403)
	if waf.SensorID != "lab-waf" || waf.Principal != "alice" || waf.RequestID == "forged" || waf.DetectorFamily != "waf-local-denial" {
		t.Fatal("invalid WAF normalization")
	}
	clock = now.Add(4 * time.Second)
	call("/api/objects/1", alice, 200)
	call("/api/objects/%31", alice, 400)
}

func TestFixedUpstreamRejectsClientForwardingMetadata(t *testing.T) {
	upstream, _ := url.Parse("http://127.0.0.1:9999")
	handler := Handler(Config{Upstream: upstream, Transport: transport(func(r *http.Request) (*http.Response, error) {
		if r.Host != upstream.Host {
			t.Errorf("upstream received untrusted Host %q", r.Host)
		}
		for _, name := range []string{"Forwarded", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Forwarded-Port", "X-Real-IP"} {
			if r.Header.Get(name) != "" {
				t.Errorf("untrusted forwarding header %s reached upstream", name)
			}
		}
		if strings.Contains(r.Header.Get("X-Forwarded-For"), "spoof") {
			t.Error("spoofed source reached upstream")
		}
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("{}")), Request: r}, nil
	})})
	request := httptest.NewRequest("GET", "/api/search", nil)
	request.Host = "spoof.invalid"
	for _, name := range []string{"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Forwarded-Port", "X-Real-IP"} {
		request.Header.Set(name, "spoof")
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != 200 {
		t.Fatal("normal forwarded request failed", response.Code)
	}
}

func TestRequestBodyAdmissionBeforeUpstream(t *testing.T) {
	for _, test := range []struct {
		name   string
		size   int
		length int64
		want   int
	}{
		{"unknown-empty", 0, -1, 200}, {"unknown-limit", 8192, -1, 200}, {"unknown-overflow", 8193, -1, 413},
		{"known-limit", 8192, 8192, 200}, {"known-overflow", 8193, 8193, 413},
	} {
		t.Run(test.name, func(t *testing.T) {
			upstream, _ := url.Parse("http://127.0.0.1:9999")
			calls := 0
			h := Handler(Config{Upstream: upstream, Transport: transport(func(r *http.Request) (*http.Response, error) {
				calls++
				var raw []byte
				var err error
				if r.Body != nil {
					raw, err = io.ReadAll(r.Body)
				}
				if err != nil {
					return nil, err
				}
				if len(raw) != test.size {
					t.Errorf("normal body changed length %d", len(raw))
				}
				return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("{}")), Request: r}, nil
			})})
			request := httptest.NewRequest("POST", "/api/upload", strings.NewReader(strings.Repeat("x", test.size)))
			request.ContentLength = test.length
			if test.length < 0 {
				request.TransferEncoding = []string{"chunked"}
			}
			response := httptest.NewRecorder()
			h.ServeHTTP(response, request)
			if response.Code != test.want {
				t.Errorf("status %d want %d", response.Code, test.want)
			}
			if test.want != 200 && calls != 0 {
				t.Error("oversized request reached upstream")
			}
		})
	}
}

func TestRequestTrailersRejectedBeforeUpstream(t *testing.T) {
	upstream, _ := url.Parse("http://127.0.0.1:9999")
	handler := Handler(Config{Upstream: upstream, Transport: transport(func(*http.Request) (*http.Response, error) {
		t.Fatal("unsupported trailers forwarded")
		return nil, nil
	})})
	request := httptest.NewRequest("POST", "/api/upload", strings.NewReader("{}"))
	request.ContentLength = -1
	request.TransferEncoding = []string{"chunked"}
	request.Trailer = http.Header{"X-Checksum": []string{"owned-test"}}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != 400 {
		t.Fatal("unsupported request trailers accepted", response.Code)
	}
}
