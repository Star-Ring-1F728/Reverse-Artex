package edge

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reverse-artex/internal/identity"
	"reverse-artex/internal/protection"
	"strings"
	"sync"
	"testing"
	"time"
)

func protectedBufferConfig(t testing.TB, maxBody int) (Config, ed25519.PrivateKey) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := protection.New(protection.Manifest{
		Schema: "protection-registry/1", Asset: "asset", Revision: "r1", TrustEpoch: "e1", Enforcer: "edge1",
		Tenants: []string{"alpha"}, Keys: map[string]string{"sdk1": base64.RawURLEncoding.EncodeToString(pub)},
		Routes: []protection.Route{{ID: "legacy", Template: "/legacy/objects/{id}", Namespace: "objects", Mode: "enforce", MaxBody: maxBody, AuthAdapter: "lab-hmac-v1", Resolver: "snapshot-v1"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	upstream, err := url.Parse("http://127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	return Config{
		Upstream: upstream, Asset: "asset", Protection: registry,
		ProtectionAudit: func(protection.Observation) error { return nil },
		IdentityKey:     []byte(strings.Repeat("i", 32)), HMACKey: []byte(strings.Repeat("h", 32)),
		IngressToken: strings.Repeat("g", 32),
	}, key
}

func protectedBufferProof(c Config, key ed25519.PrivateKey, r *http.Request, body []byte, actor string) string {
	object := strings.TrimPrefix(r.URL.Path, "/legacy/objects/")
	resource, _ := protection.ResourceID(c.HMACKey, "alpha", "objects", object)
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	now := time.Now()
	p := protection.Proof{
		Schema: "release-proof/1", KeyID: "sdk1", Asset: c.Asset, Registry: c.Protection.Digest(), Epoch: c.Protection.Epoch(),
		RequestID: r.Header.Get("X-RA-Request-ID"), Nonce: r.Header.Get("X-RA-Nonce"), Method: r.Method, Route: "legacy",
		Tenant: "alpha", Principal: actor, Session: identity.Pseudonym(token, c.HMACKey), Resource: resource,
		Action: "read", AuthzRevision: "acl1", ContentRevision: "v1", Decision: "allow", Status: 200,
		BodyLength: len(body), BodySHA: protection.BodyHash(body), Issued: now.UnixMilli(), Expires: now.Add(5 * time.Second).UnixMilli(),
	}
	raw, _ := json.Marshal(p)
	wire, _ := json.Marshal(protection.Envelope{
		KeyID: "sdk1", Payload: base64.RawURLEncoding.EncodeToString(raw),
		Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, raw)),
	})
	return string(wire)
}

func protectedBufferResponse(c Config, key ed25519.PrivateKey, r *http.Request, body []byte, actor string) *http.Response {
	h := http.Header{"Content-Type": []string{"application/json"}}
	h.Set(protection.ProofHeader, protectedBufferProof(c, key, r, body, actor))
	return &http.Response{StatusCode: http.StatusOK, Header: h, Body: io.NopCloser(bytes.NewReader(body)), Request: r}
}

func protectedBufferRequest(c Config, actor, method string) *http.Request {
	r := guardRequest(c, "/legacy/objects/one", method)
	r.Header.Set("Authorization", "Bearer "+credential(actor, c.IdentityKey, time.Now()))
	return r
}

func TestProtectedBufferReuseSeparatesActorsAndReturnsAfterFailure(t *testing.T) {
	c, key := protectedBufferConfig(t, 1024)
	c.ReuseProtectedBuffers = true
	bodies := [][]byte{
		[]byte(`{"actor":"alice","value":"ALICE_SENTINEL"}`),
		[]byte(`{"actor":"bob","value":"BOB_SENTINEL"}`),
		[]byte(`{"actor":"alice","value":"FAILED_SENTINEL"}`),
		[]byte(`{"actor":"bob","value":"AFTER_FAILURE_SENTINEL"}`),
	}
	actors := []string{"alice", "bob", "alice", "bob"}
	calls, audits := 0, 0
	c.Transport = transport(func(r *http.Request) (*http.Response, error) {
		body := bodies[calls]
		actor := actors[calls]
		calls++
		return protectedBufferResponse(c, key, r, body, actor), nil
	})
	c.ProtectionAudit = func(protection.Observation) error {
		audits++
		if audits == 3 {
			return errors.New("synthetic audit failure")
		}
		return nil
	}
	seen := [][]byte{}
	c.ProtectionGate = func(_ string, _ protection.RequestBinding, _ int, body []byte, _ time.Time) (protection.GateDecision, error) {
		seen = append(seen, append([]byte(nil), body...))
		return protection.GateDecision{}, nil
	}
	h := Handler(c)
	wantStatus := []int{200, 200, 503, 200}
	for i, actor := range actors {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, protectedBufferRequest(c, actor, http.MethodGet))
		if w.Code != wantStatus[i] {
			t.Fatalf("request %d status=%d want=%d", i, w.Code, wantStatus[i])
		}
	}
	wantBodies := [][]byte{bodies[0], bodies[1], bodies[3]}
	if len(seen) != len(wantBodies) {
		t.Fatalf("gate callback count=%d want=%d", len(seen), len(wantBodies))
	}
	for i := range wantBodies {
		if !bytes.Equal(seen[i], wantBodies[i]) {
			t.Fatalf("request body %d was contaminated: got=%q want=%q", i, seen[i], wantBodies[i])
		}
	}
}

func TestProtectedBufferReusePreservesHEADAndRejectsOversize(t *testing.T) {
	c, key := protectedBufferConfig(t, 1024)
	c.ReuseProtectedBuffers = true
	valid := []byte(`{"ok":true}`)
	oversize := []byte(`{"value":"` + strings.Repeat("x", 1024) + `"}`)
	calls := 0
	c.Transport = transport(func(r *http.Request) (*http.Response, error) {
		var body []byte
		switch calls {
		case 0: // HEAD binds an empty upstream body.
			body = nil
		case 1:
			body = oversize
		default:
			body = valid
		}
		calls++
		return protectedBufferResponse(c, key, r, body, "alice"), nil
	})
	h := Handler(c)
	for _, tc := range []struct {
		method string
		status int
	}{{http.MethodHead, 200}, {http.MethodGet, 503}, {http.MethodGet, 200}} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, protectedBufferRequest(c, "alice", tc.method))
		if w.Code != tc.status {
			t.Fatalf("%s status=%d want=%d", tc.method, w.Code, tc.status)
		}
		if tc.method == http.MethodHead && w.Body.Len() != 0 {
			t.Fatal("HEAD wrote a protected body")
		}
		if tc.status == 503 && strings.Contains(w.Body.String(), "value") {
			t.Fatal("oversized upstream body escaped")
		}
	}
}

func TestProtectedBufferReuseReturnsSlotAfterPanic(t *testing.T) {
	c, key := protectedBufferConfig(t, 1024)
	c.ReuseProtectedBuffers = true
	body := []byte(`{"ok":true}`)
	c.Transport = transport(func(r *http.Request) (*http.Response, error) {
		return protectedBufferResponse(c, key, r, body, "alice"), nil
	})
	c.ProtectionGate = func(string, protection.RequestBinding, int, []byte, time.Time) (protection.GateDecision, error) {
		return protection.GateDecision{AttemptID: "panic-path"}, nil
	}
	c.ProtectionReport = func(protection.ResponseWrite) error { return nil }
	h := Handler(c)
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("synthetic writer panic was not propagated")
			}
		}()
		h.ServeHTTP(brokenResponse{httptest.NewRecorder(), "panic"}, protectedBufferRequest(c, "alice", http.MethodGet))
	}()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, protectedBufferRequest(c, "alice", http.MethodGet))
	if w.Code != 200 || w.Body.String() != string(body) {
		t.Fatal("buffer/slot was not available after panic", w.Code, w.Body.String())
	}
}

type protectedBufferGateReader struct {
	reader  *bytes.Reader
	entered chan<- struct{}
	release <-chan struct{}
	once    sync.Once
}

func (r *protectedBufferGateReader) Read(p []byte) (int, error) {
	r.once.Do(func() {
		r.entered <- struct{}{}
		<-r.release
	})
	return r.reader.Read(p)
}

func (r *protectedBufferGateReader) Close() error { return nil }

func TestProtectedBufferReuseStaysWithinThirtyTwoConcurrentAdmissions(t *testing.T) {
	c, key := protectedBufferConfig(t, 1024)
	c.ReuseProtectedBuffers = true
	body := []byte(`{"ok":true}`)
	entered := make(chan struct{}, protectedBufferCapacity)
	release := make(chan struct{})
	c.Transport = transport(func(r *http.Request) (*http.Response, error) {
		resp := protectedBufferResponse(c, key, r, body, "alice")
		resp.Body = &protectedBufferGateReader{reader: bytes.NewReader(body), entered: entered, release: release}
		return resp, nil
	})
	h := Handler(c)
	var wg sync.WaitGroup
	statuses := make([]int, protectedBufferCapacity)
	for i := range statuses {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			w := httptest.NewRecorder()
			h.ServeHTTP(w, protectedBufferRequest(c, "alice", http.MethodGet))
			statuses[i] = w.Code
		}(i)
	}
	for i := 0; i < protectedBufferCapacity; i++ {
		select {
		case <-entered:
		case <-time.After(3 * time.Second):
			close(release)
			wg.Wait()
			t.Fatal("not all admitted requests acquired response storage")
		}
	}
	overflow := httptest.NewRecorder()
	h.ServeHTTP(overflow, protectedBufferRequest(c, "alice", http.MethodGet))
	if overflow.Code != 503 {
		close(release)
		wg.Wait()
		t.Fatal("32-slot limit admitted an extra request", overflow.Code)
	}
	close(release)
	wg.Wait()
	for i, status := range statuses {
		if status != 200 {
			t.Fatalf("admitted request %d status=%d", i, status)
		}
	}
}

func TestProtectedBufferHelpersClearAndReplaceSmallStorage(t *testing.T) {
	pool := make(chan []byte, protectedBufferCapacity)
	large := borrowProtectedBuffer(pool, 128)
	copy(large, []byte("PRIVATE_PAYLOAD"))
	returnProtectedBuffer(pool, large)
	if len(pool) != 1 {
		t.Fatal("buffer was not returned")
	}
	reused := borrowProtectedBuffer(pool, 32)
	if cap(reused) != 128 {
		t.Fatal("sufficient storage was not reused", cap(reused))
	}
	returnProtectedBuffer(pool, reused)
	cleared := <-pool
	for i, value := range cleared {
		if value != 0 {
			t.Fatalf("retained byte at offset %d was not cleared", i)
		}
	}
	tooSmall := make([]byte, 16)
	copy(tooSmall, []byte("old"))
	pool <- tooSmall
	largeReplacement := borrowProtectedBuffer(pool, 64)
	if cap(largeReplacement) < 64 || len(pool) != 0 || !bytes.Equal(tooSmall, make([]byte, len(tooSmall))) {
		t.Fatal("undersized storage was not cleared and replaced", cap(largeReplacement), len(pool), tooSmall)
	}
	returnProtectedBuffer(pool, largeReplacement)
}

func BenchmarkProtectedBodyBufferReuse(b *testing.B) {
	body := []byte(`"` + strings.Repeat("x", 1022) + `"`)
	for _, reuse := range []bool{false, true} {
		name := "off"
		if reuse {
			name = "on"
		}
		b.Run(name, func(b *testing.B) {
			c, key := protectedBufferConfig(b, 1<<20)
			c.ReuseProtectedBuffers = reuse
			c.Transport = transport(func(r *http.Request) (*http.Response, error) {
				return protectedBufferResponse(c, key, r, body, "alice"), nil
			})
			h := Handler(c)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				w := httptest.NewRecorder()
				h.ServeHTTP(w, protectedBufferRequest(c, "alice", http.MethodGet))
				if w.Code != 200 {
					b.Fatalf("protected request status=%d", w.Code)
				}
			}
		})
	}
}
