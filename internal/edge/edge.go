// Package edge performs only signature verification, bounded local policy
// lookup, and forwarding on the request path. Emission must be nonblocking.
package edge

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"reverse-artex/internal/event"
	"reverse-artex/internal/identity"
	"reverse-artex/internal/policy"
	"reverse-artex/internal/protection"
	"reverse-artex/internal/routecoverage"
	"strings"
	"time"
)

type Config struct {
	OIDC     *identity.OIDCVerifier
	Coverage *routecoverage.Gate
	// ProtectionGate consumes body synchronously; copy it before returning to retain it.
	ProtectionGate       func(string, protection.RequestBinding, int, []byte, time.Time) (protection.GateDecision, error)
	Protection           *protection.Registry
	ProtectionAudit      func(protection.Observation) error
	ProtectionReport     func(protection.ResponseWrite) error
	Upstream             *url.URL
	Asset, IngressToken  string
	IdentityKey, HMACKey []byte
	Cache                *policy.Replica
	Emit                 func(string, any)
	Now                  func() time.Time
	TimeOrderedRequestID bool
	// ReuseProtectedBuffers opts in to a per-handler body buffer cache.
	ReuseProtectedBuffers bool
	ProtectionMetrics     *ProtectionMetrics
	Transport             http.RoundTripper
}
type scope struct {
	id, tenant, principal, session, route, path, ip, method, ua string
	started                                                     time.Time
	known                                                       bool
}
type contextKey struct{}

func Route(path string) (string, bool) {
	if strings.HasPrefix(path, "/api/objects/") {
		return "/api/objects/{id}", true
	}
	if strings.HasPrefix(path, "/legacy/objects/") {
		return "/legacy/objects/{id}", true
	}
	switch path {
	case "/health", "/app.js", "/api/login", "/api/search", "/api/export", "/api/upload":
		return path, true
	}
	return "/unknown", false
}
func Handler(c Config) http.Handler {
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.Emit == nil {
		c.Emit = func(string, any) {}
	}
	proxy := httputil.NewSingleHostReverseProxy(c.Upstream)
	if c.Transport != nil {
		proxy.Transport = c.Transport
	} else {
		proxy.Transport = &http.Transport{Proxy: nil, DisableCompression: true, DialContext: (&net.Dialer{Timeout: time.Second}).DialContext, ResponseHeaderTimeout: 3 * time.Second, MaxIdleConns: 32, MaxIdleConnsPerHost: 16, MaxConnsPerHost: 64, MaxResponseHeaderBytes: 32 << 10}
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		s, _ := r.Context().Value(contextKey{}).(scope)
		if s.id != "" {
			w.Header().Set("X-Request-ID", s.id)
		}
		// A timeout can follow a successful upstream FULL commit. Correlate the
		// error with that intent without pretending it was never admitted.
		w.Header().Set("X-RA-Upstream-Outcome", "unknown")
		http.Error(w, "upstream unavailable", 503)
	}
	slots := make(chan struct{}, protectedBufferCapacity)
	var protectedBuffers chan []byte
	if c.ReuseProtectedBuffers {
		protectedBuffers = make(chan []byte, cap(slots))
	}
	proxy.ModifyResponse = func(resp *http.Response) error {
		s, _ := resp.Request.Context().Value(contextKey{}).(scope)
		resp.Header.Set("X-Request-ID", s.id)
		if resp.StatusCode == 403 && resp.Header.Get("X-RA-WAF-Blocked") == "1" {
			now := c.Now().UTC()
			declaredBytes := resp.ContentLength
			quality := "complete"
			if declaredBytes < 0 {
				declaredBytes = 0
				quality = "partial"
			}
			e := event.Event{SchemaVersion: "1.0", EventID: "waf-" + s.id, EventTime: now, IngestTime: now, SensorID: "lab-waf", TenantID: s.tenant, AssetID: c.Asset, EventType: "http", RequestID: s.id, Method: s.method, Route: s.route, Status: 403, Bytes: declaredBytes, Duration: float64(c.Now().Sub(s.started).Microseconds()) / 1000, Principal: s.principal, SessionHMAC: s.session, SrcIP: s.ip, Identity: "anonymous", TrustedProxy: true, Authorization: "unknown", Reason: "unknown", ResourceClass: "unknown", PathHMAC: identity.Pseudonym(s.path, c.HMACKey), KnownRoute: s.known, DetectorFamily: "waf-local-denial", UAHint: s.ua, DataQuality: quality, ProcessID: "unknown", ContainerID: "unknown"}
			if s.principal != "" {
				e.Identity = "authenticated"
			}
			c.Emit("waf-events", e)
		}
		resp.Header.Del("X-RA-WAF-Blocked")
		return nil
	}
	identityReady := true
	if c.Protection != nil {
		if c.Protection.AuthAdapter() == identity.OIDCAdapter {
			identityReady = c.OIDC != nil && c.OIDC.Digest() == c.Protection.IdentityDigest()
		} else {
			identityReady = c.OIDC == nil
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer protectionElapsed(c.ProtectionMetrics, protectionHandlerTotal, protectionStart(c.ProtectionMetrics))
		requestStarted := c.Now()
		if !identityReady {
			http.Error(w, "identity contract unavailable", 503)
			return
		}
		if len(r.Header.Values("Authorization")) > 1 {
			http.Error(w, "ambiguous authentication", 400)
			return
		}
		coverageStarted := protectionStart(c.ProtectionMetrics)
		coverageID, finished := coverageAdmission(c, w, r, requestStarted)
		protectionElapsed(c.ProtectionMetrics, protectionCoverage, coverageStarted)
		if finished {
			return
		}
		if r.URL.Host != "" || r.URL.Scheme != "" || len(r.URL.RequestURI()) > 2048 || r.URL.RawPath != "" || strings.Contains(r.URL.EscapedPath(), "%") || strings.Contains(r.URL.Path, "//") || strings.Contains(r.URL.Path, "/../") || strings.Contains(r.URL.Path, "/./") {
			http.Error(w, "noncanonical request", 400)
			return
		}
		if r.URL.Path == "/healthz" {
			w.WriteHeader(200)
			return
		}
		route, known := Route(r.URL.Path)
		id, idErr := coverageID, error(nil)
		if id == "" {
			id, idErr = identity.NewRequestID(c.Now(), c.TimeOrderedRequestID)
		}
		if idErr != nil {
			http.Error(w, "request identity unavailable", 503)
			return
		}
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			ip = "unknown"
		}
		s := scope{id: id, tenant: "public", route: route, path: r.URL.Path, ip: ip, method: r.Method, started: requestStarted, known: known, ua: "none"}
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			var claims identity.Claims
			var err error
			if c.OIDC != nil {
				claims, err = c.OIDC.Verify(token, c.Now())
			} else {
				claims, err = identity.Verify(token, c.IdentityKey, c.Now())
			}
			if err == nil {
				s.principal = claims.Principal
				s.tenant = claims.Tenant
				s.session = identity.Pseudonym(token, c.HMACKey)
			}
		}
		if strings.Contains(r.UserAgent(), "artex-enrich/") {
			s.ua = "enrich"
		} else if strings.Contains(r.UserAgent(), "norma/") {
			s.ua = "norma-unverified"
		}
		if c.Protection != nil {
			route, object, matched, err := c.Protection.Resolve(r.URL, r.Method)
			if err != nil {
				http.Error(w, "invalid protected request", 400)
				return
			}
			if matched && route.Mode == "enforce" {
				protectedRead(c, slots, protectedBuffers, route, object, s, w, r, proxy.Transport)
				return
			}
		}
		if s.principal != "" && c.Cache != nil {
			if p, deny := c.Cache.Match(s.tenant, c.Asset, s.principal, s.session, s.route, c.Now()); deny {
				c.Emit("actions", map[string]any{"operation": "enforced-deny", "policy_id": p.ID, "case_id": p.CaseID, "request_id": s.id, "tenant_id": p.Tenant, "asset_id": p.Asset, "route_template": p.Route, "time": c.Now().UTC(), "expires_at": p.Expires, "created_version": p.Version})
				w.Header().Set("X-Request-ID", s.id)
				w.Header().Set("X-RA-Policy-ID", p.ID)
				http.Error(w, "temporary scoped policy", 429)
				return
			}
		}
		if len(r.Trailer) > 0 {
			http.Error(w, "request trailers are unsupported", http.StatusBadRequest)
			return
		}
		if r.ContentLength > 8192 {
			// Consume only a bounded prefix before rejecting. On Windows,
			// closing a small unread request body can reset the connection
			// before the client receives the 413 response. Server ReadTimeout
			// still bounds a client that stalls while sending this prefix.
			io.Copy(io.Discard, io.LimitReader(r.Body, 16384))
			http.Error(w, "request size", 413)
			return
		}
		// Admit the complete bounded body before an upstream can act on it.
		// Server ReadTimeout still bounds clients sending an incomplete body.
		var body []byte
		if r.Body != nil {
			defer r.Body.Close()
			var err error
			body, err = io.ReadAll(http.MaxBytesReader(w, r.Body, 8192))
			if err != nil {
				var tooLarge *http.MaxBytesError
				status := http.StatusBadRequest
				if errors.As(err, &tooLarge) {
					status = http.StatusRequestEntityTooLarge
				}
				http.Error(w, "invalid request body", status)
				return
			}
		}
		copy := r.Clone(context.WithValue(r.Context(), contextKey{}, s))
		copy.Body = http.NoBody
		if len(body) > 0 {
			copy.Body = io.NopCloser(bytes.NewReader(body))
		}
		copy.ContentLength = int64(len(body))
		copy.TransferEncoding = nil
		copy.Host = c.Upstream.Host
		for k := range copy.Header {
			l := strings.ToLower(k)
			if strings.HasPrefix(l, "x-ra-") || l == "x-lab-ingress" || strings.HasPrefix(l, "x-forwarded-") || l == "forwarded" || l == "x-real-ip" || l == "x-principal-id" || l == "x-request-id" {
				copy.Header.Del(k)
			}
		}
		copy.Header.Set("X-Lab-Ingress", c.IngressToken)
		copy.Header.Set("X-RA-Request-ID", s.id)
		proxy.ServeHTTP(w, copy)
	})
}
