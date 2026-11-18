package edge

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"net/http"
	"net/http/httptrace"
	"reverse-artex/internal/protection"
	"strings"
	"sync/atomic"
	"time"
)

func protectedRead(c Config, slots chan struct{}, buffers chan []byte, route protection.Route, object string, s scope, w http.ResponseWriter, r *http.Request, transport http.RoundTripper) {
	defer protectionElapsed(c.ProtectionMetrics, protectionTotal, protectionStart(c.ProtectionMetrics))
	responseFinished := false
	fail := func(status int) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Request-ID", s.id)
		if r.Method == "HEAD" {
			w.WriteHeader(status)
		} else {
			http.Error(w, http.StatusText(status), status)
		}
		responseFinished = true
	}
	if c.Protection.Asset() != c.Asset || len(c.HMACKey) < 32 || (c.OIDC == nil && len(c.IdentityKey) < 32) || len(c.IngressToken) < 32 || c.ProtectionAudit == nil {
		fail(503)
		return
	}
	if s.principal == "" {
		fail(401)
		return
	}
	if !c.Protection.TenantAllowed(s.tenant) {
		fail(403)
		return
	}
	if r.ContentLength != 0 || len(r.TransferEncoding) > 0 || r.Header.Get("Range") != "" {
		fail(400)
		return
	}
	select {
	case slots <- struct{}{}:
		defer func() { <-slots }()
	default:
		fail(503)
		return
	}
	resource, err := protection.ResourceID(c.HMACKey, s.tenant, route.Namespace, object)
	if err != nil {
		fail(503)
		return
	}
	random := make([]byte, 24)
	if _, err = rand.Read(random); err != nil {
		fail(503)
		return
	}
	binding := protection.RequestBinding{RequestID: s.id, Nonce: hex.EncodeToString(random), Method: s.method, Route: route.ID, Tenant: s.tenant, Principal: s.principal, Session: s.session, Resource: resource, Started: s.started}
	ctx, cancel := context.WithDeadline(r.Context(), s.started.Add(protection.ProofLifetime))
	defer cancel()
	copy := r.Clone(ctx)
	// Connection lifetime is hop-by-hop, as in httputil.ReverseProxy.
	// Downstream Connection: close must not disable signed upstream reuse.
	copy.Close = false
	copy.RequestURI = ""
	copy.URL.Scheme = c.Upstream.Scheme
	copy.URL.Host = c.Upstream.Host
	copy.Host = c.Upstream.Host
	copy.Body = nil
	// Only the independently verified Authorization token and benign request
	// metadata reach the SDK. No client-selected forwarding/proof headers.
	copy.Header = make(http.Header)
	copy.Header.Set("Authorization", r.Header.Get("Authorization"))
	copy.Header.Set("Accept", "application/json")
	copy.Header.Set("Accept-Encoding", "identity")
	copy.Header.Set("X-Lab-Ingress", c.IngressToken)
	copy.Header.Set("X-RA-Request-ID", s.id)
	copy.Header.Set("X-RA-Nonce", binding.Nonce)
	copy.Header.Set("X-RA-Registry", c.Protection.Digest())
	upstreamStart := protectionStart(c.ProtectionMetrics)
	var upstreamConnected atomic.Bool
	if c.ProtectionMetrics != nil {
		trace := &httptrace.ClientTrace{GotConn: func(httptrace.GotConnInfo) {
			upstreamConnected.Store(true)
			protectionElapsed(c.ProtectionMetrics, protectionConnection, upstreamStart)
		}, GotFirstResponseByte: func() { protectionElapsed(c.ProtectionMetrics, protectionFirstByte, upstreamStart) }}
		copy = copy.WithContext(httptrace.WithClientTrace(copy.Context(), trace))
	}
	resp, err := transport.RoundTrip(copy)
	protectionElapsed(c.ProtectionMetrics, protectionHeaders, upstreamStart)
	if err != nil {
		c.ProtectionMetrics.observeUpstreamFailure(err, upstreamConnected.Load())
		fail(503)
		return
	}
	defer resp.Body.Close()
	// This path deliberately avoids ReverseProxy's early informational-header
	// forwarding: nothing upstream chooses is sent until proof verification.
	encodings := resp.Header.Values("Content-Encoding")
	if len(encodings) > 1 || (len(encodings) == 1 && encodings[0] != "" && encodings[0] != "identity") {
		fail(503)
		return
	}
	if len(resp.Header.Values("Content-Range")) > 0 || len(resp.Trailer) > 0 || len(resp.Header.Values(protection.ProofHeader)) != 1 || len(resp.Header.Values("Content-Type")) != 1 {
		fail(503)
		return
	}
	contentType := strings.ToLower(strings.TrimSpace(strings.Split(resp.Header.Get("Content-Type"), ";")[0]))
	if contentType != "application/json" {
		fail(503)
		return
	}
	// Fixed storage avoids io.ReadAll growth. Optional reuse remains bounded by
	// the same 32 admission slots; callbacks must copy bytes they retain.
	bodyStart := protectionStart(c.ProtectionMetrics)
	var body []byte
	if buffers == nil {
		body = make([]byte, route.MaxBody)
	} else {
		body = borrowProtectedBuffer(buffers, route.MaxBody)
		defer returnProtectedBuffer(buffers, body)
	}
	body, err = readProtectedBody(resp.Body, body)
	protectionElapsed(c.ProtectionMetrics, protectionBody, bodyStart)
	if err != nil {
		fail(503)
		return
	}

	raw := resp.Header.Get(protection.ProofHeader)
	verifyStart := protectionStart(c.ProtectionMetrics)
	p, err := c.Protection.Verify(raw, binding, resp.StatusCode, body, c.Now())
	protectionElapsed(c.ProtectionMetrics, protectionVerify, verifyStart)
	if err != nil {
		fail(503)
		return
	}
	audit := protection.Observation{Schema: "guard-release-check/1", Enforcer: c.Protection.Enforcer(), RequestID: s.id, Tenant: s.tenant, Asset: c.Asset, Route: route.ID, Resource: resource, Decision: p.Decision, ProofSHA: protection.BodyHash([]byte(raw)), Status: resp.StatusCode, BodyLength: len(body), At: c.Now().UTC()}
	// Callback success means durable local recording. It does not prove that
	// the client received any bytes. Audit failures keep the response closed.
	auditStart := protectionStart(c.ProtectionMetrics)
	auditErr := c.ProtectionAudit(audit)
	protectionElapsed(c.ProtectionMetrics, protectionAudit, auditStart)
	if auditErr != nil || ctx.Err() != nil {
		fail(503)
		return
	}
	verifyStart = protectionStart(c.ProtectionMetrics)
	_, err = c.Protection.Verify(raw, binding, resp.StatusCode, body, c.Now())
	protectionElapsed(c.ProtectionMetrics, protectionVerify, verifyStart)
	if err != nil {
		fail(503)
		return
	}
	if c.ProtectionGate != nil {
		gateStart := protectionStart(c.ProtectionMetrics)
		gate, err := c.ProtectionGate(raw, binding, resp.StatusCode, body, c.Now())
		protectionElapsed(c.ProtectionMetrics, protectionGate, gateStart)
		if err != nil {
			fail(503)
			return
		}
		if gate.AttemptID != "" {
			if c.ProtectionReport == nil {
				fail(503)
				return
			}
			recorder := &responseRecorder{ResponseWriter: w, digest: sha256.New()}
			w = recorder
			defer func() {
				reportStart := protectionStart(c.ProtectionMetrics)
				_ = c.ProtectionReport(protection.ResponseWrite{AttemptID: gate.AttemptID, Status: recorder.status, Bytes: recorder.bytes, BodySHA: hex.EncodeToString(recorder.digest.Sum(nil)), Complete: responseFinished && recorder.status != 0 && !recorder.failed && r.Context().Err() == nil, Error: recorder.failed || r.Context().Err() != nil, CompletedAt: time.Now().UTC()})
				protectionElapsed(c.ProtectionMetrics, protectionReport, reportStart)
			}()
		}
		verifyStart = protectionStart(c.ProtectionMetrics)
		_, err = c.Protection.Verify(raw, binding, resp.StatusCode, body, c.Now())
		protectionElapsed(c.ProtectionMetrics, protectionVerify, verifyStart)
		if err != nil || ctx.Err() != nil {
			fail(503)
			return
		}
		if gate.Deny {
			w.Header().Set("X-RA-Policy-ID", gate.PolicyID)
			fail(429)
			return
		}
	}
	if ctx.Err() != nil {
		fail(503)
		return
	}
	w.Header().Set("X-Request-ID", s.id)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("Vary", "Authorization")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	writeStart := protectionStart(c.ProtectionMetrics)
	w.WriteHeader(resp.StatusCode)
	if r.Method != "HEAD" {
		_, _ = w.Write(body)
	}
	protectionElapsed(c.ProtectionMetrics, protectionWrite, writeStart)
	responseFinished = true
}

// responseRecorder records accepted server writes; it cannot establish client receipt.
type responseRecorder struct {
	http.ResponseWriter
	digest        hash.Hash
	status, bytes int
	failed        bool
}

func (w *responseRecorder) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
		w.ResponseWriter.WriteHeader(status)
	}
}
func (w *responseRecorder) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(200)
	}
	n, err := w.ResponseWriter.Write(body)
	if n < 0 || n > len(body) {
		w.failed = true
		return 0, io.ErrShortWrite
	}
	w.digest.Write(body[:n])
	w.bytes += n
	if err != nil || n != len(body) {
		w.failed = true
	}
	return n, err
}

func readProtectedBody(reader io.Reader, storage []byte) ([]byte, error) {
	// ReadFull turns an ordinary short body's EOF into ErrUnexpectedEOF,
	// hiding the same error from an interrupted HTTP framing layer. Preserve
	// the underlying EOF/error instead, with the same fixed storage bound.
	n, emptyReads := 0, 0
	var extra [1]byte
	for {
		dst := storage[n:]
		if len(dst) == 0 {
			dst = extra[:]
		}
		count, err := reader.Read(dst)
		if count < 0 || count > len(dst) {
			return nil, errors.New("invalid protected response read count")
		}
		if n == len(storage) && count > 0 {
			return nil, errors.New("protected response exceeds registered size")
		}
		n += count
		if err != nil {
			if err == io.EOF {
				return storage[:n], nil
			}
			return nil, err
		}
		if count == 0 {
			emptyReads++
			if emptyReads >= 100 {
				return nil, io.ErrNoProgress
			}
		} else {
			emptyReads = 0
		}
	}
}
