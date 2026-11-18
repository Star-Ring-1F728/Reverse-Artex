// Package caseapi exposes verified case reads with opaque bearer authentication.
package caseapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"reverse-artex/internal/caseledger"
	"reverse-artex/internal/investigation"
)

const MaxResponseBytes = 8 << 20
const ReadTimeout = 5 * time.Second

var identity = regexp.MustCompile(`^[A-Za-z0-9_.:/{}-]{1,128}$`)

type ReadFunc func(context.Context, [32]byte, string, string) (caseledger.Stored, error)

func Handler(read ReadFunc) http.Handler {
	slots := make(chan struct{}, 4)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Type", "application/json")
		fail := func(code int, message string) {
			w.WriteHeader(code)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
		}
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			fail(405, "method not allowed")
			return
		}
		values := r.Header.Values("Authorization")
		if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") {
			w.Header().Set("WWW-Authenticate", `Bearer realm="case-api"`)
			fail(401, "authentication required")
			return
		}
		token := strings.TrimPrefix(values[0], "Bearer ")
		raw, err := base64.RawURLEncoding.Strict().DecodeString(token)
		if err != nil || len(raw) != 32 || len(token) != 43 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="case-api"`)
			fail(401, "authentication required")
			return
		}
		parts := strings.Split(r.URL.EscapedPath(), "/")
		projection := len(parts) == 7 && parts[6] == "investigation"
		response := len(parts) == 7 && parts[6] == "response-context"
		tools := len(parts) == 9 && parts[6] == "investigation" && parts[7] == "tools"
		if (len(parts) != 6 && !projection && !tools && !response) || parts[1] != "v1" || parts[2] != "tenants" || parts[4] != "cases" {
			fail(404, "case not found")
			return
		}
		tenant, e1 := url.PathUnescape(parts[3])
		id, e2 := url.PathUnescape(parts[5])
		if e1 != nil || e2 != nil || !identity.MatchString(tenant) || !identity.MatchString(id) || (!tools && (r.URL.RawQuery != "" || r.URL.ForceQuery)) || r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
			fail(400, "invalid case request")
			return
		}
		var query investigation.ToolRequest
		if tools {
			var e error
			query, e = investigation.ParseToolRequest(tenant, id, parts[8], r.URL.RawQuery)
			if e != nil {
				fail(400, "invalid tool query")
				return
			}
		}
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			w.Header().Set("Retry-After", "1")
			fail(429, "case read capacity")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), ReadTimeout)
		defer cancel()
		if read == nil {
			fail(503, "case read unavailable")
			return
		}
		result, err := read(ctx, sha256.Sum256([]byte(token)), tenant, id)
		switch {
		case errors.Is(err, caseledger.ErrUnauthenticated):
			w.Header().Set("WWW-Authenticate", `Bearer realm="case-api"`)
			fail(401, "authentication required")
			return
		case errors.Is(err, sql.ErrNoRows):
			fail(404, "case not found")
			return
		case err != nil:
			fail(503, "case read unavailable")
			return
		}
		// Buffer with an explicit byte limit: never send a partial verified result,
		// and never serialize an unbounded 64-revision history into the HTTP response.
		if response {
			view, e := caseledger.ProjectResponse(result)
			if e != nil || ctx.Err() != nil {
				fail(503, "response context unavailable")
				return
			}
			b := boundedBuffer{ctx: ctx}
			if json.NewEncoder(&b).Encode(view) != nil {
				fail(503, "response context unavailable")
				return
			}
			w.WriteHeader(200)
			_, _ = w.Write(b.Bytes())
			return
		}
		if tools {
			data, e := investigation.ProjectToolVerified(result, query)
			switch {
			case ctx.Err() != nil:
				fail(503, "case tool unavailable")
				return
			case errors.Is(e, investigation.ErrToolScope):
				fail(409, "case snapshot changed")
				return
			case errors.Is(e, investigation.ErrToolQuery):
				fail(400, "invalid tool query")
				return
			case e != nil:
				fail(503, "case tool unavailable")
				return
			}
			w.WriteHeader(200)
			_, _ = w.Write(data)
			return
		}
		if projection {
			data, e := investigation.ProjectVerified(result)
			if e != nil || ctx.Err() != nil {
				fail(503, "case projection unavailable")
				return
			}
			w.WriteHeader(200)
			_, _ = w.Write(data)
			return
		}
		b := boundedBuffer{ctx: ctx}
		if json.NewEncoder(&b).Encode(result) != nil || ctx.Err() != nil {
			fail(503, "case read unavailable")
			return
		}
		w.WriteHeader(200)
		_, _ = w.Write(b.Bytes())
	})
}

type boundedBuffer struct {
	bytes.Buffer
	ctx context.Context
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if err := b.ctx.Err(); err != nil {
		return 0, err
	}
	if len(p) > MaxResponseBytes-b.Len() {
		return 0, errors.New("case response limit")
	}
	return b.Buffer.Write(p)
}
