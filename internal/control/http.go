package control

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reverse-artex/internal/decisions"
	"reverse-artex/internal/event"
	"runtime"
	"strings"
	"time"
)

type Tokens struct {
	Admin, Reader, Evidence string
	SnapshotKey             []byte
}

func Handler(m *Manager, t Tokens) http.Handler {
	mux := http.NewServeMux()
	authorize := func(w http.ResponseWriter, r *http.Request, key string) bool {
		if len(key) < 32 || subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+key)) != 1 {
			io.Copy(io.Discard, io.LimitReader(r.Body, 16384))
			http.Error(w, "unauthorized", 401)
			return false
		}
		return true
	}
	decode := func(w http.ResponseWriter, r *http.Request, v any) bool {
		d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384))
		d.DisallowUnknownFields()
		if d.Decode(v) != nil {
			http.Error(w, "invalid command", 400)
			return false
		}
		var extra any
		if d.Decode(&extra) != io.EOF {
			http.Error(w, "one command required", 400)
			return false
		}
		return true
	}
	decodeApproved := func(w http.ResponseWriter, r *http.Request, v any) bool {
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 16384))
		if err != nil || decisions.DecodeStrict(raw, v, 16384) != nil {
			http.Error(w, "invalid approved command", 400)
			return false
		}
		return true
	}
	reply := func(w http.ResponseWriter, r Receipt, err error) {
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				w.Header().Set("Retry-After", "1")
				http.Error(w, "policy writer wait cancelled", http.StatusServiceUnavailable)
				return
			}
			if errors.Is(err, ErrEvidenceCapacity) {
				w.Header().Set("Retry-After", "1")
				http.Error(w, "recent evidence capacity", http.StatusTooManyRequests)
				return
			}
			status := 400
			if strings.Contains(err.Error(), "conflict") {
				status = 409
			} else if strings.Contains(err.Error(), "audit") {
				status = 503
			} else if strings.Contains(err.Error(), "budget") {
				status = 429
			}
			w.Header().Set("X-RA-Delivery-Permanent", "1")
			http.Error(w, "policy command rejected", status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(r)
	}
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"service": "policy-control", "evidence_to_action": "separate-authority", "audit_io": m.IOStats(), "goroutines": runtime.NumGoroutine()})
	})
	mux.HandleFunc("GET /v1/snapshot", func(w http.ResponseWriter, r *http.Request) {
		if !authorize(w, r, t.Reader) {
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 250*time.Millisecond)
		defer cancel()
		s, err := m.SnapshotContext(ctx, t.SnapshotKey)
		if err != nil {
			http.Error(w, "snapshot unavailable", 503)
			return
		}
		json.NewEncoder(w).Encode(s)
	})
	mux.HandleFunc("POST /v1/evidence", func(w http.ResponseWriter, r *http.Request) {
		if !authorize(w, r, t.Evidence) {
			return
		}
		e, err := event.Decode(http.MaxBytesReader(w, r.Body, 16384))
		if err != nil {
			http.Error(w, "invalid evidence", 400)
			return
		}
		receipt, err := m.EvidenceContext(r.Context(), e)
		if err != nil {
			reply(w, Receipt{}, err)
			return
		}
		w.WriteHeader(202)
		json.NewEncoder(w).Encode(map[string]any{"accepted": true, "action": receipt})
	})
	mux.HandleFunc("POST /v1/policies", func(w http.ResponseWriter, r *http.Request) {
		if !authorize(w, r, t.Admin) {
			return
		}
		var a Approve
		if !decode(w, r, &a) {
			return
		}
		v, err := m.ApproveContext(r.Context(), a)
		reply(w, v, err)
	})
	mux.HandleFunc("POST /v1/approved-policies", func(w http.ResponseWriter, r *http.Request) {
		if !authorize(w, r, t.Admin) {
			return
		}
		var a ApprovedPolicy
		if !decodeApproved(w, r, &a) {
			return
		}
		s, err := m.ApplyApprovedContext(r.Context(), a)
		if err != nil {
			http.Error(w, "approved policy unavailable or rejected", 503)
			return
		}
		json.NewEncoder(w).Encode(s)
	})
	mux.HandleFunc("POST /v1/approved-policies/status", func(w http.ResponseWriter, r *http.Request) {
		if !authorize(w, r, t.Reader) {
			return
		}
		var a ApprovedPolicy
		if !decodeApproved(w, r, &a) {
			return
		}
		s, err := m.ApprovedStatusContext(r.Context(), a)
		if err != nil {
			http.Error(w, "approved status unavailable or rejected", 503)
			return
		}
		json.NewEncoder(w).Encode(s)
	})
	mux.HandleFunc("POST /v1/revoke", func(w http.ResponseWriter, r *http.Request) {
		if !authorize(w, r, t.Admin) {
			return
		}
		var a Revoke
		if !decode(w, r, &a) {
			return
		}
		v, err := m.RevokeContext(r.Context(), a)
		reply(w, v, err)
	})
	mux.HandleFunc("POST /v1/rollback", func(w http.ResponseWriter, r *http.Request) {
		if !authorize(w, r, t.Admin) {
			return
		}
		var a Rollback
		if !decode(w, r, &a) {
			return
		}
		v, err := m.RollbackContext(r.Context(), a)
		reply(w, v, err)
	})
	mux.HandleFunc("POST /v1/auto", func(w http.ResponseWriter, r *http.Request) {
		if !authorize(w, r, t.Admin) {
			return
		}
		var a struct {
			Key     string `json:"idempotency_key"`
			Enabled bool   `json:"enabled"`
		}
		if !decode(w, r, &a) {
			return
		}
		v, err := m.SetAutoContext(r.Context(), a.Key, a.Enabled)
		reply(w, v, err)
	})
	// Bound requests waiting behind non-cancellable audit I/O. Snapshot and
	// health readers have separate paths and never consume mutation slots.
	slots := make(chan struct{}, 16)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			select {
			case slots <- struct{}{}:
				defer func() { <-slots }()
			default:
				w.Header().Set("Retry-After", "1")
				http.Error(w, "policy writer capacity", http.StatusTooManyRequests)
				return
			}
			if r.Context().Err() != nil {
				http.Error(w, "request cancelled", http.StatusServiceUnavailable)
				return
			}
		}
		mux.ServeHTTP(w, r)
	})
}
