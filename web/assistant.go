package web

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reverse-artex/internal/casememory"
	"reverse-artex/internal/decisions"
	"reverse-artex/internal/localassistant"
)

func registerAssistant(mux *http.ServeMux, o Options, guard func(http.HandlerFunc) http.HandlerFunc) {
	ready := func(w http.ResponseWriter) bool {
		if o.Assistant == nil {
			http.Error(w, "local assistant unavailable for this profile", 503)
			return false
		}
		return true
	}
	scope := func(w http.ResponseWriter, r *http.Request) (string, bool) {
		tenant := r.URL.Query().Get("tenant")
		for _, t := range o.Tenants {
			if t == tenant && tenant != "" {
				return tenant, true
			}
		}
		http.Error(w, "tenant not found", 404)
		return "", false
	}
	reply := func(w http.ResponseWriter, value any, err error) {
		if err != nil {
			code := 400
			switch {
			case errors.Is(err, casememory.ErrNotFound):
				code = 404
			case errors.Is(err, localassistant.ErrBusy):
				code = 429
			case errors.Is(err, localassistant.ErrUnavailable):
				code = 503
			case errors.Is(err, casememory.ErrLimit):
				code = 507
			}
			http.Error(w, err.Error(), code)
			return
		}
		json.NewEncoder(w).Encode(value)
	}
	mux.HandleFunc("GET /console/api/ai/status", guard(func(w http.ResponseWriter, r *http.Request) {
		if !ready(w) {
			return
		}
		reply(w, o.Assistant.Status(r.Context()), nil)
	}))
	mux.HandleFunc("GET /console/api/ai/runs", guard(func(w http.ResponseWriter, r *http.Request) {
		if !ready(w) {
			return
		}
		tenant, ok := scope(w, r)
		if !ok {
			return
		}
		reply(w, map[string]any{"runs": o.Assistant.List(tenant)}, nil)
	}))
	mux.HandleFunc("GET /console/api/ai/run", guard(func(w http.ResponseWriter, r *http.Request) {
		if !ready(w) {
			return
		}
		tenant, ok := scope(w, r)
		if !ok {
			return
		}
		run, err := o.Assistant.Get(tenant, r.URL.Query().Get("id"))
		reply(w, run, err)
	}))
	mux.HandleFunc("POST /console/api/ai/cancel", guard(func(w http.ResponseWriter, r *http.Request) {
		if !ready(w) {
			return
		}
		tenant, ok := scope(w, r)
		if !ok {
			return
		}
		err := o.Assistant.Cancel(tenant, r.URL.Query().Get("id"))
		reply(w, map[string]bool{"cancel_requested": err == nil}, err)
	}))
	mux.HandleFunc("POST /console/api/ai/runs", guard(func(w http.ResponseWriter, r *http.Request) {
		if !ready(w) {
			return
		}
		tenant, ok := scope(w, r)
		if !ok {
			return
		}
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4096))
		var request localassistant.Request
		if err != nil || decisions.DecodeStrict(raw, &request, 4096) != nil || request.Tenant != tenant {
			http.Error(w, "invalid bound assistant request", 400)
			return
		}
		run, err := o.Assistant.Start(request)
		if err != nil {
			reply(w, nil, err)
			return
		}
		w.WriteHeader(202)
		reply(w, run, nil)
	}))
}
