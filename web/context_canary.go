package web

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reverse-artex/internal/contextrelease"
	"reverse-artex/internal/contractjson"
)

func registerContextCanary(mux *http.ServeMux, o Options, guard func(http.HandlerFunc) http.HandlerFunc) {
	for _, action := range []string{"status", "stop"} {
		method := "GET"
		if action == "stop" {
			method = "POST"
		}
		mux.HandleFunc(method+" /console/api/cases/context-canary/"+action, guard(func(w http.ResponseWriter, r *http.Request) {
			q, e := parseContextShadowQuery(r, false)
			if e != nil {
				http.Error(w, "exact tenant query required", 400)
				return
			}
			allowed := false
			for _, tenant := range o.Tenants {
				allowed = allowed || tenant == q.tenant
			}
			if !allowed {
				http.Error(w, "tenant not found", 404)
				return
			}
			if o.ContextCanary == nil {
				if action == "status" {
					state := "NOT_CONFIGURED"
					reasons := []string{}
					if o.ContextCanaryUnavailable != "" {
						state = "UNAVAILABLE"
						reasons = append(reasons, o.ContextCanaryUnavailable)
					}
					json.NewEncoder(w).Encode(contextrelease.Status{Release: contextrelease.View{Tenant: q.tenant, State: state, History: []contextrelease.Version{}, Blockers: reasons}})
				} else {
					http.Error(w, "v2 canary unavailable", 503)
				}
				return
			}
			if o.ContextCanary.Tenant() != q.tenant {
				http.Error(w, "canary not configured for tenant", 404)
				return
			}
			if action == "status" {
				json.NewEncoder(w).Encode(o.ContextCanary.Status())
				return
			}
			if r.Header.Get("Content-Type") != "application/json" {
				http.Error(w, "JSON required", 415)
				return
			}
			raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 2048))
			if e != nil {
				http.Error(w, "bounded stop required", 400)
				return
			}
			var request struct {
				Expected int    `json:"expected_revision"`
				Reason   string `json:"reason"`
			}
			if contractjson.Decode(raw, &request, 2048, 4) != nil {
				http.Error(w, "exact stop contract required", 400)
				return
			}
			v, e := o.ContextCanary.Stop(request.Expected, request.Reason)
			if e != nil {
				code := 503
				if errors.Is(e, contextrelease.ErrConflict) {
					code = 409
				}
				http.Error(w, e.Error(), code)
				return
			}
			json.NewEncoder(w).Encode(v)
		}))
	}
}
