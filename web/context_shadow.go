package web

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"reverse-artex/internal/contextlearning"
	"reverse-artex/internal/contextshadow"
	"reverse-artex/internal/contractjson"
	"strconv"
)

func registerContextShadow(mux *http.ServeMux, o Options, guard func(http.HandlerFunc) http.HandlerFunc) {
	for _, action := range []string{"status", "start", "capture", "stop", "history"} {
		method := "POST"
		if action == "status" || action == "history" {
			method = "GET"
		}
		mux.HandleFunc(method+" /console/api/cases/context-shadow/"+action, guard(func(w http.ResponseWriter, r *http.Request) {
			q, err := parseContextShadowQuery(r, action == "history")
			if err != nil {
				http.Error(w, "exact tenant query required", 400)
				return
			}
			allowed := false
			for _, t := range o.Tenants {
				allowed = allowed || t == q.tenant
			}
			if !allowed {
				http.Error(w, "tenant not found", 404)
				return
			}
			if o.ContextShadow == nil {
				if action == "status" {
					json.NewEncoder(w).Encode(contextshadow.LiveStatus{History: []contextshadow.AttemptSummary{}})
				} else {
					http.Error(w, "v2 shadow profile not configured", 503)
				}
				return
			}
			if o.ContextShadow.Tenant() != q.tenant {
				http.Error(w, "v2 shadow profile not configured for tenant", 404)
				return
			}
			switch action {
			case "status":
				json.NewEncoder(w).Encode(o.ContextShadow.Status())
				return
			case "history":
				a, e := o.ContextShadow.History(q.sequence)
				if e != nil {
					http.Error(w, "history not found", 404)
					return
				}
				json.NewEncoder(w).Encode(a)
				return
			}
			if r.Header.Get("Content-Type") != "application/json" {
				http.Error(w, "JSON required", 415)
				return
			}
			b, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 1024))
			if e != nil {
				http.Error(w, "bounded request required", 400)
				return
			}
			var accepted contextshadow.LiveStatus
			if action == "stop" {
				var empty struct{}
				if contractjson.Decode(b, &empty, 1024, 4) != nil {
					http.Error(w, "empty object required", 400)
					return
				}
				o.ContextShadow.Stop()
				accepted = o.ContextShadow.Status()
			} else {
				var request struct {
					Pin string `json:"candidate_sha256"`
				}
				if contractjson.Decode(b, &request, 1024, 4) != nil {
					http.Error(w, "exact candidate pin required", 400)
					return
				}
				if accepted, e = o.ContextShadow.RequestWithStatus(request.Pin, action == "start"); e != nil {
					code := 503
					if errors.Is(e, contextlearning.ErrInvalid) {
						code = 400
					}
					if errors.Is(e, contextshadow.ErrConflict) {
						code = 409
					}
					if errors.Is(e, contextshadow.ErrLimit) {
						code = 507
					}
					http.Error(w, e.Error(), code)
					return
				}
			}
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(accepted)
		}))
	}
}

type shadowQuery struct {
	tenant   string
	sequence int
}

func parseContextShadowQuery(r *http.Request, history bool) (shadowQuery, error) {
	q := shadowQuery{}
	v, e := r.URL.Query(), error(nil)
	if r.URL.RawQuery == "" {
		return q, contextlearning.ErrInvalid
	}
	// ParseQuery reports malformed escaping rather than silently ignoring fields.
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return q, err
	}
	v = values
	expected := 1
	if history {
		expected = 2
	}
	if len(v) != expected || len(v["tenant"]) != 1 || v.Get("tenant") == "" {
		return q, contextlearning.ErrInvalid
	}
	q.tenant = v.Get("tenant")
	if history {
		if len(v["sequence"]) != 1 {
			return q, contextlearning.ErrInvalid
		}
		q.sequence, e = strconv.Atoi(v.Get("sequence"))
		if e != nil || q.sequence < 1 || strconv.Itoa(q.sequence) != v.Get("sequence") {
			return q, contextlearning.ErrInvalid
		}
	}
	return q, nil
}
