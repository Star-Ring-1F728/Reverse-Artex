package web

import (
	"io"
	"mime"
	"net/http"

	"reverse-artex/internal/casememory"
)

func registerLearningLifecycle(mux *http.ServeMux, o Options, guard func(http.HandlerFunc) http.HandlerFunc, ready func(http.ResponseWriter) bool, scope func(http.ResponseWriter, *http.Request) (string, bool), respond func(http.ResponseWriter, any, error)) {
	for _, kind := range []string{"automatic", "advisory"} {
		for _, method := range []string{"GET", "POST"} {
			mux.HandleFunc(method+" /console/api/cases/learning/"+kind, guard(func(w http.ResponseWriter, r *http.Request) {
				detail := ""
				if kind == "automatic" {
					detail = "run_id"
				}
				if !ready(w) || !learningQuery(w, r, detail) {
					return
				}
				tenant, ok := scope(w, r)
				if !ok {
					return
				}
				run := r.URL.Query().Get("run_id")
				if method == "GET" {
					if kind == "automatic" {
						result, err := o.Cases.Automatic(tenant, run)
						var worker any
						if o.AutomaticStatus != nil {
							worker = o.AutomaticStatus()
						}
						respond(w, map[string]any{"automation": result, "worker": worker}, err)
					} else {
						result, err := o.Cases.Advisory(tenant)
						respond(w, result, err)
					}
					return
				}
				media, _, mediaErr := mime.ParseMediaType(r.Header.Get("Content-Type"))
				if mediaErr != nil || media != "application/json" {
					http.Error(w, "JSON required", 415)
					return
				}
				raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 8192))
				if err != nil {
					http.Error(w, "invalid learning request", 400)
					return
				}
				var auto casememory.AutoRequest
				var advisory casememory.AdvisoryRequest
				if kind == "automatic" {
					err = decodeReviewObject(raw, &auto, "expected_revision", "enabled", "reason")
				} else {
					err = decodeReviewObject(raw, &advisory, "expected_revision", "action", "run_id", "review_decision_sha256", "shadow_snapshot_sha256", "percent", "reason")
				}
				if err != nil {
					http.Error(w, "invalid learning request", 400)
					return
				}
				// Stop remains available when evidence verification is unavailable.
				activating := (kind == "automatic" && auto.Enabled) || (kind == "advisory" && advisory.Action != "stop")
				if activating && o.SyncCases != nil {
					if _, err = o.SyncCases(r.Context()); err != nil {
						respond(w, nil, err)
						return
					}
				}
				if kind == "automatic" {
					result, err := o.Cases.SetAutomatic(tenant, run, auto)
					respond(w, map[string]any{"automation": result}, err)
				} else {
					result, err := o.Cases.ChangeAdvisory(tenant, advisory)
					respond(w, result, err)
				}
			}))
		}
	}
}
