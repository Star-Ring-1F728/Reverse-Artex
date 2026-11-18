package web

import (
	"io"
	"mime"
	"net/http"
	"reverse-artex/internal/casememory"
)

// Trust and production policy installation remain filesystem-operator actions.
func registerProductionLearning(mux *http.ServeMux, o Options, guard func(http.HandlerFunc) http.HandlerFunc, ready func(http.ResponseWriter) bool, scope func(http.ResponseWriter, *http.Request) (string, bool), respond func(http.ResponseWriter, any, error)) {
	for _, path := range []string{"quality", "production"} {
		mux.HandleFunc("GET /console/api/cases/learning/"+path, guard(func(w http.ResponseWriter, r *http.Request) {
			extra := ""
			if path == "quality" {
				extra = "plan_id"
			}
			if !ready(w) || !learningQuery(w, r, extra) {
				return
			}
			tenant, ok := scope(w, r)
			if !ok {
				return
			}
			if path == "quality" {
				v, err := o.Cases.Quality(tenant, r.URL.Query().Get("plan_id"))
				respond(w, v, err)
			} else {
				v, err := o.Cases.Production(tenant)
				respond(w, v, err)
			}
		}))
	}
	for _, action := range []string{"quality/prepare", "quality/cohort", "quality/report", "production", "production/stop"} {
		mux.HandleFunc("POST /console/api/cases/learning/"+action, guard(func(w http.ResponseWriter, r *http.Request) {
			if !ready(w) || !learningQuery(w, r, "") {
				return
			}
			tenant, ok := scope(w, r)
			if !ok {
				return
			}
			media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
			if err != nil || media != "application/json" {
				http.Error(w, "JSON required", 415)
				return
			}
			raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 32768))
			if err != nil {
				http.Error(w, "bounded learning contract required", 400)
				return
			}
			var prepare struct {
				CandidateID string `json:"candidate_id"`
			}
			var stop struct {
				Expected int    `json:"expected_revision"`
				Reason   string `json:"reason"`
			}
			var cohort casememory.CohortSeal
			var report casememory.SignedQualityReport
			var production casememory.SignedProductionChange
			var target any
			switch action {
			case "quality/prepare":
				target = &prepare
			case "quality/cohort":
				target = &cohort
			case "quality/report":
				target = &report
			case "production":
				target = &production
			case "production/stop":
				target = &stop
			}
			if err = casememory.DecodeLearningJSON(raw, target); err != nil {
				http.Error(w, "exact signed learning contract required", 400)
				return
			}
			if (action == "quality/cohort" && cohort.Tenant != tenant) || (action == "quality/report" && report.Tenant != tenant) || (action == "production" && production.Tenant != tenant) {
				http.Error(w, "tenant mismatch", 400)
				return
			}
			// Emergency stop remains available during source verification failures.
			if action != "production/stop" && o.SyncCases != nil {
				if _, err = o.SyncCases(r.Context()); err != nil {
					respond(w, nil, err)
					return
				}
			}
			switch action {
			case "quality/prepare":
				v, err := o.Cases.PrepareQuality(tenant, prepare.CandidateID)
				respond(w, v, err)
			case "quality/cohort":
				v, err := o.Cases.AdmitQualityCohort(tenant, cohort)
				respond(w, v, err)
			case "quality/report":
				v, err := o.Cases.ImportQuality(tenant, report)
				respond(w, v, err)
			case "production":
				v, err := o.Cases.ChangeProduction(tenant, production)
				respond(w, v, err)
			case "production/stop":
				v, err := o.Cases.StopProduction(tenant, stop.Expected, stop.Reason)
				respond(w, v, err)
			}
		}))
	}
}
