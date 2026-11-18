package web

import (
	"io"
	"mime"
	"net/http"

	"reverse-artex/internal/casememory"
)

// Public-key trust is installed by a filesystem operator, never by console
// request data. The console may only submit statements signed under that pin.
func registerVerifiedLearning(mux *http.ServeMux, o Options, guard func(http.HandlerFunc) http.HandlerFunc, ready func(http.ResponseWriter) bool, scope func(http.ResponseWriter, *http.Request) (string, bool), respond func(http.ResponseWriter, any, error)) {
	mux.HandleFunc("GET /console/api/cases/learning/trust", guard(func(w http.ResponseWriter, r *http.Request) {
		if !ready(w) || !learningQuery(w, r, "") {
			return
		}
		tenant, ok := scope(w, r)
		if !ok {
			return
		}
		p, err := o.Cases.LearningTrust(tenant)
		respond(w, map[string]any{"trust": p, "trust_sha256": casememory.LearningTrustDigest(p)}, err)
	}))
	for _, method := range []string{"GET", "POST"} {
		mux.HandleFunc(method+" /console/api/cases/selection/verified", guard(func(w http.ResponseWriter, r *http.Request) {
			if !ready(w) || !learningQuery(w, r, "") {
				return
			}
			tenant, ok := scope(w, r)
			if !ok {
				return
			}
			if o.SyncCases != nil {
				if _, err := o.SyncCases(r.Context()); err != nil {
					respond(w, nil, err)
					return
				}
			}
			v, err := o.Cases.SelectVerified(tenant, r.Method == "POST")
			respond(w, v, err)
		}))
	}
	for _, kind := range []string{"label", "advisory"} {
		path := "/console/api/cases/label/verified"
		if kind == "advisory" {
			path = "/console/api/cases/learning/advisory/verified"
		}
		mux.HandleFunc("POST "+path, guard(func(w http.ResponseWriter, r *http.Request) {
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
				http.Error(w, "invalid verified learning request", 400)
				return
			}
			var label casememory.SignedLabel
			var advisory casememory.SignedAdvisory
			if kind == "label" {
				err = casememory.DecodeLearningJSON(raw, &label)
			} else {
				err = casememory.DecodeLearningJSON(raw, &advisory)
			}
			if err != nil {
				http.Error(w, "invalid signed contract", 400)
				return
			}
			// The path tenant is checked before synchronization or persistent writes.
			if (kind == "label" && label.Tenant != tenant) || (kind == "advisory" && advisory.Tenant != tenant) {
				http.Error(w, "tenant mismatch", 400)
				return
			}
			if o.SyncCases != nil {
				if _, err = o.SyncCases(r.Context()); err != nil {
					respond(w, nil, err)
					return
				}
			}
			if kind == "label" {
				v, err := o.Cases.ImportVerifiedLabel(tenant, label)
				respond(w, v, err)
			} else {
				v, err := o.Cases.ChangeSignedAdvisory(tenant, advisory)
				respond(w, v, err)
			}
		}))
	}
}
