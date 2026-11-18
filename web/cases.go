package web

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"reverse-artex/internal/casememory"
)

func registerCases(mux *http.ServeMux, o Options, guard func(http.HandlerFunc) http.HandlerFunc) {
	ready := func(w http.ResponseWriter) bool {
		if o.Cases == nil {
			http.Error(w, "case memory unavailable for this profile", 503)
			return false
		}
		return true
	}
	scope := func(w http.ResponseWriter, r *http.Request) (string, bool) {
		tenant := r.URL.Query().Get("tenant")
		for _, allowed := range o.Tenants {
			if tenant == allowed && tenant != "" {
				return tenant, true
			}
		}
		http.Error(w, "tenant not found", 404)
		return "", false
	}
	respond := func(w http.ResponseWriter, result any, err error) {
		if err != nil {
			code := 503
			switch {
			case errors.Is(err, casememory.ErrInvalid):
				code = 400
			case errors.Is(err, casememory.ErrConflict):
				code = 409
			case errors.Is(err, casememory.ErrNotFound):
				code = 404
			case errors.Is(err, casememory.ErrLimit):
				code = 507
			}
			http.Error(w, err.Error(), code)
			return
		}
		b, encodeErr := json.Marshal(result)
		if encodeErr != nil || len(b) > 8<<20 {
			http.Error(w, "case response exceeds 8 MiB; inspect the local journal for older revisions", 503)
			return
		}
		w.Write(b)
	}
	registerLearningLifecycle(mux, o, guard, ready, scope, respond)
	registerVerifiedLearning(mux, o, guard, ready, scope, respond)
	registerProductionLearning(mux, o, guard, ready, scope, respond)
	mux.HandleFunc("POST /console/api/cases/sync", guard(func(w http.ResponseWriter, r *http.Request) {
		if !ready(w) {
			return
		}
		if o.SyncCases == nil {
			http.Error(w, "case synchronization unavailable", 503)
			return
		}
		n, err := o.SyncCases(r.Context())
		respond(w, map[string]int{"changed_cases": n}, err)
	}))
	mux.HandleFunc("GET /console/api/cases", guard(func(w http.ResponseWriter, r *http.Request) {
		if !ready(w) {
			return
		}
		tenant, ok := scope(w, r)
		if !ok {
			return
		}
		list, err := o.Cases.Summaries(tenant)
		respond(w, map[string]any{"cases": list}, err)
	}))
	mux.HandleFunc("GET /console/api/cases/detail", guard(func(w http.ResponseWriter, r *http.Request) {
		if !ready(w) {
			return
		}
		tenant, ok := scope(w, r)
		if !ok {
			return
		}
		item, err := o.Cases.Get(tenant, r.URL.Query().Get("case_id"))
		respond(w, item, err)
	}))
	mux.HandleFunc("POST /console/api/cases/label", guard(func(w http.ResponseWriter, r *http.Request) {
		if !ready(w) {
			return
		}
		tenant, ok := scope(w, r)
		if !ok {
			return
		}
		if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			http.Error(w, "JSON required", 415)
			return
		}
		raw, readErr := io.ReadAll(http.MaxBytesReader(w, r.Body, 8192))
		var q casememory.LabelRequest
		if readErr != nil || decodeLabel(raw, &q) != nil {
			http.Error(w, "invalid label request", 400)
			return
		}
		if o.SyncCases != nil {
			if _, err := o.SyncCases(r.Context()); err != nil {
				respond(w, nil, err)
				return
			}
		}
		label, err := o.Cases.SetLabel(tenant, r.URL.Query().Get("case_id"), q)
		respond(w, label, err)
	}))
	for _, method := range []string{"GET", "POST"} {
		mux.HandleFunc(method+" /console/api/cases/selection", guard(func(w http.ResponseWriter, r *http.Request) {
			if !ready(w) {
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
			result, err := o.Cases.Select(tenant, r.Method == "POST")
			respond(w, result, err)
		}))
	}
	mux.HandleFunc("GET /console/api/cases/selection/saved", guard(func(w http.ResponseWriter, r *http.Request) {
		if !ready(w) {
			return
		}
		tenant, ok := scope(w, r)
		if !ok {
			return
		}
		result, err := o.Cases.SavedSelection(tenant, r.URL.Query().Get("sha256"))
		respond(w, result, err)
	}))
	mux.HandleFunc("POST /console/api/cases/learning", guard(func(w http.ResponseWriter, r *http.Request) {
		if !ready(w) || !learningQuery(w, r, "") {
			return
		}
		tenant, ok := scope(w, r)
		if !ok {
			return
		}
		if r.Header.Get("Content-Type") != "application/json" {
			http.Error(w, "JSON required", 415)
			return
		}
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1024))
		pin, decodeErr := decodeSelectionPin(raw)
		if err != nil || decodeErr != nil {
			http.Error(w, "exact saved selection_sha256 required", 400)
			return
		}
		if o.SyncCases != nil {
			if _, err := o.SyncCases(r.Context()); err != nil {
				respond(w, nil, err)
				return
			}
		}
		result, err := o.Cases.CreateCandidate(tenant, pin)
		respond(w, result, err)
	}))
	mux.HandleFunc("GET /console/api/cases/learning", guard(func(w http.ResponseWriter, r *http.Request) {
		if !ready(w) || !learningQuery(w, r, "") {
			return
		}
		tenant, ok := scope(w, r)
		if !ok {
			return
		}
		result, err := o.Cases.Candidates(tenant)
		respond(w, map[string]any{"candidates": result}, err)
	}))
	mux.HandleFunc("GET /console/api/cases/learning/detail", guard(func(w http.ResponseWriter, r *http.Request) {
		if !ready(w) || !learningQuery(w, r, "candidate_id") {
			return
		}
		tenant, ok := scope(w, r)
		if !ok {
			return
		}
		result, err := o.Cases.Candidate(tenant, r.URL.Query().Get("candidate_id"))
		respond(w, result, err)
	}))
	mux.HandleFunc("GET /console/api/cases/learning/diagnostics", guard(func(w http.ResponseWriter, r *http.Request) {
		if !ready(w) || !learningQuery(w, r, "candidate_id") {
			return
		}
		tenant, ok := scope(w, r)
		if !ok {
			return
		}
		v, err := o.Cases.CandidateFeatureDiagnostics(tenant, r.URL.Query().Get("candidate_id"))
		respond(w, v, err)
	}))
	for _, capture := range []bool{false, true} {
		path, field := "POST /console/api/cases/learning/shadow", "candidate_id"
		if capture {
			path, field = "POST /console/api/cases/learning/shadow/capture", "run_id"
		}
		mux.HandleFunc(path, guard(func(w http.ResponseWriter, r *http.Request) {
			if !ready(w) || !learningQuery(w, r, "") {
				return
			}
			tenant, ok := scope(w, r)
			if !ok {
				return
			}
			if r.Header.Get("Content-Type") != "application/json" {
				http.Error(w, "JSON required", 415)
				return
			}
			raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1024))
			pin, decodeErr := decodeLearningPin(raw, field)
			if err != nil || decodeErr != nil {
				http.Error(w, "exact "+field+" required", 400)
				return
			}
			if o.SyncCases != nil {
				if _, err := o.SyncCases(r.Context()); err != nil {
					respond(w, nil, err)
					return
				}
			}
			var result casememory.ShadowView
			if capture {
				result, err = o.Cases.CaptureShadow(tenant, pin)
			} else {
				result, err = o.Cases.StartShadow(tenant, pin)
			}
			respond(w, result, err)
		}))
	}
	mux.HandleFunc("GET /console/api/cases/learning/shadow", guard(func(w http.ResponseWriter, r *http.Request) {
		if !ready(w) || !learningQuery(w, r, "") {
			return
		}
		tenant, ok := scope(w, r)
		if !ok {
			return
		}
		result, err := o.Cases.Shadows(tenant)
		respond(w, map[string]any{"runs": result}, err)
	}))
	mux.HandleFunc("GET /console/api/cases/learning/shadow/detail", guard(func(w http.ResponseWriter, r *http.Request) {
		if !ready(w) {
			return
		}
		query, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil {
			http.Error(w, "invalid shadow query", 400)
			return
		}
		revision := 0
		if values, ok := query["revision"]; ok {
			if len(values) != 1 {
				http.Error(w, "one revision required", 400)
				return
			}
			revision, err = strconv.Atoi(values[0])
			if err != nil || revision < 1 || revision > casememory.MaxShadowSnapshots || strconv.Itoa(revision) != values[0] {
				http.Error(w, "invalid shadow revision", 400)
				return
			}
			query.Del("revision")
		}
		if err != nil || len(query) != 2 || len(query["tenant"]) != 1 || len(query["run_id"]) != 1 || query.Get("tenant") == "" || query.Get("run_id") == "" || r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
			http.Error(w, "invalid shadow query", 400)
			return
		}
		tenant, ok := scope(w, r)
		if !ok {
			return
		}
		result, err := o.Cases.Shadow(tenant, query.Get("run_id"), revision)
		respond(w, result, err)
	}))
	mux.HandleFunc("GET /console/api/cases/learning/review", guard(func(w http.ResponseWriter, r *http.Request) {
		if !ready(w) || !learningQuery(w, r, "run_id") {
			return
		}
		tenant, ok := scope(w, r)
		if !ok {
			return
		}
		result, err := o.Cases.Review(tenant, r.URL.Query().Get("run_id"))
		respond(w, result, err)
	}))
	for _, register := range []bool{true, false} {
		path := "POST /console/api/cases/learning/review"
		if register {
			path += "/plan"
		}
		mux.HandleFunc(path, guard(func(w http.ResponseWriter, r *http.Request) {
			if !ready(w) || !learningQuery(w, r, "run_id") {
				return
			}
			tenant, ok := scope(w, r)
			if !ok {
				return
			}
			if r.Header.Get("Content-Type") != "application/json" {
				http.Error(w, "JSON required", 415)
				return
			}
			raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 8192))
			if err != nil {
				http.Error(w, "bounded JSON required", 400)
				return
			}
			var criteria casememory.ReviewCriteria
			var decision casememory.ReviewRequest
			if register {
				err = decodeReviewObject(raw, &criteria, "minimum_confirmed_attack", "minimum_confirmed_benign", "minimum_observation_seconds", "minimum_label_coverage_bps", "maximum_false_attack_bps")
			} else {
				err = decodeReviewObject(raw, &decision, "expected_review_revision", "review_plan_sha256", "shadow_snapshot_sha256", "decision", "reason")
			}
			if err != nil {
				http.Error(w, "exact review fields required", 400)
				return
			}
			if o.SyncCases != nil {
				if _, err := o.SyncCases(r.Context()); err != nil {
					respond(w, nil, err)
					return
				}
			}
			var result casememory.ReviewView
			if register {
				result, err = o.Cases.RegisterReview(tenant, r.URL.Query().Get("run_id"), criteria)
			} else {
				result, err = o.Cases.SubmitReview(tenant, r.URL.Query().Get("run_id"), decision)
			}
			respond(w, result, err)
		}))
	}
}

func decodeReviewObject(raw []byte, target any, fields ...string) error {
	allowed := map[string]bool{}
	for _, key := range fields {
		allowed[key] = true
	}
	seen := map[string]bool{}
	d := json.NewDecoder(bytes.NewReader(raw))
	start, err := d.Token()
	if err != nil || start != json.Delim('{') {
		return casememory.ErrInvalid
	}
	for d.More() {
		key, err := d.Token()
		if err != nil {
			return casememory.ErrInvalid
		}
		name, ok := key.(string)
		if !ok || !allowed[name] || seen[name] {
			return casememory.ErrInvalid
		}
		seen[name] = true
		var value json.RawMessage
		if d.Decode(&value) != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return casememory.ErrInvalid
		}
	}
	end, err := d.Token()
	if err != nil || end != json.Delim('}') || len(seen) != len(allowed) || d.Decode(new(any)) != io.EOF {
		return casememory.ErrInvalid
	}
	return json.Unmarshal(raw, target)
}

func learningQuery(w http.ResponseWriter, r *http.Request, detail string) bool {
	query, err := url.ParseQuery(r.URL.RawQuery)
	want := 1
	if detail != "" {
		want++
	}
	if err != nil || len(query) != want || len(query["tenant"]) != 1 || query.Get("tenant") == "" ||
		(detail != "" && (len(query[detail]) != 1 || query.Get(detail) == "")) ||
		(r.Method == http.MethodGet && (r.ContentLength != 0 || len(r.TransferEncoding) != 0)) {
		http.Error(w, "invalid learning request", 400)
		return false
	}
	return true
}

func decodeSelectionPin(raw []byte) (string, error) {
	return decodeLearningPin(raw, "selection_sha256")
}

func decodeLearningPin(raw []byte, field string) (string, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	start, err := d.Token()
	if err != nil || start != json.Delim('{') || !d.More() {
		return "", casememory.ErrInvalid
	}
	key, err := d.Token()
	if err != nil || key != field {
		return "", casememory.ErrInvalid
	}
	var pin string
	if d.Decode(&pin) != nil || pin == "" || d.More() {
		return "", casememory.ErrInvalid
	}
	if end, err := d.Token(); err != nil || end != json.Delim('}') || d.Decode(new(any)) != io.EOF {
		return "", casememory.ErrInvalid
	}
	return pin, nil
}

// Require the exact public field names and reject duplicate/aliased fields.
func decodeLabel(raw []byte, q *casememory.LabelRequest) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	start, err := d.Token()
	if err != nil || start != json.Delim('{') {
		return casememory.ErrInvalid
	}
	fields := map[string]bool{}
	for d.More() {
		key, err := d.Token()
		if err != nil {
			return err
		}
		name, ok := key.(string)
		if !ok || fields[name] || (name != "expected_label_revision" && name != "case_sha256" && name != "value" && name != "reason") {
			return casememory.ErrInvalid
		}
		fields[name] = true
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return casememory.ErrInvalid
		}
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return casememory.ErrInvalid
		}
	}
	if len(fields) != 4 {
		return casememory.ErrInvalid
	}
	if _, err = d.Token(); err != nil || d.Decode(new(any)) != io.EOF {
		return casememory.ErrInvalid
	}
	return json.Unmarshal(raw, q)
}
