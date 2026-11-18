package responsev2

import (
	"crypto/subtle"
	"encoding/json"
	"io"
	"net/http"
	"reverse-artex/internal/decisions"
)

type Command struct {
	Mode       string  `json:"mode,omitempty"`
	SourceRun  string  `json:"source_run,omitempty"`
	Epoch      int     `json:"epoch,omitempty"`
	Tenant     string  `json:"tenant"`
	CaseID     string  `json:"case_id,omitempty"`
	CaseSHA    string  `json:"case_sha256,omitempty"`
	RequestID  string  `json:"request_id,omitempty"`
	Intent     *Intent `json:"intent,omitempty"`
	PolicyID   string  `json:"policy_id,omitempty"`
	Owner      string  `json:"owner,omitempty"`
	Run        string  `json:"run_id,omitempty"`
	Generation int     `json:"generation,omitempty"`
}

func Handler(s *Store, r *Runner, reader, operator string, engines ...*L3Engine) http.Handler {
	var l3 *L3Engine
	if len(engines) > 0 {
		l3 = engines[0]
	}
	return http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if !sameOrigin(q) {
			http.Error(w, "local same-origin management only", 403)
			return
		}
		if q.URL.Path == "/v2/console" && q.Method == "GET" {
			console(w, q)
			return
		}
		auth := q.Header.Get("Authorization")
		isReader := len(reader) >= 32 && subtle.ConstantTimeCompare([]byte(auth), []byte("Bearer "+reader)) == 1
		isOperator := len(operator) >= 32 && subtle.ConstantTimeCompare([]byte(auth), []byte("Bearer "+operator)) == 1
		if (!isReader && !isOperator) || (q.Method != "GET" && !isOperator) {
			http.Error(w, "unauthorized", 401)
			return
		}

		write := func(v any) { w.Header().Set("Content-Type", "application/json"); json.NewEncoder(w).Encode(v) }
		tenant := q.URL.Query().Get("tenant")
		if q.URL.Path == "/v2/status" && q.Method == "GET" {
			write(map[string]any{"schema": "response-status/2", "decisions": r.Status(), "local_enforcer": s.registry.Enforcer(), "registry_digest": s.registry.Digest(), "effect": "unknown until observed; SDK denial masks policy contribution", "outcome_audit": s.OutcomeHealth(), "l3": func() any {
				if l3 != nil {
					return l3.Status()
				}
				return map[string]any{"enabled": false}
			}()})
			return
		}
		if q.Method == "GET" {
			if !s.registry.TenantAllowed(tenant) {
				http.Error(w, "tenant scope required", 400)
				return
			}
			switch q.URL.Path {
			case "/v2/cases":
				write(s.Cases(tenant))
				return
			case "/v2/case":
				v, e := s.Case(tenant, q.URL.Query().Get("id"))
				if e == nil {
					write(v)
					return
				}
			case "/v2/strategy":
				v, e := s.Strategy(tenant, q.URL.Query().Get("id"))
				if e == nil {
					write(v)
					return
				}
			case "/v2/policies":
				write(s.Policies(tenant))
				return
			case "/v2/l3-run":
				v, e := s.L3Run(tenant, q.URL.Query().Get("id"))
				if e == nil {
					write(v)
					return
				}
			case "/v2/outcome":
				v, e := s.Outcome(tenant, q.URL.Query().Get("id"), q.URL.Query().Get("episode"))
				if e == nil {
					write(v)
					return
				}
			case "/v2/job":
				v, e := r.Job(tenant, q.URL.Query().Get("id"))
				if e == nil {
					write(v)
					return
				}
			}
			http.Error(w, "not found", 404)
			return
		}
		if q.Method != "POST" {
			http.Error(w, "method", 405)
			return
		}
		raw, err := io.ReadAll(http.MaxBytesReader(w, q.Body, 16384))
		var c Command
		if err != nil || decisions.DecodeStrict(raw, &c, 16384) != nil {
			http.Error(w, "invalid command", 400)
			return
		}
		if q.URL.Path == "/v2/pause" || q.URL.Path == "/v2/resume" {
			if e := s.Pause(q.URL.Path == "/v2/pause"); e != nil {
				http.Error(w, "journal unavailable", 503)
				return
			}
			if l3 != nil {
				l3.CancelActive()
			}
			write(map[string]any{"epoch": s.Epoch(), "paused": q.URL.Path == "/v2/pause"})
			return
		}
		if !s.registry.TenantAllowed(c.Tenant) {
			http.Error(w, "tenant scope required", 400)
			return
		}
		var result any
		switch q.URL.Path {
		case "/v2/l3":
			if l3 == nil {
				err = ErrUnavailable
			} else {
				result, err = l3.Enqueue(L3Request{ID: c.RequestID, Tenant: c.Tenant, CaseID: c.CaseID, CaseSHA: c.CaseSHA, Mode: c.Mode, SourceRun: c.SourceRun})
			}
		case "/v2/l3-cancel":
			if l3 == nil {
				err = ErrUnavailable
			} else {
				err = l3.Cancel(c.Tenant, c.Run)
				if err == nil {
					result, err = s.L3Run(c.Tenant, c.Run)
				}
			}
		case "/v2/l3-release":
			result, err = s.ReleaseL3(q.Context(), c.Tenant, c.SourceRun, c.CaseSHA, c.RequestID, c.Epoch, c.Generation)
		case "/v2/decisions":
			result, err = r.Enqueue(c.Tenant, c.CaseID, c.CaseSHA, c.RequestID)
		case "/v2/apply":
			if c.Intent == nil || c.Intent.Owner != "operator" {
				err = ErrStale
			} else {
				result, err = s.Apply(q.Context(), c.Tenant, *c.Intent)
			}
		case "/v2/release":
			if c.Owner != "operator" {
				err = ErrStale
			} else {
				result, err = s.Release(q.Context(), c.Tenant, c.PolicyID, c.Owner, c.Run, c.RequestID, c.Generation)
			}
		default:
			http.Error(w, "not found", 404)
			return
		}
		if err != nil {
			http.Error(w, "v2 command rejected; query exact case/job/policy before retry", 409)
			return
		}
		write(result)
	})
}
