package hostresponse

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reverse-artex/internal/hostguard"
	"strings"
	"time"
)

type Config struct {
	SensorToken, ReaderToken, OperatorToken  string
	Sensor, Tenant, Asset, Service, Workload string
}

func (c Config) Validate() bool {
	if len(c.SensorToken) < 32 || len(c.ReaderToken) < 32 || len(c.OperatorToken) < 32 || c.SensorToken == c.ReaderToken || c.SensorToken == c.OperatorToken || c.ReaderToken == c.OperatorToken {
		return false
	}
	for _, s := range []string{c.Sensor, c.Tenant, c.Asset, c.Service, c.Workload} {
		if !hostguard.ID.MatchString(s) {
			return false
		}
	}
	return true
}
func Handler(m *Manager, c Config) http.Handler {
	mux := http.NewServeMux()
	mode := "simulation"
	if adapter, ok := m.adapter.(interface{ Mode() string }); ok {
		mode = adapter.Mode()
	}
	auth := func(w http.ResponseWriter, r *http.Request, key string) bool {
		if !c.Validate() || subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+key)) != 1 {
			io.Copy(io.Discard, io.LimitReader(r.Body, 16384))
			http.Error(w, "unauthorized", 401)
			return false
		}
		return true
	}
	decode := func(w http.ResponseWriter, r *http.Request, v any) bool {
		d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384))
		d.DisallowUnknownFields()
		var extra any
		if d.Decode(v) != nil || d.Decode(&extra) != io.EOF {
			http.Error(w, "invalid command", 400)
			return false
		}
		return true
	}
	reply := func(w http.ResponseWriter, v any, err error) {
		if err != nil {
			status := 503
			message := err.Error()
			if errors.Is(err, ErrAuthorization) {
				status = 403
			} else if strings.Contains(message, "conflict") || strings.Contains(message, "already") {
				status = 409
			} else if strings.Contains(message, "invalid approval") || strings.Contains(message, "required") || strings.Contains(message, "unknown action") {
				status = 400
			} else if strings.Contains(message, "budget") {
				status = 429
			}
			http.Error(w, "host action rejected", status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(v)
	}
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"service": "host-response", "adapter": mode, "actual_host_isolation": mode == "linux-nftables-netns"})
	})
	mux.HandleFunc("POST /v1/host-evidence", func(w http.ResponseWriter, r *http.Request) {
		if !auth(w, r, c.SensorToken) {
			return
		}
		e, err := hostguard.Decode(http.MaxBytesReader(w, r.Body, 16384), time.Now().UTC())
		if err != nil {
			http.Error(w, "invalid host evidence", 400)
			return
		}
		if e.SensorID != c.Sensor || e.TenantID != c.Tenant || e.AssetID != c.Asset || e.ServiceID != c.Service || e.WorkloadID != c.Workload {
			http.Error(w, "host scope denied", 403)
			return
		}
		alerts, status, err := m.Observe(e, time.Now().UTC())
		reply(w, map[string]any{"status": status, "alerts": alerts, "adapter": mode}, err)
	})
	mux.HandleFunc("GET /v1/host-actions", func(w http.ResponseWriter, r *http.Request) {
		if !auth(w, r, c.ReaderToken) {
			return
		}
		cases, actions, err := m.Status(time.Now().UTC())
		availability := "ready"
		if err != nil {
			availability = "degraded"
		}
		for _, a := range actions {
			if a.State == "unknown" || a.State == "releasing" || a.State == "pending" {
				availability = "degraded"
			}
		}
		w.Header().Set("Content-Type", "application/json")
		if availability == "degraded" {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		json.NewEncoder(w).Encode(map[string]any{"cases": cases, "actions": actions, "adapter": mode, "availability": availability, "actual_host_isolation": mode == "linux-nftables-netns"})
	})
	mux.HandleFunc("POST /v1/host-approve", func(w http.ResponseWriter, r *http.Request) {
		if !auth(w, r, c.OperatorToken) {
			return
		}
		var command Approve
		if !decode(w, r, &command) {
			return
		}
		a, err := m.Approve(command, time.Now().UTC())
		reply(w, a, err)
	})
	mux.HandleFunc("GET /v1/host-signing-context", func(w http.ResponseWriter, r *http.Request) {
		if !auth(w, r, c.ReaderToken) {
			return
		}
		v, err := m.SigningContext()
		reply(w, v, err)
	})
	for _, kind := range []string{"approve", "release"} {
		mux.HandleFunc("POST /v1/host-signed-"+kind, func(w http.ResponseWriter, r *http.Request) {
			if !auth(w, r, c.OperatorToken) {
				return
			}
			raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 8192))
			if err != nil {
				http.Error(w, "invalid authorization", 400)
				return
			}
			s, err := DecodeHostSigned(raw)
			if err != nil {
				http.Error(w, "invalid authorization", 400)
				return
			}
			if kind == "approve" {
				v, e := m.SignedApprove(s, time.Now().UTC())
				reply(w, v, e)
			} else {
				v, e := m.SignedRelease(s, time.Now().UTC())
				reply(w, v, e)
			}
		})
	}
	mux.HandleFunc("POST /v1/host-release", func(w http.ResponseWriter, r *http.Request) {
		if !auth(w, r, c.OperatorToken) {
			return
		}
		var command struct {
			ID string `json:"action_id"`
		}
		if !decode(w, r, &command) {
			return
		}
		a, err := m.Release(command.ID, time.Now().UTC())
		reply(w, a, err)
	})
	return mux
}
