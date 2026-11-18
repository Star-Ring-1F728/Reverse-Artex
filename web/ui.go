// Package web serves the local operator console embedded in the collector.
package web

import (
	"bufio"
	"bytes"
	"context"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reverse-artex/internal/casememory"
	"reverse-artex/internal/contextactivation"
	"reverse-artex/internal/contextrelease"
	"reverse-artex/internal/contextshadow"
	"reverse-artex/internal/localassistant"
	"strings"
	"time"

	"reverse-artex/internal/detect"
	"reverse-artex/internal/event"
)

//go:embed index.html app.js styles.css
var assets embed.FS

type Options struct {
	ContextProduction            *contextactivation.Service
	ContextProductionUnavailable string
	ContextCanary                contextrelease.RuntimeService
	ContextCanaryUnavailable     string
	ContextShadow                *contextshadow.Live
	Assistant                    *localassistant.Service
	Cases                        *casememory.Store
	Tenants                      []string
	SyncCases                    func(context.Context) (int, error)
	AutomaticStatus              func() any
	Token                        string
	Listen                       string
	Directory                    string
	SensorToken                  string
	Settings                     any
	Status                       func() any
}

func Register(mux *http.ServeMux, options Options) {
	guard := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			if !localHost(r.Host, options.Listen) {
				http.Error(w, "local console host required", http.StatusForbidden)
				return
			}
			if origin := r.Header.Get("Origin"); origin != "" {
				u, err := url.Parse(origin)
				if err != nil || u.Scheme != "http" || u.Host != r.Host || u.Path != "" || u.User != nil {
					http.Error(w, "same origin required", http.StatusForbidden)
					return
				}
			}
			if len(r.Header.Values("Authorization")) != 1 || len(options.Token) < 32 || subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+options.Token)) != 1 {
				http.Error(w, "console access key required", http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			next(w, r)
		}
	}
	registerCases(mux, options, guard)
	registerContextShadow(mux, options, guard)
	registerContextCanary(mux, options, guard)
	registerContextProduction(mux, options, guard)
	registerAssistant(mux, options, guard)
	mux.HandleFunc("GET /console/api/status", guard(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(options.Status())
	}))
	mux.HandleFunc("GET /console/api/settings", guard(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(options.Settings)
	}))
	mux.HandleFunc("GET /console/api/sensor-credential", guard(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"token": options.SensorToken})
	}))
	mux.HandleFunc("GET /console/api/stream", guard(func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		switch name {
		case "events", "alerts", "evaluations", "host-events", "host-alerts":
		default:
			http.Error(w, "unknown stream", http.StatusBadRequest)
			return
		}
		rows, truncated, err := tail(filepath.Join(options.Directory, name+".jsonl"))
		if err != nil {
			http.Error(w, "evidence file unavailable", http.StatusServiceUnavailable)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"rows": rows, "truncated": truncated, "scope": "active segment; latest 200 complete records"})
	}))
	mux.HandleFunc("POST /console/api/analyze", guard(func(w http.ResponseWriter, r *http.Request) {
		result, err := analyze(http.MaxBytesReader(w, r.Body, 1<<20))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		json.NewEncoder(w).Encode(result)
	}))
	mux.HandleFunc("POST /console/api/sample", guard(func(w http.ResponseWriter, r *http.Request) {
		var input bytes.Buffer
		now := time.Now().UTC().Add(-20 * time.Second)
		for i := 0; i < 12; i++ {
			t := now.Add(time.Duration(i) * time.Second)
			e := event.Event{SchemaVersion: "1.0", EventID: fmt.Sprintf("sample-e-%d", i), RequestID: fmt.Sprintf("sample-r-%d", i), EventTime: t, IngestTime: t,
				SensorID: "lab-app", TenantID: "alpha", AssetID: "lab-api", EventType: "http", Method: "GET", Route: "/unknown", Status: 404,
				Principal: "sample-user", SessionHMAC: "sample-session", PathHMAC: fmt.Sprintf("sample-path-%d", i), Identity: "authenticated", TrustedProxy: true,
				Authorization: "deny", Reason: "unknown-route", ResourceClass: "business", DetectorFamily: "none", UAHint: "none", DataQuality: "complete"}
			json.NewEncoder(&input).Encode(e)
		}
		result, err := analyze(&input)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(result)
	}))
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if !localHost(r.Host, options.Listen) {
			http.Error(w, "local console host required", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		switch r.URL.Path {
		case "/", "/app.js", "/styles.css":
			http.FileServer(http.FS(assets)).ServeHTTP(w, r)
		default:
			http.NotFound(w, r)
		}
	})
}

func localHost(host, listen string) bool {
	h, p, err := net.SplitHostPort(host)
	if err != nil {
		return false
	}
	_, expectedPort, err := net.SplitHostPort(listen)
	if err != nil || p != expectedPort {
		return false
	}
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// Read a bounded active-file tail. Sealed historical segments are not rescanned.
func tail(path string) ([]json.RawMessage, bool, error) {
	rows := make([]json.RawMessage, 0)
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return rows, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if !info.Mode().IsRegular() {
		return nil, false, fmt.Errorf("regular evidence file required")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	const maximum = int64(1 << 20)
	start := max(int64(0), info.Size()-maximum)
	if _, err = f.Seek(start, io.SeekStart); err != nil {
		return nil, false, err
	}
	data, err := io.ReadAll(io.LimitReader(f, maximum))
	if err != nil {
		return nil, false, err
	}
	if start > 0 {
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			data = data[i+1:]
		} else {
			data = nil
		}
	}
	parts := bytes.Split(data, []byte{'\n'})
	truncated := start > 0
	// The last part may be an in-progress append, so only newline-terminated rows count.
	for _, line := range parts[:len(parts)-1] {
		if len(line) == 0 {
			continue
		}
		if !json.Valid(line) {
			return nil, false, fmt.Errorf("invalid complete evidence record")
		}
		rows = append(rows, json.RawMessage(bytes.Clone(line)))
	}
	if len(rows) > 200 {
		rows, truncated = rows[len(rows)-200:], true
	}
	for i, j := 0, len(rows)-1; i < j; i, j = i+1, j-1 {
		rows[i], rows[j] = rows[j], rows[i]
	}
	return rows, truncated, nil
}

func analyze(input io.Reader) (map[string]any, error) {
	engine := detect.New()
	alerts := make([]detect.Alert, 0)
	scan := bufio.NewScanner(input)
	scan.Buffer(make([]byte, 4096), 16384)
	count := 0
	var previous time.Time
	for scan.Scan() {
		if len(bytes.TrimSpace(scan.Bytes())) == 0 {
			continue
		}
		count++
		if count > 1024 {
			return nil, fmt.Errorf("maximum 1024 events per analysis")
		}
		var header struct {
			Ingest time.Time `json:"ingest_time"`
		}
		if err := json.Unmarshal(scan.Bytes(), &header); err != nil {
			return nil, fmt.Errorf("line %d: invalid JSON", count)
		}
		e, err := event.DecodeAt(strings.NewReader(scan.Text()), header.Ingest)
		if err != nil {
			return nil, fmt.Errorf("line %d: %v", count, err)
		}
		if !previous.IsZero() && e.IngestTime.Before(previous) {
			return nil, fmt.Errorf("line %d: ingest_time must be ordered", count)
		}
		previous = e.IngestTime
		found, status := engine.Process(e, e.IngestTime)
		if status == "capacity_rejected" {
			return nil, fmt.Errorf("analysis correlation capacity reached")
		}
		alerts = append(alerts, found...)
	}
	if err := scan.Err(); err != nil {
		return nil, fmt.Errorf("input exceeds a size or record limit")
	}
	if count == 0 {
		return nil, fmt.Errorf("a non-empty JSONL event file is required")
	}
	return map[string]any{"mode": "offline", "events": count, "alerts": alerts, "live_evidence_changed": false, "policy_actions": 0}, nil
}
