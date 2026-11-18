package detect

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"reverse-artex/internal/event"
)

var updateWindowFixture = flag.Bool("update-window-fixture", false, "explicitly regenerate the window-accounting fixture")

func windowFixtureEvents(profile string) []event.Event {
	result := make([]event.Event, 128)
	ages := []time.Duration{time.Second, time.Minute, time.Minute + time.Nanosecond, 10 * time.Minute, 10*time.Minute + time.Nanosecond, time.Hour, time.Hour + time.Nanosecond}
	for i := range result {
		now := detectTestNow
		if profile == "mixed" || profile == "capacity" {
			if i >= 64 {
				now = now.Add(61 * time.Second)
			}
			if i >= 96 {
				now = now.Add(time.Hour)
			}
		}
		e := detectEvent(fmt.Sprint("event-", i), fmt.Sprint("request-", i), now.Add(-50*time.Second+time.Duration(i)*250*time.Millisecond))
		e.IngestTime = now
		e.PathHMAC = fmt.Sprint("path-", i)
		switch profile {
		case "recon":
			e.KnownRoute, e.Status = false, 404
		case "validation":
			e.Route, e.DetectorFamily, e.Status = fmt.Sprint("/api/", i%4), []string{"schema", "type"}[(i/4)%2], 400
		case "mixed", "capacity":
			e.EventTime = now.Add(-ages[i%len(ages)])
			e.RequestID = fmt.Sprint("request-", i/2)
			e.TenantID, e.AssetID = fmt.Sprint("tenant-", i%2), fmt.Sprint("asset-", i%3)
			e.Principal, e.SessionHMAC = fmt.Sprint("user-", i%2), fmt.Sprint("session-", i%4)
			e.Route, e.PathHMAC = fmt.Sprint("/api/", i%3), fmt.Sprint("path-", i%11)
			if i%2 == 0 {
				e.Authorization, e.ResourceHMAC = "deny", fmt.Sprint("resource-", i%5)
			}
			if i%3 == 0 {
				e.DetectorFamily, e.Status = []string{"schema", "type"}[(i/3)%2], 400
			}
			if i%5 == 0 {
				e.KnownRoute, e.Status = false, 404
			}
			if i%7 == 0 {
				e.DataQuality = "partial"
			}
			if i%11 == 0 {
				e.Identity = "anonymous"
			}
			if i%17 == 0 && i > 0 {
				e.EventID, e.TenantID, e.AssetID = result[i-1].EventID, result[i-1].TenantID, result[i-1].AssetID
			}
			if i%19 == 0 {
				e.UAHint = "fixture-enrich"
			}
			if i%31 == 0 {
				e.CanaryID, e.ResourceClass, e.Authorization, e.DataQuality = "fixture-canary", "canary", "deny", "complete"
			}
		}
		result[i] = e
	}
	return result
}

func TestWindowAccountingMatchesPreviousEngineFixture(t *testing.T) {
	type step struct {
		Status string  `json:"status"`
		Alerts []Alert `json:"alerts"`
	}
	type scenario struct {
		Mode    string         `json:"mode"`
		Profile string         `json:"profile"`
		Steps   []step         `json:"steps"`
		Stats   map[string]int `json:"stats"`
	}
	var scenarios []scenario
	for _, mode := range []string{"session", "principal"} {
		for _, profile := range []string{"normal", "recon", "validation", "mixed", "capacity"} {
			engine := New()
			if mode == "principal" {
				engine = NewPrincipal()
			}
			engine.Canaries = map[string]bool{"fixture-canary": true}
			if profile == "capacity" {
				engine.MaxSubjects, engine.MaxEvents, engine.MaxHistory, engine.MaxSeen = 2, 16, 24, 32
			}
			s := scenario{Mode: mode, Profile: profile}
			for _, e := range windowFixtureEvents(profile) {
				alerts, status := engine.Process(e, e.IngestTime)
				s.Steps = append(s.Steps, step{Status: status, Alerts: alerts})
			}
			s.Stats = engine.Stats()
			scenarios = append(scenarios, s)
		}
	}
	got, err := json.MarshalIndent(scenarios, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	path := filepath.Join("testdata", "window-accounting.json")
	if *updateWindowFixture {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("previous-engine fixture changed: compare statuses, complete alerts, evidence order, quality, windows, and final budgets before accepting")
	}
}
