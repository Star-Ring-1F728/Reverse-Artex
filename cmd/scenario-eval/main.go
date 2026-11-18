// scenario-eval evaluates isolated event streams against a separate answer key.
// Only event.Event and a simulated arrival clock enter detect.Engine.
package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"reverse-artex/internal/detect"
	"reverse-artex/internal/event"
	"sort"
	"time"
)

type step struct {
	EventMS   int64       `json:"event_ms"`
	ArrivalMS int64       `json:"arrival_ms"`
	Event     event.Event `json:"event"`
}
type scenario struct {
	ID    string `json:"id"`
	Split string `json:"split"`
	Steps []step `json:"steps"`
}
type expectation struct {
	Count     int    `json:"count"`
	Window    string `json:"window"`
	TriggerMS int64  `json:"trigger_ms"`
	FirstMS   int64  `json:"first_malicious_ms"`
}
type truth struct {
	ID       string                 `json:"scenario_id"`
	Split    string                 `json:"split"`
	Category string                 `json:"category"`
	Expected map[string]expectation `json:"expected"`
}
type metric struct {
	TP        int      `json:"tp"`
	FP        int      `json:"fp"`
	FN        int      `json:"fn"`
	TN        int      `json:"tn"`
	Precision *float64 `json:"precision"`
	Recall    *float64 `json:"recall"`
}

func readLines[T any](path string) []T {
	f, err := os.Open(path)
	must(err)
	defer f.Close()
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 4096), 8<<20)
	var out []T
	for s.Scan() {
		var v T
		must(json.Unmarshal(s.Bytes(), &v))
		out = append(out, v)
	}
	must(s.Err())
	return out
}
func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}
func digest(path string) string {
	b, e := os.ReadFile(path)
	must(e)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// Verify provenance separately from the rule threshold proof.
func withinScope(a detect.Alert, e event.Event) bool {
	window, err := time.ParseDuration(a.Window)
	if a.RuleID == "RA-001" {
		window, err = time.Hour, nil
	}
	age := a.Time.Sub(e.EventTime)
	if err != nil || age < 0 || age > window || a.Tenant != e.TenantID || a.Asset != e.AssetID {
		return false
	}
	if e.DataQuality != "complete" && a.DataQuality == "complete" {
		return false
	}
	switch a.CorrelationScope {
	case "principal":
		return e.Identity == "authenticated" && e.Principal != "" && e.SessionHMAC != "" && a.Principal == e.Principal && a.Subject == e.Principal && a.SessionHMAC == ""
	case "session":
		return e.Identity == "authenticated" && a.Principal == e.Principal && a.SessionHMAC == e.SessionHMAC && a.Subject == e.Principal+":"+e.SessionHMAC
	case "asset":
		return e.Identity == "anonymous" && a.Subject == "anonymous-asset" && a.Principal == "" && a.SessionHMAC == ""
	}
	return false
}

func witness(a detect.Alert, events map[string]event.Event) bool {
	var es []event.Event
	requests := map[string]bool{}
	for _, id := range a.Evidence {
		e, ok := events[id]
		if !ok || requests[e.RequestID] || !withinScope(a, e) {
			return false
		}
		requests[e.RequestID] = true
		es = append(es, e)
	}
	sort.SliceStable(es, func(i, j int) bool { return es[i].EventTime.Before(es[j].EventTime) })
	paths, resources := map[string]bool{}, map[string]bool{}
	errorsN, unknown, denied := 0, 0, 0
	var recon, validation time.Time
	chain := false
	route := ""
	families := map[string]bool{}
	for _, e := range es {
		if e.PathHMAC != "" {
			paths[e.PathHMAC] = true
		}
		if e.Status >= 400 {
			errorsN++
		}
		if !e.KnownRoute {
			unknown++
		}
		if a.RuleID == "RA-003" {
			if e.Authorization == "deny" && !validation.IsZero() && e.EventTime.After(validation) {
				chain = true
			}
			if e.DetectorFamily != "" && e.DetectorFamily != "unknown" && !recon.IsZero() && e.EventTime.After(recon) && validation.IsZero() {
				validation = e.EventTime
			}
			if (!e.KnownRoute || e.Route == "/app.js") && recon.IsZero() {
				recon = e.EventTime
			}
		}
		if e.Authorization == "deny" {
			denied++
			if e.ResourceHMAC != "" {
				resources[e.ResourceHMAC] = true
			}
		}
		if a.RuleID == "RA-005" {
			if !e.KnownRoute || e.DetectorFamily == "" || e.DetectorFamily == "unknown" {
				return false
			}
			if route != "" && e.Route != route {
				return false
			}
			route = e.Route
			families[e.DetectorFamily] = true
		}
	}
	switch a.RuleID {
	case "RA-002":
		return len(paths) >= 8 && errorsN >= 6 && unknown >= 4
	case "RA-003":
		return chain
	case "RA-004":
		return denied >= 4 && len(resources) >= 3
	case "RA-005":
		return len(es) >= 4 && len(families) >= 2
	}
	return true
}
func main() {
	input := flag.String("input", "lab/scenarios/security-v1/inputs.jsonl", "event streams")
	answer := flag.String("truth", "lab/scenarios/security-v1/ground-truth.jsonl", "separate labels")
	out := flag.String("out", "", "new result JSON path")
	split := flag.String("split", "tuning", "tuning or validation")
	correlation := flag.String("correlation", "session", "observe correlation: session or principal (verified account across sessions)")
	flag.Parse()
	if *out == "" || (*split != "tuning" && *split != "validation") || (*correlation != "session" && *correlation != "principal") {
		must(fmt.Errorf("out, valid split and correlation required"))
	}
	answers := map[string]truth{}
	for _, v := range readLines[truth](*answer) {
		if _, ok := answers[v.ID]; ok {
			must(fmt.Errorf("duplicate truth %s", v.ID))
		}
		answers[v.ID] = v
	}
	base := time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC)
	rules := []string{"RA-002", "RA-003", "RA-004", "RA-005"}
	metrics := map[string]*metric{}
	for _, r := range rules {
		metrics[r] = &metric{}
	}
	results := []map[string]any{}
	passed := true
	seenCases := map[string]bool{}
	for _, c := range readLines[scenario](*input) {
		if c.Split != *split {
			continue
		}
		if seenCases[c.ID] {
			must(fmt.Errorf("duplicate case"))
		}
		seenCases[c.ID] = true
		t, ok := answers[c.ID]
		if !ok || t.Split != c.Split {
			must(fmt.Errorf("missing/mismatched truth %s", c.ID))
		}
		d := detect.New()
		if *correlation == "principal" {
			d = detect.NewPrincipal()
		}
		var alerts []detect.Alert
		events := map[string]event.Event{}
		statuses := map[string]int{}
		last := int64(-1)
		for _, s := range c.Steps {
			if s.ArrivalMS < last {
				must(fmt.Errorf("arrival clock moved backwards in %s", c.ID))
			}
			last = s.ArrivalMS
			e := s.Event
			now := base.Add(time.Duration(s.ArrivalMS) * time.Millisecond)
			e.EventTime = base.Add(time.Duration(s.EventMS) * time.Millisecond)
			e.IngestTime = now
			must(e.Validate(now))
			events[e.EventID] = e
			a, status := d.Process(e, now)
			statuses[status]++
			alerts = append(alerts, a...)
		}
		checks := map[string]bool{"no_capacity_rejection": statuses["capacity_rejected"] == 0}
		delays := []map[string]any{}
		for _, r := range rules {
			ex := t.Expected[r]
			n := 0
			for _, a := range alerts {
				if a.RuleID != r {
					continue
				}
				n++
				checks[r+"-evidence-valid"] = witness(a, events) && (checks[r+"-evidence-valid"] || n == 1)
				checks[r+"-window"] = a.Window == ex.Window && (checks[r+"-window"] || n == 1)
				if ex.Count > 0 {
					trigger := float64(a.Time.Sub(base).Milliseconds() - ex.TriggerMS)
					checks[r+"-trigger-delay-nonnegative"] = trigger >= 0
					delays = append(delays, map[string]any{"rule": r, "first_malicious_to_alert_simulated_ms": a.Time.Sub(base).Milliseconds() - ex.FirstMS, "condition_to_alert_simulated_ms": trigger, "ingest_to_alert_simulated_ms": a.LatencyMS})
				}
			}
			checks[r+"-count"] = n == ex.Count
			m := metrics[r]
			m.TP += min(n, ex.Count)
			m.FP += max(0, n-ex.Count)
			m.FN += max(0, ex.Count-n)
			if n == 0 && ex.Count == 0 {
				m.TN++
			}
		}
		ok = true
		for _, v := range checks {
			ok = ok && v
		}
		passed = passed && ok
		results = append(results, map[string]any{"scenario_id": c.ID, "category": t.Category, "expected": t.Expected, "actual": alerts, "statuses": statuses, "checks": checks, "delays": delays, "passed": ok})
	}
	if len(results) == 0 {
		must(fmt.Errorf("empty split"))
	}
	for _, m := range metrics {
		if m.TP+m.FP > 0 {
			x := float64(m.TP) / float64(m.TP+m.FP)
			m.Precision = &x
		}
		if m.TP+m.FN > 0 {
			x := float64(m.TP) / float64(m.TP+m.FN)
			m.Recall = &x
		}
	}
	exe, err := os.Executable()
	must(err)
	report := map[string]any{"passed": passed, "correlation_scope": *correlation, "split": *split, "scenario_count": len(results), "metrics": metrics, "cases": results, "input_sha256": digest(*input), "truth_sha256": digest(*answer), "binary_sha256": digest(exe), "scope": "synthetic isolated streams; simulated clock delays; no HTTP/ARTEX or operational accuracy claim", "labels_not_ingested": true}
	f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	must(err)
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	must(enc.Encode(report))
	must(f.Close())
	fmt.Printf("%s: cases=%d passed=%v\n", *split, len(results), passed)
	if !passed {
		os.Exit(1)
	}
}
