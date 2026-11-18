// host-eval checks normalized fixtures with a logical clock; no OS/model calls.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"reflect"
	"reverse-artex/internal/hostguard"
	"sort"
	"time"
)

func main() {
	input := flag.String("input", "lab/scenarios/m5-v1/host-fixtures.json", "fixed synthetic host cases")
	out := flag.String("out", "", "new JSON result path")
	flag.Parse()
	if *out == "" {
		panic("new output path required")
	}
	var fixture struct {
		Cases []struct {
			ID    string `json:"scenario_id"`
			Steps []struct {
				EventMS   int64           `json:"event_ms"`
				ArrivalMS int64           `json:"arrival_ms"`
				Event     hostguard.Event `json:"event"`
			} `json:"steps"`
			Truth struct {
				Rules []string `json:"expected_rule_ids"`
			} `json:"ground_truth"`
		} `json:"cases"`
	}
	b, err := os.ReadFile(*input)
	must(err)
	must(json.Unmarshal(b, &fixture))
	if len(fixture.Cases) == 0 {
		panic("empty fixture")
	}
	base := time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)
	results := []map[string]any{}
	passed := true
	for _, c := range fixture.Cases {
		d := hostguard.New([]string{"canary-fixture"})
		alerts := []hostguard.Alert{}
		events := map[string]hostguard.Event{}
		clock := int64(-1)
		ok := true
		for _, step := range c.Steps {
			if step.ArrivalMS < clock {
				panic("arrival clock moved backwards")
			}
			clock = step.ArrivalMS
			e := step.Event
			e.EventTime = base.Add(time.Duration(step.EventMS) * time.Millisecond)
			e.IngestTime = base.Add(time.Duration(clock) * time.Millisecond)
			must(e.Validate(e.IngestTime))
			events[e.EventID] = e
			a, status, _ := d.Process(e, e.IngestTime)
			ok = ok && (status == "accepted" || status == "duplicate")
			alerts = append(alerts, a...)
		}
		got := []string{}
		for _, a := range alerts {
			got = append(got, a.RuleID)
			ok = ok && witness(a, events)
		}
		sort.Strings(got)
		want := append([]string{}, c.Truth.Rules...)
		sort.Strings(want)
		ok = ok && reflect.DeepEqual(got, want)
		passed = passed && ok
		results = append(results, map[string]any{"scenario_id": c.ID, "expected": want, "actual": alerts, "passed": ok})
	}
	report := map[string]any{"passed": passed, "scenario_count": len(results), "cases": results, "actual_ARTEX_executed": false, "native_linux_sensor_tested": false, "scope": "fixed logical-clock normalized host observations; no native sensor or isolation claim"}
	f, err := os.OpenFile(*out, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	must(err)
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	must(enc.Encode(report))
	must(f.Close())
	fmt.Printf("host scenarios=%d passed=%v\n", len(results), passed)
	if !passed {
		os.Exit(1)
	}
}
func must(err error) {
	if err != nil {
		panic(err)
	}
}
func witness(a hostguard.Alert, events map[string]hostguard.Event) bool {
	es := []hostguard.Event{}
	ids := map[string]bool{}
	for _, ref := range a.Evidence {
		e, ok := events[ref]
		if !ok || ids[ref] || e.TenantID != a.Tenant || e.AssetID != a.Asset || e.ServiceID != a.Service || e.WorkloadID != a.Workload || e.ProcessKey != a.ProcessKey || e.Lineage != "verified" || e.DataQuality != "complete" || e.EventTime.After(a.Time) || e.EventTime.Before(a.Time.Add(-time.Minute)) {
			return false
		}
		ids[ref] = true
		es = append(es, e)
	}
	if a.RuleID == "RA-008" {
		return len(es) == 1 && es[0].EventType == "canary_access" && es[0].CanaryID == "canary-fixture"
	}
	return a.RuleID == "RA-006" && len(es) == 2 && es[0].EventType == "process_start" && es[0].Classification == "unexpected_child" && es[1].EventType == "network_connect" && es[1].Classification == "unapproved_destination" && es[0].ParentKey == es[1].ParentKey && es[1].EventTime.After(es[0].EventTime)
}
