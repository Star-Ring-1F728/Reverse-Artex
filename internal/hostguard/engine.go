package hostguard

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync"
	"time"
)

type Alert struct {
	CaseID        string    `json:"case_id"`
	RuleID        string    `json:"rule_id"`
	Version       string    `json:"rule_version"`
	Time          time.Time `json:"alert_time"`
	Tenant        string    `json:"tenant_id"`
	Asset         string    `json:"asset_id"`
	Service       string    `json:"service_id"`
	Workload      string    `json:"workload_id"`
	ProcessKey    string    `json:"process_key"`
	Evidence      []string  `json:"evidence_refs"`
	Mode          string    `json:"mode"`
	Quality       string    `json:"data_quality"`
	RequestLinked bool      `json:"request_linked"`
}
type processState struct{ Start, Connection Event }
type Engine struct {
	mu                    sync.Mutex
	seen                  map[string]time.Time
	processes             map[string]processState
	emitted               map[string]time.Time
	canaries              map[string]bool
	lastSweep             time.Time
	MaxSeen, MaxProcesses int
}

func New(canaries []string) *Engine {
	d := &Engine{seen: map[string]time.Time{}, processes: map[string]processState{}, emitted: map[string]time.Time{}, canaries: map[string]bool{}, MaxSeen: 65536, MaxProcesses: 1024}
	for _, s := range canaries {
		if ID.MatchString(s) {
			d.canaries[s] = true
		}
	}
	return d
}
func tuple(parts ...string) string {
	b, _ := json.Marshal(parts)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func (d *Engine) Process(e Event, now time.Time) ([]Alert, string, map[string]string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	rules := map[string]string{"RA-006": "not_evaluable_missing_process_network_chain", "RA-008": "not_evaluable_no_canary_observation"}
	if e.Validate(now) != nil {
		return nil, "invalid", rules
	}
	if d.lastSweep.IsZero() || now.Sub(d.lastSweep) >= time.Second {
		for k, t := range d.seen {
			if t.Before(now.Add(-time.Hour)) {
				delete(d.seen, k)
			}
		}
		for k, s := range d.processes {
			if s.Start.EventTime.Before(now.Add(-time.Minute)) && s.Connection.EventTime.Before(now.Add(-time.Minute)) {
				delete(d.processes, k)
			}
		}
		for k, t := range d.emitted {
			if t.Before(now.Add(-time.Minute)) {
				delete(d.emitted, k)
			}
		}
		d.lastSweep = now
	}
	dedup := tuple(e.TenantID, e.AssetID, e.SensorID, e.EventID)
	if _, ok := d.seen[dedup]; ok {
		return nil, "duplicate", rules
	}
	key := tuple(e.TenantID, e.AssetID, e.ServiceID, e.WorkloadID, e.ProcessKey, e.ParentKey)
	if len(d.seen) >= d.MaxSeen {
		return nil, "capacity_rejected", rules
	}
	// Unknown lineage, partial data and future timestamps cannot justify response.
	eligible := e.Lineage == "verified" && e.DataQuality == "complete" && !e.EventTime.After(now) && !e.EventTime.Before(now.Add(-time.Minute))
	if eligible && e.EventType != "canary_access" {
		if _, ok := d.processes[key]; !ok && len(d.processes) >= d.MaxProcesses {
			return nil, "capacity_rejected", rules
		}
	}
	d.seen[dedup] = now
	if !eligible {
		rules["RA-006"] = "not_evaluable_lineage_quality_or_time"
		rules["RA-008"] = "not_evaluable_lineage_quality_or_time"
		return nil, "accepted", rules
	}
	var out []Alert
	capacity := false
	emit := func(rule string, refs []string, linked bool) {
		cooldown := key + rule
		if t, ok := d.emitted[cooldown]; ok && now.Sub(t) < time.Minute {
			return
		}
		// One cooldown per process/rule; its map is bounded by processes + seen keys.
		if len(d.emitted) >= d.MaxProcesses*2 {
			capacity = true
			return
		}
		d.emitted[cooldown] = now
		out = append(out, Alert{CaseID: "host-" + tuple(cooldown, e.EventID)[:32], RuleID: rule, Version: "1.0", Time: now, Tenant: e.TenantID, Asset: e.AssetID, Service: e.ServiceID, Workload: e.WorkloadID, ProcessKey: e.ProcessKey, Evidence: refs, Mode: "observe", Quality: "complete", RequestLinked: linked})
	}
	if e.EventType == "canary_access" {
		if d.canaries[e.CanaryID] {
			rules["RA-008"] = "evaluable"
			emit("RA-008", []string{e.EventID}, false)
		} else {
			rules["RA-008"] = "not_evaluable_unconfigured_canary"
		}
		if capacity {
			delete(d.seen, dedup)
			rules["RA-006"] = "not_evaluable_capacity_rejected"
			rules["RA-008"] = "not_evaluable_capacity_rejected"
			return nil, "capacity_rejected", rules
		}
		return out, "accepted", rules
	}
	s := d.processes[key]
	if e.EventType == "process_start" && e.Classification == "unexpected_child" {
		s.Start = e
	}
	if e.EventType == "network_connect" && e.Classification == "unapproved_destination" {
		s.Connection = e
	}
	d.processes[key] = s
	if !s.Start.EventTime.Before(now.Add(-time.Minute)) && !s.Connection.EventTime.Before(now.Add(-time.Minute)) && s.Connection.EventTime.After(s.Start.EventTime) && s.Connection.EventID != s.Start.EventID {
		rules["RA-006"] = "evaluable"
		emit("RA-006", []string{s.Start.EventID, s.Connection.EventID}, s.Start.RequestID != "" && s.Start.RequestID == s.Connection.RequestID)
	}
	if capacity {
		delete(d.seen, dedup)
		rules["RA-006"] = "not_evaluable_capacity_rejected"
		rules["RA-008"] = "not_evaluable_capacity_rejected"
		return nil, "capacity_rejected", rules
	}
	return out, "accepted", rules
}
