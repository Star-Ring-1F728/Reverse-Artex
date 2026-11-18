package detect

import (
	"crypto/sha256"
	"encoding/hex"
	"reverse-artex/internal/event"
	"sort"
	"sync"
	"time"
)

type Alert struct {
	CaseID           string    `json:"case_id"`
	RuleID           string    `json:"rule_id"`
	Version          string    `json:"rule_version"`
	Time             time.Time `json:"alert_time"`
	Tenant           string    `json:"tenant_id"`
	Asset            string    `json:"asset_id"`
	Subject          string    `json:"subject"`
	CorrelationScope string    `json:"correlation_scope"`
	Principal        string    `json:"principal_id,omitempty"`
	SessionHMAC      string    `json:"session_hmac,omitempty"`
	Mode             string    `json:"mode"`
	Evidence         []string  `json:"evidence_refs"`
	Families         []string  `json:"evidence_families"`
	Confidence       string    `json:"confidence"`
	DataQuality      string    `json:"data_quality"`
	LatencyMS        float64   `json:"ingest_to_alert_ms"`
	Window           string    `json:"window"`
}
type Engine struct {
	principalCorrelation bool
	Canaries             map[string]bool
	mu                   sync.Mutex
	subjects             map[string][]event.Event
	emitted              map[emissionKey]time.Time
	MaxSubjects          int
	MaxEvents            int
	// Compact replay keys retain the full hour without retaining full events.
	MaxSeen     int
	MaxHistory  int
	seenCompact map[[32]byte]int64
	expiry      []seenKey
	expiryHead  int
	lastSweep   time.Time
	history     int
	critical    *criticalReserve
	fairness    *tenantFairness
}
type seenKey struct {
	key [32]byte
	at  int64
}

// Keep cooldown lookup allocation-free even when the subject key is long.
// The serialized case-ID input still uses the original subject|rule encoding.
type emissionKey struct {
	subject string
	rule    string
}

func New() *Engine {
	return &Engine{subjects: map[string][]event.Event{}, emitted: map[emissionKey]time.Time{}, MaxSubjects: 1024, MaxEvents: 512, MaxSeen: 524288, MaxHistory: 16384, seenCompact: map[[32]byte]int64{}}
}

// NewPrincipal correlates verified accounts across sessions within one tenant
// and asset. It only emits observe alerts; policy evidence keeps original sessions.
// It shares the same finite state budgets as New, rather than duplicating history.
func NewPrincipal() *Engine {
	d := New()
	d.principalCorrelation = true
	return d
}

func (d *Engine) Process(e event.Event, now time.Time) ([]Alert, string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.fairness != nil {
		if _, known := d.fairness.usage[e.TenantID]; !known {
			if d.fairness.unknown != ^uint64(0) {
				d.fairness.unknown++
			}
			return nil, "capacity_rejected"
		}
	}
	cutoff := now.Add(-time.Hour)
	for d.expiryHead < len(d.expiry) && d.expiry[d.expiryHead].at < cutoff.UnixNano() {
		x := d.expiry[d.expiryHead]
		delete(d.seenCompact, x.key)
		if d.fairness != nil {
			d.fairness.charge(d.fairness.expiryTenants[d.expiryHead], tenantUsage{0, 0, -1}, d.fairLimits())
			d.fairness.expiryTenants[d.expiryHead] = ""
		}
		d.expiryHead++
	}
	if d.expiryHead > 4096 && d.expiryHead*2 >= len(d.expiry) {
		if d.fairness != nil {
			d.fairness.expiryTenants = append([]string(nil), d.fairness.expiryTenants[d.expiryHead:]...)
		}
		d.expiry = append([]seenKey(nil), d.expiry[d.expiryHead:]...)
		d.expiryHead = 0
	}
	if d.lastSweep.IsZero() || now.Sub(d.lastSweep) >= time.Second {
		if d.critical != nil {
			d.critical.sweep(cutoff)
		}
		for k, t := range d.emitted {
			if t.Before(cutoff) {
				delete(d.emitted, k)
			}
		}
		for k, es := range d.subjects {
			keep := es[:0]
			for _, x := range es {
				if !x.EventTime.Before(cutoff) {
					keep = append(keep, x)
				}
			}
			if len(keep) == 0 {
				delete(d.subjects, k)
			} else {
				d.subjects[k] = keep
			}
			if d.fairness != nil {
				removedSubject := 0
				if len(keep) == 0 {
					removedSubject = -1
				}
				d.fairness.charge(subjectTenant(k), tenantUsage{removedSubject, len(keep) - len(es), 0}, d.fairLimits())
			}
			d.history -= len(es) - len(keep)
			clear(es[len(keep):])
		}
		d.lastSweep = now
	}
	// Deduplicate across authenticated sensor feeds and per request before scoring.
	dedup := sha256.Sum256([]byte(e.TenantID + "|" + e.AssetID + "|" + e.EventID))
	if _, ok := d.seenCompact[dedup]; ok {
		return nil, "duplicate"
	}
	if d.critical != nil {
		if _, ok := d.critical.seen[dedup]; ok {
			return nil, "duplicate"
		}
	}
	if len(d.seenCompact) >= d.MaxSeen {
		return d.capacityResult(e, now, dedup)
	}
	identity := d.subjectFor(e)
	subject, scope, principal, session, verified := identity.subject, identity.scope, identity.principal, identity.session, identity.verified
	// Identifiers may contain colons. Use unambiguous internal tuple boundaries
	// and a scope discriminator so neither session pairs nor anonymous subjects
	// can collide with authenticated principal names.
	key := identity.key
	if _, ok := d.subjects[key]; !ok && len(d.subjects) >= d.MaxSubjects {
		return d.capacityResult(e, now, dedup)
	}
	es := d.subjects[key]
	hadSubject := len(es) > 0
	oldEventCount := len(es)
	kept := es[:0]
	for _, x := range es {
		if !x.EventTime.Before(cutoff) {
			kept = append(kept, x)
		}
	}
	d.history -= len(es) - len(kept)
	clear(es[len(kept):])
	es = kept
	if len(es) > 0 {
		d.subjects[key] = es
	} else {
		delete(d.subjects, key)
	}
	if d.fairness != nil {
		removedSubject := 0
		if hadSubject && len(es) == 0 {
			removedSubject = -1
		}
		d.fairness.charge(e.TenantID, tenantUsage{removedSubject, len(kept) - oldEventCount, 0}, d.fairLimits())
	}
	// Successful known-route requests contribute only path presence to RA-002.
	// Keeping the latest eight distinct benign paths preserves the >=8 threshold
	// in every window. Recon/denials/errors/validation events are never compacted.
	remove, retain := -1, true
	if benign(e) {
		benignN, oldest := 0, -1
		for i, x := range es {
			if benign(x) {
				benignN++
				if oldest < 0 {
					oldest = i
				}
				if x.PathHMAC == e.PathHMAC {
					remove = i
					break
				}
			}
		}
		if remove < 0 && benignN >= 8 {
			remove = oldest
		}
		if remove >= 0 && es[remove].EventTime.After(e.EventTime) {
			remove = -1
			retain = false
		}
	}
	growth := 0
	if retain && remove < 0 {
		growth = 1
	}
	if len(es)+growth > d.MaxEvents || d.history+growth > d.MaxHistory {
		return d.capacityResult(e, now, dedup)
	}
	if d.fairness != nil {
		newSubject := 0
		if len(es) == 0 {
			newSubject = 1
		}
		delta := tenantUsage{newSubject, growth, 1}
		if !d.fairness.admit(e.TenantID, delta, d.fairLimits()) {
			return d.capacityResult(e, now, dedup)
		}
		d.fairness.charge(e.TenantID, delta, d.fairLimits())
		// Retain the configured name rather than each decoded event's string.
		d.fairness.expiryTenants = append(d.fairness.expiryTenants, d.fairness.canonical[e.TenantID])
	}
	d.seenCompact[dedup] = now.UnixNano()
	d.expiry = append(d.expiry, seenKey{dedup, now.UnixNano()})
	if remove >= 0 {
		copy(es[remove:], es[remove+1:])
		es[len(es)-1] = event.Event{}
		es = es[:len(es)-1]
		d.history--
	}
	if retain {
		// Pruning and compaction preserve order. Most inputs already arrive in
		// event-time order; only late arrivals need a stable insertion.
		n := len(es)
		if n == 0 || !e.EventTime.Before(es[n-1].EventTime) {
			es = append(es, e)
		} else {
			// Insert after equal timestamps so request deduplication and evidence
			// witnesses retain the same arrival order as the former stable sort.
			at := sort.Search(n, func(i int) bool { return es[i].EventTime.After(e.EventTime) })
			es = append(es, event.Event{})
			copy(es[at+1:], es[at:n])
			es[at] = e
		}
		d.history++
	}
	d.subjects[key] = es
	var out []Alert
	canEmit := func(rule string) bool {
		return d.canEmit(key, rule, now)
	}
	emit := func(rule string, refs []string, families []string, confidence string, window string) {
		if !canEmit(rule) {
			return
		}
		ek := key + "|" + rule
		d.emitted[emissionKey{key, rule}] = now
		h := sha256.Sum256([]byte(ek + "|" + e.EventID))
		quality := e.DataQuality
		used := map[string]bool{}
		for _, id := range refs {
			used[id] = true
		}
		for _, x := range es {
			if used[x.EventID] && x.DataQuality != "complete" {
				quality = "partial"
			}
		}
		version := "1.0"
		if rule == "RA-002" || rule == "RA-003" || rule == "RA-004" || rule == "RA-005" {
			version = "1.1"
			if d.principalCorrelation {
				version = "1.2"
			}
		}
		out = append(out, Alert{CaseID: hex.EncodeToString(h[:16]), RuleID: rule, Version: version, Time: now, Tenant: e.TenantID, Asset: e.AssetID, Subject: subject, CorrelationScope: scope, Principal: principal, SessionHMAC: session, Mode: "observe", Evidence: refs, Families: families, Confidence: confidence, DataQuality: quality, LatencyMS: float64(now.Sub(e.IngestTime).Microseconds()) / 1000, Window: window})
	}
	if e.Budget != nil && e.Budget.Validate() == nil && e.Budget.Decision == "deny" && e.Identity == "authenticated" && e.DataQuality == "complete" {
		emit("RA-007", []string{e.EventID}, []string{"pre-response-budget"}, "medium", "single-event")
	}
	if e.CanaryID != "" && d.Canaries[e.CanaryID] && e.ResourceClass == "canary" && e.Authorization == "deny" && e.DataQuality == "complete" {
		emit("RA-008", []string{e.EventID}, []string{"private-canary"}, "medium", "single-event")
	}
	if e.UAHint != "none" {
		emit("RA-001", []string{e.EventID}, []string{"ua"}, "informational", "single-event")
	}
	// Read each cooldown once for this evaluation. Only an emission below can
	// change it while the engine lock is held and now remains fixed.
	scoreRecon := canEmit("RA-002")
	scoreChain := canEmit("RA-003")
	scoreAuthorization := verified && canEmit("RA-004")
	scoreValidation := canEmit("RA-005")
	previousStart := -1
	for _, window := range []time.Duration{time.Minute, 10 * time.Minute, time.Hour} {
		if !scoreRecon && !scoreChain && !scoreAuthorization && !scoreValidation {
			break
		}
		// The same suffix has the same requests and witnesses. Any qualifying
		// rule already emitted in the narrower window and entered cooldown.
		start := windowStart(es, now.Add(-window))
		if start == previousStart {
			continue
		}
		previousStart = start
		// Independent request IDs contribute once, even when edge/app feeds overlap.
		req := map[string]bool{}
		paths := map[string]bool{}
		resources := map[string]bool{}
		families := map[string]map[string]bool{}
		invalidByRoute := map[string]int{}
		validationIndices := map[string][]int{}
		var windowIndices []int
		errorsN, unknown, denied := 0, 0, 0
		reconBefore, validationAfter, chain := false, false, false
		var reconTime, validationTime time.Time
		var reconID, validationID string
		var chainRefs []string
		// History is ordered by event time. Skip the expired prefix before
		// request deduplication, so an older copy cannot hide a request in-window.
		for i := start; i < len(es); i++ {
			x := &es[i]
			if req[x.RequestID] {
				continue
			}
			req[x.RequestID] = true
			// Keep a bounded view into the immutable history for this evaluation,
			// rather than copying each full event into every window and route.
			if scoreRecon || scoreAuthorization {
				windowIndices = append(windowIndices, i)
			}
			if scoreRecon {
				if x.PathHMAC != "" {
					paths[x.PathHMAC] = true
				}
				if x.Status >= 400 {
					errorsN++
				}
				if !x.KnownRoute {
					unknown++
				}
			}
			// Evaluate later stages first: one request cannot supply two stages.
			// Equal timestamps do not establish a chronological transition.
			if x.Authorization == "deny" {
				if scoreAuthorization {
					denied++
					if x.ResourceHMAC != "" {
						resources[x.ResourceHMAC] = true
					}
				}
				if scoreChain && validationAfter && x.EventTime.After(validationTime) && !chain {
					chain = true
					chainRefs = []string{reconID, validationID, x.EventID}
				}
			}
			if x.DetectorFamily != "" && x.DetectorFamily != "unknown" {
				// A shared /unknown placeholder is not a common endpoint.
				if x.KnownRoute && scoreValidation {
					invalidByRoute[x.Route]++
					validationIndices[x.Route] = append(validationIndices[x.Route], i)
					if families[x.Route] == nil {
						families[x.Route] = map[string]bool{}
					}
					families[x.Route][x.DetectorFamily] = true
				}
				if scoreChain && reconBefore && x.EventTime.After(reconTime) && !validationAfter {
					validationAfter = true
					validationTime, validationID = x.EventTime, x.EventID
				}
			}
			if scoreChain && (!x.KnownRoute || x.Route == "/app.js") && !reconBefore {
				reconBefore = true
				reconTime, reconID = x.EventTime, x.EventID
			}
		}
		if len(paths) >= 8 && errorsN >= 6 && unknown >= 4 {
			emit("RA-002", thresholdEvidence(es, windowIndices, "RA-002"), []string{"path-diversity", "http-errors", "schema"}, "medium", window.String())
			scoreRecon = false
		}
		if chain {
			emit("RA-003", chainRefs, []string{"recon", "validation", "authorization"}, "medium", window.String())
			scoreChain = false
		}
		if denied >= 4 && len(resources) >= 3 {
			emit("RA-004", thresholdEvidence(es, windowIndices, "RA-004"), []string{"authorization"}, "medium", window.String())
			scoreAuthorization = false
		}
		if !scoreValidation {
			continue
		}
		// Stable route order makes evidence selection reproducible when several
		// endpoints qualify in the same arrival (one subject/rule cooldown).
		routes := make([]string, 0, len(invalidByRoute))
		for route := range invalidByRoute {
			routes = append(routes, route)
		}
		sort.Strings(routes)
		for _, route := range routes {
			n := invalidByRoute[route]
			if n >= 4 && len(families[route]) >= 2 {
				emit("RA-005", thresholdEvidence(es, validationIndices[route], "RA-005"), []string{"validation"}, "medium", window.String())
				scoreValidation = false
				// One subject/rule cooldown allows only the first qualifying route.
				break
			}
		}
	}
	return out, "accepted"
}

// windowStart returns the first event at or after the inclusive cutoff. The
// common all-recent case needs no search; equal timestamps remain in order.
func windowStart(es []event.Event, cutoff time.Time) int {
	if len(es) == 0 || !es[0].EventTime.Before(cutoff) {
		return 0
	}
	if es[len(es)-1].EventTime.Before(cutoff) {
		return len(es)
	}
	return sort.Search(len(es), func(i int) bool {
		return !es[i].EventTime.Before(cutoff)
	})
}

// Retain a bounded proof of every threshold, rather than the last 32 arbitrary
// requests, which could omit the reason for an alert or reference other routes.
func thresholdEvidence(es []event.Event, indices []int, rule string) []string {
	chosen := map[string]bool{}
	paths, resources, families := map[string]bool{}, map[string]bool{}, map[string]bool{}
	errorsN, unknown, denied := 0, 0, 0
	for _, i := range indices {
		x := &es[i]
		use := false
		switch rule {
		case "RA-002":
			if x.PathHMAC != "" && len(paths) < 8 && !paths[x.PathHMAC] {
				paths[x.PathHMAC] = true
				use = true
			}
			if x.Status >= 400 && errorsN < 6 {
				errorsN++
				use = true
			}
			if !x.KnownRoute && unknown < 4 {
				unknown++
				use = true
			}
		case "RA-004":
			if x.Authorization == "deny" {
				if denied < 4 {
					denied++
					use = true
				}
				if x.ResourceHMAC != "" && len(resources) < 3 && !resources[x.ResourceHMAC] {
					resources[x.ResourceHMAC] = true
					use = true
				}
			}
		case "RA-005":
			if len(families) < 2 && !families[x.DetectorFamily] {
				families[x.DetectorFamily] = true
				use = true
			}
		}
		if use {
			chosen[x.EventID] = true
		}
	}
	if rule == "RA-005" {
		for _, i := range indices {
			x := &es[i]
			if len(chosen) >= 4 {
				break
			}
			chosen[x.EventID] = true
		}
	}
	refs := []string{}
	for _, i := range indices {
		x := &es[i]
		if chosen[x.EventID] {
			refs = append(refs, x.EventID)
		}
	}
	return refs
}
func benign(e event.Event) bool {
	return e.Budget == nil && e.ExportApproval == nil && e.CanaryID == "" && e.Status < 400 && e.KnownRoute && e.Route != "/app.js" && e.PathHMAC != "" && e.Authorization != "deny" && (e.DetectorFamily == "" || e.DetectorFamily == "unknown") && e.DataQuality == "complete"
}
func (d *Engine) Stats() map[string]int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return map[string]int{"dedup_keys": len(d.seenCompact), "dedup_limit": d.MaxSeen, "history_events": d.history, "history_limit": d.MaxHistory, "subjects": len(d.subjects)}
}
func Evaluability() map[string]string {
	return map[string]string{"RA-001": "requires_ua_hint", "RA-002": "requires_path_hmac_and_route_classification", "RA-003": "requires_ordered_recon_validation_authorization", "RA-004": "not_evaluable_without_verified_identity_and_resource_hmac", "RA-005": "not_evaluable_without_validation_families", "RA-006": "not_evaluable_no_linux_sensor", "RA-007": "not_evaluable_no_export_budget_sensor", "RA-008": "not_evaluable_no_canary_sensor"}
}

// Missing telemetry is explicit; no-alert is never an assertion of safety.
func EvaluabilityFor(e event.Event) map[string]string {
	r := map[string]string{"RA-001": "evaluable", "RA-002": "evaluable", "RA-003": "evaluable", "RA-004": "evaluable", "RA-005": "evaluable", "RA-006": "not_evaluable_no_linux_sensor", "RA-007": "not_evaluable_no_export_budget_sensor", "RA-008": "not_evaluable_no_canary_sensor"}
	if e.PathHMAC == "" || e.DataQuality != "complete" {
		r["RA-002"] = "not_evaluable_missing_route_quality"
	}
	if e.Authorization == "unknown" || e.DetectorFamily == "unknown" {
		r["RA-003"] = "not_evaluable_missing_authorization_or_validation"
	}
	if e.Identity != "authenticated" || e.ResourceHMAC == "" || e.Authorization == "unknown" {
		r["RA-004"] = "not_evaluable_missing_verified_resource_authorization"
	}
	if e.DetectorFamily == "unknown" || !e.KnownRoute {
		r["RA-005"] = "not_evaluable_missing_validation"
	}
	if e.Budget != nil && e.Budget.Validate() == nil && e.Identity == "authenticated" && e.DataQuality == "complete" {
		r["RA-007"] = "evaluable"
	}
	if e.CanaryID != "" {
		r["RA-008"] = "requires_configured_canary"
	}
	return r
}
func (d *Engine) EvaluabilityFor(e event.Event) map[string]string {
	r := EvaluabilityFor(e)
	if e.CanaryID != "" && d.Canaries[e.CanaryID] && e.DataQuality == "complete" {
		r["RA-008"] = "evaluable"
	}
	return r
}
