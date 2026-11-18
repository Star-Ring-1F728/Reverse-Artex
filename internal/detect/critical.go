package detect

import (
	"crypto/sha256"
	"encoding/hex"
	"reverse-artex/internal/event"
	"time"
)

// CriticalReserveVersion binds fixed limits and signal-only semantics to replay.
const CriticalReserveVersion = "1.0"

type criticalLimits struct {
	seen, tenantSeen, sensorSeen int
	keys, tenantKeys, sensorKeys int
}

type criticalQuota struct{ tenant, sensor string }
type criticalUsage struct{ seen, keys int }
type criticalSeen struct {
	at    time.Time
	quota criticalQuota
}
type criticalCooldown struct {
	at, emitted time.Time
	quota       criticalQuota
}

type criticalReserve struct {
	limits    criticalLimits
	seen      map[[32]byte]criticalSeen
	cooldowns map[emissionKey]criticalCooldown
	tenants   map[string]criticalUsage
	sensors   map[criticalQuota]criticalUsage
	rejected  [6]uint64
}

// NewWithCriticalReserve enables bounded, observe-only RA-007/008 evaluation
// when correlation admission fails. New/NewPrincipal retain the legacy contract.
// This is a construction-time option, never a live configuration transition.
func NewWithCriticalReserve(principalCorrelation bool) *Engine {
	d := New()
	d.principalCorrelation = principalCorrelation
	d.critical = &criticalReserve{
		limits: criticalLimits{4096, 1024, 512, 256, 64, 32},
		seen:   map[[32]byte]criticalSeen{}, cooldowns: map[emissionKey]criticalCooldown{},
		tenants: map[string]criticalUsage{}, sensors: map[criticalQuota]criticalUsage{},
	}
	return d
}

func (d *Engine) CriticalReserveEnabled() bool { return d.critical != nil }

type subjectScope struct {
	key, subject, scope, principal, session string
	verified                                bool
}

func (d *Engine) subjectFor(e event.Event) subjectScope {
	s := subjectScope{subject: "anonymous-asset", scope: "asset"}
	s.verified = e.Identity == "authenticated" && e.Principal != "" && e.SessionHMAC != ""
	if s.verified {
		s.principal, s.session, s.scope = e.Principal, e.SessionHMAC, "session"
		s.subject = s.principal + ":" + s.session
		if d.principalCorrelation {
			s.subject, s.session, s.scope = s.principal, "", "principal"
		}
	}
	s.key = e.TenantID + "\x00" + e.AssetID + "\x00" + s.scope + "\x00" + s.principal + "\x00" + s.session
	return s
}

func (d *Engine) canEmit(key, rule string, now time.Time) bool {
	ek := emissionKey{key, rule}
	if at, ok := d.emitted[ek]; ok && now.Sub(at) < time.Minute {
		return false
	}
	if d.critical != nil && (rule == "RA-007" || rule == "RA-008") {
		if rec, ok := d.critical.cooldowns[ek]; ok && !rec.emitted.IsZero() && now.Sub(rec.emitted) < time.Minute {
			return false
		}
	}
	return true
}

func (r *criticalReserve) charge(q criticalQuota, seen, keys int) {
	t, s := r.tenants[q.tenant], r.sensors[q]
	t.seen, t.keys = t.seen+seen, t.keys+keys
	s.seen, s.keys = s.seen+seen, s.keys+keys
	if t.seen == 0 && t.keys == 0 {
		delete(r.tenants, q.tenant)
	} else {
		r.tenants[q.tenant] = t
	}
	if s.seen == 0 && s.keys == 0 {
		delete(r.sensors, q)
	} else {
		r.sensors[q] = s
	}
}

func (r *criticalReserve) sweep(cutoff time.Time) {
	for id, rec := range r.seen {
		if rec.at.Before(cutoff) {
			delete(r.seen, id)
			r.charge(rec.quota, -1, 0)
		}
	}
	for key, rec := range r.cooldowns {
		if rec.at.Before(cutoff) {
			delete(r.cooldowns, key)
			r.charge(rec.quota, 0, -1)
		}
	}
}

func (d *Engine) criticalRule(e event.Event) (string, string) {
	if e.DataQuality != "complete" {
		return "", ""
	}
	if e.Budget != nil && e.Budget.Validate() == nil && e.Budget.Decision == "deny" && e.Identity == "authenticated" {
		return "RA-007", "pre-response-budget"
	}
	if e.CanaryID != "" && d.Canaries[e.CanaryID] && e.ResourceClass == "canary" && e.Authorization == "deny" {
		return "RA-008", "private-canary"
	}
	return "", ""
}

// capacityResult is called with the engine lock held. No correlation history,
// ordinary replay key, or policy forwarding is admitted by this path.
func (d *Engine) capacityResult(e event.Event, now time.Time, dedup [32]byte) ([]Alert, string) {
	r := d.critical
	if r == nil {
		return nil, "capacity_rejected"
	}
	rule, family := d.criticalRule(e)
	if rule == "" || e.Validate(now) != nil {
		return nil, "capacity_rejected"
	}
	s := d.subjectFor(e)
	ek, q := emissionKey{s.key, rule}, criticalQuota{e.TenantID, e.SensorID}
	old, exists := r.cooldowns[ek]
	tenant, sensor := r.tenants[q.tenant], r.sensors[q]
	checks := [...]bool{
		len(r.seen) >= r.limits.seen,
		tenant.seen >= r.limits.tenantSeen,
		sensor.seen >= r.limits.sensorSeen,
		!exists && len(r.cooldowns) >= r.limits.keys,
		!exists && tenant.keys >= r.limits.tenantKeys,
		!exists && sensor.keys >= r.limits.sensorKeys,
	}
	for reason, refused := range checks {
		if refused {
			if r.rejected[reason] != ^uint64(0) {
				r.rejected[reason]++
			}
			return nil, "capacity_rejected"
		}
	}
	r.seen[dedup] = criticalSeen{now, q}
	r.charge(q, 1, 0)
	if !exists {
		old.quota = q
		r.charge(q, 0, 1)
	}
	old.at = now
	emit := d.canEmit(s.key, rule, now)
	if emit {
		old.emitted = now
	}
	r.cooldowns[ek] = old
	if !emit {
		return nil, "signal_only"
	}
	h := sha256.Sum256([]byte(s.key + "|" + rule + "|" + e.EventID))
	a := Alert{CaseID: hex.EncodeToString(h[:16]), RuleID: rule, Version: "1.1", Time: now,
		Tenant: e.TenantID, Asset: e.AssetID, Subject: s.subject, CorrelationScope: s.scope,
		Principal: s.principal, SessionHMAC: s.session, Mode: "observe", Evidence: []string{e.EventID},
		Families: []string{family}, Confidence: "medium", DataQuality: e.DataQuality,
		LatencyMS: float64(now.Sub(e.IngestTime).Microseconds()) / 1000, Window: "single-event"}
	return []Alert{a}, "signal_only"
}

// EvaluabilityForResult is shared by live ingest and recovery, so a signal-only
// receipt cannot imply that the correlation rules were evaluated successfully.
func (d *Engine) EvaluabilityForResult(e event.Event, result string) map[string]string {
	rules := d.EvaluabilityFor(e)
	if result == "capacity_rejected" || result == "signal_only" {
		for rule := range rules {
			rules[rule] = "not_evaluable_capacity_rejected"
		}
		if result == "signal_only" {
			if rule, _ := d.criticalRule(e); rule != "" {
				rules[rule] = "evaluable_reserved_signal"
			}
		}
	}
	return rules
}

func (d *Engine) CriticalReserveStats() map[string]any {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.critical == nil {
		return map[string]any{"enabled": false}
	}
	r := d.critical
	return map[string]any{"enabled": true, "version": CriticalReserveVersion,
		"dedup_keys": len(r.seen), "dedup_limit": r.limits.seen,
		"tenant_dedup_limit": r.limits.tenantSeen, "sensor_dedup_limit": r.limits.sensorSeen,
		"cooldown_keys": len(r.cooldowns), "cooldown_limit": r.limits.keys,
		"tenant_cooldown_limit": r.limits.tenantKeys, "sensor_cooldown_limit": r.limits.sensorKeys,
		"tenant_scopes": len(r.tenants), "sensor_scopes": len(r.sensors),
		"refused_global_dedup": r.rejected[0], "refused_tenant_dedup": r.rejected[1],
		"refused_sensor_dedup": r.rejected[2], "refused_global_cooldown": r.rejected[3],
		"refused_tenant_cooldown": r.rejected[4], "refused_sensor_cooldown": r.rejected[5]}
}
