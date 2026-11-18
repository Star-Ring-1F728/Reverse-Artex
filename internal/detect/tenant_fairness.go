package detect

import (
	"errors"
	"sort"
	"strings"
)

// TenantFairnessVersion binds the fixed minimum-share policy and accounting to replay.
const TenantFairnessVersion = "1.0"

const (
	fairSubjects = iota
	fairHistory
	fairSeen
)

type tenantUsage [3]int

type TenantFairnessProfile struct {
	Version          string   `json:"version"`
	Tenants          []string `json:"tenants"`
	Subjects         int      `json:"subjects"`
	EventsPerSubject int      `json:"events_per_subject"`
	History          int      `json:"history"`
	Seen             int      `json:"seen"`
}

type tenantFairness struct {
	tenants   []string
	usage     map[string]tenantUsage
	canonical map[string]string
	shared    tenantUsage
	// Parallel to Engine.expiry only in this opt-in profile. The legacy replay
	// key representation and its default-mode memory footprint stay unchanged.
	expiryTenants []string
	rejected      [3]uint64
	unknown       uint64
}

// NewWithTenantFairness reserves a minimum resource share for each configured
// tenant and allows the remaining capacity to be shared. Max* fields must be
// fixed before the first Process call; the CLI exposes no live budget mutation.
func NewWithTenantFairness(principalCorrelation, criticalReserve bool, tenants []string) (*Engine, error) {
	ids := append([]string(nil), tenants...)
	sort.Strings(ids)
	unique := ids[:0]
	for _, id := range ids {
		if len(id) == 0 || len(id) > 128 {
			return nil, errors.New("invalid fairness tenant identifier")
		}
		for _, c := range id {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("_.:/{}-", c)) {
				return nil, errors.New("invalid fairness tenant identifier")
			}
		}
		if len(unique) == 0 || unique[len(unique)-1] != id {
			unique = append(unique, id)
		}
	}
	if len(unique) == 0 || len(unique) > 64 {
		return nil, errors.New("fairness requires 1 to 64 configured tenants")
	}
	d := New()
	if criticalReserve {
		d = NewWithCriticalReserve(principalCorrelation)
	} else {
		d.principalCorrelation = principalCorrelation
	}
	d.fairness = &tenantFairness{tenants: unique, usage: map[string]tenantUsage{}, canonical: map[string]string{}}
	for _, id := range unique {
		d.fairness.usage[id] = tenantUsage{}
		d.fairness.canonical[id] = id
	}
	return d, nil
}

func (d *Engine) fairLimits() tenantUsage { return tenantUsage{d.MaxSubjects, d.MaxHistory, d.MaxSeen} }

func fairMinimum(limit, tenants int) int {
	if limit < tenants {
		return 0
	}
	return max(1, limit/(2*tenants))
}

func (f *tenantFairness) admit(tenant string, delta, limits tenantUsage) bool {
	used := f.usage[tenant]
	for resource, limit := range limits {
		minimum := fairMinimum(limit, len(f.tenants))
		extra := max(0, used[resource]+delta[resource]-minimum) - max(0, used[resource]-minimum)
		if minimum == 0 || f.shared[resource]+extra > limit-minimum*len(f.tenants) {
			if f.rejected[resource] != ^uint64(0) {
				f.rejected[resource]++
			}
			return false
		}
	}
	return true
}

// Charge only admitted net growth, or the exact state removed by pruning.
func (f *tenantFairness) charge(tenant string, delta, limits tenantUsage) {
	used := f.usage[tenant]
	for resource, limit := range limits {
		minimum := fairMinimum(limit, len(f.tenants))
		before := used[resource]
		used[resource] += delta[resource]
		f.shared[resource] += max(0, used[resource]-minimum) - max(0, before-minimum)
	}
	f.usage[tenant] = used
}

func subjectTenant(key string) string { tenant, _, _ := strings.Cut(key, "\x00"); return tenant }

func (d *Engine) FairnessProfile() *TenantFairnessProfile {
	if d.fairness == nil {
		return nil
	}
	return &TenantFairnessProfile{Version: TenantFairnessVersion, Tenants: append([]string(nil), d.fairness.tenants...), Subjects: d.MaxSubjects, EventsPerSubject: d.MaxEvents, History: d.MaxHistory, Seen: d.MaxSeen}
}

func (d *Engine) TenantFairnessStats() map[string]any {
	d.mu.Lock()
	defer d.mu.Unlock()
	f := d.fairness
	if f == nil {
		return map[string]any{"enabled": false}
	}
	limits := d.fairLimits()
	minimum, sharedLimits := tenantUsage{}, tenantUsage{}
	for i, limit := range limits {
		minimum[i] = fairMinimum(limit, len(f.tenants))
		sharedLimits[i] = limit - minimum[i]*len(f.tenants)
	}
	perTenant := map[string]any{}
	for _, id := range f.tenants {
		u := f.usage[id]
		perTenant[id] = map[string]int{"subjects": u[fairSubjects], "history_events": u[fairHistory], "dedup_keys": u[fairSeen]}
	}
	return map[string]any{"enabled": true, "version": TenantFairnessVersion, "configured_tenants": append([]string(nil), f.tenants...),
		"minimum_subjects": minimum[fairSubjects], "minimum_history": minimum[fairHistory], "minimum_dedup": minimum[fairSeen],
		"shared_subjects": f.shared[fairSubjects], "shared_history": f.shared[fairHistory], "shared_dedup": f.shared[fairSeen],
		"shared_subject_limit": sharedLimits[fairSubjects], "shared_history_limit": sharedLimits[fairHistory], "shared_dedup_limit": sharedLimits[fairSeen],
		"tenant_usage": perTenant, "refused_subjects": f.rejected[fairSubjects], "refused_history": f.rejected[fairHistory], "refused_dedup": f.rejected[fairSeen], "refused_unknown_tenant": f.unknown}
}
