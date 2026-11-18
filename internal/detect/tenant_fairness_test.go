package detect

import (
	"fmt"
	"reflect"
	"reverse-artex/internal/event"
	"testing"
	"time"
)

func TestTenantFloodLeavesConfiguredTenantSubjectShare(t *testing.T) {
	d, err := NewWithTenantFairness(false, false, []string{"alpha", "beta"})
	if err != nil {
		t.Fatal(err)
	}
	d.MaxSubjects, d.MaxHistory, d.MaxSeen = 8, 64, 64
	for i := 0; i < 6; i++ {
		e := detectEvent(fmt.Sprint("alpha-", i), fmt.Sprint("alpha-", i), detectTestNow)
		e.TenantID, e.SessionHMAC = "alpha", fmt.Sprint("session-", i)
		if _, result := d.Process(e, detectTestNow); result != "accepted" {
			t.Fatal(result)
		}
	}
	e := detectEvent("alpha-overflow", "alpha-overflow", detectTestNow)
	e.TenantID, e.SessionHMAC = "alpha", "session-overflow"
	if _, result := d.Process(e, detectTestNow); result != "capacity_rejected" {
		t.Fatalf("noisy tenant consumed protected subject share: %s", result)
	}
	for i := 0; i < 2; i++ {
		e := detectEvent(fmt.Sprint("beta-", i), fmt.Sprint("beta-", i), detectTestNow)
		e.TenantID, e.SessionHMAC = "beta", fmt.Sprint("session-", i)
		if _, result := d.Process(e, detectTestNow); result != "accepted" {
			t.Fatal("configured tenant lost guaranteed subject share", result)
		}
	}
}

func fairnessEngine(t *testing.T, critical bool) *Engine {
	t.Helper()
	d, err := NewWithTenantFairness(false, critical, []string{"alpha", "beta"})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func tenantEvent(id, tenant string, at time.Time) event.Event {
	e := detectEvent(id, id, at)
	e.TenantID, e.IngestTime, e.PathHMAC = tenant, at, "known-path"
	return e
}

func assertTenantAccounting(t *testing.T, d *Engine) {
	t.Helper()
	want := map[string]tenantUsage{}
	for _, tenant := range d.fairness.tenants {
		want[tenant] = tenantUsage{}
	}
	for key, es := range d.subjects {
		tenant := subjectTenant(key)
		u := want[tenant]
		u[fairSubjects]++
		u[fairHistory] += len(es)
		want[tenant] = u
	}
	if len(d.expiry) != len(d.fairness.expiryTenants) {
		t.Fatal("owner/expiry queue lengths diverged")
	}
	for _, tenant := range d.fairness.expiryTenants[d.expiryHead:] {
		u := want[tenant]
		u[fairSeen]++
		want[tenant] = u
	}
	if !reflect.DeepEqual(want, d.fairness.usage) {
		t.Fatal("tenant accounting differs from retained state", want, d.fairness.usage)
	}
	shared := tenantUsage{}
	for _, u := range want {
		for r, limit := range d.fairLimits() {
			shared[r] += max(0, u[r]-fairMinimum(limit, len(want)))
		}
	}
	if shared != d.fairness.shared {
		t.Fatal("shared accounting differs", shared, d.fairness.shared)
	}
	seen := 0
	for _, u := range want {
		seen += u[fairSeen]
	}
	if seen != len(d.seenCompact) {
		t.Fatal("tenant replay accounting differs from global state")
	}
}

func TestTenantHistoryAndReplaySharesAreIndependent(t *testing.T) {
	for _, resource := range []int{fairHistory, fairSeen} {
		t.Run(fmt.Sprint(resource), func(t *testing.T) {
			d := fairnessEngine(t, false)
			d.MaxSubjects, d.MaxHistory, d.MaxSeen = 64, 64, 64
			if resource == fairHistory {
				d.MaxHistory = 8
			} else {
				d.MaxSeen = 8
			}
			for i := 0; i < 6; i++ {
				e := tenantEvent(fmt.Sprint("alpha-", i), "alpha", detectTestNow)
				if resource == fairHistory {
					e.Status = 403
					e.Authorization = "deny"
				}
				if _, s := d.Process(e, detectTestNow); s != "accepted" {
					t.Fatal(s)
				}
			}
			before := d.fairness.usage["alpha"]
			e := tenantEvent("alpha-overflow", "alpha", detectTestNow)
			if resource == fairHistory {
				e.Status = 403
				e.Authorization = "deny"
			}
			if _, s := d.Process(e, detectTestNow); s != "capacity_rejected" {
				t.Fatal("tenant exhausted protected capacity", s)
			}
			if d.fairness.usage["alpha"] != before || d.fairness.rejected[resource] != 1 {
				t.Fatal("quota rejection consumed state")
			}
			e.EventID, e.RequestID = "alpha-0", "alpha-0"
			if _, s := d.Process(e, detectTestNow); s != "duplicate" {
				t.Fatal("quota-full replay was not duplicate", s)
			}
			for i := 0; i < 2; i++ {
				e := tenantEvent(fmt.Sprint("beta-", i), "beta", detectTestNow)
				if resource == fairHistory {
					e.Status = 403
					e.Authorization = "deny"
				}
				if _, s := d.Process(e, detectTestNow); s != "accepted" {
					t.Fatal("configured minimum lost", s)
				}
			}
			assertTenantAccounting(t, d)
		})
	}
}

func TestTenantCompactionChargesNetHistoryGrowth(t *testing.T) {
	d := fairnessEngine(t, false)
	d.MaxSubjects, d.MaxHistory, d.MaxSeen = 8, 8, 64
	for i := 0; i < 5; i++ {
		e := tenantEvent(fmt.Sprint("deny-", i), "alpha", detectTestNow)
		e.Status, e.Authorization = 403, "deny"
		d.Process(e, detectTestNow)
	}
	e := tenantEvent("benign", "alpha", detectTestNow)
	if _, s := d.Process(e, detectTestNow); s != "accepted" {
		t.Fatal(s)
	}
	e.EventID, e.RequestID = "replace", "replace"
	if _, s := d.Process(e, detectTestNow); s != "accepted" {
		t.Fatal("replacement charged new history", s)
	}
	e.EventID, e.RequestID, e.PathHMAC = "new-path", "new-path", "different-path"
	if _, s := d.Process(e, detectTestNow); s != "capacity_rejected" {
		t.Fatal("new history bypassed tenant quota", s)
	}
	if d.fairness.usage["alpha"][fairHistory] != 6 {
		t.Fatal("history replacement lost exact count")
	}
	assertTenantAccounting(t, d)
}

func TestTenantPerSubjectPruningAndHourReclamation(t *testing.T) {
	d := fairnessEngine(t, false)
	d.MaxSubjects, d.MaxHistory, d.MaxSeen = 8, 8, 64
	e := tenantEvent("almost-expired", "alpha", detectTestNow)
	e.EventTime = detectTestNow.Add(-time.Hour + time.Millisecond)
	if _, s := d.Process(e, detectTestNow); s != "accepted" {
		t.Fatal(s)
	}
	// Less than a second has passed, so only the current-subject prune runs.
	at := detectTestNow.Add(2 * time.Millisecond)
	e = tenantEvent("replacement", "alpha", at)
	if _, s := d.Process(e, at); s != "accepted" {
		t.Fatal(s)
	}
	if d.fairness.usage["alpha"] != (tenantUsage{1, 1, 2}) {
		t.Fatal("current-subject prune did not reclaim quota", d.fairness.usage)
	}
	assertTenantAccounting(t, d)
	at = detectTestNow.Add(time.Hour + time.Second)
	e = tenantEvent("after-hour", "beta", at)
	if _, s := d.Process(e, at); s != "accepted" {
		t.Fatal(s)
	}
	if d.fairness.usage["alpha"] != (tenantUsage{}) {
		t.Fatal("expired tenant retained quota")
	}
	assertTenantAccounting(t, d)
}

func TestTenantReplayOwnerQueueCompactsWithExpiry(t *testing.T) {
	d := fairnessEngine(t, false)
	for i := 0; i < 5000; i++ {
		tenant := []string{"alpha", "beta"}[i%2]
		e := tenantEvent(fmt.Sprint(i), tenant, detectTestNow)
		if _, s := d.Process(e, detectTestNow); s != "accepted" {
			t.Fatal(s)
		}
	}
	at := detectTestNow.Add(time.Hour + time.Nanosecond)
	e := tenantEvent("fresh", "beta", at)
	if _, s := d.Process(e, at); s != "accepted" {
		t.Fatal(s)
	}
	if d.expiryHead != 0 || len(d.fairness.expiryTenants) != 1 {
		t.Fatal("owner queue compaction failed")
	}
	assertTenantAccounting(t, d)
}

func TestTenantConfigurationAndUnknownTenantAreBounded(t *testing.T) {
	for _, ids := range [][]string{nil, {""}, {"bad tenant"}, {"bad\x00tenant"}, make([]string, 65)} {
		if len(ids) == 65 {
			for i := range ids {
				ids[i] = fmt.Sprint("tenant-", i)
			}
		}
		if _, err := NewWithTenantFairness(false, false, ids); err == nil {
			t.Fatal("invalid tenant registry accepted")
		}
	}
	ids := []string{"beta", "alpha", "alpha"}
	d, err := NewWithTenantFairness(false, true, ids)
	if err != nil {
		t.Fatal(err)
	}
	ids[0] = "mutated"
	p := d.FairnessProfile()
	if !reflect.DeepEqual(p.Tenants, []string{"alpha", "beta"}) {
		t.Fatal("profile is not a canonical private copy")
	}
	p.Tenants[0] = "mutated"
	if d.FairnessProfile().Tenants[0] != "alpha" {
		t.Fatal("profile getter exposed mutable registry")
	}
	e := criticalEvent("unknown", "RA-007")
	e.TenantID = "unregistered"
	if a, s := d.Process(e, detectTestNow); s != "capacity_rejected" || len(a) != 0 || len(d.critical.seen) != 0 {
		t.Fatal("unknown tenant bypassed registry via reserve", s, a)
	}
}

func TestTenantFairnessCanUseCriticalReserveWithoutCorrelationAdmission(t *testing.T) {
	d := fairnessEngine(t, true)
	d.MaxSubjects, d.MaxHistory, d.MaxSeen = 8, 64, 64
	for i := 0; i < 6; i++ {
		e := tenantEvent(fmt.Sprint("alpha-", i), "alpha", detectTestNow)
		e.SessionHMAC = fmt.Sprint(i)
		d.Process(e, detectTestNow)
	}
	before := d.fairness.usage["alpha"]
	e := criticalEvent("critical", "RA-007")
	e.TenantID, e.SessionHMAC = "alpha", "new-session"
	if a, s := d.Process(e, detectTestNow); s != "signal_only" || len(a) != 1 {
		t.Fatal("fairness rejection lost independent reserve", s, a)
	}
	if d.fairness.usage["alpha"] != before {
		t.Fatal("reserved signal consumed normal tenant quota")
	}
	assertTenantAccounting(t, d)
}

func TestTenantFairnessPreservesUnsaturatedFixedInputs(t *testing.T) {
	for _, principal := range []bool{false, true} {
		for _, profile := range []string{"normal", "recon", "validation", "mixed"} {
			t.Run(fmt.Sprintf("principal=%t/%s", principal, profile), func(t *testing.T) {
				legacy := New()
				if principal {
					legacy = NewPrincipal()
				}
				candidate, err := NewWithTenantFairness(principal, false, []string{"tenant-a", "tenant-0", "tenant-1"})
				if err != nil {
					t.Fatal(err)
				}
				legacy.Canaries, candidate.Canaries = map[string]bool{"fixture-canary": true}, map[string]bool{"fixture-canary": true}
				for _, e := range windowFixtureEvents(profile) {
					want, ws := legacy.Process(e, e.IngestTime)
					got, gs := candidate.Process(e, e.IngestTime)
					if ws != gs || !reflect.DeepEqual(want, got) {
						t.Fatal("unsaturated output changed", e.EventID, ws, gs)
					}
				}
				if !reflect.DeepEqual(candidate.Stats(), legacy.Stats()) {
					t.Fatal("normal state budgets changed")
				}
				assertTenantAccounting(t, candidate)
			})
		}
	}
}
