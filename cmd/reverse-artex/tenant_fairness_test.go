package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reverse-artex/internal/detect"
	"reverse-artex/internal/event"
	"reverse-artex/internal/hostguard"
	"strings"
	"testing"
	"time"
)

func tenantRecoveryEngine(t *testing.T, principal, critical bool, tenants []string) *detect.Engine {
	t.Helper()
	d, err := detect.NewWithTenantFairness(principal, critical, tenants)
	if err != nil {
		t.Fatal(err)
	}
	d.MaxSubjects, d.MaxHistory, d.MaxSeen = 8, 64, 64
	return d
}

func tenantRecoveryEvent(id, tenant string, at time.Time) event.Event {
	e := recoveryHTTP(id, "session-"+id, "resource-"+id, at)
	e.TenantID, e.Principal = tenant, "user-"+id
	return e
}

func TestTenantFairnessRecoveryPreservesSharesAndConfiguration(t *testing.T) {
	for _, scope := range []string{"session", "principal"} {
		t.Run(scope, func(t *testing.T) {
			dir, at := t.TempDir(), time.Now().UTC()
			s := recoveryStore(t, dir)
			defer s.Close()
			d := tenantRecoveryEngine(t, scope == "principal", false, []string{"alpha", "beta"})
			if err := restoreState(s, dir, scope, nil, d, hostguard.New(nil)); err != nil {
				t.Fatal(err)
			}
			i := &ingester{store: s, engine: d, clock: func() time.Time { return at }}
			for n := 0; n < 6; n++ {
				if result, err := i.process(tenantRecoveryEvent(fmt.Sprint("alpha-", n), "alpha", at)); result != "accepted" || err != nil {
					t.Fatal(result, err)
				}
			}
			if result, err := i.process(tenantRecoveryEvent("overflow", "alpha", at)); result != "capacity_rejected" || err != nil {
				t.Fatal(result, err)
			}
			d = tenantRecoveryEngine(t, scope == "principal", false, []string{"beta", "alpha", "alpha"})
			if err := restoreState(s, dir, scope, nil, d, hostguard.New(nil)); err != nil {
				t.Fatal("canonical registry replay failed", err)
			}
			i.engine = d
			if result, err := i.process(tenantRecoveryEvent("alpha-0", "alpha", at)); result != "duplicate" || err != nil {
				t.Fatal("replay quota was reset", result, err)
			}
			for n := 0; n < 2; n++ {
				if result, err := i.process(tenantRecoveryEvent(fmt.Sprint("beta-", n), "beta", at)); result != "accepted" || err != nil {
					t.Fatal("reserved share lost on replay", result, err)
				}
			}
			for _, wrong := range []string{"off", "tenants", "limits"} {
				candidate := tenantRecoveryEngine(t, scope == "principal", false, []string{"alpha", "beta"})
				switch wrong {
				case "off":
					candidate = recoveryEngine(scope)
				case "tenants":
					candidate = tenantRecoveryEngine(t, scope == "principal", false, []string{"alpha", "gamma"})
				case "limits":
					candidate.MaxSubjects++
				}
				if err := restoreState(s, dir, scope, nil, candidate, hostguard.New(nil)); err == nil {
					t.Fatal("changed fairness configuration accepted", wrong)
				}
			}
		})
	}
}

func TestTenantFairnessCannotUpgradeExistingEvidenceProfile(t *testing.T) {
	dir := t.TempDir()
	s := recoveryStore(t, dir)
	defer s.Close()
	if err := restoreState(s, dir, "session", nil, detect.New(), hostguard.New(nil)); err != nil {
		t.Fatal(err)
	}
	if err := restoreState(s, dir, "session", nil, tenantRecoveryEngine(t, false, false, []string{"alpha", "beta"}), hostguard.New(nil)); err == nil {
		t.Fatal("existing evidence silently upgraded")
	}
}

func TestTenantFairnessEvidenceFailureCannotContinueAdmission(t *testing.T) {
	s := &recordingStore{fail: "evaluations"}
	d := tenantRecoveryEngine(t, false, false, []string{"alpha", "beta"})
	i := &ingester{store: s, engine: d}
	e := tenantRecoveryEvent("uncertain", "alpha", time.Now().UTC())
	if _, err := i.process(e); err == nil || !i.degraded() {
		t.Fatal("uncertain evidence accepted")
	}
	before, _ := json.Marshal(d.TenantFairnessStats())
	if _, err := i.process(e); err == nil {
		t.Fatal("ingestion continued without recovery")
	}
	after, _ := json.Marshal(d.TenantFairnessStats())
	if string(before) != string(after) {
		t.Fatal("degraded retry consumed more quota")
	}
}

func TestTenantFairnessMetadataCannotCreateOversizedRecoveryFile(t *testing.T) {
	dir := t.TempDir()
	s := recoveryStore(t, dir)
	defer s.Close()
	ids := make([]string, 64)
	for n := range ids {
		ids[n] = fmt.Sprintf("%02d-", n) + strings.Repeat("t", 120)
	}
	d := tenantRecoveryEngine(t, false, false, ids)
	if err := restoreState(s, dir, "session", nil, d, hostguard.New(nil)); err == nil {
		t.Fatal("oversized metadata accepted")
	}
	if _, err := os.Stat(filepath.Join(dir, "recovery.meta.json")); !os.IsNotExist(err) {
		t.Fatal("unreadable metadata was written", err)
	}
}
