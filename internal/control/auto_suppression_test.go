package control

import (
	"fmt"
	"testing"
	"time"
)

func qualifyingBatch(t *testing.T, m *Manager, prefix string, at time.Time) *Receipt {
	t.Helper()
	var last *Receipt
	for i := 0; i < 4; i++ {
		sensor := "lab-app"
		if i < 2 {
			sensor = "lab-waf"
		}
		e := specimen(fmt.Sprintf("%s-%d", prefix, i), sensor, at)
		e.Status = 403
		if i < 2 {
			e.Authorization = "unknown"
			e.DetectorFamily = "waf-local-denial"
		} else {
			e.Authorization = "deny"
			e.ResourceHMAC = e.EventID
		}
		r, err := m.Evidence(e, at)
		if err != nil {
			t.Fatal(err)
		}
		if r != nil {
			last = r
		}
	}
	return last
}

func TestAutoChangedRefsCannotMultiplyOrExtendLeaseAcrossRestart(t *testing.T) {
	now := time.Now().UTC()
	m := manager(t)
	if _, err := m.SetAuto("on", true, now); err != nil {
		t.Fatal(err)
	}
	first := qualifyingBatch(t, m, "first", now)
	if first == nil {
		t.Fatal("no first policy")
	}
	original := m.active[first.PolicyID]
	if r := qualifyingBatch(t, m, "changed", now.Add(10*time.Second)); r != nil {
		t.Fatal("refs change minted a new policy", r)
	}
	if len(m.active) != 1 || m.active[first.PolicyID] != original {
		t.Fatal("lease changed")
	}
	restored, err := Open(m.dir)
	if err != nil {
		t.Fatal(err)
	}
	if r := qualifyingBatch(t, restored, "restart", now.Add(20*time.Second)); r != nil {
		t.Fatal("restart reset suppression")
	}
	if len(restored.active) != 1 || restored.active[first.PolicyID] != original {
		t.Fatal("restart changed lease")
	}
	if _, err = restored.Revoke(Revoke{"release", first.PolicyID, "false_positive"}, now.Add(25*time.Second)); err != nil {
		t.Fatal(err)
	}
	if r := qualifyingBatch(t, restored, "revoked", now.Add(26*time.Second)); r != nil {
		t.Fatal("revoke immediately reissued auto policy")
	}
	// Original 60s expiry followed by 60s cooldown; new independent requests
	// may qualify only after that interval.
	if r := qualifyingBatch(t, restored, "cooldown", now.Add(80*time.Second)); r != nil {
		t.Fatal("cooldown ignored")
	}
	if r := qualifyingBatch(t, restored, "next", now.Add(121*time.Second)); r == nil {
		t.Fatal("new episode never recovered")
	}
}

func TestAutoNormalTrafficCannotRenewAndFutureEvidenceCannotQualify(t *testing.T) {
	now := time.Now().UTC()
	m := manager(t)
	m.SetAuto("on", true, now)
	first := qualifyingBatch(t, m, "first", now)
	original := m.active[first.PolicyID]
	e := specimen("legitimate", "lab-app", now.Add(10*time.Second))
	if r, err := m.Evidence(e, e.EventTime); err != nil || r != nil {
		t.Fatal("normal traffic renewed", r, err)
	}
	if m.active[first.PolicyID] != original {
		t.Fatal("normal traffic changed expiry")
	}
	// Event.Validate allows bounded clock skew; action selection must still
	// exclude future evidence even while preserving it as telemetry.
	x := manager(t)
	x.SetAuto("on", true, now)
	for i := 0; i < 4; i++ {
		sensor := "lab-app"
		if i < 2 {
			sensor = "lab-waf"
		}
		f := specimen(fmt.Sprintf("future-%d", i), sensor, now.Add(time.Second))
		f.IngestTime = now
		f.Status = 403
		if i < 2 {
			f.Authorization = "unknown"
			f.DetectorFamily = "waf-local-denial"
		} else {
			f.Authorization = "deny"
			f.ResourceHMAC = f.EventID
		}
		if r, err := x.Evidence(f, now); err == nil && r != nil {
			t.Fatal("future evidence authorized policy")
		}
	}
	if len(x.active) != 0 {
		t.Fatal("future policy active")
	}
	// High-water mark reconstructed from the WAL prevents a clock rollback.
	restored, err := Open(m.dir)
	if err != nil {
		t.Fatal(err)
	}
	if r := qualifyingBatch(t, restored, "clock-back", now.Add(-time.Second)); r != nil {
		t.Fatal("clock rollback authorized new policy")
	}
}
