package detect

import (
	"fmt"
	"testing"
	"time"
)

func TestNormalTrafficCompactsWithoutLosingReplayProtection(t *testing.T) {
	d := New()
	for i := 0; i < 90000; i++ {
		e := detectEvent(fmt.Sprint("normal-", i), fmt.Sprint("request-", i), detectTestNow.Add(time.Duration(i)*10*time.Millisecond))
		e.PathHMAC = fmt.Sprint("path-", i%12)
		alerts, status := d.Process(e, e.EventTime)
		if status != "accepted" || len(alerts) != 0 {
			t.Fatalf("normal %d: %s alerts=%d", i, status, len(alerts))
		}
	}
	if s := d.Stats(); s["dedup_keys"] != 90000 || s["history_events"] != 8 {
		t.Fatalf("unbounded or lost state: %v", s)
	}
	e := detectEvent("normal-0", "request-0", detectTestNow)
	if _, status := d.Process(e, detectTestNow.Add(15*time.Minute)); status != "duplicate" {
		t.Fatal("compaction lost replay key")
	}
	// Event-time reordering must keep the latest eight distinct paths, not grow history.
	e.EventID = "late"
	e.RequestID = "late"
	e.PathHMAC = "new-old-path"
	if _, status := d.Process(e, detectTestNow.Add(15*time.Minute)); status != "accepted" {
		t.Fatal(status)
	}
	if d.Stats()["history_events"] != 8 {
		t.Fatal("late benign event grew history")
	}
	if _, status := d.Process(detectEvent("after-hour", "after-hour", detectTestNow.Add(2*time.Hour)), detectTestNow.Add(2*time.Hour)); status != "accepted" {
		t.Fatal(status)
	}
	if d.Stats()["dedup_keys"] != 1 {
		t.Fatal("expired replay keys retained")
	}
}

func TestCompactionPreservesPathThresholdInAllWindows(t *testing.T) {
	for _, age := range []time.Duration{time.Second, 2 * time.Minute, 20 * time.Minute} {
		d := New()
		var found bool
		for i := 0; i < 30; i++ {
			e := detectEvent(fmt.Sprint("path-", i), fmt.Sprint("p-", i), detectTestNow.Add(-age))
			e.PathHMAC = fmt.Sprint("path-", i)
			if _, s := d.Process(e, detectTestNow); s != "accepted" {
				t.Fatal(s)
			}
		}
		for i := 0; i < 6; i++ {
			e := detectEvent(fmt.Sprint("err-", i), fmt.Sprint("err-", i), detectTestNow.Add(-age))
			e.Status = 404
			e.KnownRoute = false
			e.PathHMAC = fmt.Sprint("path-", 29-i)
			alerts, s := d.Process(e, detectTestNow)
			if s != "accepted" {
				t.Fatal(s)
			}
			for _, a := range alerts {
				if a.RuleID == "RA-002" {
					found = true
				}
			}
		}
		if !found {
			t.Fatalf("RA-002 threshold lost at age %s", age)
		}
	}
}

func TestCompactBudgetsStillRejectExplicitly(t *testing.T) {
	d := New()
	d.MaxSeen = 1
	e := detectEvent("a", "a", detectTestNow)
	e.PathHMAC = "p"
	if _, s := d.Process(e, detectTestNow); s != "accepted" {
		t.Fatal(s)
	}
	e.EventID = "b"
	e.RequestID = "b"
	if _, s := d.Process(e, detectTestNow); s != "capacity_rejected" {
		t.Fatal("replay budget not enforced", s)
	}
	d = New()
	d.MaxHistory = 1
	e.Status = 403
	e.Authorization = "deny"
	if _, s := d.Process(e, detectTestNow); s != "accepted" {
		t.Fatal(s)
	}
	e.EventID = "c"
	e.RequestID = "c"
	e.SessionHMAC = "second-subject"
	if _, s := d.Process(e, detectTestNow); s != "capacity_rejected" {
		t.Fatal("global history budget not enforced", s)
	}
}
