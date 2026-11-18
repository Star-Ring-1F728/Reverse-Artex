package control

import (
	"fmt"
	"reverse-artex/internal/detect"
	"reverse-artex/internal/policy"
	"testing"
	"time"
)

func TestPrincipalAlertDoesNotBroadenAutomaticPolicy(t *testing.T) {
	m := manager(t)
	now := time.Now().UTC()
	if _, err := m.SetAuto("enable-principal-test", true, now); err != nil {
		t.Fatal(err)
	}
	engine := detect.NewPrincipal()
	sawAlert := false
	// Same principal: each session has one WAF request and two object denials.
	// Account correlation qualifies RA-004; neither session qualifies M3 auto.
	for i := 0; i < 6; i++ {
		sensor := "lab-app"
		if i%3 == 0 {
			sensor = "lab-waf"
		}
		e := specimen(fmt.Sprint("split-", i), sensor, now)
		e.SessionHMAC = fmt.Sprint("session-", i/3)
		e.EventTime = now.Add(time.Duration(i-6) * time.Second)
		e.Status = 403
		if sensor == "lab-waf" {
			e.DetectorFamily, e.Authorization, e.Route = "waf-local-denial", "unknown", "/api/search"
		} else {
			e.Authorization, e.ResourceHMAC = "deny", fmt.Sprint("resource-", i)
		}
		alerts, status := engine.Process(e, now)
		if status != "accepted" {
			t.Fatal(status)
		}
		for _, a := range alerts {
			if a.RuleID == "RA-004" && a.CorrelationScope == "principal" {
				sawAlert = true
			}
		}
		receipt, err := m.Evidence(e, now)
		if err != nil || receipt != nil {
			t.Fatal("cross-session evidence created policy", receipt, err)
		}
	}
	if !sawAlert || len(m.active) != 0 {
		t.Fatal("expected account alert without session policy")
	}
	// Complete the predicate in session-0 only. Existing scope and TTL still apply.
	e := specimen("complete-session-0", "lab-waf", now)
	e.SessionHMAC, e.Status, e.Authorization, e.Route, e.DetectorFamily = "session-0", 403, "unknown", "/api/search", "waf-local-denial"
	receipt, err := m.Evidence(e, now)
	if err != nil || receipt == nil {
		t.Fatal("complete session predicate failed", receipt, err)
	}
	snapshot, err := m.Snapshot(now, []byte("01234567890123456789012345678901"))
	if err != nil || len(snapshot.Policies) != 1 {
		t.Fatal("unexpected policy snapshot", err)
	}
	p := snapshot.Policies[0]
	if p.Session != "session-0" || p.Principal != "alice" || p.Expires.Sub(p.Issued) != time.Minute || p.RuleVersion != "RA-M3-001-1.0" {
		t.Fatal("broadened policy", p)
	}
	cache := policy.New()
	if err := cache.Apply(p, now); err != nil {
		t.Fatal(err)
	}
	if !cache.Denied("alpha", "lab-api", "alice", "session-0", "/api/objects/{id}", now) {
		t.Fatal("expected scoped enforcement")
	}
	for _, scope := range [][5]string{
		{"alpha", "lab-api", "alice", "session-1", "/api/objects/{id}"},
		{"alpha", "lab-api", "carol", "session-0", "/api/objects/{id}"},
		{"beta", "lab-api", "alice", "session-0", "/api/objects/{id}"},
		{"alpha", "other-api", "alice", "session-0", "/api/objects/{id}"},
		{"alpha", "lab-api", "alice", "session-0", "/api/search"},
	} {
		if cache.Denied(scope[0], scope[1], scope[2], scope[3], scope[4], now) {
			t.Fatal("unrelated scope denied", scope)
		}
	}
	if cache.Denied("alpha", "lab-api", "alice", "session-0", "/api/objects/{id}", now.Add(time.Minute)) {
		t.Fatal("policy outlived TTL")
	}
}
