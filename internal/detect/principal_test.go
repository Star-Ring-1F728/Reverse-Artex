package detect

import (
	"fmt"
	"reverse-artex/internal/event"
	"testing"
	"time"
)

func rotatingDenials() []event.Event {
	var es []event.Event
	for i := 0; i < 4; i++ {
		e := detectEvent(fmt.Sprint("rotating-", i), fmt.Sprint("request-", i), detectTestNow.Add(time.Duration(i-4)*time.Second))
		e.Authorization, e.Status = "deny", 403
		e.ResourceHMAC = fmt.Sprint("resource-", i%3)
		e.SessionHMAC = fmt.Sprint("session-", i)
		e.SrcIP = "192.0.2.1"
		es = append(es, e)
	}
	return es
}

func TestPrincipalCorrelationKeepsEvidenceAndSessionMode(t *testing.T) {
	es := rotatingDenials()
	es[1].DataQuality = "partial"
	es[0], es[3] = es[3], es[0] // arrival order does not establish event order
	if alerts := processAccepted(t, New(), es); len(alerts) != 0 {
		t.Fatal("legacy session scope changed", alerts)
	}
	d := NewPrincipal()
	a := requireOnlyAlert(t, processAccepted(t, d, es), "RA-004", "medium")
	if a.CorrelationScope != "principal" || a.Subject != "user-a" || a.Principal != "user-a" || a.SessionHMAC != "" || a.Version != "1.2" || a.DataQuality != "partial" {
		t.Fatal("ambiguous scope or concealed evidence quality", a)
	}
	if len(a.Evidence) != 4 {
		t.Fatal("missing threshold proof", a)
	}
	for _, e := range es {
		if alerts, status := d.Process(e, detectTestNow); status != "duplicate" || len(alerts) != 0 {
			t.Fatal("replayed evidence scored again", status, alerts)
		}
	}
}

func TestPrincipalScopeSeparatesNATUsersTenantsAssetsAndAnonymous(t *testing.T) {
	for _, field := range []string{"principal", "tenant", "asset", "anonymous"} {
		t.Run(field, func(t *testing.T) {
			es := rotatingDenials()
			for i := range es {
				switch field {
				case "principal":
					es[i].Principal = fmt.Sprint("user-", i%2)
				case "tenant":
					es[i].TenantID = fmt.Sprint("tenant-", i%2)
				case "asset":
					es[i].AssetID = fmt.Sprint("asset-", i%2)
				case "anonymous":
					es[i].Identity, es[i].Principal, es[i].SessionHMAC = "anonymous", "", ""
				}
			}
			for _, a := range processAccepted(t, NewPrincipal(), es) {
				if a.RuleID == "RA-004" {
					t.Fatal("unverified or unrelated identities merged", a)
				}
			}
		})
	}
}

func TestPrincipalBudgetCoversSessionChurnAndReclaimsAfterHour(t *testing.T) {
	d := NewPrincipal()
	d.MaxEvents, d.MaxHistory, d.MaxSubjects = 3, 3, 1
	es := rotatingDenials()
	processAccepted(t, d, es[:3])
	if _, s := d.Process(es[3], detectTestNow); s != "capacity_rejected" {
		t.Fatal("rotation bypassed account budget", s)
	}
	// Rejected events are not marked seen: legitimate retries can succeed after expiry.
	later := detectTestNow.Add(2 * time.Hour)
	es[3].EventTime, es[3].IngestTime = later, later
	if _, s := d.Process(es[3], later); s != "accepted" {
		t.Fatal("capacity could not recover", s)
	}
	if stats := d.Stats(); stats["history_events"] != 1 || stats["subjects"] != 1 || stats["dedup_keys"] != 1 {
		t.Fatal("expired state leaked", stats)
	}
}

func TestPrincipalCompactionRemainsBoundedAcrossNormalSessions(t *testing.T) {
	d := NewPrincipal()
	for i := 0; i < 2000; i++ {
		e := detectEvent(fmt.Sprint(i), fmt.Sprint(i), detectTestNow)
		e.SessionHMAC, e.PathHMAC = fmt.Sprint("session-", i), fmt.Sprint("path-", i%12)
		if a, s := d.Process(e, detectTestNow); s != "accepted" || len(a) != 0 {
			t.Fatal("normal session rotation", s, a)
		}
	}
	if stats := d.Stats(); stats["history_events"] != 8 || stats["subjects"] != 1 || stats["dedup_keys"] != 2000 {
		t.Fatal("unbounded principal state", stats)
	}
}

func TestSubjectTupleCannotAliasAtColonBoundary(t *testing.T) {
	// Both pairs render as a:b:c, but are distinct authenticated identities.
	es := rotatingDenials()
	for i := range es {
		es[i].Principal, es[i].SessionHMAC = "a:b", "c"
		if i%2 == 1 {
			es[i].Principal, es[i].SessionHMAC = "a", "b:c"
		}
	}
	for _, d := range []*Engine{New(), NewPrincipal()} {
		for _, a := range processAccepted(t, d, es) {
			if a.RuleID == "RA-004" {
				t.Fatal("colon collision merged users", a)
			}
		}
	}
}

func TestPrincipalAndAnonymousSubjectNamesCannotAlias(t *testing.T) {
	es := rotatingDenials()
	for i := range es {
		es[i].Principal = "anonymous-asset"
		if i%2 == 1 {
			es[i].Identity, es[i].Principal, es[i].SessionHMAC = "anonymous", "", ""
		}
	}
	for _, a := range processAccepted(t, NewPrincipal(), es) {
		if a.RuleID == "RA-004" {
			t.Fatal("anonymous evidence joined authenticated principal", a)
		}
	}
}
