package control

import (
	"container/heap"
	"reverse-artex/internal/event"
	"time"
)

// The manager mutex owns both indexes and events. Each retained event has one
// scope entry and one heap entry; expiration leaves no stale queue nodes.
type evidenceScope struct {
	tenant, asset, principal, session string
}

func scopeOf(e event.Event) evidenceScope {
	return evidenceScope{e.TenantID, e.AssetID, e.Principal, e.SessionHMAC}
}

type evidenceDeadline struct {
	id string
	at time.Time
}

type evidenceDeadlines []evidenceDeadline

func (q evidenceDeadlines) Len() int { return len(q) }
func (q evidenceDeadlines) Less(i, j int) bool {
	if q[i].at.Equal(q[j].at) {
		return q[i].id < q[j].id
	}
	return q[i].at.Before(q[j].at)
}
func (q evidenceDeadlines) Swap(i, j int) { q[i], q[j] = q[j], q[i] }
func (q *evidenceDeadlines) Push(x any)   { *q = append(*q, x.(evidenceDeadline)) }
func (q *evidenceDeadlines) Pop() any {
	old := *q
	n := len(old) - 1
	x := old[n]
	old[n] = evidenceDeadline{}
	*q = old[:n]
	return x
}

// Called only by replay, after a successful Sync or while reading validated
// audit records. Duplicate/conflicting IDs have already been checked.
func (m *Manager) retainEvidence(e event.Event) {
	if m.evidenceScopes == nil {
		m.evidenceScopes = make(map[evidenceScope]map[string]struct{})
	}
	key := scopeOf(e)
	ids := m.evidenceScopes[key]
	if ids == nil {
		ids = make(map[string]struct{})
		m.evidenceScopes[key] = ids
	}
	m.events[e.EventID] = e
	ids[e.EventID] = struct{}{}
	heap.Push(&m.evidenceExpiry, evidenceDeadline{e.EventID, e.EventTime})
}

func (m *Manager) pruneEvidence(now time.Time) {
	cutoff := now.Add(-time.Minute)
	// The inclusive one-minute boundary and physical deletion on clock advance
	// match the old full scan. A clock rollback does not resurrect removed IDs.
	for len(m.evidenceExpiry) > 0 && m.evidenceExpiry[0].at.Before(cutoff) {
		entry := heap.Pop(&m.evidenceExpiry).(evidenceDeadline)
		e := m.events[entry.id]
		key := scopeOf(e)
		delete(m.events, entry.id)
		delete(m.evidenceScopes[key], entry.id)
		if len(m.evidenceScopes[key]) == 0 {
			delete(m.evidenceScopes, key)
		}
	}
}
