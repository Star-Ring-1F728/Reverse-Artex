package control

import (
	"container/heap"
	"reverse-artex/internal/policy"
	"sort"
	"time"
)

type policyDeadline struct {
	id string
	at time.Time
}

// The manager mutex owns this indexed heap. Removal is immediate, so revoked,
// replaced and rolled-back policies leave no stale deadlines behind.
type policyDeadlines struct {
	entries   []policyDeadline
	positions map[string]int
}

func (q policyDeadlines) Len() int { return len(q.entries) }
func (q policyDeadlines) Less(i, j int) bool {
	if q.entries[i].at.Equal(q.entries[j].at) {
		return q.entries[i].id < q.entries[j].id
	}
	return q.entries[i].at.Before(q.entries[j].at)
}
func (q policyDeadlines) Swap(i, j int) {
	q.entries[i], q.entries[j] = q.entries[j], q.entries[i]
	q.positions[q.entries[i].id], q.positions[q.entries[j].id] = i, j
}
func (q *policyDeadlines) Push(value any) {
	entry := value.(policyDeadline)
	if q.positions == nil {
		q.positions = make(map[string]int)
	}
	q.positions[entry.id] = len(q.entries)
	q.entries = append(q.entries, entry)
}
func (q *policyDeadlines) Pop() any {
	n := len(q.entries) - 1
	entry := q.entries[n]
	delete(q.positions, entry.id)
	q.entries[n] = policyDeadline{}
	q.entries = q.entries[:n]
	return entry
}
func (q *policyDeadlines) retain(p policy.Policy) {
	if index, ok := q.positions[p.ID]; ok {
		q.entries[index].at = p.Expires
		heap.Fix(q, index)
		return
	}
	heap.Push(q, policyDeadline{p.ID, p.Expires})
}
func (q *policyDeadlines) remove(id string) {
	if index, ok := q.positions[id]; ok {
		heap.Remove(q, index)
	}
}

// Read-only selection: a failed write/Sync must leave every deadline available
// for the existing retry/fail-closed path. Heap order lets us skip entire future
// subtrees; equal deadlines are due, matching !Expires.After(now).
func (q *policyDeadlines) expiredIDs(now time.Time) []string {
	var ids []string
	var visit func(int)
	visit = func(index int) {
		if index >= len(q.entries) || q.entries[index].at.After(now) {
			return
		}
		ids = append(ids, q.entries[index].id)
		visit(index*2 + 1)
		visit(index*2 + 2)
	}
	visit(0)
	sort.Strings(ids)
	return ids
}
