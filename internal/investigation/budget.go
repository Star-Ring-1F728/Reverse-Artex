package investigation

import (
	"errors"
	"sync"
)

const MaxStepBytes = MaxView + 8192 // Tool view + bound scope + provider output.

// Budget is shared across cases, retries and revisions for this process lifetime.
// Counters are reservations, not measured model tokens or currency. No refunds.
type Usage struct {
	Calls  int `json:"calls"`
	Tools  int `json:"tools"`
	Tokens int `json:"reserved_tokens"`
	Cost   int `json:"reserved_cost_units"`
	Bytes  int `json:"reserved_bytes"`
}
type Budget struct {
	mu      sync.Mutex
	total   Usage
	tenants map[string]Usage
	parents map[string]Usage
	active  map[string]bool
	running int
}

func NewBudget() *Budget {
	return &Budget{tenants: map[string]Usage{}, parents: map[string]Usage{}, active: map[string]bool{}}
}
func plus(a, b Usage) Usage {
	return Usage{a.Calls + b.Calls, a.Tools + b.Tools, a.Tokens + b.Tokens, a.Cost + b.Cost, a.Bytes + b.Bytes}
}
func allows(u Usage, calls, tools int) bool {
	return u.Calls <= calls && u.Tools <= tools && u.Tokens <= calls*512 && u.Cost <= calls*100 && u.Bytes <= calls*MaxStepBytes+tools*MaxView
}
func (b *Budget) enter(s Scope) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.running >= 2 || b.active[s.Tenant] {
		return false
	}
	b.active[s.Tenant] = true
	b.running++
	return true
}
func (b *Budget) leave(s Scope) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.active, s.Tenant)
	b.running--
}
func (b *Budget) reserve(s Scope, tool bool) error {
	return b.reserveUsage(s, tool, false)
}
func (b *Budget) reserveAgent(s Scope, tool bool) error { return b.reserveUsage(s, tool, true) }
func (b *Budget) reserveUsage(s Scope, tool, hosted bool) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	key := hash([]string{s.Tenant, s.Case}) // Never revision, commit or retry ID.
	u := Usage{Calls: 1, Tokens: 512, Cost: 100, Bytes: MaxStepBytes}
	if hosted {
		u = Usage{Calls: 1, Bytes: MaxAgentPacket}
	}
	if tool {
		u = Usage{Tools: 1, Bytes: MaxView}
	}
	p, t, g := plus(b.parents[key], u), plus(b.tenants[s.Tenant], u), plus(b.total, u)
	if (b.parents[key] == (Usage{}) && len(b.parents) >= 128) || !allows(p, 4, 8) || !allows(t, 60, 120) || !allows(g, 120, 240) {
		return errors.New("shared budget exhausted")
	}
	b.parents[key], b.tenants[s.Tenant], b.total = p, t, g
	return nil
}
func (b *Budget) Usage() Usage { b.mu.Lock(); defer b.mu.Unlock(); return b.total }
