package control

import (
	"reverse-artex/internal/policy"
	"sort"
	"time"
)

// Immutable, published only by replay after a successful audit Sync. Expired
// policies use Snapshot's original locked expiry/tombstone path.
type committedPolicyView struct {
	epoch    string
	version  uint64
	policies []policy.Policy
	expires  time.Time
}

func (m *Manager) publishPolicyView(changed bool) {
	old := m.view.Load()
	view := &committedPolicyView{epoch: m.epoch, version: m.version}
	if old != nil && !changed {
		view.policies, view.expires = old.policies, old.expires
	} else {
		view.policies = []policy.Policy{}
		for _, p := range m.active {
			view.policies = append(view.policies, p)
			if view.expires.IsZero() || p.Expires.Before(view.expires) {
				view.expires = p.Expires
			}
		}
		sort.Slice(view.policies, func(i, j int) bool { return view.policies[i].ID < view.policies[j].ID })
	}
	m.view.Store(view)
}

type ioDuration struct {
	Calls   uint64    `json:"calls"`
	TotalMS float64   `json:"total_ms"`
	MaxMS   float64   `json:"max_ms"`
	Slow    uint64    `json:"over_250ms"`
	Buckets [9]uint64 `json:"buckets_le_1_5_20_100_500_1000_5000_60000_inf_ms"`
}

func (m *Manager) recordIO(phase string, started time.Time) {
	duration := float64(time.Since(started)) / float64(time.Millisecond)
	m.ioMu.Lock()
	defer m.ioMu.Unlock()
	if m.ioTiming == nil {
		m.ioTiming = map[string]ioDuration{}
	}
	v := m.ioTiming[phase]
	v.Calls++
	v.TotalMS += duration
	v.MaxMS = max(v.MaxMS, duration)
	index := 8
	for j, limit := range [...]float64{1, 5, 20, 100, 500, 1000, 5000, 60000} {
		if duration <= limit {
			index = j
			break
		}
	}
	v.Buckets[index]++
	if duration >= 250 {
		v.Slow++
	}
	m.ioTiming[phase] = v
}

// IOStats never waits on the audit writer's main mutex.
func (m *Manager) IOStats() map[string]ioDuration {
	m.ioMu.Lock()
	defer m.ioMu.Unlock()
	out := make(map[string]ioDuration, len(m.ioTiming))
	for k, v := range m.ioTiming {
		out[k] = v
	}
	return out
}
