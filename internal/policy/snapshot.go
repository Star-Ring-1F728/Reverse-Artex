package policy

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"sort"
	"sync"
	"time"
)

type Snapshot struct {
	Epoch     string    `json:"epoch"`
	Version   uint64    `json:"version"`
	Generated time.Time `json:"generated_at"`
	Policies  []Policy  `json:"policies"`
	MAC       string    `json:"mac"`
}

func signature(s Snapshot, key []byte) string {
	s.MAC = ""
	b, _ := json.Marshal(s)
	m := hmac.New(sha256.New, key)
	m.Write(b)
	return hex.EncodeToString(m.Sum(nil))
}
func Sign(s Snapshot, key []byte) Snapshot { s.MAC = signature(s, key); return s }

var ID = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)

func AllowedRoute(s string) bool {
	switch s {
	case "/api/objects/{id}", "/legacy/objects/{id}", "/api/search", "/api/upload", "/api/export":
		return true
	}
	return false
}
func ValidateScoped(p Policy, now time.Time) error {
	for _, v := range []string{p.ID, p.CaseID, p.Tenant, p.Asset, p.Principal, p.Session, p.RuleVersion} {
		if !ID.MatchString(v) {
			return errors.New("scoped policy required")
		}
	}
	if !AllowedRoute(p.Route) || p.Issued.IsZero() || p.Issued.After(now.Add(5*time.Second)) || !p.Expires.After(now) || !p.Expires.After(p.Issued) || p.Expires.Sub(p.Issued) > 60*time.Second {
		return errors.New("invalid route or TTL")
	}
	return nil
}

// Replica holds absolute expiries AND local monotonic deadlines. A controller
// failure or a backward wall-clock adjustment cannot extend an existing deny.
type Replica struct {
	mu        sync.Mutex
	epoch     string
	version   uint64
	digest    string
	items     map[string]Policy
	deadlines map[string]time.Time
	dead      map[string]bool
	byScope   map[replicaScope][]string
	// Sorted at replacement time. Match consumes only due entries, rather
	// than scanning unrelated live policies on every request. Keep both
	// clocks: observing an absolute expiry must also survive clock rollback.
	expiries     []policyExpiry
	deadlinesDue []policyExpiry
}

// A tuple avoids collisions when valid identifiers themselves contain colons.
type replicaScope struct {
	tenant, asset, principal, session, route string
}

type policyExpiry struct {
	id string
	at time.Time
}

func NewReplica() *Replica {
	return &Replica{items: map[string]Policy{}, deadlines: map[string]time.Time{}, dead: map[string]bool{}}
}
func (r *Replica) Replace(s Snapshot, key []byte, now time.Time) error {
	if len(key) < 32 || !hmac.Equal([]byte(s.MAC), []byte(signature(s, key))) || !ID.MatchString(s.Epoch) || s.Generated.Before(now.Add(-5*time.Second)) || s.Generated.After(now.Add(time.Second)) || len(s.Policies) > 1024 {
		return errors.New("invalid snapshot")
	}
	unique := map[string]bool{}
	for _, p := range s.Policies {
		if !ID.MatchString(p.ID) || unique[p.ID] {
			return errors.New("invalid or duplicate policy ID")
		}
		unique[p.ID] = true
		if p.Expires.After(now) {
			if err := ValidateScoped(p, now); err != nil {
				return err
			}
		}
	}
	// Digest excludes the heartbeat timestamp; same version must mean same state.
	check := s
	check.Generated = time.Time{}
	check.MAC = ""
	b, _ := json.Marshal(check)
	hash := sha256.Sum256(b)
	digest := hex.EncodeToString(hash[:])
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.epoch != "" && (s.Epoch != r.epoch || s.Version < r.version || s.Version == r.version && r.digest != "" && digest != r.digest) {
		return errors.New("snapshot rollback rejected")
	}
	if len(r.dead)+len(s.Policies) > 16384 {
		return errors.New("replica budget exceeded")
	}
	next := map[string]Policy{}
	nextDeadlines := map[string]time.Time{}
	nextScopes := map[replicaScope][]string{}
	expiries := make([]policyExpiry, 0, len(s.Policies))
	deadlinesDue := make([]policyExpiry, 0, len(s.Policies))
	for _, p := range s.Policies {
		if r.dead[p.ID] || !p.Expires.After(now) {
			r.dead[p.ID] = true
			continue
		}
		deadline := now.Add(p.Expires.Sub(now))
		if old, ok := r.deadlines[p.ID]; ok {
			if !old.After(now) {
				r.dead[p.ID] = true
				continue
			}
			if old.Before(deadline) {
				deadline = old
			}
		}
		if _, duplicate := next[p.ID]; duplicate {
			return errors.New("duplicate policy ID")
		}
		next[p.ID] = p
		nextDeadlines[p.ID] = deadline
		scope := replicaScope{p.Tenant, p.Asset, p.Principal, p.Session, p.Route}
		nextScopes[scope] = append(nextScopes[scope], p.ID)
		expiries = append(expiries, policyExpiry{p.ID, p.Expires})
		deadlinesDue = append(deadlinesDue, policyExpiry{p.ID, deadline})
	}
	// Overlapping denies have the same enforcement effect. Select the smallest
	// policy ID deterministically for the response header and action evidence.
	for _, ids := range nextScopes {
		sort.Strings(ids)
	}
	for _, entries := range [][]policyExpiry{expiries, deadlinesDue} {
		sort.Slice(entries, func(i, j int) bool { return entries[i].at.Before(entries[j].at) })
	}
	for id := range r.items {
		if _, ok := next[id]; !ok {
			r.dead[id] = true
		}
	}
	r.items = next
	r.deadlines = nextDeadlines
	// All maps and expiry indexes become visible at the same lock boundary.
	// A Match begun after a revocation Replace returns cannot use the old index.
	r.byScope = nextScopes
	r.expiries, r.deadlinesDue = expiries, deadlinesDue
	r.epoch = s.Epoch
	r.version = s.Version
	r.digest = digest
	return nil
}
func (r *Replica) Match(tenant, asset, principal, session, route string, now time.Time) (Policy, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.expireLocked(now)
	scope := replicaScope{tenant, asset, principal, session, route}
	ids := r.byScope[scope]
	for at, id := range ids {
		if p, ok := r.items[id]; ok {
			// Drop any expired prefix without rebuilding the other scopes.
			if at > 0 {
				r.byScope[scope] = ids[at:]
			}
			return p, true
		}
	}
	delete(r.byScope, scope)
	return Policy{}, false
}

// Expiry work is amortized over the bounded snapshot: each of the two indexes
// has at most 1,024 entries. A mass expiry can still require O(P) work in one
// request; the exact-key fast path is not an unconditional latency guarantee.
func (r *Replica) expireLocked(now time.Time) {
	for _, queue := range []*[]policyExpiry{&r.expiries, &r.deadlinesDue} {
		entries := *queue
		for len(entries) > 0 && !entries[0].at.After(now) {
			id := entries[0].id
			delete(r.items, id)
			delete(r.deadlines, id)
			r.dead[id] = true
			entries[0] = policyExpiry{}
			entries = entries[1:]
		}
		*queue = entries
	}
}

func (r *Replica) Status(now time.Time) map[string]any {
	r.mu.Lock()
	defer r.mu.Unlock()
	ids := []string{}
	for id, p := range r.items {
		if p.Expires.After(now) && r.deadlines[id].After(now) {
			ids = append(ids, id)
		}
	}
	return map[string]any{"epoch": r.epoch, "version": r.version, "active_policy_ids": ids, "fallback": "adaptive_allow_base_WAF_and_app_authorization_continue"}
}
