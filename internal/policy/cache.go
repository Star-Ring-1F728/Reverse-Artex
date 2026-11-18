// Package policy implements policy scope/lifetime primitives. Replica is the
// M3 enforcement cache; Cache retains the M1/M2 primitive API for regression.
package policy

import (
	"errors"
	"sync"
	"time"
)

type Policy struct {
	ID          string    `json:"id"`
	CaseID      string    `json:"case_id"`
	Tenant      string    `json:"tenant_id"`
	Asset       string    `json:"asset_id"`
	Principal   string    `json:"principal_id"`
	Session     string    `json:"session_hmac"`
	Route       string    `json:"route_template"`
	RuleVersion string    `json:"rule_version"`
	Issued      time.Time `json:"issued_at"`
	Expires     time.Time `json:"expires_at"`
	Version     uint64    `json:"created_version"`
}
type Cache struct {
	mu    sync.Mutex
	items map[string]Policy
	keys  map[string]bool
}

func New() *Cache { return &Cache{items: map[string]Policy{}, keys: map[string]bool{}} }
func (c *Cache) Apply(p Policy, now time.Time) error {
	if p.ID == "" || p.CaseID == "" || p.Tenant == "" || p.Asset == "" || p.Principal == "" || p.Session == "" || p.Route == "" || p.RuleVersion == "" {
		return errors.New("scoped verified policy required")
	}
	if !p.Expires.After(now) || p.Expires.After(now.Add(60*time.Second)) {
		return errors.New("TTL must be positive and at most 60 seconds")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.keys[p.ID] {
		return nil
	}
	if len(c.keys) >= 4096 {
		return errors.New("idempotency budget exceeded")
	}
	c.keys[p.ID] = true
	c.items[p.ID] = p
	return nil
}
func (c *Cache) Denied(tenant, asset, principal, session, route string, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for id, p := range c.items {
		if !p.Expires.After(now) {
			delete(c.items, id)
			continue
		}
		if p.Tenant == tenant && p.Asset == asset && p.Principal == principal && p.Session == session && p.Route == route {
			return true
		}
	}
	return false
}
func (c *Cache) Revoke(id string) { c.mu.Lock(); defer c.mu.Unlock(); delete(c.items, id) }
