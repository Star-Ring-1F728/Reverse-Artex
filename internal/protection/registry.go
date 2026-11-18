// Package protection defines opt-in, operator-owned object-read contracts.
// It has no AI, network, policy mutation, or credential lookup capability.
package protection

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"reverse-artex/internal/decisions"
	"reverse-artex/internal/identity"
	"strings"
)

var ErrContract = errors.New("invalid object-read protection contract")
var opaque = regexp.MustCompile("^[A-Za-z0-9_-]{1,64}$")
var segment = regexp.MustCompile("^[a-z][a-z0-9_-]{0,31}$")

type Route struct {
	ID          string `json:"id"`
	Template    string `json:"template"`
	Namespace   string `json:"namespace"`
	Mode        string `json:"mode"`
	MaxBody     int    `json:"max_body_bytes"`
	AuthAdapter string `json:"auth_adapter_version"`
	Resolver    string `json:"resolver_version"`
}
type Manifest struct {
	Schema         string            `json:"schema"`
	Asset          string            `json:"asset"`
	Revision       string            `json:"revision"`
	TrustEpoch     string            `json:"trust_epoch"`
	Enforcer       string            `json:"enforcer_id"`
	Tenants        []string          `json:"tenants"`
	Keys           map[string]string `json:"proof_keys"`
	Routes         []Route           `json:"routes"`
	IdentityDigest string            `json:"identity_config_sha256,omitempty"`
}
type Registry struct {
	manifest Manifest
	digest   string
	keys     map[string]ed25519.PublicKey
}

func Parse(raw []byte) (*Registry, error) {
	var m Manifest
	if decisions.DecodeStrict(raw, &m, 64<<10) != nil {
		return nil, ErrContract
	}
	return New(m)
}
func New(m Manifest) (*Registry, error) {
	// Detach caller-owned slices/maps before accepting the operator contract.
	raw, err := json.Marshal(m)
	if err != nil {
		return nil, ErrContract
	}
	m = Manifest{}
	if json.Unmarshal(raw, &m) != nil || m.Schema != "protection-registry/1" || !opaque.MatchString(m.Asset) || !opaque.MatchString(m.Revision) || !opaque.MatchString(m.TrustEpoch) || !opaque.MatchString(m.Enforcer) || len(m.Tenants) == 0 || len(m.Tenants) > 64 || len(m.Keys) == 0 || len(m.Keys) > 8 || len(m.Routes) == 0 || len(m.Routes) > 32 {
		return nil, ErrContract
	}
	tenants := map[string]bool{}
	for _, t := range m.Tenants {
		if !opaque.MatchString(t) || tenants[t] {
			return nil, ErrContract
		}
		tenants[t] = true
	}
	keys := map[string]ed25519.PublicKey{}
	for id, value := range m.Keys {
		k, e := base64.RawURLEncoding.DecodeString(value)
		if !opaque.MatchString(id) || e != nil || len(k) != ed25519.PublicKeySize || base64.RawURLEncoding.EncodeToString(k) != value {
			return nil, ErrContract
		}
		keys[id] = ed25519.PublicKey(k)
	}
	ids, bases := map[string]bool{}, map[string]bool{}
	adapter := ""
	for _, r := range m.Routes {
		if !opaque.MatchString(r.ID) || ids[r.ID] || !opaque.MatchString(r.Namespace) || (r.Mode != "observe" && r.Mode != "enforce") || r.MaxBody < 1 || r.MaxBody > 1<<20 || (r.AuthAdapter != "lab-hmac-v1" && r.AuthAdapter != identity.OIDCAdapter) || (r.Resolver != "snapshot-v1" && r.Resolver != "session-snapshot-v1") || !strings.HasSuffix(r.Template, "/{id}") {
			return nil, ErrContract
		}
		if adapter != "" && adapter != r.AuthAdapter {
			return nil, ErrContract
		}
		adapter = r.AuthAdapter
		if r.AuthAdapter == identity.OIDCAdapter && r.Resolver != "session-snapshot-v1" {
			return nil, ErrContract
		}
		base := strings.TrimSuffix(r.Template, "/{id}")
		if len(base) > 128 || !strings.HasPrefix(base, "/") || bases[base] {
			return nil, ErrContract
		}
		for _, part := range strings.Split(strings.TrimPrefix(base, "/"), "/") {
			if !segment.MatchString(part) {
				return nil, ErrContract
			}
		}
		// No namespace can shadow a more specific registered route.
		for b := range bases {
			if strings.HasPrefix(base, b+"/") || strings.HasPrefix(b, base+"/") {
				return nil, ErrContract
			}
		}
		ids[r.ID] = true
		bases[base] = true
	}
	if (adapter == identity.OIDCAdapter && !decisions.ValidHash(m.IdentityDigest)) || (adapter != "" && adapter != identity.OIDCAdapter && m.IdentityDigest != "") {
		return nil, ErrContract
	}
	return &Registry{m, decisions.Hash(m), keys}, nil
}

// Routes returns a detached declaration inventory, not observed route discovery.
func (r *Registry) Routes() []Route { return append([]Route(nil), r.manifest.Routes...) }

func (r *Registry) AuthAdapter() string    { return r.manifest.Routes[0].AuthAdapter }
func (r *Registry) IdentityDigest() string { return r.manifest.IdentityDigest }
func (r *Registry) Digest() string         { return r.digest }
func (r *Registry) Asset() string          { return r.manifest.Asset }
func (r *Registry) Epoch() string          { return r.manifest.TrustEpoch }
func (r *Registry) Enforcer() string       { return r.manifest.Enforcer }
func (r *Registry) TenantAllowed(t string) bool {
	for _, v := range r.manifest.Tenants {
		if v == t {
			return true
		}
	}
	return false
}

// Resolve reserves the complete registered path family: malformed children and
// unsupported methods cannot silently fall back to an unprotected proxy path.
func (r *Registry) Resolve(u *url.URL, method string) (Route, string, bool, error) {
	for _, route := range r.manifest.Routes {
		base := strings.TrimSuffix(route.Template, "/{id}")
		if u.Path != base && !strings.HasPrefix(u.Path, base+"/") {
			continue
		}
		id := strings.TrimPrefix(u.Path, base+"/")
		if u.Path == base || !opaque.MatchString(id) || u.RawPath != "" || strings.Contains(u.EscapedPath(), "%") || u.RawQuery != "" || u.ForceQuery || (method != "GET" && method != "HEAD") {
			return route, "", true, ErrContract
		}
		return route, id, true, nil
	}
	return Route{}, "", false, nil
}

// ResourceID binds the tenant and namespace; raw IDs never enter the proof.
func ResourceID(key []byte, tenant, namespace, id string) (string, error) {
	if len(key) < 32 || !opaque.MatchString(tenant) || !opaque.MatchString(namespace) || !opaque.MatchString(id) {
		return "", ErrContract
	}
	raw, _ := json.Marshal([]string{tenant, namespace, id})
	mac := hmac.New(sha256.New, key)
	mac.Write(raw)
	return hex.EncodeToString(mac.Sum(nil)), nil
}
