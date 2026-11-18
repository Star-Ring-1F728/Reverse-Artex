// Package routecoverage bounds the ingress surface to SDK routes and explicit
// application exceptions. It never discovers or approves routes automatically.
package routecoverage

import (
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"reverse-artex/internal/decisions"
	"reverse-artex/internal/protection"
	"strings"
	"sync/atomic"
	"time"
)

var ErrContract = errors.New("invalid route coverage contract")
var ErrAudit = errors.New("route coverage audit unavailable")
var identifier = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
var pathPart = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$`)
var digest = regexp.MustCompile(`^[0-9a-f]{64}$`)
var methods = map[string]bool{"GET": true, "HEAD": true, "POST": true, "PUT": true, "PATCH": true, "DELETE": true, "OPTIONS": true}

type Exception struct {
	ID      string   `json:"id"`
	Path    string   `json:"path"`
	Methods []string `json:"methods"`
	Query   string   `json:"query"`
	Reason  string   `json:"reason"`
}
type Manifest struct {
	Schema     string      `json:"schema"`
	Asset      string      `json:"asset"`
	Revision   string      `json:"revision"`
	Registry   string      `json:"registry_digest"`
	Exceptions []Exception `json:"unprotected_routes"`
}
type Policy struct {
	manifest Manifest
	registry *protection.Registry
	sha      string
	paths    map[string]Exception
}

func Parse(raw []byte, registry *protection.Registry) (*Policy, error) {
	var m Manifest
	if decisions.DecodeStrict(raw, &m, 64<<10) != nil {
		return nil, ErrContract
	}
	return New(m, registry)
}
func New(m Manifest, registry *protection.Registry) (*Policy, error) {
	raw, err := json.Marshal(m)
	if err != nil {
		return nil, ErrContract
	}
	m = Manifest{}
	if json.Unmarshal(raw, &m) != nil || registry == nil || m.Schema != "route-coverage/1" || m.Asset != registry.Asset() || !identifier.MatchString(m.Revision) || m.Registry != registry.Digest() || len(m.Exceptions) > 64 {
		return nil, ErrContract
	}
	for _, r := range registry.Routes() {
		if r.Mode != "enforce" {
			return nil, ErrContract
		}
	}
	ids, paths := map[string]bool{}, map[string]Exception{}
	for _, r := range registry.Routes() {
		ids[r.ID] = true
	}
	for _, e := range m.Exceptions {
		if !identifier.MatchString(e.ID) || ids[e.ID] || !validPath(e.Path) || e.Path == "/healthz" || len(e.Methods) == 0 || len(e.Methods) > 7 || (e.Query != "deny" && e.Query != "allow") || strings.TrimSpace(e.Reason) != e.Reason || len(e.Reason) == 0 || len(e.Reason) > 500 {
			return nil, ErrContract
		}
		if _, ok := paths[e.Path]; ok {
			return nil, ErrContract
		}
		u, _ := url.Parse(e.Path)
		if _, _, matched, _ := registry.Resolve(u, "GET"); matched {
			return nil, ErrContract
		}
		seen := map[string]bool{}
		for _, method := range e.Methods {
			if !methods[method] || seen[method] {
				return nil, ErrContract
			}
			seen[method] = true
		}
		ids[e.ID] = true
		paths[e.Path] = e
	}
	return &Policy{m, registry, decisions.Hash(m), paths}, nil
}
func validPath(path string) bool {
	if path == "/" {
		return true
	}
	if len(path) > 256 || !strings.HasPrefix(path, "/") {
		return false
	}
	for _, part := range strings.Split(path[1:], "/") {
		if !pathPart.MatchString(part) || part == "." || part == ".." {
			return false
		}
	}
	return true
}
func (p *Policy) Digest() string         { return p.sha }
func (p *Policy) RegistryDigest() string { return p.manifest.Registry }
func (p *Policy) Asset() string          { return p.manifest.Asset }

type Class string

const (
	SDK         Class = "sdk_route_admitted"
	Application Class = "explicit_app_route_admitted"
	Local       Class = "local_health"
	Denied      Class = "unregistered_denied"
	Invalid     Class = "invalid_denied"
)

type Decision struct {
	Class   Class
	RouteID string
	Status  int
}

func (p *Policy) Decide(u *url.URL, method string) Decision {
	if u == nil || u.Host != "" || u.Scheme != "" || u.RawPath != "" || len(u.RequestURI()) > 2048 || strings.Contains(u.EscapedPath(), "%") || strings.Contains(u.Path, "//") || strings.Contains(u.Path, "/../") || strings.Contains(u.Path, "/./") {
		return Decision{Class: Invalid, Status: 400}
	}
	if u.Path == "/healthz" {
		if (method == "GET" || method == "HEAD") && u.RawQuery == "" && !u.ForceQuery {
			return Decision{Class: Local, RouteID: "edge-health"}
		}
		return Decision{Class: Invalid, Status: 400}
	}
	route, _, matched, err := p.registry.Resolve(u, method)
	if err != nil {
		return Decision{Class: Invalid, RouteID: route.ID, Status: 400}
	}
	if matched && route.Mode == "enforce" {
		return Decision{Class: SDK, RouteID: route.ID}
	}
	if e, ok := p.paths[u.Path]; ok {
		allowed := false
		for _, m := range e.Methods {
			allowed = allowed || m == method
		}
		if allowed && (e.Query == "allow" || (u.RawQuery == "" && !u.ForceQuery)) {
			return Decision{Class: Application, RouteID: e.ID}
		}
	}
	return Decision{Class: Denied, Status: 404}
}

type Observation struct {
	Schema       string    `json:"schema"`
	Asset        string    `json:"asset"`
	Coverage     string    `json:"coverage_digest"`
	Registry     string    `json:"registry_digest"`
	RequestID    string    `json:"request_id"`
	Class        Class     `json:"classification"`
	RouteID      string    `json:"route_id,omitempty"`
	Method       string    `json:"method"`
	PathHMAC     string    `json:"path_hmac"`
	QueryPresent bool      `json:"query_present"`
	At           time.Time `json:"at"`
}
type Gate struct {
	policy                                          *Policy
	audit                                           func(Observation) error
	sdk, app, local, denied, invalid, auditFailures atomic.Uint64
	auditAvailable                                  atomic.Bool
}

func NewGate(p *Policy, audit func(Observation) error) *Gate {
	g := &Gate{policy: p, audit: audit}
	g.auditAvailable.Store(audit != nil)
	return g
}
func (g *Gate) Policy() *Policy                           { return g.policy }
func (g *Gate) Decide(u *url.URL, method string) Decision { return g.policy.Decide(u, method) }
func (g *Gate) Record(d Decision, requestID, method, pathHMAC string, query bool, at time.Time) error {
	switch d.Class {
	case SDK:
		g.sdk.Add(1)
	case Application:
		g.app.Add(1)
	case Local:
		g.local.Add(1)
	case Denied:
		g.denied.Add(1)
	case Invalid:
		g.invalid.Add(1)
	default:
		return ErrContract
	}
	if !methods[method] {
		method = "OTHER"
	}
	o := Observation{"route-coverage-observation/1", g.policy.Asset(), g.policy.Digest(), g.policy.RegistryDigest(), requestID, d.Class, d.RouteID, method, pathHMAC, query, at.UTC()}
	if !identifier.MatchString(requestID) || !digest.MatchString(pathHMAC) || g.audit == nil || g.audit(o) != nil {
		g.auditAvailable.Store(false)
		g.auditFailures.Add(1)
		return ErrAudit
	}
	g.auditAvailable.Store(true)
	return nil
}

type State struct {
	Schema         string             `json:"schema"`
	Configured     bool               `json:"configured"`
	Digest         string             `json:"coverage_digest"`
	Registry       string             `json:"registry_digest"`
	Default        string             `json:"unregistered_action"`
	Protected      []protection.Route `json:"sdk_routes"`
	Exceptions     []Exception        `json:"unprotected_routes"`
	Counts         map[Class]uint64   `json:"request_classifications"`
	AuditAvailable bool               `json:"audit_available"`
	AuditFailures  uint64             `json:"audit_failures"`
	CoverageScope  string             `json:"scope"`
}

func (g *Gate) State() State {
	raw, _ := json.Marshal(g.policy.manifest.Exceptions)
	var exceptions []Exception
	json.Unmarshal(raw, &exceptions)
	return State{"route-coverage-state/1", true, g.policy.Digest(), g.policy.RegistryDigest(), "deny", g.policy.registry.Routes(), exceptions, map[Class]uint64{SDK: g.sdk.Load(), Application: g.app.Load(), Local: g.local.Load(), Denied: g.denied.Load(), Invalid: g.invalid.Load()}, g.auditAvailable.Load(), g.auditFailures.Load(), "configured ingress admissions only; application exceptions are not SDK-protected; no route discovery or client receipt"}
}
