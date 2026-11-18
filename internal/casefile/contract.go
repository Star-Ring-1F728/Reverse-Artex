// Package casefile derives bounded, deterministic offline case envelopes from
// HTTP evidence lines and an operator-supplied fixture sensor registry. It does
// not authenticate sensors, read a live store, call models, or apply policies.
package casefile

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"time"
)

const (
	MaxBundle   = 3 << 20
	MaxLine     = 16 << 10
	MaxRecords  = 128
	MaxSensors  = 32
	MaxAssets   = 8
	MaxEnvelope = 1 << 20
)

var identifier = regexp.MustCompile(`^[A-Za-z0-9_.:/{}-]{1,128}$`)
var sha = regexp.MustCompile(`^[a-f0-9]{64}$`)

type Window struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// RequestNamespace identifies a locally asserted, server-issued request-ID
// domain. Empty means no trustworthy cross-sensor request correlation.
// IdentityAuthority is required explicitly; it is not runtime authentication.
type Sensor struct {
	ID                string `json:"sensor_id"`
	Tenant            string `json:"tenant_id"`
	Asset             string `json:"asset_id"`
	Kind              string `json:"kind"`
	Status            string `json:"status"`
	RequestNamespace  string `json:"request_namespace"`
	IdentityAuthority *bool  `json:"identity_authority"`
}

type Record struct {
	LineSHA string `json:"line_sha256"`
	Line    string `json:"line"`
}

type Bundle struct {
	Schema     string    `json:"schema_version"`
	CaseID     string    `json:"case_id"`
	Revision   int       `json:"revision"`
	Tenant     string    `json:"tenant_id"`
	Assets     []string  `json:"asset_ids"`
	Window     Window    `json:"observed_window"`
	ObservedAt time.Time `json:"observed_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	Sensors    []Sensor  `json:"sensors"`
	Records    []Record  `json:"records"`
}

// Evidence preserves source lineage and a limited factual projection. The raw
// line, IP, UA, session token/HMAC, and request bodies are never copied here.
type Evidence struct {
	ID               string    `json:"ref_id"`
	Stream           string    `json:"stream"`
	Tenant           string    `json:"tenant_id"`
	Asset            string    `json:"asset_id"`
	Sensor           string    `json:"sensor_id"`
	SensorKind       string    `json:"sensor_kind"`
	EventID          string    `json:"event_id"`
	LineSHA          string    `json:"line_sha256"`
	Time             time.Time `json:"event_time"`
	IngestTime       time.Time `json:"ingest_time"`
	RequestID        string    `json:"request_id"`
	RequestNamespace string    `json:"request_namespace"`
	Method           string    `json:"method"`
	Route            string    `json:"route_template"`
	KnownRoute       bool      `json:"known_route"`
	Status           int       `json:"status"`
	Authorization    string    `json:"authorization_result"`
	Family           string    `json:"detector_family"`
	Principal        string    `json:"principal_id"`
	IdentityBasis    string    `json:"identity_basis"`
	Quality          string    `json:"data_quality"`
}

type Coverage struct {
	ID                string `json:"coverage_id"`
	Sensor            string `json:"sensor_id"`
	Tenant            string `json:"tenant_id"`
	Asset             string `json:"asset_id"`
	Kind              string `json:"kind"`
	DeclaredStatus    string `json:"declared_status"`
	RequestNamespace  string `json:"request_namespace"`
	IdentityAuthority bool   `json:"identity_authority"`
	Status            string `json:"coverage_status"`
	Records           int    `json:"unique_records"`
}

type Group struct {
	ID        string   `json:"group_id"`
	Asset     string   `json:"asset_id"`
	Basis     string   `json:"basis"`
	Refs      []string `json:"evidence_refs"`
	Countable bool     `json:"countable_request"`
}

// No caller-supplied assertions are accepted. Hypotheses/model text are a
// future, separate contract and cannot be promoted to observed facts here.
type Assertion struct {
	ID      string   `json:"assertion_id"`
	Kind    string   `json:"kind"`
	Code    string   `json:"code"`
	Subject string   `json:"subject_id"`
	Refs    []string `json:"evidence_refs"`
}

type Envelope struct {
	Schema       string      `json:"schema_version"`
	Scope        string      `json:"scope"`
	CaseID       string      `json:"case_id"`
	Revision     int         `json:"revision"`
	Tenant       string      `json:"tenant_id"`
	Assets       []string    `json:"asset_ids"`
	Window       Window      `json:"observed_window"`
	ObservedAt   time.Time   `json:"observed_at"`
	ExpiresAt    time.Time   `json:"expires_at"`
	Quality      string      `json:"data_quality"`
	Evidence     []Evidence  `json:"evidence"`
	Coverage     []Coverage  `json:"sensor_coverage"`
	Groups       []Group     `json:"request_groups"`
	RequestCount int         `json:"correlated_request_count"`
	Assertions   []Assertion `json:"assertions"`
}

type Document struct {
	Envelope Envelope `json:"envelope"`
	SHA256   string   `json:"envelope_sha256"`
}

func hashBytes(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func hash(v any) string            { b, _ := json.Marshal(v); return hashBytes(b) }
func tuple(parts ...string) string { return hash(parts) }

func (b Bundle) validate(at time.Time) error {
	bad := errors.New("invalid bounded case fixture contract")
	if b.Schema != "case-fixture/1" || !identifier.MatchString(b.CaseID) || !identifier.MatchString(b.Tenant) || b.Revision < 1 || b.Revision > 1000000 ||
		len(b.Assets) < 1 || len(b.Assets) > MaxAssets || len(b.Sensors) < 1 || len(b.Sensors) > MaxSensors || b.Records == nil || len(b.Records) > MaxRecords {
		return bad
	}
	if at.IsZero() || b.Window.Start.IsZero() || b.Window.End.IsZero() || b.ObservedAt.IsZero() || b.ExpiresAt.IsZero() ||
		b.Window.End.Before(b.Window.Start) || b.Window.End.After(b.ObservedAt) || b.Window.Start.Before(b.ObservedAt.Add(-time.Hour)) ||
		!b.ExpiresAt.After(b.ObservedAt) || b.ExpiresAt.After(b.ObservedAt.Add(time.Hour)) || at.Before(b.ObservedAt) || !at.Before(b.ExpiresAt) {
		return errors.New("case window or explicit as-of freshness violated")
	}
	assets := map[string]bool{}
	for _, a := range b.Assets {
		if !identifier.MatchString(a) || assets[a] {
			return bad
		}
		assets[a] = true
	}
	seen, covered := map[string]bool{}, map[string]bool{}
	for _, s := range b.Sensors {
		k := tuple(s.Tenant, s.Asset, s.ID)
		if !identifier.MatchString(s.ID) || s.Tenant != b.Tenant || !assets[s.Asset] || seen[k] || s.IdentityAuthority == nil ||
			(s.Kind != "app" && s.Kind != "waf") || (s.Status != "available" && s.Status != "degraded" && s.Status != "missing") ||
			(s.RequestNamespace != "" && !identifier.MatchString(s.RequestNamespace)) {
			return bad
		}
		seen[k], covered[s.Asset] = true, true
	}
	if len(covered) != len(assets) {
		return errors.New("expected sensor coverage required for every asset")
	}
	return nil
}
