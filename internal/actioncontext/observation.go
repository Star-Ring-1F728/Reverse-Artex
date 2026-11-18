// Package actioncontext authenticates request facts and separately scoped QA
// permission. Neither certificate contains a disposition, label, or model output.
package actioncontext

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"reverse-artex/internal/contractjson"
	"time"
)

var ErrInvalid = errors.New("untrusted action context")
var id = regexp.MustCompile(`^[A-Za-z0-9_.:/{}-]{1,128}$`)

type Key struct {
	ID        string `json:"key_id"`
	Role      string `json:"role"`
	Tenant    string `json:"tenant_id"`
	Asset     string `json:"asset_id"`
	Sensor    string `json:"sensor_id"`
	PublicKey string `json:"public_key_base64"`
	Revoked   bool   `json:"revoked"`
}
type Trust struct {
	Schema         string   `json:"schema"`
	Revision       int      `json:"revision"`
	Keys           []Key    `json:"keys"`
	RevokedPermits []string `json:"revoked_permit_ids"`
}
type Binding struct {
	EventSHA         string    `json:"canonical_event_sha256"`
	EventID          string    `json:"event_id"`
	Tenant           string    `json:"tenant_id"`
	Asset            string    `json:"asset_id"`
	Sensor           string    `json:"sensor_id"`
	Principal        string    `json:"principal_hmac"`
	Session          string    `json:"session_hmac"`
	Route            string    `json:"route_template"`
	Method           string    `json:"method"`
	Resource         string    `json:"resource_hmac"`
	ResourceClass    string    `json:"resource_class"`
	Authorization    string    `json:"authorization_result"`
	Status           int       `json:"status"`
	ValidationFamily string    `json:"validation_family"`
	CanaryID         string    `json:"canary_id"`
	Identity         string    `json:"identity_confidence"`
	Quality          string    `json:"data_quality"`
	At               time.Time `json:"event_time"`
}
type Permit struct {
	Schema    string    `json:"schema"`
	ID        string    `json:"permit_id"`
	Tenant    string    `json:"tenant_id"`
	Asset     string    `json:"asset_id"`
	Sensor    string    `json:"sensor_id"`
	Principal string    `json:"principal_hmac"`
	Session   string    `json:"session_hmac"`
	Route     string    `json:"route_template"`
	Method    string    `json:"method"`
	Resource  string    `json:"resource_hmac"`
	Action    string    `json:"action"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	KeyID     string    `json:"key_id"`
	Signature string    `json:"signature_base64"`
}
type Observation struct {
	Schema     string  `json:"schema"`
	Binding    Binding `json:"binding"`
	Permission *Permit `json:"permission,omitempty"`
	KeyID      string  `json:"key_id"`
	Signature  string  `json:"signature_base64"`
}

func (o *Observation) UnmarshalJSON(raw []byte) error {
	type alias Observation
	var a alias
	if err := contractjson.Decode(raw, &a, 16384, 64); err != nil {
		return err
	}
	*o = Observation(a)
	return nil
}
func Digest(v any) string {
	raw, _ := json.Marshal(v)
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}
func ObservationBytes(o Observation) []byte {
	o.Signature = ""
	b, _ := json.Marshal(o)
	return append([]byte("reverse-artex/action-observation/2\n"), b...)
}
func PermitBytes(p Permit) []byte {
	p.Signature = ""
	b, _ := json.Marshal(p)
	return append([]byte("reverse-artex/scoped-test-permission/2\n"), b...)
}
func (t Trust) Validate() error {
	if t.Schema != "action-context-trust/2" || t.Revision < 1 || len(t.Keys) < 2 || len(t.Keys) > 8 || len(t.RevokedPermits) > 32 || t.RevokedPermits == nil {
		return ErrInvalid
	}
	seen, pubs := map[string]bool{}, map[string]bool{}
	roles := map[string]bool{}
	for _, k := range t.Keys {
		pub, e := base64.StdEncoding.Strict().DecodeString(k.PublicKey)
		if e != nil || len(pub) != 32 || !id.MatchString(k.ID) || !id.MatchString(k.Tenant) || !id.MatchString(k.Asset) || !id.MatchString(k.Sensor) || (k.Role != "observation_sensor" && k.Role != "scope_issuer") || seen[k.ID] || pubs[hex.EncodeToString(pub)] {
			return ErrInvalid
		}
		seen[k.ID] = true
		pubs[hex.EncodeToString(pub)] = true
		roles[k.Role] = true
	}
	if !roles["observation_sensor"] || !roles["scope_issuer"] {
		return ErrInvalid
	}
	seen = map[string]bool{}
	for _, p := range t.RevokedPermits {
		if !id.MatchString(p) || seen[p] {
			return ErrInvalid
		}
		seen[p] = true
	}
	return nil
}
func (t Trust) verify(keyID, role string, b Binding, payload []byte, signature string) bool {
	for _, k := range t.Keys {
		if k.ID == keyID && k.Role == role && !k.Revoked && k.Tenant == b.Tenant && k.Asset == b.Asset && k.Sensor == b.Sensor {
			pub, e := base64.StdEncoding.Strict().DecodeString(k.PublicKey)
			sig, f := base64.StdEncoding.Strict().DecodeString(signature)
			return e == nil && f == nil && len(pub) == 32 && len(sig) == 64 && ed25519.Verify(pub, payload, sig)
		}
	}
	return false
}
func (o Observation) ValidateShape(b Binding) error {
	if o.Schema != "action-observation/2" || Digest(o.Binding) != Digest(b) || !id.MatchString(o.KeyID) || b.At.IsZero() || b.Identity != "authenticated" || b.Quality != "complete" || len(b.EventSHA) != 64 || (b.Authorization != "allow" && b.Authorization != "deny") {
		return ErrInvalid
	}
	for _, s := range []string{b.EventID, b.Tenant, b.Asset, b.Sensor, b.Principal, b.Session, b.Route, b.Method, b.Resource} {
		if !id.MatchString(s) {
			return ErrInvalid
		}
	}
	if _, e := base64.StdEncoding.Strict().DecodeString(o.Signature); e != nil {
		return ErrInvalid
	}
	if o.Permission != nil {
		p := o.Permission
		if p.Schema != "scoped-test-permission/2" || !id.MatchString(p.ID) || p.IssuedAt.IsZero() || !p.ExpiresAt.After(p.IssuedAt) || p.ExpiresAt.Sub(p.IssuedAt) > time.Hour || (p.Action != "authorization_probe" && p.Action != "input_validation" && p.Action != "canary_audit") {
			return ErrInvalid
		}
		for _, s := range []string{p.Tenant, p.Asset, p.Sensor, p.Principal, p.Session, p.Route, p.Method, p.Resource, p.KeyID} {
			if !id.MatchString(s) {
				return ErrInvalid
			}
		}
	}
	return nil
}

// Verify requires an authenticated sensor even for a failed/forged permission
// claim. Such a claim remains observed risk; it never becomes positive scope.
func (t *Trust) Verify(o *Observation, b Binding) error {
	if o == nil {
		if t != nil {
			return ErrInvalid
		}
		return nil
	}
	if t == nil || t.Validate() != nil || o.ValidateShape(b) != nil || !t.verify(o.KeyID, "observation_sensor", b, ObservationBytes(*o), o.Signature) {
		return ErrInvalid
	}
	return nil
}
func (t Trust) PermissionGranted(o Observation) bool {
	if t.Verify(&o, o.Binding) != nil {
		return false
	}
	p := o.Permission
	b := o.Binding
	if p == nil {
		return false
	}
	for _, x := range t.RevokedPermits {
		if x == p.ID {
			return false
		}
	}
	if p.Tenant != b.Tenant || p.Asset != b.Asset || p.Sensor != b.Sensor || p.Principal != b.Principal || p.Session != b.Session || p.Route != b.Route || p.Method != b.Method || p.Resource != b.Resource || b.At.Before(p.IssuedAt) || !b.At.Before(p.ExpiresAt) {
		return false
	}
	compatible := p.Action == "authorization_probe" && b.Status == 403 && b.Authorization == "deny" && b.CanaryID == "" && !ValidationRejected(b) || p.Action == "input_validation" && ValidationRejected(b) && b.Authorization != "deny" && b.CanaryID == "" || p.Action == "canary_audit" && b.Status == 403 && b.CanaryID != "" && b.ResourceClass == "canary" && b.Authorization == "deny" && !ValidationRejected(b)
	return compatible && t.verify(p.KeyID, "scope_issuer", b, PermitBytes(*p), p.Signature)
}
func ValidationRejected(b Binding) bool {
	return b.Status >= 400 && b.Status < 500 && b.ValidationFamily != "" && b.ValidationFamily != "unknown" && b.ValidationFamily != "none"
}
