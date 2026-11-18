package identity

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"net/url"
	"regexp"
	"reverse-artex/internal/decisions"
	"strconv"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

const OIDCAdapter = "oidc-jwt-rs256-v1"

var ErrOIDC = errors.New("OIDC identity rejected")
var oidcTokenID = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)
var oidcID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

type OIDCSubject struct {
	Principal string `json:"principal"`
	Tenant    string `json:"tenant"`
}
type OIDCKey struct {
	KID string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}
type OIDCConfig struct {
	Schema      string                 `json:"schema"`
	Issuer      string                 `json:"issuer"`
	Audience    string                 `json:"audience"`
	Client      string                 `json:"client_id"`
	TenantClaim string                 `json:"tenant_claim"`
	MaxLifetime int64                  `json:"max_lifetime_seconds"`
	Subjects    map[string]OIDCSubject `json:"subjects"`
	Keys        []OIDCKey              `json:"keys"`
}
type OIDCVerifier struct {
	config OIDCConfig
	keys   map[string]*rsa.PublicKey
	sha    string
}

func ParseOIDC(raw []byte) (*OIDCVerifier, error) {
	var c OIDCConfig
	if decisions.DecodeStrict(raw, &c, 64<<10) != nil {
		return nil, ErrOIDC
	}
	return NewOIDC(c)
}
func NewOIDC(c OIDCConfig) (*OIDCVerifier, error) {
	raw, err := json.Marshal(c)
	if err != nil {
		return nil, ErrOIDC
	}
	c = OIDCConfig{}
	if json.Unmarshal(raw, &c) != nil || c.Schema != "oidc-rs256/1" || !validIssuer(c.Issuer) || !id.MatchString(c.Audience) || !id.MatchString(c.Client) || !id.MatchString(c.TenantClaim) || c.MaxLifetime < 1 || c.MaxLifetime > 600 || len(c.Subjects) == 0 || len(c.Subjects) > 256 || len(c.Keys) == 0 || len(c.Keys) > 8 {
		return nil, ErrOIDC
	}
	for _, reserved := range []string{"iss", "sub", "aud", "typ", "azp", "exp", "iat", "nbf", "jti", "sid"} {
		if c.TenantClaim == reserved {
			return nil, ErrOIDC
		}
	}
	for sub, mapping := range c.Subjects {
		if !oidcID.MatchString(sub) || !id.MatchString(mapping.Principal) || !id.MatchString(mapping.Tenant) {
			return nil, ErrOIDC
		}
	}
	keys := map[string]*rsa.PublicKey{}
	for _, k := range c.Keys {
		n, ne := decodeOIDC(k.N, 684)
		e, ee := decodeOIDC(k.E, 8)
		modulus := new(big.Int).SetBytes(n)
		exponent := new(big.Int).SetBytes(e)
		if !oidcID.MatchString(k.KID) || keys[k.KID] != nil || ne != nil || ee != nil || len(n) == 0 || len(e) == 0 || n[0] == 0 || e[0] == 0 || modulus.Bit(0) == 0 || modulus.BitLen() < 2048 || modulus.BitLen() > 4096 || !exponent.IsInt64() || exponent.Int64() < 3 || exponent.Int64() > 2147483647 || exponent.Int64()%2 == 0 {
			return nil, ErrOIDC
		}
		keys[k.KID] = &rsa.PublicKey{N: modulus, E: int(exponent.Int64())}
	}
	// Map serialization sorts every JSON object, matching the SDK contract.
	var canonical map[string]any
	json.Unmarshal(raw, &canonical)
	return &OIDCVerifier{c, keys, decisions.Hash(canonical)}, nil
}
func validIssuer(raw string) bool {
	if len(raw) == 0 || len(raw) > 256 || strings.ContainsAny(raw, "?#%") {
		return false
	}
	for _, r := range raw {
		if r < 33 || r > 126 || strings.ContainsRune(`<>"&\`, r) {
			return false
		}
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" || strings.HasSuffix(raw, "/") || strings.Contains(u.Path, "//") || strings.Contains(u.Path, "/../") {
		return false
	}
	if port := u.Port(); port != "" {
		n, e := strconv.Atoi(port)
		if e != nil || n < 1 || n > 65535 {
			return false
		}
	}
	if u.Scheme == "https" {
		return true
	}
	ip := net.ParseIP(u.Hostname())
	return u.Scheme == "http" && ip != nil && ip.IsLoopback()
}
func decodeOIDC(raw string, limit int) ([]byte, error) {
	if len(raw) == 0 || len(raw) > limit {
		return nil, ErrOIDC
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(raw)
	if err != nil || base64.RawURLEncoding.EncodeToString(b) != raw {
		return nil, ErrOIDC
	}
	return b, nil
}
func (v *OIDCVerifier) Digest() string { return v.sha }
func (v *OIDCVerifier) Issuer() string { return v.config.Issuer }
func (v *OIDCVerifier) Verify(token string, now time.Time) (Claims, error) {
	bad := func() (Claims, error) { return Claims{}, ErrOIDC }
	if len(token) > 8192 {
		return bad()
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return bad()
	}
	h, err := decodeOIDC(parts[0], 1024)
	if err != nil {
		return bad()
	}
	var header map[string]json.RawMessage
	if decisions.DecodeStrict(h, &header, 768) != nil || len(header) != 3 || textClaim(header, "alg") != "RS256" || textClaim(header, "typ") != "JWT" {
		return bad()
	}
	key := v.keys[textClaim(header, "kid")]
	if key == nil {
		return bad()
	}
	payload, err := decodeOIDC(parts[1], 7500)
	if err != nil {
		return bad()
	}
	var claims map[string]json.RawMessage
	if decisions.DecodeStrict(payload, &claims, 6144) != nil {
		return bad()
	}
	if !validAudience(claims["aud"]) {
		return bad()
	}
	// The JWT library verifies signature, algorithm, issuer, audience, exp and nbf.
	parsed, err := jwt.Parse(token, func(t *jwt.Token) (any, error) { return key, nil }, jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(v.config.Issuer), jwt.WithAudience(v.config.Audience), jwt.WithExpirationRequired(), jwt.WithJSONNumber(), jwt.WithStrictDecoding(), jwt.WithTimeFunc(func() time.Time { return now }))
	if err != nil || parsed == nil || !parsed.Valid {
		return bad()
	}
	issued, okI := intClaim(claims, "iat")
	expires, okE := intClaim(claims, "exp")
	if !okI || !okE || issued <= 0 || expires <= now.Unix() || issued > now.Unix()+5 || expires <= issued || expires-issued > v.config.MaxLifetime || textClaim(claims, "typ") != "Bearer" || textClaim(claims, "azp") != v.config.Client {
		return bad()
	}
	if raw, ok := claims["nbf"]; ok {
		var nbf int64
		if json.Unmarshal(raw, &nbf) != nil || nbf > now.Unix() {
			return bad()
		}
	}
	jti, sid := textClaim(claims, "jti"), textClaim(claims, "sid")
	if !oidcTokenID.MatchString(jti) || !oidcTokenID.MatchString(sid) {
		return bad()
	}
	sub := textClaim(claims, "sub")
	mapping, ok := v.config.Subjects[sub]
	if !ok || textClaim(claims, v.config.TenantClaim) != mapping.Tenant {
		return bad()
	}
	return Claims{Principal: mapping.Principal, Tenant: mapping.Tenant, JTI: jti, Exp: expires, Issued: issued}, nil
}
func textClaim(claims map[string]json.RawMessage, key string) string {
	var s string
	if json.Unmarshal(claims[key], &s) != nil {
		return ""
	}
	return s
}
func intClaim(claims map[string]json.RawMessage, key string) (int64, bool) {
	var n int64
	err := json.Unmarshal(claims[key], &n)
	return n, err == nil
}

func validAudience(raw json.RawMessage) bool {
	var audiences []string
	var single string
	if json.Unmarshal(raw, &single) == nil {
		audiences = []string{single}
	} else if json.Unmarshal(raw, &audiences) != nil {
		return false
	}
	if len(audiences) < 1 || len(audiences) > 8 {
		return false
	}
	for _, a := range audiences {
		if len(a) == 0 || len(a) > 256 {
			return false
		}
	}
	return true
}
