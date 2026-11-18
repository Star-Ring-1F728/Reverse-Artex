package identity

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

func oidcFixture(t *testing.T) (OIDCConfig, *OIDCVerifier, *rsa.PrivateKey, jwt.MapClaims, time.Time) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cfg := OIDCConfig{Schema: "oidc-rs256/1", Issuer: "http://127.0.0.1:18721/realms/test", Audience: "reverse-artex", Client: "console", TenantClaim: "ra_tenant", MaxLifetime: 300, Subjects: map[string]OIDCSubject{"subject-alice": {Principal: "alice", Tenant: "alpha"}}, Keys: []OIDCKey{{KID: "key1", N: base64.RawURLEncoding.EncodeToString(key.N.Bytes()), E: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}}}
	v, err := NewOIDC(cfg)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	claims := jwt.MapClaims{"iss": cfg.Issuer, "aud": cfg.Audience, "azp": cfg.Client, "typ": "Bearer", "sub": "subject-alice", "ra_tenant": "alpha", "jti": "onrtac:token-one", "sid": "session-one", "iat": now.Unix(), "exp": now.Unix() + 60}
	return cfg, v, key, claims, now
}
func signOIDC(t *testing.T, key *rsa.PrivateKey, claims jwt.MapClaims, header map[string]any) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "key1"
	for k, v := range header {
		token.Header[k] = v
	}
	raw, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func rawOIDC(t *testing.T, key *rsa.PrivateKey, header, payload []byte) string {
	t.Helper()
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	h := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}
func TestOIDCPinnedScopeSignatureAndTokenClass(t *testing.T) {
	cfg, v, key, base, now := oidcFixture(t)
	valid := signOIDC(t, key, base, nil)
	c, err := v.Verify(valid, now)
	if err != nil || c.Principal != "alice" || c.Tenant != "alpha" {
		t.Fatal(c, err)
	}
	for _, kind := range []string{"issuer", "audience", "authorized-client", "tenant", "subject", "id-token", "expired", "future", "too-long", "string-exp", "boolean-iat", "missing-exp", "no-session", "unknown-key", "remote-key", "critical-header", "padding", "tamper", "duplicate-payload", "duplicate-header"} {
		t.Run(kind, func(t *testing.T) {
			claims := jwt.MapClaims{}
			for k, x := range base {
				claims[k] = x
			}
			header := map[string]any{}
			switch kind {
			case "issuer":
				claims["iss"] = "https://other.invalid"
			case "audience":
				claims["aud"] = "other"
			case "authorized-client":
				claims["azp"] = "other"
			case "tenant":
				claims["ra_tenant"] = "beta"
			case "subject":
				claims["sub"] = "unknown"
			case "id-token":
				claims["typ"] = "ID"
			case "expired":
				claims["exp"] = now.Unix()
			case "future":
				claims["iat"] = now.Unix() + 6
			case "too-long":
				claims["exp"] = now.Unix() + 301
			case "string-exp":
				claims["exp"] = "9999999999"
			case "boolean-iat":
				claims["iat"] = true
			case "missing-exp":
				delete(claims, "exp")
			case "no-session":
				delete(claims, "sid")
			case "unknown-key":
				header["kid"] = "other"
			case "remote-key":
				header["jku"] = "https://other.invalid/keys"
			case "critical-header":
				header["crit"] = []string{"custom"}
			}
			token := signOIDC(t, key, claims, header)
			if kind == "padding" {
				token += "="
			}
			if kind == "tamper" {
				parts := strings.Split(token, ".")
				parts[1] = base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"forged"}`))
				token = strings.Join(parts, ".")
			}
			if kind == "duplicate-payload" {
				payload, _ := json.Marshal(claims)
				payload = []byte(strings.Replace(string(payload), "{", "{\"sub\":\"subject-alice\",", 1))
				token = rawOIDC(t, key, []byte(`{"alg":"RS256","typ":"JWT","kid":"key1"}`), payload)
			}
			if kind == "duplicate-header" {
				payload, _ := json.Marshal(claims)
				token = rawOIDC(t, key, []byte(`{"alg":"RS256","alg":"RS256","typ":"JWT","kid":"key1"}`), payload)
			}
			if _, err := v.Verify(token, now); err == nil {
				t.Fatal("invalid OIDC access token accepted")
			}
		})
	}
	// Caller-owned subject/key slices cannot alter an accepted trust pin.
	pin := v.Digest()
	cfg.Subjects["subject-alice"] = OIDCSubject{Principal: "attacker", Tenant: "alpha"}
	cfg.Keys[0].KID = "other"
	c, err = v.Verify(valid, now)
	if err != nil || c.Principal != "alice" || v.Digest() != pin {
		t.Fatal("mutable trust config", c, err)
	}
	base["aud"] = []string{"extra", "reverse-artex"}
	base["iat"] = now.Unix() + 4
	if _, err := v.Verify(signOIDC(t, key, base, nil), now); err != nil {
		t.Fatal("bounded future iat or audience list rejected", err)
	}
}
func TestOIDCConfigRejectsRemoteHTTPAndUnboundedTrust(t *testing.T) {
	cfg, _, _, _, _ := oidcFixture(t)
	for _, issuer := range []string{"http://example.com/realm", "https://example.com/realm?", "https://example.com/realm#", "https://example.com/realm/", "https://example.com:99999/realm", "https://user@example.com/realm"} {
		c := cfg
		c.Issuer = issuer
		if _, err := NewOIDC(c); err == nil {
			t.Fatal("invalid issuer accepted", issuer)
		}
	}
	c := cfg
	c.TenantClaim = "sub"
	if _, err := NewOIDC(c); err == nil {
		t.Fatal("reserved tenant claim accepted")
	}
	raw, _ := json.Marshal(cfg)
	raw = []byte(strings.Replace(string(raw), "{", "{\"schema\":\"duplicate\",", 1))
	if _, err := ParseOIDC(raw); err == nil {
		t.Fatal("duplicate config accepted")
	}
}
