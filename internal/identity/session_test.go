package identity

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func signedIdentityForTest(t *testing.T, claims Claims, key []byte) string {
	t.Helper()

	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal identity claims: %v", err)
	}
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(encodedPayload))
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return encodedPayload + "." + signature
}

func TestVerifyReturnsSignedPrincipalAndTenant(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	key := []byte("identity-test-key-material-32-byte")
	claims := Claims{
		Principal: "alice_1",
		Tenant:    "tenant-a",
		JTI:       "session-123",
		Exp:       now.Add(5 * time.Minute).Unix(),
		Issued:    now.Add(-time.Second).Unix(),
	}
	token := signedIdentityForTest(t, claims, key)

	got, err := Verify(token, key, now)
	if err != nil {
		t.Fatalf("Verify(valid token) error = %v", err)
	}
	if got != claims {
		t.Fatalf("Verify(valid token) = %#v, want %#v", got, claims)
	}
}

func TestVerifyRejectsTamperedWrongKeyAndInvalidTimeClaims(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	key := []byte("identity-test-key-material-32-byte")
	wrongKey := []byte("different-test-key-material-32byt")
	base := Claims{
		Principal: "alice_1",
		Tenant:    "tenant-a",
		JTI:       "session-123",
		Exp:       now.Add(5 * time.Minute).Unix(),
		Issued:    now.Add(-time.Second).Unix(),
	}

	tests := []struct {
		name  string
		token string
		key   []byte
	}{
		{
			name: "tampered payload",
			token: func() string {
				parts := strings.Split(signedIdentityForTest(t, base, key), ".")
				first := byte('A')
				if parts[0][0] == first {
					first = 'B'
				}
				parts[0] = string(first) + parts[0][1:]
				return strings.Join(parts, ".")
			}(),
			key: key,
		},
		{
			name:  "wrong signing key",
			token: signedIdentityForTest(t, base, wrongKey),
			key:   key,
		},
		{
			name: "expired identity",
			token: signedIdentityForTest(t, func() Claims {
				claims := base
				claims.Exp = now.Unix()
				return claims
			}(), key),
			key: key,
		},
		{
			name: "future issued-at beyond clock-skew allowance",
			token: signedIdentityForTest(t, func() Claims {
				claims := base
				claims.Issued = now.Add(6 * time.Second).Unix()
				claims.Exp = now.Add(5 * time.Minute).Unix()
				return claims
			}(), key),
			key: key,
		},
		{
			name: "lifetime over 600 seconds",
			token: signedIdentityForTest(t, func() Claims {
				claims := base
				claims.Issued = now.Add(-time.Second).Unix()
				claims.Exp = claims.Issued + 601
				return claims
			}(), key),
			key: key,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Verify(tt.token, tt.key, now); err == nil {
				t.Fatal("Verify accepted an invalid identity")
			}
		})
	}
}

func TestVerifyRejectsNoncanonicalSignatureText(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	key := []byte("identity-test-key-material-32-byte")
	token := signedIdentityForTest(t, Claims{Principal: "alice", Tenant: "alpha", JTI: "session", Issued: now.Unix(), Exp: now.Add(time.Minute).Unix()}, key)
	parts := strings.Split(token, ".")
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	last := strings.IndexByte(alphabet, parts[1][len(parts[1])-1])
	for _, suffix := range []string{string(alphabet[last+1]), string(alphabet[last+2]), string(alphabet[last+3]), string(parts[1][len(parts[1])-1]) + "\n"} {
		alternate := parts[0] + "." + parts[1][:len(parts[1])-1] + suffix
		if _, err := Verify(alternate, key, now); err == nil {
			t.Fatal("noncanonical signature accepted")
		}
	}
}

func TestVerifyRejectsAmbiguousClaimContracts(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	key := []byte("identity-test-key-material-32-byte")
	for _, raw := range []string{
		`{"principal":"bob","principal":"alice","tenant":"alpha","jti":"session","iat":1900000000,"exp":1900000060}`,
		`{"principal":"alice","tenant":"alpha","iat":1900000000,"exp":1900000060}`,
		`{"Principal":"alice","tenant":"alpha","jti":"session","iat":1900000000,"exp":1900000060}`,
		`{"principal":"alice","tenant":null,"jti":"session","iat":1900000000,"exp":1900000060}`,
	} {
		payload := base64.RawURLEncoding.EncodeToString([]byte(raw))
		mac := hmac.New(sha256.New, key)
		mac.Write([]byte(payload))
		token := payload + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
		if _, err := Verify(token, key, now); err == nil {
			t.Error("ambiguous claims accepted")
		}
	}
}
