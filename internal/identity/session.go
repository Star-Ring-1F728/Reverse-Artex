// Package identity verifies lab-issued identities without database/LLM access.
package identity

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"regexp"
	"reverse-artex/internal/contractjson"
	"strings"
	"time"
)

type Claims struct {
	Principal string `json:"principal"`
	Tenant    string `json:"tenant"`
	JTI       string `json:"jti"`
	Exp       int64  `json:"exp"`
	Issued    int64  `json:"iat"`
}

var id = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

func Verify(token string, key []byte, now time.Time) (Claims, error) {
	var c Claims
	if len(key) < 32 || len(token) > 2048 {
		return c, errors.New("invalid identity")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return c, errors.New("invalid identity")
	}
	sig, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if err != nil || len(sig) != sha256.Size || base64.RawURLEncoding.EncodeToString(sig) != parts[1] {
		return c, errors.New("invalid identity")
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(parts[0]))
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return c, errors.New("invalid identity")
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(parts[0])
	if err != nil || base64.RawURLEncoding.EncodeToString(b) != parts[0] || contractjson.Decode(b, &c, 2048, 8) != nil {
		return Claims{}, errors.New("invalid identity")
	}
	if !id.MatchString(c.Principal) || !id.MatchString(c.Tenant) || !id.MatchString(c.JTI) || c.Exp <= now.Unix() || c.Issued > now.Unix()+5 || c.Exp <= c.Issued || c.Exp-c.Issued > 600 {
		return Claims{}, errors.New("invalid identity")
	}
	return c, nil
}
func Pseudonym(value string, key []byte) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(value))
	return hex.EncodeToString(m.Sum(nil))
}
