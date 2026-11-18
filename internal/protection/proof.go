package protection

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"reverse-artex/internal/decisions"
	"time"
)

const ProofHeader = "X-RA-Release-Proof"
const MaxProof = 8192
const ProofLifetime = 5 * time.Second

// Same-host Python and Go wall clock samples can quantize on opposite sides
// of a millisecond. The fresh request nonce and original monotonic 5s deadline
// remain authoritative; this tolerance never extends the edge deadline.
const ProofClockSkew = 5 * time.Millisecond

// The signature covers exact payload bytes, avoiding cross-language JSON
// reserialization. Both envelope and payload reject duplicates/unknown fields.
type Envelope struct {
	KeyID     string `json:"key_id"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}
type Proof struct {
	Schema          string `json:"schema"`
	KeyID           string `json:"key_id"`
	Asset           string `json:"asset"`
	Registry        string `json:"registry_digest"`
	Epoch           string `json:"trust_epoch"`
	RequestID       string `json:"request_id"`
	Nonce           string `json:"nonce"`
	Method          string `json:"method"`
	Route           string `json:"route_id"`
	Tenant          string `json:"tenant"`
	Principal       string `json:"principal"`
	Session         string `json:"session"`
	Resource        string `json:"resource_hmac"`
	Action          string `json:"action"`
	AuthzRevision   string `json:"authz_revision"`
	ContentRevision string `json:"content_revision"`
	Decision        string `json:"decision"`
	Status          int    `json:"status"`
	BodyLength      int    `json:"body_length"`
	BodySHA         string `json:"body_sha256"`
	Issued          int64  `json:"issued_ms"`
	Expires         int64  `json:"expires_ms"`
}
type RequestBinding struct {
	RequestID, Nonce, Method, Route, Tenant, Principal, Session, Resource string
	Started                                                               time.Time
}

func BodyHash(body []byte) string { h := sha256.Sum256(body); return hex.EncodeToString(h[:]) }
func (r *Registry) verifyMetadata(raw string, b RequestBinding, status, length int, digest string, now time.Time) (Proof, error) {
	var env Envelope
	var p Proof
	invalid := func() (Proof, error) { return Proof{}, ErrContract }
	if decisions.DecodeStrict([]byte(raw), &env, MaxProof) != nil {
		return invalid()
	}
	key := r.keys[env.KeyID]
	payload, e := base64.RawURLEncoding.DecodeString(env.Payload)
	sig, se := base64.RawURLEncoding.DecodeString(env.Signature)
	if len(key) != ed25519.PublicKeySize || e != nil || se != nil || base64.RawURLEncoding.EncodeToString(payload) != env.Payload || base64.RawURLEncoding.EncodeToString(sig) != env.Signature || !ed25519.Verify(key, payload, sig) {
		return invalid()
	}
	if decisions.DecodeStrict(payload, &p, 4096) != nil {
		return invalid()
	}
	if p.Schema != "release-proof/1" || p.KeyID != env.KeyID || p.Asset != r.Asset() || p.Registry != r.Digest() || p.Epoch != r.Epoch() || p.RequestID != b.RequestID || p.Nonce != b.Nonce || p.Method != b.Method || p.Route != b.Route || p.Tenant != b.Tenant || p.Principal != b.Principal || p.Session != b.Session || p.Resource != b.Resource || p.Action != "read" || !r.TenantAllowed(p.Tenant) || !opaque.MatchString(p.AuthzRevision) || !opaque.MatchString(p.ContentRevision) {
		return invalid()
	}
	if b.Started.IsZero() || now.Before(b.Started) || now.Sub(b.Started) >= ProofLifetime || p.Issued < b.Started.Add(-ProofClockSkew).UnixMilli() || p.Issued > now.Add(ProofClockSkew).UnixMilli() || p.Expires <= now.UnixMilli() || p.Expires-p.Issued > ProofLifetime.Milliseconds() || p.Expires <= p.Issued {
		return invalid()
	}
	if p.Status != status || p.BodyLength != length || p.BodySHA != digest || (b.Method == "HEAD" && length != 0) {
		return invalid()
	}
	known := false
	for _, route := range r.manifest.Routes {
		if route.ID == p.Route && route.Mode == "enforce" && length >= 0 && length <= route.MaxBody {
			known = (p.Decision == "allow" && status == 200) ||
				(p.Decision == "deny" && status == 403) ||
				(p.Decision == "unknown" && status == 503) ||
				(route.Resolver == "session-snapshot-v1" && p.AuthzRevision == "unknown" && p.ContentRevision == "unknown" &&
					((p.Decision == "unauthenticated" && status == 401) || (p.Decision == "not_found" && status == 404)))
		}
	}
	if !known || (b.Method != "GET" && b.Method != "HEAD") || !decisions.ValidHash(digest) {
		return invalid()
	}
	return p, nil
}
func (r *Registry) Verify(raw string, b RequestBinding, status int, body []byte, now time.Time) (Proof, error) {
	return r.verifyMetadata(raw, b, status, len(body), BodyHash(body), now)
}

// VerifyRecorded validates a previously observed signed representation during
// local journal replay. It does not claim that bytes reached a client.
func (r *Registry) VerifyRecorded(raw string, b RequestBinding, status, length int, digest string, at time.Time) (Proof, error) {
	return r.verifyMetadata(raw, b, status, length, digest, at)
}

// Observation is a local pre-release audit, not a post-release effect claim.
// No payload, raw object ID, token or ACL/grant list is serialized.
type Observation struct {
	Schema     string    `json:"schema"`
	Enforcer   string    `json:"enforcer_id"`
	RequestID  string    `json:"request_id"`
	Tenant     string    `json:"tenant"`
	Asset      string    `json:"asset"`
	Route      string    `json:"route_id"`
	Resource   string    `json:"resource_hmac"`
	Decision   string    `json:"decision"`
	ProofSHA   string    `json:"proof_sha256"`
	Status     int       `json:"status"`
	BodyLength int       `json:"body_length"`
	At         time.Time `json:"at"`
}

// GateDecision is a local response decision; it grants no remote authority.
type GateDecision struct {
	CaseID, CaseSHA, PolicyID string
	Deny                      bool
	AttemptID                 string
}

// ResponseWrite is an in-process server write observation, not a client receipt.
type ResponseWrite struct {
	AttemptID   string    `json:"attempt_id"`
	Status      int       `json:"status"`
	Bytes       int       `json:"bytes"`
	BodySHA     string    `json:"body_sha256"`
	Complete    bool      `json:"complete"`
	Error       bool      `json:"write_error"`
	CompletedAt time.Time `json:"completed_at"`
}
