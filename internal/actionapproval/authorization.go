// Package actionapproval is a signed-approval and intent ledger. Its explicit
// simulation API can change only a local policy replica. Default ledger/CLI
// operations never call an adapter, model, case service or policy writer.
// RunExecution is a separate explicit authenticated service integration.
package actionapproval

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"time"

	"reverse-artex/internal/actionproposal"
	"reverse-artex/internal/decisions"
)

var identifier = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

type Key struct {
	ID        string    `json:"key_id"`
	PublicKey string    `json:"public_key_hex"`
	Actor     string    `json:"actor"`
	Role      string    `json:"role"`
	Tenant    string    `json:"tenant_id"`
	From      time.Time `json:"valid_from"`
	Until     time.Time `json:"valid_until"`
}

// Trust is supplied by the local operator outside model/request input. It
// authenticates possession of a configured signing key, not a human identity.
type Trust struct {
	Schema string `json:"schema"`
	Domain string `json:"domain"`
	Keys   []Key  `json:"keys"`
}

func (t Trust) Validate() error {
	if t.Schema != "action-approval-trust/1" || !identifier.MatchString(t.Domain) || len(t.Keys) < 1 || len(t.Keys) > 16 {
		return errors.New("bounded explicit approval trust policy required")
	}
	seen, public := map[string]bool{}, map[string]bool{}
	for _, k := range t.Keys {
		b, err := hex.DecodeString(k.PublicKey)
		if err != nil || len(b) != ed25519.PublicKeySize || hex.EncodeToString(b) != k.PublicKey ||
			seen[k.ID] || public[k.PublicKey] || !identifier.MatchString(k.ID) || !identifier.MatchString(k.Actor) ||
			!identifier.MatchString(k.Tenant) || k.From.IsZero() || !k.Until.After(k.From) ||
			(k.Role != "response-operator" && k.Role != "response-observer" && k.Role != "response-supervisor") {
			return errors.New("unique scoped public signing keys required")
		}
		seen[k.ID], public[k.PublicKey] = true, true
	}
	return nil
}

// Command has no approved bool or free-form instructions. Kind determines the
// exact allowed payload. A separate observer key attests declared observations.
type Command struct {
	Schema        string    `json:"schema"`
	Domain        string    `json:"domain"`
	LedgerID      string    `json:"ledger_id"`
	Kind          string    `json:"kind"`
	KeyID         string    `json:"key_id"`
	Actor         string    `json:"actor"`
	Role          string    `json:"role"`
	Tenant        string    `json:"tenant_id"`
	Nonce         string    `json:"nonce"`
	Issued        time.Time `json:"issued_at"`
	Expires       time.Time `json:"expires_at"`
	ProposalSHA   string    `json:"proposal_sha256,omitempty"`
	TargetSHA     string    `json:"target_sha256,omitempty"`
	TTL           int       `json:"ttl_seconds,omitempty"`
	EntryID       string    `json:"entry_id,omitempty"`
	EntrySHA      string    `json:"entry_sha256,omitempty"`
	HeadSHA       string    `json:"expected_head_sha256,omitempty"`
	ObservedState string    `json:"observed_state,omitempty"`
	EvidenceSHA   string    `json:"observation_evidence_sha256,omitempty"`
	ActionExpires time.Time `json:"action_expires_at"`
}

type Signed struct {
	Command   Command `json:"command"`
	Signature string  `json:"signature_hex"`
}

// SigningBytes is shared with an isolated signer. No private-key loader or
// signer exists in the ledger or its CLI.
func SigningBytes(c Command) []byte {
	b, err := json.Marshal(c)
	if err != nil {
		return nil
	}
	return append([]byte("reverse-artex/action-authorization/1\n"), b...)
}

func verifySignature(t Trust, id string, s Signed, now time.Time) error {
	c := s.Command
	if t.Validate() != nil || c.Schema != "action-authorization/1" || c.Domain != t.Domain || c.LedgerID != id ||
		!decisions.ValidHash(c.Nonce) || now.IsZero() || c.Issued.IsZero() || c.Issued.After(now) ||
		!now.Before(c.Expires) || !c.Expires.After(c.Issued) || c.Expires.Sub(c.Issued) > 30*time.Second {
		return errors.New("fresh ledger-bound authorization required")
	}
	var key *Key
	for _, k := range t.Keys {
		if k.ID == c.KeyID {
			copy := k
			key = &copy
		}
	}
	if key == nil || c.Actor != key.Actor || c.Role != key.Role || c.Tenant != key.Tenant ||
		c.Issued.Before(key.From) || !c.Issued.Before(key.Until) || !now.Before(key.Until) || c.Expires.After(key.Until) {
		return errors.New("signing key identity/role/tenant/lifetime mismatch")
	}
	pub, _ := hex.DecodeString(key.PublicKey)
	sig, err := hex.DecodeString(s.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize || hex.EncodeToString(sig) != s.Signature || !ed25519.Verify(pub, SigningBytes(c), sig) {
		return errors.New("invalid approval signature")
	}
	return nil
}

func verifyApproval(c Command, p actionproposal.Proposal) error {
	if c.Kind != "approve" || c.Role != "response-operator" || c.Tenant != p.Target.Tenant ||
		c.ProposalSHA != decisions.Hash(p) || c.TargetSHA != decisions.Hash(p.Target) || c.TTL != p.TTL ||
		c.Issued.Before(p.Created) || c.Expires.After(p.Expires) || c.EntryID != "" || c.ObservedState != "" ||
		c.EntrySHA != "" || c.HeadSHA != "" || c.EvidenceSHA != "" || !c.ActionExpires.IsZero() {
		return errors.New("approval must bind exact proposal, target, TTL and expiry")
	}
	return nil
}
