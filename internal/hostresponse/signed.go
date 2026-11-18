package hostresponse

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reverse-artex/internal/actionapproval"
	"reverse-artex/internal/decisions"
	"reverse-artex/internal/hostguard"
	"strings"
	"time"
)

var ErrAuthorization = errors.New("host signed authorization rejected")
var ErrAuthorizationReplay = errors.New("host authorization already consumed")

// HostCommand is a separate authority domain from session/route approval.
// The signer pins the entire original lease, including its absolute deadline.
type HostCommand struct {
	Schema   string    `json:"schema"`
	Domain   string    `json:"domain"`
	LedgerID string    `json:"ledger_id"`
	Kind     string    `json:"kind"`
	KeyID    string    `json:"key_id"`
	Actor    string    `json:"actor"`
	Role     string    `json:"role"`
	Nonce    string    `json:"nonce"`
	Issued   time.Time `json:"issued_at"`
	Expires  time.Time `json:"expires_at"`
	ScopeSHA string    `json:"scope_sha256"`
	CaseSHA  string    `json:"case_sha256"`
	Lease    Lease     `json:"lease"`
}

type HostSigned struct {
	Command   HostCommand `json:"command"`
	Signature string      `json:"signature_hex"`
}

func HostSigningBytes(c HostCommand) []byte {
	b, err := json.Marshal(c)
	if err != nil {
		return nil
	}
	return append([]byte("reverse-artex/linux-isolation-authorization/1\n"), b...)
}

func DecodeHostSigned(raw []byte) (HostSigned, error) {
	var s HostSigned
	err := decodeHostJSON(raw, &s, 8192)
	return s, err
}

func decodeHostJSON(raw []byte, out any, limit int) error {
	if err := decisions.DecodeStrict(raw, out, limit); err != nil {
		return err
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return err
	}
	var canonical func(any) bool
	canonical = func(v any) bool {
		switch x := v.(type) {
		case map[string]any:
			for k, child := range x {
				if k != strings.ToLower(k) || !canonical(child) {
					return false
				}
			}
		case []any:
			for _, child := range x {
				if !canonical(child) {
					return false
				}
			}
		}
		return true
	}
	if !canonical(v) {
		return ErrAuthorization
	}
	return nil
}

type SigningContext struct {
	Schema   string `json:"schema"`
	LedgerID string `json:"ledger_id"`
	Domain   string `json:"domain"`
	ScopeSHA string `json:"scope_sha256"`
	TrustSHA string `json:"trust_sha256"`
}

type hostSigning struct {
	context SigningContext
	trust   actionapproval.Trust
	path    string
	scope   LinuxScope
	owner   *os.File
	nonces  map[string]bool
	head    string
}

func readHostTrust(path string) (actionapproval.Trust, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 16384 {
		return actionapproval.Trust{}, ErrAuthorization
	}
	f, err := os.Open(path)
	if err != nil {
		return actionapproval.Trust{}, ErrAuthorization
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 16385))
	if err != nil || len(raw) > 16384 {
		return actionapproval.Trust{}, ErrAuthorization
	}
	return actionapproval.DecodeTrust(raw)
}

func openHostSigning(dir, trustPath string, scope LinuxScope) (*hostSigning, error) {
	if !scope.Valid() {
		return nil, ErrAuthorization
	}
	t, err := readHostTrust(trustPath)
	if err != nil {
		return nil, err
	}
	if err = os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	owner, err := os.OpenFile(filepath.Join(dir, "signed-owner"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = lockSignedOwner(owner); err != nil {
		owner.Close()
		return nil, errors.New("host signing ledger already owned")
	}
	s := &hostSigning{trust: t, path: trustPath, scope: scope, owner: owner, nonces: map[string]bool{}}
	fail := func(err error) (*hostSigning, error) { unlockSignedOwner(owner); owner.Close(); return nil, err }
	meta := filepath.Join(dir, "signed-context.json")
	if info, e := os.Lstat(meta); e == nil && (!info.Mode().IsRegular() || info.Size() > 4096) {
		return fail(ErrAuthorization)
	}
	raw, err := os.ReadFile(meta)
	if os.IsNotExist(err) {
		// Never adopt an existing unsigned or orphaned audit as a fresh ledger.
		f, e := os.OpenFile(filepath.Join(dir, "host-actions.jsonl"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			return fail(errors.New("new signed host audit required"))
		}
		e = f.Sync()
		e = errors.Join(e, f.Close())
		if e != nil {
			return fail(e)
		}
		id := make([]byte, 32)
		if _, e = rand.Read(id); e != nil {
			return fail(e)
		}
		s.context = SigningContext{"linux-isolation-signing-context/1", hex.EncodeToString(id), t.Domain, scope.SHA(), digest(t)}
		raw, _ = json.Marshal(s.context)
		f, e = os.OpenFile(meta, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			return fail(e)
		}
		n, e := f.Write(raw)
		if e == nil && n != len(raw) {
			e = errors.New("incomplete signing context")
		}
		e = errors.Join(e, f.Sync(), f.Close())
		if e != nil {
			return fail(e)
		}
	} else {
		if err != nil || decodeHostJSON(raw, &s.context, 4096) != nil ||
			s.context.Schema != "linux-isolation-signing-context/1" || !decisions.ValidHash(s.context.LedgerID) ||
			s.context.Domain != t.Domain || s.context.TrustSHA != digest(t) || s.context.ScopeSHA != scope.SHA() {
			return fail(ErrAuthorization)
		}
		info, e := os.Lstat(filepath.Join(dir, "host-actions.jsonl"))
		if e != nil || !info.Mode().IsRegular() {
			return fail(ErrAuthorization)
		}
	}
	return s, nil
}

func OpenSigned(dir string, adapter Adapter, canaries []string, scope LinuxScope, trustPath string) (*Manager, error) {
	if adapter == nil {
		return nil, errors.New("adapter required")
	}
	s, err := openHostSigning(dir, trustPath, scope)
	if err != nil {
		return nil, err
	}
	m, err := openAt(dir, adapter, canaries, time.Now().UTC(), s)
	if err != nil {
		unlockSignedOwner(s.owner)
		s.owner.Close()
		return nil, err
	}
	m.clock = func() time.Time { return time.Now().UTC() }
	return m, nil
}

func (m *Manager) Close() error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.signing != nil && m.signing.owner != nil {
		unlockSignedOwner(m.signing.owner)
		err := m.signing.owner.Close()
		m.signing.owner = nil
		m.auditFailed = true
		return err
	}
	return nil
}

func (m *Manager) SigningContext() (SigningContext, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.signing == nil || m.auditFailed {
		return SigningContext{}, ErrAuthorization
	}
	return m.signing.context, nil
}

func pendingLease(a Lease) Lease {
	a.State = "pending"
	a.ReleaseRequested = false
	a.UnknownReason = ""
	return a
}

// Historical replay uses pinned trust at recorded_at. Live dispatch also re-reads
// the operator file, so removal, mutation or expiry cannot silently authorize it.
func (m *Manager) verifyHost(s HostSigned, kind string, at time.Time, live bool) error {
	g := m.signing
	if g == nil || at.IsZero() {
		return ErrAuthorization
	}
	c, a := s.Command, s.Command.Lease
	if live {
		t, err := readHostTrust(g.path)
		if err != nil || digest(t) != g.context.TrustSHA {
			return ErrAuthorization
		}
	}
	if c.Schema != "linux-isolation-authorization/1" || c.Kind != kind || (kind != "approve" && kind != "release") ||
		c.Domain != g.context.Domain || c.LedgerID != g.context.LedgerID || c.ScopeSHA != g.context.ScopeSHA ||
		c.Role != "response-operator" || !decisions.ValidHash(c.Nonce) || !decisions.ValidHash(c.CaseSHA) ||
		c.Issued.IsZero() || c.Issued.After(at) || !at.Before(c.Expires) || !c.Expires.After(c.Issued) || c.Expires.Sub(c.Issued) > 30*time.Second ||
		a != pendingLease(a) || a.Tenant != g.scope.Tenant || a.Asset != g.scope.Asset || a.Workload != g.scope.Workload {
		return ErrAuthorization
	}
	incident, ok := m.cases[a.CaseID]
	if !ok || digest(incident) != c.CaseSHA {
		return ErrAuthorization
	}
	ttl := a.Expires.Sub(a.Issued)
	if !hostguardID(a.Key) || ttl < time.Second || ttl > time.Minute || ttl%time.Second != 0 ||
		a.Hash != digest(Approve{Key: a.Key, CaseID: a.CaseID, TTL: int(ttl / time.Second)}) || a.ID != "isolate-"+a.Hash[:32] {
		return ErrAuthorization
	}
	if kind == "approve" {
		if !a.Issued.Equal(c.Issued) || !at.Before(a.Expires) || c.Expires.After(a.Expires) || incident.Time.After(a.Issued) || at.Sub(incident.Time) > time.Minute {
			return ErrAuthorization
		}
	} else {
		old, exists := m.actions[a.ID]
		if !exists || !sameBinding(a, old) {
			return ErrAuthorization
		}
	}
	var key *actionapproval.Key
	for _, k := range g.trust.Keys {
		if k.ID == c.KeyID {
			copy := k
			key = &copy
		}
	}
	if key == nil || key.Actor != c.Actor || key.Role != c.Role || key.Tenant != a.Tenant ||
		c.Issued.Before(key.From) || !at.Before(key.Until) || c.Expires.After(key.Until) {
		return ErrAuthorization
	}
	pub, _ := hex.DecodeString(key.PublicKey)
	sig, err := hex.DecodeString(s.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize || hex.EncodeToString(sig) != s.Signature || !ed25519.Verify(pub, HostSigningBytes(c), sig) {
		return ErrAuthorization
	}
	if live && g.nonces[c.Nonce] {
		return ErrAuthorizationReplay
	}
	return nil
}

func hostguardID(s string) bool { return hostguard.ID.MatchString(s) }

func (m *Manager) SignedApprove(s HostSigned, now time.Time) (Lease, error) {
	a := s.Command.Lease
	return m.approve(Approve{Key: a.Key, CaseID: a.CaseID, TTL: int(a.Expires.Sub(a.Issued) / time.Second)}, now, &s)
}

func (m *Manager) SignedRelease(s HostSigned, now time.Time) (Lease, error) {
	return m.release(s.Command.Lease.ID, now, &s)
}

func signedRecordSHA(r record) string { r.SHA = ""; return digest(r) }

func (m *Manager) checkSignedRecord(r record) error {
	if m.signing == nil {
		if r.Authorization != nil || r.Previous != "" || r.SHA != "" {
			return ErrAuthorization
		}
		return nil
	}
	if r.Previous != m.signing.head || r.SHA != signedRecordSHA(r) {
		return errors.New("invalid signed host audit chain")
	}
	if r.Action == nil {
		if r.Authorization != nil {
			return ErrAuthorization
		}
		return nil
	}
	a := *r.Action
	old, exists := m.actions[a.ID]
	required := ""
	if !exists {
		required = "approve"
	} else if a.ReleaseRequested && !old.ReleaseRequested {
		required = "release"
	}
	if required == "" {
		if r.Authorization != nil {
			return ErrAuthorization
		}
		return nil
	}
	if r.Authorization == nil || m.signing.nonces[r.Authorization.Command.Nonce] ||
		m.verifyHost(*r.Authorization, required, r.Time, false) != nil || !sameBinding(a, r.Authorization.Command.Lease) ||
		(required == "approve" && (a.State != "pending" || a.ReleaseRequested)) ||
		(required == "release" && a.State != "releasing") {
		return ErrAuthorization
	}
	return nil
}
