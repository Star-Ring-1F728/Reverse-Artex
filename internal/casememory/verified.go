package casememory

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"time"
)

// These are operator-pinned public keys. A signature proves key authorization,
// not reviewer independence, incident truth, or production deployment approval.
type LearningKey struct {
	ID        string `json:"key_id"`
	Actor     string `json:"actor"`
	Role      string `json:"role"`
	PublicKey string `json:"public_key_base64"`
	Revoked   bool   `json:"revoked"`
}
type LearningTrust struct {
	Schema   string        `json:"schema"`
	Tenant   string        `json:"tenant_id"`
	Revision int           `json:"revision"`
	Keys     []LearningKey `json:"keys"`
}
type SignedLabel struct {
	TrustSHA    string    `json:"trust_sha256"`
	Schema      string    `json:"schema"`
	Tenant      string    `json:"tenant_id"`
	CaseID      string    `json:"case_id"`
	Expected    int       `json:"expected_label_revision"`
	Previous    string    `json:"previous_label_sha256"`
	CaseSHA     string    `json:"case_sha256"`
	SourceSHA   string    `json:"source_snapshot_sha256"`
	EvidenceSHA string    `json:"evidence_sha256"`
	Value       string    `json:"value"`
	Reason      string    `json:"reason"`
	Basis       string    `json:"basis"`
	KeyID       string    `json:"key_id"`
	IssuedAt    time.Time `json:"issued_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	Signature   string    `json:"signature_base64"`
}
type LabelProof struct {
	TrustSHA  string      `json:"trust_sha256"`
	Statement SignedLabel `json:"statement"`
}
type SignedAdvisory struct {
	Schema    string          `json:"schema"`
	Tenant    string          `json:"tenant_id"`
	TrustSHA  string          `json:"trust_sha256"`
	Request   AdvisoryRequest `json:"request"`
	KeyID     string          `json:"key_id"`
	IssuedAt  time.Time       `json:"issued_at"`
	ExpiresAt time.Time       `json:"expires_at"`
	Signature string          `json:"signature_base64"`
}
type AdvisoryAuthorization struct {
	Statement SignedAdvisory `json:"statement"`
}

func LearningTrustDigest(p LearningTrust) string { return hash(p) }
func LabelSigningBytes(q SignedLabel) []byte {
	q.Signature = ""
	b, _ := json.Marshal(q)
	return append([]byte("reverse-artex/verified-label/1\n"), b...)
}
func AdvisorySigningBytes(q SignedAdvisory) []byte {
	q.Signature = ""
	b, _ := json.Marshal(q)
	return append([]byte("reverse-artex/verified-advisory/1\n"), b...)
}
func validTrust(p LearningTrust) bool {
	if p.Schema != "case-learning-trust/1" || !identity.MatchString(p.Tenant) || p.Revision < 1 || p.Revision > 8192 || len(p.Keys) == 0 || len(p.Keys) > 32 {
		return false
	}
	seen := map[string]bool{}
	for _, k := range p.Keys {
		public, err := base64.StdEncoding.Strict().DecodeString(k.PublicKey)
		if !identity.MatchString(k.ID) || !identity.MatchString(k.Actor) || seen[k.ID] || !validLearningRole(k.Role) || err != nil || len(public) != ed25519.PublicKeySize {
			return false
		}
		seen[k.ID] = true
	}
	return true
}
func (s *Store) validateLearningTrust(p LearningTrust) error {
	if !validTrust(p) {
		return ErrInvalid
	}
	old, ok := s.trust[p.Tenant]
	if ok && (p.Revision != old.Revision+1) {
		return ErrConflict
	}
	if !ok && p.Revision != 1 {
		return ErrConflict
	}
	return nil
}

// SetLearningTrust is an explicit local operator action, never supplied by a
// signed-label body. Revisions cannot fork or roll back inside this journal.
func (s *Store) SetLearningTrust(p LearningTrust) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return "", err
	}
	if old, ok := s.trust[p.Tenant]; ok && reflect.DeepEqual(old, p) {
		return hash(old), nil
	}
	if err := s.append(record{LearningTrust: &p}); err != nil {
		return "", err
	}
	return hash(p), nil
}
func authorizedKey(p LearningTrust, id, role string) (LearningKey, bool) {
	for _, k := range p.Keys {
		if k.ID == id && k.Role == role && !k.Revoked {
			return k, true
		}
	}
	return LearningKey{}, false
}
func validSignature(k LearningKey, signature string, payload []byte) bool {
	public, e1 := base64.StdEncoding.Strict().DecodeString(k.PublicKey)
	sig, e2 := base64.StdEncoding.Strict().DecodeString(signature)
	return e1 == nil && e2 == nil && len(public) == ed25519.PublicKeySize && len(sig) == ed25519.SignatureSize && ed25519.Verify(public, payload, sig)
}
func admissionTime(issued, expires, at time.Time) bool {
	return !issued.IsZero() && !expires.IsZero() && !at.IsZero() && !at.Before(issued) && at.Before(expires) && expires.After(issued) && expires.Sub(issued) <= 24*time.Hour
}
func (s *Store) validateLabelProof(l Label, rev Revision) error {
	proof := l.Verification
	if proof == nil {
		return ErrInvalid
	}
	p, ok := s.trustHistory[proof.TrustSHA]
	if !ok || hash(s.trust[l.Tenant]) != proof.TrustSHA || p.Tenant != l.Tenant {
		return ErrConflict
	}
	q := proof.Statement
	k, ok := authorizedKey(p, q.KeyID, "label_reviewer")
	if !ok || q.TrustSHA != proof.TrustSHA || q.Schema != "case-verified-label/1" || q.Tenant != l.Tenant || q.CaseID != l.CaseID || q.Expected+1 != l.Revision || q.Previous != l.Previous || q.CaseSHA != l.CaseSHA || q.SourceSHA != rev.Source || q.EvidenceSHA != hash(rev.Case.Evidence) || q.Value != l.Value || q.Reason != l.Reason || q.Basis != "evidence_review" || l.Actor != k.Actor || !admissionTime(q.IssuedAt, q.ExpiresAt, l.At) || !validSignature(k, q.Signature, LabelSigningBytes(q)) {
		return ErrInvalid
	}
	return nil
}
func (s *Store) ImportVerifiedLabel(tenant string, q SignedLabel) (Label, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return Label{}, err
	}
	if tenant != q.Tenant {
		return Label{}, ErrInvalid
	}
	entry, ok := s.cases[caseKey(tenant, q.CaseID)]
	if !ok {
		return Label{}, ErrNotFound
	}
	p := s.trust[tenant]
	k, ok := authorizedKey(p, q.KeyID, "label_reviewer")
	if !ok {
		return Label{}, ErrInvalid
	}
	// Exact retries only acknowledge a still-current receipt; no prediction or
	// label is rewritten, and later corrections cannot be replayed backwards.
	if len(entry.Labels) > 0 {
		old := entry.Labels[len(entry.Labels)-1]
		if old.Verification != nil && old.Verification.TrustSHA == hash(p) && reflect.DeepEqual(old.Verification.Statement, q) && old.CaseSHA == entry.Revisions[len(entry.Revisions)-1].SHA {
			return clone(old), nil
		}
	}
	previous := ""
	if len(entry.Labels) > 0 {
		previous = entry.Labels[len(entry.Labels)-1].SHA
	}
	if q.Expected != len(entry.Labels) || q.Previous != previous {
		return Label{}, ErrConflict
	}
	l := Label{Tenant: tenant, CaseID: q.CaseID, Revision: q.Expected + 1, Previous: previous, CaseSHA: q.CaseSHA, Value: q.Value, Reason: q.Reason, Actor: k.Actor, At: time.Now().UTC(), Verification: &LabelProof{hash(p), q}}
	l.SHA = labelHash(l)
	// Reject invalid signatures before automatic observation can have effects.
	if err := s.validate(record{Label: &l}); err != nil {
		return Label{}, err
	}
	if err := s.captureAutomaticLocked(); err != nil {
		return Label{}, err
	}
	l.At = time.Now().UTC()
	l.SHA = labelHash(l)
	if err := s.append(record{Label: &l}); err != nil {
		return Label{}, err
	}
	return clone(l), s.captureAutomaticLocked()
}
func (s *Store) verifiedBinding(tenant, id, sha string, policy LearningTrust) bool {
	e, ok := s.cases[caseKey(tenant, id)]
	if !ok || len(e.Labels) == 0 {
		return false
	}
	l := e.Labels[len(e.Labels)-1]
	if l.SHA != sha || l.CaseSHA != e.Revisions[len(e.Revisions)-1].SHA || l.Verification == nil {
		return false
	}
	old, ok := s.trustHistory[l.Verification.TrustSHA]
	if !ok {
		return false
	}
	previousKey, ok := authorizedKey(old, l.Verification.Statement.KeyID, "label_reviewer")
	currentKey, allowed := authorizedKey(policy, l.Verification.Statement.KeyID, "label_reviewer")
	return ok && allowed && reflect.DeepEqual(previousKey, currentKey)
}
func (s *Store) selectVerified(tenant string) Selection {
	x := s.selectCases(tenant)
	x.Schema = "case-learning-selection/2"
	x.TrustSHA = hash(s.trust[tenant])
	x.Eligible, x.Excluded = 0, 0
	for i := range x.Items {
		b := &x.Items[i]
		if b.Exclusion == "" && !s.verifiedBinding(tenant, b.CaseID, b.LabelSHA, s.trust[tenant]) {
			b.Exclusion = "unverified_label_authority"
		}
		if b.Exclusion == "" {
			x.Eligible++
		} else {
			x.Excluded++
		}
	}
	x.SHA = selectionHash(x)
	return x
}
func (s *Store) selectionFor(old Selection) Selection {
	if old.TrustSHA != "" {
		return s.selectVerified(old.Tenant)
	}
	return s.selectCases(old.Tenant)
}
func (s *Store) SelectVerified(tenant string, save bool) (Selection, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return Selection{}, err
	}
	if !validTrust(s.trust[tenant]) {
		return Selection{}, ErrInvalid
	}
	x := s.selectVerified(tenant)
	if save {
		if _, exists := s.selections[x.SHA]; !exists {
			if err := s.append(record{Selection: &x}); err != nil {
				return Selection{}, err
			}
		}
	}
	return clone(x), nil
}
func (s *Store) validateAdvisoryAuthorization(c AdvisoryChange) error {
	if c.Request.Action == "stop" {
		if c.Authorization != nil {
			return ErrInvalid
		}
		return nil
	}
	state := s.shadows[c.Request.RunID]
	candidate := s.candidates[state.Plan.CandidateID]
	if c.Authorization == nil {
		if candidate.Selection.TrustSHA != "" || s.trust[c.Tenant].Schema != "" {
			return ErrInvalid
		}
		return nil
	}
	q := c.Authorization.Statement
	p := s.trust[c.Tenant]
	key, ok := authorizedKey(p, q.KeyID, "release_approver")
	if !ok || candidate.Selection.TrustSHA == "" || candidate.Selection.TrustSHA != hash(p) || q.TrustSHA != hash(p) || q.Schema != "case-verified-advisory/1" || q.Tenant != c.Tenant || q.Request != c.Request || !admissionTime(q.IssuedAt, q.ExpiresAt, c.At) || !validSignature(key, q.Signature, AdvisorySigningBytes(q)) {
		return ErrInvalid
	}
	snapshot := reviewSnapshot(state)
	if snapshot == nil {
		return ErrConflict
	}
	for _, row := range snapshot.Rows {
		if row.Status == "scored" {
			if !s.verifiedBinding(c.Tenant, row.CaseID, row.LabelSHA, p) {
				return ErrConflict
			}
			entry := s.cases[caseKey(c.Tenant, row.CaseID)]
			if !entry.Labels[len(entry.Labels)-1].Verification.Statement.IssuedAt.After(row.PredictedAt) {
				return ErrConflict
			}
		}
	}
	return nil
}
func (s *Store) ChangeSignedAdvisory(tenant string, q SignedAdvisory) (AdvisoryView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return AdvisoryView{}, err
	}
	if tenant != q.Tenant || q.Request.Reason != strings.TrimSpace(q.Request.Reason) || q.Request.Action == "stop" {
		return AdvisoryView{}, ErrInvalid
	}
	return s.changeAdvisoryLocked(tenant, q.Request, &AdvisoryAuthorization{q})
}

// LearningTrust returns the last operator-installed policy, including public
// key revocations. Callers cannot change it through a label or release request.
func (s *Store) LearningTrust(tenant string) (LearningTrust, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return LearningTrust{}, err
	}
	p, ok := s.trust[tenant]
	if !ok {
		return LearningTrust{}, ErrNotFound
	}
	return clone(p), nil
}
