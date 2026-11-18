package contextrelease

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"regexp"
	"reverse-artex/internal/contextadmission"
	"reverse-artex/internal/contextlearning"
	"reverse-artex/internal/evidence"
	"reverse-artex/internal/incident"
	"reverse-artex/internal/recovery"
	"sort"
	"strings"
	"time"
)

var pin = regexp.MustCompile(`^[a-f0-9]{64}$`)
var id = regexp.MustCompile(`^[A-Za-z0-9_.:/{}-]{1,128}$`)

func clone[T any](v T) T        { raw, _ := json.Marshal(v); var out T; json.Unmarshal(raw, &out); return out }
func reasonValid(v string) bool { return strings.TrimSpace(v) != "" && len(v) <= 512 }

func ValidateConfig(c Config) error {
	p := c.Policy
	t, err := contextadmission.PolicyTemplate(p.Tenant, c.Authorities, c.Context)
	if err != nil {
		return ErrInvalid
	}
	t.Enabled = c.Admission.Enabled
	t.Revision = c.Admission.Revision
	t.MaximumReportAgeSeconds = c.Admission.MaximumReportAgeSeconds
	if c.Admission != t || t.Revision < 1 || t.MaximumReportAgeSeconds < 60 || t.MaximumReportAgeSeconds > 86400 || p.Schema != "case-context-canary-policy/2" || p.Revision < 1 || p.Scope != "canary_observation/2" || p.AdmissionPolicySHA != contextlearning.Digest(c.Admission) || p.SourceSHA != SourceSHA() || len(p.Approvers) < 1 || len(p.Approvers) > 4 {
		return ErrInvalid
	}
	ids, actors, pubs := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, k := range c.Authorities.Keys {
		actors[k.Actor] = true
		raw, _ := base64.StdEncoding.Strict().DecodeString(k.PublicKey)
		pubs[string(raw)] = true
	}
	for _, k := range c.Context.Keys {
		raw, _ := base64.StdEncoding.Strict().DecodeString(k.PublicKey)
		pubs[string(raw)] = true
	}
	active := false
	for _, k := range p.Approvers {
		raw, e := base64.StdEncoding.Strict().DecodeString(k.PublicKey)
		if e != nil || len(raw) != 32 || !id.MatchString(k.ID) || !id.MatchString(k.Actor) || k.Role != "context_canary_approver" || ids[k.ID] || actors[k.Actor] || pubs[string(raw)] {
			return ErrInvalid
		}
		ids[k.ID], actors[k.Actor], pubs[string(raw)] = true, true, true
		active = active || !k.Revoked
	}
	if !active {
		return ErrInvalid
	}
	return nil
}

func assess(c Config, b Bundle, at time.Time) (contextadmission.Decision, error) {
	if ValidateConfig(c) != nil || !c.Policy.Enabled {
		return contextadmission.Decision{}, ErrInvalid
	}
	d, e := contextadmission.Assess(c.Admission, b.Capsule, b.Endorsement, c.Authorities, c.Context, at)
	if e != nil || !d.Accepted {
		return d, ErrInvalid
	}
	return d, nil
}

func verifyApproval(c Config, b Bundle, base Baseline, a Approval, at time.Time) error {
	d, e := assess(c, b, at)
	if e != nil {
		return e
	}
	r := a.Request
	if a.Schema != "case-context-canary-approval/2" || a.Tenant != c.Policy.Tenant || r.Action != "canary" && r.Action != "rollback" || r.BundleSHA != BundleSHA(b) || r.PolicySHA != contextlearning.Digest(c.Policy) || r.BaselineSHA != contextlearning.Digest(base) || r.Percent < 1 || r.Percent > 50 || !pin.MatchString(r.Nonce) || !reasonValid(r.Reason) || !at.Before(r.Until) || r.Until.After(d.ValidUntil) || a.IssuedAt.IsZero() || a.IssuedAt.After(at) || !at.Before(a.ExpiresAt) || a.ExpiresAt.Sub(a.IssuedAt) > 15*time.Minute || !a.ExpiresAt.After(a.IssuedAt) {
		return ErrInvalid
	}
	sig, e := base64.StdEncoding.Strict().DecodeString(a.Signature)
	if e != nil || len(sig) != 64 {
		return ErrInvalid
	}
	for _, k := range c.Policy.Approvers {
		if k.ID == a.KeyID && !k.Revoked {
			pub, _ := base64.StdEncoding.Strict().DecodeString(k.PublicKey)
			if ed25519.Verify(pub, SigningBytes(a), sig) {
				return nil
			}
		}
	}
	return ErrInvalid
}

func CaptureBaseline(snapshot *evidence.Snapshot, tenant string) (Baseline, error) {
	if snapshot == nil || !id.MatchString(tenant) || recovery.VerifySnapshot(snapshot) != nil {
		return Baseline{}, ErrInvalid
	}
	m, e := incident.Build(snapshot)
	if e != nil {
		return Baseline{}, e
	}
	b := Baseline{SourceSHA: snapshot.SHA256(), Cases: []string{}, Evidence: []string{}}
	keys := map[string]bool{}
	for _, c := range m.Cases {
		if c.Tenant != tenant {
			continue
		}
		b.Cases = append(b.Cases, c.ID)
		for _, r := range c.Evidence {
			keys[contextlearning.Digest([]string{r.Stream, r.Tenant, r.Asset, r.EventID, r.LineSHA})] = true
		}
	}
	for key := range keys {
		b.Evidence = append(b.Evidence, key)
	}
	sort.Strings(b.Cases)
	sort.Strings(b.Evidence)
	if !validBaseline(b) {
		return Baseline{}, ErrLimit
	}
	return b, nil
}
func validBaseline(b Baseline) bool {
	if !pin.MatchString(b.SourceSHA) || b.Cases == nil || b.Evidence == nil || len(b.Cases) > 512 || len(b.Evidence) > 4096 || !sort.StringsAreSorted(b.Cases) || !sort.StringsAreSorted(b.Evidence) {
		return false
	}
	for i, v := range b.Cases {
		if !id.MatchString(v) || i > 0 && v == b.Cases[i-1] {
			return false
		}
	}
	for i, v := range b.Evidence {
		if !pin.MatchString(v) || i > 0 && v == b.Evidence[i-1] {
			return false
		}
	}
	return true
}
func branch(candidate, tenant, caseID string, percent int) string {
	s := sha256.Sum256([]byte(contextlearning.Digest([]string{"context-canary-bucket/2", candidate, tenant, caseID})))
	if int(binary.BigEndian.Uint64(s[:8])%100) < percent {
		return "candidate"
	}
	return "reference"
}
