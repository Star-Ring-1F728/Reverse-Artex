package caseledger

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"time"

	"reverse-artex/internal/control"
	"reverse-artex/internal/event"
	"reverse-artex/internal/evidence"
	"reverse-artex/internal/policy"
)

const MaxPolicyWAL = 4 << 20
const MaxPolicyBinding = 256 << 10
const MaxPolicyRows = 128

type policyAudit struct {
	Version   uint64         `json:"version"`
	Epoch     string         `json:"epoch"`
	Time      time.Time      `json:"time"`
	Operation string         `json:"operation"`
	Actor     string         `json:"actor"`
	Key       string         `json:"command_key,omitempty"`
	Hash      string         `json:"command_hash,omitempty"`
	Policy    *policy.Policy `json:"policy,omitempty"`
	Removed   []string       `json:"removed,omitempty"`
	Auto      bool           `json:"auto_enabled"`
	Refs      []string       `json:"evidence_refs,omitempty"`
	Evidence  *event.Event   `json:"evidence,omitempty"`
}

// PolicyBinding is a finite, explicit selection from an imported offline WAL.
// It is not a tenant-wide history or a statement of current enforcement state.
// Raw rows stay inside the trusted ledger and never enter a tool projection.
type PolicyBinding struct {
	Schema        string    `json:"schema"`
	Case          Receipt   `json:"case"`
	AuditSource   string    `json:"audit_source_id"`
	WALSHA        string    `json:"wal_sha256"`
	WALRows       int       `json:"wal_rows"`
	Epoch         string    `json:"epoch"`
	AsOf          time.Time `json:"as_of"`
	PolicyIDs     []string  `json:"policy_ids"`
	AuditRows     [][]byte  `json:"audit_rows"`
	EvidenceLines [][]byte  `json:"evidence_lines"`
}
type PolicyReview struct {
	Binding PolicyBinding `json:"binding"`
	SHA256  string        `json:"binding_sha256"`
}
type PreparedPolicyHistory struct {
	data []byte
	sha  string
}

func (p *PreparedPolicyHistory) Review() PolicyReview {
	var b PolicyBinding
	if p == nil {
		return PolicyReview{}
	}
	_ = json.Unmarshal(p.data, &b)
	return PolicyReview{b, p.sha}
}

// PolicyEntry contains recorded operations, never inferred active policies.
type PolicyEntry struct {
	Policy    policy.Policy
	Operation string
	Time      time.Time
	Epoch     string
	Version   uint64
	LineSHA   string
	Refs      []string
}

func decodePolicyAudit(raw []byte) (policyAudit, error) {
	var r policyAudit
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if len(raw) > 1<<20 || d.Decode(&r) != nil {
		return r, errors.New("invalid policy audit row")
	}
	var extra any
	if d.Decode(&extra) != io.EOF || r.Version < 1 || r.Version > 100000 || !policy.ID.MatchString(r.Epoch) || r.Time.IsZero() {
		return r, errors.New("invalid policy audit identity")
	}
	return r, nil
}

func readPolicyWAL(path string) ([]byte, error) {
	st, err := os.Lstat(path)
	if err != nil || !st.Mode().IsRegular() || st.Size() < 1 || st.Size() > MaxPolicyWAL || filepath.Base(path) != "actions.jsonl" {
		return nil, errors.New("bounded offline actions.jsonl required")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("policy WAL unavailable")
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, MaxPolicyWAL+1))
	if err != nil || len(raw) == 0 || len(raw) > MaxPolicyWAL || raw[len(raw)-1] != '\n' {
		return nil, errors.New("complete bounded policy WAL required")
	}
	return raw, nil
}

// PreparePolicyHistory needs both private B04 replay and the same frozen
// detector snapshot. A serialized review is never an offline replay proof.
func PreparePolicyHistory(p *Prepared, s *evidence.Snapshot, path, auditSource string, ids []string, asOf time.Time) (*PreparedPolicyHistory, error) {
	if p == nil || s == nil || !identifier.MatchString(auditSource) || len(ids) < 1 || len(ids) > 16 || asOf.IsZero() {
		return nil, errors.New("replayed case, audit source, selected policies and as-of required")
	}
	r := p.Review()
	if s.SHA256() != r.Plan.Commit.SnapshotSHA || asOf.Before(r.Plan.Commit.ObservedAt) {
		return nil, errors.New("policy source or as-of mismatch")
	}
	raw, err := readPolicyWAL(path)
	if err != nil {
		return nil, err
	}
	// Replay a private copy of the bounded frozen bytes. Never open the source
	// controller for writing or let a concurrent append enter recovery replay.
	tmp, err := os.MkdirTemp("", "ra-policy-replay-")
	if err != nil {
		return nil, errors.New("policy replay workspace unavailable")
	}
	defer os.RemoveAll(tmp)
	if err = os.WriteFile(filepath.Join(tmp, "actions.jsonl"), raw, 0600); err != nil {
		return nil, errors.New("policy replay copy unavailable")
	}
	m, err := control.Open(tmp)
	if err != nil {
		return nil, errors.New("policy WAL recovery refused")
	}
	_ = m.Close()
	ids = append([]string{}, ids...)
	sort.Strings(ids)
	selected := map[string]bool{}
	for _, id := range ids {
		if !policy.ID.MatchString(id) || selected[id] {
			return nil, errors.New("unique policy selection required")
		}
		selected[id] = true
	}
	b := PolicyBinding{Schema: "case-policy-binding/1", Case: receipt(r.Plan, r.SHA256), AuditSource: auditSource, WALSHA: hash(raw), AsOf: asOf.UTC(), PolicyIDs: ids, AuditRows: [][]byte{}, EvidenceLines: [][]byte{}}
	var previous time.Time
	for _, line := range bytes.Split(raw[:len(raw)-1], []byte{'\n'}) {
		x, e := decodePolicyAudit(line)
		if e != nil || x.Version != uint64(b.WALRows+1) || (!previous.IsZero() && x.Time.Before(previous)) || (b.Epoch != "" && b.Epoch != x.Epoch) {
			return nil, errors.New("policy WAL chain or time mismatch")
		}
		b.Epoch = x.Epoch
		b.WALRows++
		previous = x.Time
		if b.WALRows > 100000 {
			return nil, errors.New("policy WAL row limit")
		}
		if x.Time.After(asOf) {
			continue
		}
		keep := x.Policy != nil && selected[x.Policy.ID]
		for _, id := range x.Removed {
			keep = keep || selected[id]
		}
		if keep {
			// A mixed batch could disclose another tenant's IDs through the raw
			// proof. Require an explicit selection containing the whole batch.
			for _, id := range x.Removed {
				if !selected[id] {
					return nil, errors.New("mixed policy removal batch outside selection")
				}
			}
			b.AuditRows = append(b.AuditRows, bytes.Clone(line))
		}
	}
	needed := map[string]bool{}
	for _, line := range b.AuditRows {
		x, _ := decodePolicyAudit(line)
		if x.Policy != nil {
			for _, id := range x.Refs {
				needed[id] = true
			}
		}
	}
	if err = s.VisitRecords("events", func(line []byte) error {
		var e event.Event
		if json.Unmarshal(line, &e) != nil {
			return errors.New("invalid source event")
		}
		if needed[e.EventID] {
			b.EvidenceLines = append(b.EvidenceLines, bytes.Clone(line))
		}
		return nil
	}); err != nil {
		return nil, err
	}
	data := encoded(b)
	out := PolicyReview{b, hash(data)}
	if _, err = ValidatePolicyHistory(r, out); err != nil {
		return nil, err
	}
	current, err := readPolicyWAL(path)
	if err != nil || !bytes.Equal(raw, current) {
		return nil, errors.New("policy WAL changed during preparation")
	}
	return &PreparedPolicyHistory{data, out.SHA256}, nil
}

// ValidatePolicyHistory checks the frozen selection against a verified case.
// DB readers additionally match every raw row to the existing legacy audit.
func ValidatePolicyHistory(r Review, review PolicyReview) ([]PolicyEntry, error) {
	bad := errors.New("policy history binding inconsistent")
	b := review.Binding
	if len(encoded(b)) > MaxPolicyBinding || review.SHA256 != hash(encoded(b)) || b.Schema != "case-policy-binding/1" || b.Case != receipt(r.Plan, r.SHA256) || !identifier.MatchString(b.AuditSource) || !digest.MatchString(b.WALSHA) || b.WALRows < 1 || b.WALRows > 100000 || !policy.ID.MatchString(b.Epoch) || b.AsOf.Before(r.Plan.Commit.ObservedAt) || len(b.PolicyIDs) < 1 || len(b.PolicyIDs) > 16 || len(b.AuditRows) < 1 || len(b.AuditRows) > MaxPolicyRows || len(b.EvidenceLines) > 128 {
		return nil, bad
	}
	selected := map[string]bool{}
	for i, id := range b.PolicyIDs {
		if !policy.ID.MatchString(id) || selected[id] || (i > 0 && b.PolicyIDs[i-1] >= id) {
			return nil, bad
		}
		selected[id] = true
	}
	type proof struct {
		event event.Event
		ref   string
	}
	events := map[string]proof{}
	for _, line := range b.EvidenceLines {
		var e event.Event
		if json.Unmarshal(line, &e) != nil || e.EventID == "" {
			return nil, bad
		}
		ref := ""
		matches := 0
		for _, x := range r.Plan.Source.Bindings {
			if x.Stream == "events" && x.EventID == e.EventID && x.Tenant == e.TenantID && x.Asset == e.AssetID && x.Sensor == e.SensorID && x.LineSHA == hash(line) {
				ref = x.RefID
				matches++
			}
		}
		if matches != 1 {
			return nil, bad
		}
		if _, ok := events[e.EventID]; ok {
			return nil, bad
		}
		events[e.EventID] = proof{e, ref}
	}
	policies := map[string]policy.Policy{}
	removed := map[string]bool{}
	used := map[string]bool{}
	var result []PolicyEntry
	var version uint64
	var previous time.Time
	for _, line := range b.AuditRows {
		x, err := decodePolicyAudit(line)
		if err != nil || x.Epoch != b.Epoch || x.Version <= version || x.Version > uint64(b.WALRows) || x.Time.After(b.AsOf) || (!previous.IsZero() && x.Time.Before(previous)) {
			return nil, bad
		}
		version = x.Version
		previous = x.Time
		if x.Policy != nil {
			p := *x.Policy
			if !selected[p.ID] || policies[p.ID].ID != "" || (x.Operation != "approve" && x.Operation != "auto-deny") || len(x.Removed) != 0 || p.Version != x.Version || !p.Issued.Equal(x.Time) || policy.ValidateScoped(p, x.Time) != nil || p.Tenant != b.Case.Tenant || len(x.Refs) < 1 || len(x.Refs) > 16 {
				return nil, bad
			}
			asset := false
			for _, a := range r.Plan.Commit.Assets {
				asset = asset || a == p.Asset
			}
			if !asset {
				return nil, bad
			}
			refs := []string{}
			seen := map[string]bool{}
			for _, id := range x.Refs {
				e, ok := events[id]
				if !ok || seen[id] || e.event.TenantID != p.Tenant || e.event.AssetID != p.Asset || e.event.Principal != p.Principal || e.event.SessionHMAC != p.Session || e.event.EventTime.After(p.Issued) {
					return nil, bad
				}
				seen[id] = true
				used[id] = true
				refs = append(refs, e.ref)
			}
			if x.Operation == "auto-deny" && x.Evidence == nil {
				return nil, bad
			}
			if x.Evidence != nil {
				e, ok := events[x.Evidence.EventID]
				if !ok || !seen[x.Evidence.EventID] {
					return nil, bad
				}
				a, c := e.event, *x.Evidence
				a.IngestTime = time.Time{}
				c.IngestTime = time.Time{}
				if !reflect.DeepEqual(a, c) {
					return nil, bad
				}
			}
			sort.Strings(refs)
			policies[p.ID] = p
			result = append(result, PolicyEntry{p, x.Operation, x.Time, x.Epoch, x.Version, hash(line), refs})
		} else {
			if (x.Operation != "expire" && x.Operation != "revoke" && x.Operation != "rollback") || len(x.Removed) < 1 || len(x.Removed) > 16 {
				return nil, bad
			}
			seen := map[string]bool{}
			for _, id := range x.Removed {
				p, ok := policies[id]
				if !selected[id] || !ok || removed[id] || seen[id] || x.Time.Before(p.Issued) {
					return nil, bad
				}
				seen[id] = true
				removed[id] = true
				result = append(result, PolicyEntry{p, x.Operation, x.Time, x.Epoch, x.Version, hash(line), []string{}})
			}
		}
	}
	if len(policies) != len(selected) || len(used) != len(events) || len(result) > MaxPolicyRows {
		return nil, bad
	}
	return result, nil
}

func policyAuditKeys(b PolicyBinding) []string {
	keys := []string{}
	for _, line := range b.AuditRows {
		x, _ := decodePolicyAudit(line)
		keys = append(keys, x.Epoch+":"+strconv.FormatUint(x.Version, 10))
	}
	return keys
}
