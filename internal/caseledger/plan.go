// Package caseledger binds replay-verified case history to an existing source
// ledger. Its DB commit hash is distinct from the unchanged B03 revision hash.
package caseledger

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"regexp"
	"reverse-artex/internal/casefile"
	"reverse-artex/internal/evidence"
	"reverse-artex/internal/sourceledger"
	"time"
)

const MaxPlan = 4 << 20

var digest = regexp.MustCompile(`^[a-f0-9]{64}$`)
var identifier = regexp.MustCompile(`^[A-Za-z0-9_.:/{}-]{1,128}$`)

type Commit struct {
	Schema           string    `json:"schema_version"`
	Namespace        string    `json:"source_namespace"`
	Tenant           string    `json:"tenant_id"`
	CaseID           string    `json:"case_id"`
	Assets           []string  `json:"asset_ids"`
	Revision         int       `json:"revision"`
	DocumentSHA      string    `json:"document_sha256"`
	SourceReceiptSHA string    `json:"source_receipt_sha256"`
	SourcePlanSHA    string    `json:"source_plan_sha256"`
	SnapshotSHA      string    `json:"snapshot_sha256"`
	Previous         string    `json:"previous_commit_sha256"`
	ObservedAt       time.Time `json:"observed_at"`
}
type Plan struct {
	Schema    string                 `json:"schema_version"`
	AsOf      time.Time              `json:"as_of"`
	Context   casefile.ContextResult `json:"context"`
	Source    casefile.SourceReceipt `json:"source_receipt"`
	Commit    Commit                 `json:"commit"`
	CommitSHA string                 `json:"commit_sha256"`
}
type Review struct {
	Plan   Plan   `json:"plan"`
	SHA256 string `json:"plan_sha256"`
}

// Prepared contains canonical, frozen bytes created only by Prepare. No JSON
// review file is accepted as evidence of replay. Review is a detached copy.
type Prepared struct {
	data []byte
	sha  string
}

func hash(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func encoded(v any) []byte { b, _ := json.Marshal(v); return b }
func (p *Prepared) Review() Review {
	var v Plan
	if p != nil {
		_ = json.Unmarshal(p.data, &v)
		return Review{v, p.sha}
	}
	return Review{}
}

func Prepare(namespace, tenant string, b casefile.ContextBundle, previous *casefile.ContextResult, expected string, at time.Time, s *evidence.Snapshot) (*Prepared, error) {
	// Freeze before builders sort slices or inspect pointer-valued declarations.
	raw, err := json.Marshal(b)
	if err != nil || len(raw) > casefile.MaxBundle {
		return nil, errors.New("bounded case fixture required")
	}
	if err = json.Unmarshal(raw, &b); err != nil {
		return nil, err
	}
	if previous != nil {
		raw, err = json.Marshal(previous)
		if err != nil || len(raw) > casefile.MaxPrevious {
			return nil, errors.New("bounded predecessor required")
		}
		var v casefile.ContextResult
		if err = json.Unmarshal(raw, &v); err != nil {
			return nil, err
		}
		previous = &v
	}
	if b.HTTP.Tenant != tenant || (b.HTTP.Revision == 1 && (expected != "" || previous != nil)) || (b.HTTP.Revision > 1 && (!digest.MatchString(expected) || previous == nil || len(previous.History.Entries) != b.HTTP.Revision-1)) {
		return nil, errors.New("case tenant and explicit DB/document predecessors required")
	}
	source, err := sourceledger.Prepare(namespace, tenant, s)
	if err != nil {
		return nil, err
	}
	result, err := casefile.Advance(previous, b, at)
	if err != nil {
		return nil, err
	}
	checked, err := casefile.CheckSource(b, at, s)
	if err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(result.Document, checked.Document) {
		return nil, errors.New("case/source document mismatch")
	}
	meta := result.Document.Envelope.HTTP
	c := Commit{"case-ledger-commit/1", namespace, tenant, meta.CaseID, append([]string{}, meta.Assets...), meta.Revision, metaSHA(result), checked.SHA256, source.Review().SHA256, checked.Receipt.SnapshotSHA, expected, meta.ObservedAt.UTC()}
	v := Plan{"case-ledger-plan/1", at.UTC(), result, checked.Receipt, c, hash(encoded(c))}
	raw = encoded(v)
	if len(raw) > MaxPlan {
		return nil, errors.New("case ledger plan byte limit")
	}
	if err = validate(v); err != nil {
		return nil, err
	}
	return &Prepared{raw, hash(raw)}, nil
}
func metaSHA(p casefile.ContextResult) string { return p.Document.SHA256 }

// validate deliberately uses the recorded as-of; historical expiry is never
// reinterpreted against wall-clock time. B03 history validation remains intact.
func validate(v Plan) error {
	bad := errors.New("inconsistent case ledger plan")
	c, r, h, e := v.Commit, v.Source, v.Context.History, v.Context.Document.Envelope
	m := e.HTTP
	if len(encoded(v)) > MaxPlan || v.Schema != "case-ledger-plan/1" || v.AsOf.IsZero() || v.AsOf.Before(m.ObservedAt) || !v.AsOf.Before(m.ExpiresAt) || casefile.ValidatePrevious(v.Context) != nil {
		return bad
	}
	if c.Schema != "case-ledger-commit/1" || c.Tenant != h.Tenant || c.CaseID != h.CaseID || !reflect.DeepEqual(c.Assets, h.Assets) || c.Revision != len(h.Entries) || c.DocumentSHA != v.Context.Document.SHA256 || !c.ObservedAt.Equal(m.ObservedAt) || !digest.MatchString(c.SourcePlanSHA) || !digest.MatchString(c.SnapshotSHA) || c.SourceReceiptSHA != hash(encoded(r)) || v.CommitSHA != hash(encoded(c)) || (c.Revision == 1 && c.Previous != "") || (c.Revision > 1 && !digest.MatchString(c.Previous)) {
		return bad
	}
	if r.Schema != "case-source-receipt/1" || r.Scope != "offline_replayed_detector_snapshot" || r.DocumentSHA != c.DocumentSHA || r.SnapshotSHA != c.SnapshotSHA || !digest.MatchString(r.MetadataSHA) || len(r.Streams) != 6 || len(r.Bindings) != len(e.Evidence)+len(m.Evidence) {
		return bad
	}
	// Each receipt binding must match exactly one context reference. Stream and
	// raw identity are bound here; evaluation commitments are checked against DB.
	refs := map[string]casefile.SourceBinding{}
	for _, x := range m.Evidence {
		refs[x.ID] = casefile.SourceBinding{RefID: x.ID, Stream: x.Stream, Tenant: x.Tenant, Asset: x.Asset, Sensor: x.Sensor, EventID: x.EventID, LineSHA: x.LineSHA}
	}
	for _, x := range e.Evidence {
		if _, ok := refs[x.ID]; ok {
			return bad
		}
		refs[x.ID] = casefile.SourceBinding{RefID: x.ID, Stream: x.Stream, Tenant: x.Tenant, Asset: x.Asset, Sensor: x.Sensor, EventID: x.EventID, LineSHA: x.LineSHA}
	}
	for i, x := range r.Bindings {
		want, ok := refs[x.RefID]
		if !ok || (i > 0 && r.Bindings[i-1].RefID >= x.RefID) || x.Tenant != c.Tenant || x.Ordinal < 1 || x.Ordinal > 100000 || !digest.MatchString(x.EvaluationSHA) || x.Result == "" {
			return bad
		}
		x.Ordinal = 0
		x.EvaluationSHA = ""
		x.Result = ""
		if x != want {
			return bad
		}
		delete(refs, x.RefID)
	}
	if len(refs) != 0 {
		return bad
	}
	return nil
}
