package casefile

import (
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"time"
)

const MaxPrevious = 2 << 20

type Revision struct {
	Number      int       `json:"revision"`
	DocumentSHA string    `json:"document_sha256"`
	Previous    string    `json:"previous_revision_sha256"`
	ObservedAt  time.Time `json:"observed_at"`
	SHA256      string    `json:"revision_sha256"`
}
type History struct {
	Schema  string     `json:"schema_version"`
	Tenant  string     `json:"tenant_id"`
	CaseID  string     `json:"case_id"`
	Assets  []string   `json:"asset_ids"`
	Entries []Revision `json:"entries"`
}
type ContextResult struct {
	Document ContextDocument `json:"document"`
	History  History         `json:"history"`
}

func revisionHash(h History, r Revision) string {
	r.SHA256 = ""
	return hash([]any{h.Schema, h.Tenant, h.CaseID, h.Assets, r})
}

// ValidatePrevious checks internal consistency, not authenticity or a global
// newest-head guarantee. An operator must select the trusted predecessor.
func ValidatePrevious(p ContextResult) error {
	bad := errors.New("invalid or inconsistent offline revision history")
	data, err := json.Marshal(p)
	if err != nil || len(data) > MaxPrevious {
		return bad
	}
	h := p.History
	e := p.Document.Envelope
	meta := e.HTTP
	if h.Schema != "case-revisions/1" || !identifier.MatchString(h.Tenant) || !identifier.MatchString(h.CaseID) || len(h.Assets) < 1 || len(h.Assets) > MaxAssets || len(h.Entries) < 1 || len(h.Entries) > MaxRevisions ||
		e.Schema != "case-context-envelope/1" || e.Scope != "offline_fixture_registry" || meta.Schema != "case-envelope/1" || meta.Scope != "offline_fixture_registry" || meta.CaseID != h.CaseID || meta.Tenant != h.Tenant || !reflect.DeepEqual(meta.Assets, h.Assets) || !sha.MatchString(p.Document.SHA256) || hash(e) != p.Document.SHA256 {
		return bad
	}
	for i, a := range h.Assets {
		if !identifier.MatchString(a) || (i > 0 && h.Assets[i-1] >= a) {
			return bad
		}
	}
	previous := ""
	var observed time.Time
	for i, r := range h.Entries {
		if r.Number != i+1 || !sha.MatchString(r.DocumentSHA) || r.Previous != previous || r.ObservedAt.IsZero() || r.ObservedAt.Before(observed) || !sha.MatchString(r.SHA256) || revisionHash(h, r) != r.SHA256 {
			return bad
		}
		previous, observed = r.SHA256, r.ObservedAt
	}
	head := h.Entries[len(h.Entries)-1]
	if meta.Revision != head.Number || p.Document.SHA256 != head.DocumentSHA || !meta.ObservedAt.Equal(head.ObservedAt) || e.Previous != head.Previous {
		return bad
	}
	return nil
}

func DecodePrevious(r io.Reader) (ContextResult, error) {
	var p ContextResult
	if err := decodeBounded(r, &p, MaxPrevious); err != nil {
		return p, err
	}
	return p, ValidatePrevious(p)
}

// Advance produces a new immutable output file's contents; it does not mutate
// the predecessor, own a writer lock, arbitrate concurrent forks or stop rollback
// to an older trusted file. Those are requirements of a later durable service.
func Advance(previous *ContextResult, b ContextBundle, at time.Time) (ContextResult, error) {
	if previous != nil {
		if err := ValidatePrevious(*previous); err != nil {
			return ContextResult{}, err
		}
	}
	doc, err := BuildContext(b, at)
	if err != nil {
		return ContextResult{}, err
	}
	meta := doc.Envelope.HTTP
	h := History{Schema: "case-revisions/1", Tenant: meta.Tenant, CaseID: meta.CaseID, Assets: append([]string{}, meta.Assets...), Entries: []Revision{}}
	if previous == nil {
		if meta.Revision != 1 || b.Previous != "" {
			return ContextResult{}, errors.New("new offline history requires revision 1 with empty parent")
		}
	} else {
		h = copyContext(previous.History)
		if h.Tenant != meta.Tenant || h.CaseID != meta.CaseID || !reflect.DeepEqual(h.Assets, meta.Assets) {
			return ContextResult{}, errors.New("revision cannot change case scope")
		}
		head := h.Entries[len(h.Entries)-1]
		if meta.Revision == head.Number {
			if doc.SHA256 != head.DocumentSHA {
				return ContextResult{}, errors.New("same revision has different content")
			}
			return copyContext(*previous), nil
		}
		if len(h.Entries) >= MaxRevisions || meta.Revision != head.Number+1 || b.Previous != head.SHA256 || meta.ObservedAt.Before(head.ObservedAt) {
			return ContextResult{}, errors.New("revision must extend the explicit latest supplied head within capacity")
		}
	}
	r := Revision{Number: meta.Revision, DocumentSHA: doc.SHA256, Previous: b.Previous, ObservedAt: meta.ObservedAt.UTC()}
	r.SHA256 = revisionHash(h, r)
	h.Entries = append(h.Entries, r)
	return ContextResult{doc, h}, nil
}
