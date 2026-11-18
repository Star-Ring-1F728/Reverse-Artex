package casefile

import (
	"encoding/json"
	"errors"
	"fmt"
	"reverse-artex/internal/evidence"
	"reverse-artex/internal/recovery"
	"sort"
	"time"
)

// SourceBinding locates one exact raw event within a fully replayed snapshot.
// Ordinal is one-based in both event and evaluation streams. It is not an
// incremental import cursor or a globally unique database sequence.
type SourceBinding struct {
	RefID         string `json:"ref_id"`
	Stream        string `json:"stream"`
	Tenant        string `json:"tenant_id"`
	Asset         string `json:"asset_id"`
	Sensor        string `json:"sensor_id"`
	EventID       string `json:"event_id"`
	LineSHA       string `json:"line_sha256"`
	Ordinal       int    `json:"commit_ordinal"`
	EvaluationSHA string `json:"evaluation_sha256"`
	Result        string `json:"evaluation_result"`
}

type SourceReceipt struct {
	Schema      string                      `json:"schema_version"`
	Scope       string                      `json:"scope"`
	DocumentSHA string                      `json:"document_sha256"`
	SnapshotSHA string                      `json:"snapshot_sha256"`
	MetadataSHA string                      `json:"metadata_sha256"`
	Streams     []evidence.StreamCommitment `json:"streams"`
	Bindings    []SourceBinding             `json:"bindings"`
}

// SourceResult deliberately has its own contract, separate from revision
// history: replaying persisted bytes does not authenticate fixture enrichment.
type SourceResult struct {
	Document ContextDocument `json:"document"`
	Receipt  SourceReceipt   `json:"source_receipt"`
	SHA256   string          `json:"source_receipt_sha256"`
}

// CheckSource verifies the entire bounded detector snapshot, then resolves every
// case reference by (stream, tenant, asset, sensor, event ID) and exact line SHA.
// An ambiguous source anywhere in the snapshot refuses the whole operation.
// All returned data is detached from the source and no source files are written.
func CheckSource(b ContextBundle, at time.Time, s *evidence.Snapshot) (SourceResult, error) {
	doc, err := BuildContext(b, at)
	if err != nil {
		return SourceResult{}, err
	}
	if err := recovery.VerifySnapshot(s); err != nil {
		return SourceResult{}, err
	}
	r := SourceReceipt{Schema: "case-source-receipt/1", Scope: "offline_replayed_detector_snapshot", DocumentSHA: doc.SHA256, SnapshotSHA: s.SHA256(), MetadataSHA: hashBytes(s.Metadata()), Streams: s.Commitments(), Bindings: []SourceBinding{}}
	bySource := map[string]SourceBinding{}
	for _, pair := range [][2]string{{"events", "evaluations"}, {"host-events", "host-evaluations"}} {
		var evals []struct{ SHA, Result string }
		err := s.VisitRecords(pair[1], func(line []byte) error {
			var ev recovery.Evaluation
			if err := json.Unmarshal(line, &ev); err != nil {
				return err
			}
			evals = append(evals, struct{ SHA, Result string }{hashBytes(line), ev.Result})
			return nil
		})
		if err != nil {
			return SourceResult{}, err
		}
		ordinal := 0
		err = s.VisitRecords(pair[0], func(line []byte) error {
			var v struct {
				Tenant  string `json:"tenant_id"`
				Asset   string `json:"asset_id"`
				Sensor  string `json:"sensor_id"`
				EventID string `json:"event_id"`
			}
			if err := json.Unmarshal(line, &v); err != nil {
				return err
			}
			if ordinal >= len(evals) {
				return errors.New("source cursor mismatch")
			}
			ev := evals[ordinal]
			ordinal++
			key := tuple(pair[0], v.Tenant, v.Asset, v.Sensor, v.EventID)
			ref := SourceBinding{Stream: pair[0], Tenant: v.Tenant, Asset: v.Asset, Sensor: v.Sensor, EventID: v.EventID, LineSHA: hashBytes(line), Ordinal: ordinal, EvaluationSHA: ev.SHA, Result: ev.Result}
			if old, exists := bySource[key]; exists {
				if old.LineSHA != ref.LineSHA {
					return errors.New("ambiguous scoped source in detector snapshot")
				}
				return nil // exact replay: retain its first recorded evaluation
			}
			bySource[key] = ref
			return nil
		})
		if err != nil {
			return SourceResult{}, err
		}
	}
	bind := func(id, stream, tenant, asset, sensor, eventID, lineSHA string) error {
		ref, ok := bySource[tuple(stream, tenant, asset, sensor, eventID)]
		if !ok || ref.LineSHA != lineSHA {
			return fmt.Errorf("case ref %s does not match replayed source", id)
		}
		ref.RefID = id
		r.Bindings = append(r.Bindings, ref)
		return nil
	}
	for _, v := range doc.Envelope.HTTP.Evidence {
		if err := bind(v.ID, v.Stream, v.Tenant, v.Asset, v.Sensor, v.EventID, v.LineSHA); err != nil {
			return SourceResult{}, err
		}
	}
	for _, v := range doc.Envelope.Evidence {
		if err := bind(v.ID, v.Stream, v.Tenant, v.Asset, v.Sensor, v.EventID, v.LineSHA); err != nil {
			return SourceResult{}, err
		}
	}
	sort.Slice(r.Bindings, func(i, j int) bool { return r.Bindings[i].RefID < r.Bindings[j].RefID })
	return SourceResult{doc, r, hash(r)}, nil
}
