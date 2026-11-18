// Package contextshadow observes offline collector snapshots with a pinned v2
// candidate. It cannot install models, consume labels, or change a policy.
package contextshadow

import (
	"embed"
	"encoding/json"
	"errors"
	"reverse-artex/internal/actioncontext"
	"reverse-artex/internal/casememory"
	"reverse-artex/internal/contextlearning"
	"reverse-artex/internal/event"
	"reverse-artex/internal/evidence"
	"reverse-artex/internal/incident"
	"reverse-artex/internal/recovery"
	"time"
)

//go:embed shadow.go
var sourceFiles embed.FS

func SourceSHA() string {
	b, _ := sourceFiles.ReadFile("shadow.go")
	return contextlearning.Digest(string(b))
}

type Row struct {
	CaseID       string                             `json:"case_id"`
	CaseSHA      string                             `json:"case_sha256"`
	Status       string                             `json:"status"`
	Prediction   string                             `json:"prediction"`
	Reason       string                             `json:"reason,omitempty"`
	Features     *[contextlearning.FeatureCount]int `json:"features,omitempty"`
	EvidenceKeys []string                           `json:"evidence_keys_sha256"`
}
type Receipt struct {
	ObserverSourceSHA string    `json:"observer_source_sha256"`
	Schema            string    `json:"schema"`
	Mode              string    `json:"mode"`
	Tenant            string    `json:"tenant_id"`
	CandidateSHA      string    `json:"candidate_sha256"`
	RuntimeSHA        string    `json:"runtime_source_sha256"`
	FeatureSHA        string    `json:"feature_schema_sha256"`
	ContextTrustSHA   string    `json:"context_trust_sha256"`
	SourceSHA         string    `json:"source_snapshot_sha256"`
	ManifestSHA       string    `json:"case_manifest_sha256"`
	StartedAt         time.Time `json:"started_at"`
	FinishedAt        time.Time `json:"finished_at"`
	Planned           int       `json:"planned"`
	Observed          int       `json:"observed"`
	Unavailable       int       `json:"unavailable"`
	OtherTenantCases  int       `json:"other_tenant_cases"`
	CoverageBPS       int       `json:"coverage_bps"`
	DeploymentAllowed bool      `json:"deployment_allowed"`
	Rows              []Row     `json:"rows"`
	SHA               string    `json:"receipt_sha256"`
}

func ReceiptSHA(r Receipt) string { r.SHA = ""; return contextlearning.Digest(r) }

func ValidateCandidate(c contextlearning.Candidate, expected string, authorities casememory.LearningTrust, trust actioncontext.Trust) error {
	if expected == "" || c.SHA != expected || c.ContextTrustSHA != contextlearning.Digest(trust) || trust.Validate() != nil || c.ReviewTrustSHA != casememory.LearningTrustDigest(authorities) {
		return contextlearning.ErrInvalid
	}
	// Freeze validates the exact candidate schema, source/model/vector pins and
	// nondeploying flag without altering the candidate or creating a quality run.
	_, err := contextlearning.Freeze(c, authorities, c.TrainingRecipeSHA)
	return err
}

type records struct{ rows [][]byte }

func (r records) VisitRecords(stream string, visit func([]byte) error) error {
	if stream != "events" {
		return errors.New("HTTP observation stream required")
	}
	for _, raw := range r.rows {
		if err := visit(raw); err != nil {
			return err
		}
	}
	return nil
}
func key(tenant, asset, id string) string { return contextlearning.Digest([]string{tenant, asset, id}) }

// Observe requires a stopped collector or an offline copy, as Capture is not
// an atomic snapshot of a running writer. All selected cases stay in the
// denominator, including host-only, incomplete and training-overlap cases.
func Observe(directory string, c contextlearning.Candidate, expected string, authorities casememory.LearningTrust, trust actioncontext.Trust) (Receipt, error) {
	if err := ValidateCandidate(c, expected, authorities, trust); err != nil {
		return Receipt{}, err
	}
	snapshot, err := evidence.Capture(directory)
	if err != nil {
		return Receipt{}, err
	}
	return ObserveSnapshot(snapshot, c, expected, authorities, trust)
}

// ObserveSnapshot consumes only an immutable snapshot supplied by the collector
// under its commit mutex. Replay and inference run after that mutex is released.
func ObserveSnapshot(snapshot *evidence.Snapshot, c contextlearning.Candidate, expected string, authorities casememory.LearningTrust, trust actioncontext.Trust) (Receipt, error) {
	if err := ValidateCandidate(c, expected, authorities, trust); err != nil {
		return Receipt{}, err
	}
	if snapshot == nil {
		return Receipt{}, contextlearning.ErrInvalid
	}
	start := time.Now().UTC()
	var err error
	if err = recovery.VerifySnapshot(snapshot); err != nil {
		return Receipt{}, err
	}
	var meta recovery.Metadata
	if json.Unmarshal(snapshot.Metadata(), &meta) != nil || meta.ContextTrust == nil || contextlearning.Digest(*meta.ContextTrust) != c.ContextTrustSHA {
		return Receipt{}, contextlearning.ErrInvalid
	}
	manifest, err := incident.Build(snapshot)
	if err != nil {
		return Receipt{}, err
	}
	selected := []incident.Case{}
	other := 0
	for _, x := range manifest.Cases {
		if x.Tenant == c.Tenant {
			selected = append(selected, x)
		} else {
			other++
		}
	}
	if len(selected) > 512 {
		return Receipt{}, errors.New("shadow snapshot exceeds 512 tenant cases; no cases sampled")
	}
	source := map[string][]byte{}
	if err = snapshot.VisitRecords("events", func(raw []byte) error {
		var e event.Event
		if err := json.Unmarshal(raw, &e); err != nil {
			return err
		}
		source[key(e.TenantID, e.AssetID, e.EventID)] = raw
		return nil
	}); err != nil {
		return Receipt{}, err
	}
	r := Receipt{ObserverSourceSHA: SourceSHA(), Schema: "case-context-shadow-receipt/2", Mode: "shadow", Tenant: c.Tenant, CandidateSHA: c.SHA, RuntimeSHA: c.RuntimeSHA, FeatureSHA: c.FeatureSHA, ContextTrustSHA: c.ContextTrustSHA, SourceSHA: snapshot.SHA256(), ManifestSHA: contextlearning.Digest(manifest), StartedAt: start, Planned: len(selected), OtherTenantCases: other, Rows: []Row{}}
	trained := map[string]bool{}
	for _, k := range c.TrainingEvidence {
		trained[k] = true
	}
	for _, x := range selected {
		row := Row{CaseID: x.ID, CaseSHA: contextlearning.Digest(x), Status: "unavailable", Prediction: "unknown", EvidenceKeys: []string{}}
		raw := records{}
		for _, ref := range x.Evidence {
			if ref.Stream == "events" {
				if b, ok := source[key(ref.Tenant, ref.Asset, ref.EventID)]; ok {
					raw.rows = append(raw.rows, b)
				}
			}
		}
		features, e := contextlearning.Extract(raw, []incident.Case{x}, trust)
		if e != nil {
			row.Reason = "incomplete_or_invalid_v2_context"
		} else {
			f := features[0]
			row.EvidenceKeys = f.EvidenceKeys
			overlap := snapshot.SHA256() == c.TrainingSourceSHA
			for _, k := range f.EvidenceKeys {
				overlap = overlap || trained[k]
			}
			if overlap {
				row.Reason = "training_evidence_overlap"
			} else {
				prediction, e := contextlearning.Predict(c.Model, f.Features)
				if e != nil {
					row.Reason = "invalid_feature_vector"
				} else {
					row.Status = "observed"
					row.Prediction = prediction
					row.Features = &f.Features
					r.Observed++
				}
			}
		}
		if row.Status == "unavailable" {
			r.Unavailable++
		}
		r.Rows = append(r.Rows, row)
	}
	if r.Planned > 0 {
		r.CoverageBPS = r.Observed * 10000 / r.Planned
	}
	r.FinishedAt = time.Now().UTC()
	r.SHA = ReceiptSHA(r)
	return r, nil
}
