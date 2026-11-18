// Package contextlearning provides the versioned, nondeploying G09 feature-v2
// trainer/evaluator. Legacy 14-element models and arrays are never padded.
package contextlearning

import (
	"encoding/json"
	"errors"
	"reverse-artex/internal/actioncontext"
	"reverse-artex/internal/event"
	"reverse-artex/internal/incident"
	"reverse-artex/internal/recovery"
	"sort"
	"time"
)

const FeatureCount = 24
const Schema = "case-context-features/2"

var ErrInvalid = errors.New("invalid context-learning v2 contract")
var FeatureNames = [FeatureCount]string{"evidence_count", "alert_count", "duration_seconds_capped_86400", "http_evidence_count", "host_evidence_count", "distinct_rules", "ra001_count", "ra002_count", "ra003_count", "ra004_count", "ra005_count", "ra006_count", "ra007_count", "ra008_count", "unpermitted_sensitive_observations", "authorization_denials", "validation_rejections", "private_canary_observations", "scoped_test_permissions", "unpermitted_authorization_denials", "unpermitted_validation_rejections", "unpermitted_canary_observations", "permitted_sensitive_observations", "authorized_successes"}

func Digest(v any) string { return actioncontext.Digest(v) }

type Row struct {
	ID                 string            `json:"id"`
	Family             string            `json:"family"`
	SourceGroup        string            `json:"source_group"`
	EvidenceKeys       []string          `json:"evidence_keys_sha256"`
	Features           [FeatureCount]int `json:"features"`
	ContextCoverageBPS int               `json:"context_coverage_bps"`
}
type Inputs struct {
	CreatedAt       time.Time `json:"created_at"`
	RecipeSHA       string    `json:"recipe_sha256"`
	Schema          string    `json:"schema"`
	Purpose         string    `json:"purpose"`
	DatasetID       string    `json:"dataset_id"`
	Tenant          string    `json:"tenant_id"`
	SourceSHA       string    `json:"source_snapshot_sha256"`
	ContextTrustSHA string    `json:"context_trust_sha256"`
	Rows            []Row     `json:"rows"`
}
type GoldRow struct {
	ID    string `json:"id"`
	Value string `json:"value"`
}
type Gold struct {
	Schema    string    `json:"schema"`
	DatasetID string    `json:"dataset_id"`
	Rows      []GoldRow `json:"rows"`
}

func baseFeatures(c incident.Case) [FeatureCount]int {
	v := [FeatureCount]int{len(c.Evidence), len(c.Alerts), int(min(c.Last.Sub(c.First)/time.Second, 86400))}
	for _, e := range c.Evidence {
		if e.Stream == "events" {
			v[3]++
		} else if e.Stream == "host-events" {
			v[4]++
		}
	}
	rules := map[string]bool{}
	for _, a := range c.Alerts {
		rules[a.Rule] = true
		for index, r := range []string{"RA-001", "RA-002", "RA-003", "RA-004", "RA-005", "RA-006", "RA-007", "RA-008"} {
			if a.Rule == r {
				v[index+6]++
			}
		}
	}
	v[5] = len(rules)
	return v
}

// Extract reads actual referenced HTTP rows and verifies both their line hash and
// signed sensor binding. Absent/partial/host-only context is an error, not zero.
func Extract(store recovery.Reader, cases []incident.Case, trust actioncontext.Trust) ([]Row, error) {
	if trust.Validate() != nil {
		return nil, ErrInvalid
	}
	type source struct {
		e   event.Event
		sha string
	}
	byID := map[string]source{}
	err := store.VisitRecords("events", func(raw []byte) error {
		var e event.Event
		if json.Unmarshal(raw, &e) != nil || e.Validate(e.IngestTime) != nil {
			return ErrInvalid
		}
		k := Digest([]string{e.TenantID, e.AssetID, e.EventID})
		sha := rawSHA(raw)
		if old, ok := byID[k]; ok && old.sha != sha {
			return ErrInvalid
		}
		byID[k] = source{e, sha}
		return nil
	})
	if err != nil {
		return nil, err
	}
	rows := []Row{}
	for _, c := range cases {
		if len(c.Evidence) == 0 || len(c.Evidence) > 128 {
			return nil, ErrInvalid
		}
		v := baseFeatures(c)
		keys := []string{}
		seen := map[string]bool{}
		for _, ref := range c.Evidence {
			src, ok := byID[Digest([]string{ref.Tenant, ref.Asset, ref.EventID})]
			if !ok || ref.Stream != "events" || src.sha != ref.LineSHA || ref.Tenant != c.Tenant || ref.Asset != c.Asset || seen[ref.EventID] {
				return nil, ErrInvalid
			}
			seen[ref.EventID] = true
			e := src.e
			if e.Context == nil || trust.Verify(e.Context, e.ContextBinding()) != nil {
				return nil, ErrInvalid
			}
			b := e.Context.Binding
			deny := b.Authorization == "deny"
			validation := actioncontext.ValidationRejected(b)
			canary := b.CanaryID != "" && b.ResourceClass == "canary"
			risk := deny || validation || canary
			permit := trust.PermissionGranted(*e.Context)
			if deny {
				v[15]++
			}
			if validation {
				v[16]++
			}
			if canary {
				v[17]++
			}
			if permit {
				v[18]++
			}
			if risk && !permit {
				v[14]++
			}
			if deny && !permit {
				v[19]++
			}
			if validation && !permit {
				v[20]++
			}
			if canary && !permit {
				v[21]++
			}
			if risk && permit {
				v[22]++
			}
			if b.Status >= 200 && b.Status < 300 && b.Authorization == "allow" {
				v[23]++
			}
			keys = append(keys, Digest([]string{ref.Stream, ref.Tenant, ref.Asset, ref.EventID, ref.LineSHA}))
		}
		sort.Strings(keys)
		rows = append(rows, Row{ID: c.ID, EvidenceKeys: keys, Features: v, ContextCoverageBPS: 10000})
	}
	return rows, nil
}
