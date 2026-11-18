// Package incident builds a read-only, deterministic case projection from
// committed JSONL evidence. Database writes and retention are separate steps.
package incident

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reverse-artex/internal/recovery"
	"sort"
	"time"
)

type EvidenceRef struct {
	Stream  string    `json:"stream"`
	Tenant  string    `json:"tenant_id"`
	Asset   string    `json:"asset_id"`
	EventID string    `json:"event_id"`
	LineSHA string    `json:"line_sha256"`
	Time    time.Time `json:"event_time"`
}

type AlertRef struct {
	Stream  string    `json:"stream"`
	LineSHA string    `json:"line_sha256"`
	Time    time.Time `json:"alert_time"`
	Rule    string    `json:"rule_id"`
	Refs    []string  `json:"evidence_refs"`
}

type Case struct {
	ID       string        `json:"case_id"`
	Tenant   string        `json:"tenant_id"`
	Asset    string        `json:"asset_id"`
	First    time.Time     `json:"first_alert_at"`
	Last     time.Time     `json:"last_alert_at"`
	Evidence []EvidenceRef `json:"evidence"`
	Alerts   []AlertRef    `json:"alerts"`
}

type Manifest struct {
	Version int    `json:"version"`
	Cases   []Case `json:"cases"`
}

type source struct {
	EventID string    `json:"event_id"`
	Tenant  string    `json:"tenant_id"`
	Asset   string    `json:"asset_id"`
	Time    time.Time `json:"event_time"`
}

type alert struct {
	CaseID string    `json:"case_id"`
	Tenant string    `json:"tenant_id"`
	Asset  string    `json:"asset_id"`
	Rule   string    `json:"rule_id"`
	Time   time.Time `json:"alert_time"`
	Refs   []string  `json:"evidence_refs"`
}

func hash(line []byte) string {
	sum := sha256.Sum256(line)
	return hex.EncodeToString(sum[:])
}

func key(stream, tenant, asset, eventID string) string {
	parts, _ := json.Marshal([]string{stream, tenant, asset, eventID})
	return string(parts)
}

// Build refuses an orphaned or ambiguous reference. It does not delete or
// alter source evidence, and a caller must first verify the M6-2 commit cursor.
func Build(store recovery.Reader) (Manifest, error) {
	manifest := Manifest{Version: 1, Cases: []Case{}}
	byEvent := map[string]EvidenceRef{}
	for _, stream := range []string{"events", "host-events"} {
		err := store.VisitRecords(stream, func(line []byte) error {
			var row source
			if err := json.Unmarshal(line, &row); err != nil {
				return err
			}
			if row.EventID == "" || row.Tenant == "" || row.Asset == "" || row.Time.IsZero() {
				return errors.New("incomplete source event")
			}
			ref := EvidenceRef{stream, row.Tenant, row.Asset, row.EventID, hash(line), row.Time}
			k := key(stream, row.Tenant, row.Asset, row.EventID)
			if previous, exists := byEvent[k]; exists && previous.LineSHA != ref.LineSHA {
				return fmt.Errorf("ambiguous source event %s", row.EventID)
			}
			byEvent[k] = ref
			return nil
		})
		if err != nil {
			return manifest, fmt.Errorf("%s: %w", stream, err)
		}
	}
	byCase := map[string]*Case{}
	for _, pair := range [][2]string{{"alerts", "events"}, {"host-alerts", "host-events"}} {
		alertStream, eventStream := pair[0], pair[1]
		err := store.VisitRecords(alertStream, func(line []byte) error {
			var a alert
			if err := json.Unmarshal(line, &a); err != nil {
				return err
			}
			if a.CaseID == "" || a.Tenant == "" || a.Asset == "" || a.Rule == "" || a.Time.IsZero() || len(a.Refs) == 0 || len(a.Refs) > 128 {
				return errors.New("incomplete case alert")
			}
			c := byCase[a.CaseID]
			if c == nil {
				c = &Case{ID: a.CaseID, Tenant: a.Tenant, Asset: a.Asset, First: a.Time, Last: a.Time,
					Evidence: []EvidenceRef{}, Alerts: []AlertRef{}}
				byCase[a.CaseID] = c
			} else if c.Tenant != a.Tenant || c.Asset != a.Asset {
				return errors.New("case crosses tenant or asset")
			}
			if a.Time.Before(c.First) {
				c.First = a.Time
			}
			if a.Time.After(c.Last) {
				c.Last = a.Time
			}
			seen := map[string]bool{}
			for _, id := range a.Refs {
				if id == "" || seen[id] {
					return errors.New("empty or repeated alert reference")
				}
				seen[id] = true
				ref, ok := byEvent[key(eventStream, a.Tenant, a.Asset, id)]
				if !ok {
					return fmt.Errorf("orphan evidence reference %s", id)
				}
				already := false
				for _, existing := range c.Evidence {
					if existing.Stream == ref.Stream && existing.EventID == ref.EventID {
						already = true
						break
					}
				}
				if !already {
					c.Evidence = append(c.Evidence, ref)
				}
			}
			c.Alerts = append(c.Alerts, AlertRef{alertStream, hash(line), a.Time, a.Rule, a.Refs})
			return nil
		})
		if err != nil {
			return manifest, fmt.Errorf("%s: %w", alertStream, err)
		}
	}
	for _, c := range byCase {
		sort.Slice(c.Evidence, func(i, j int) bool {
			if c.Evidence[i].Stream != c.Evidence[j].Stream {
				return c.Evidence[i].Stream < c.Evidence[j].Stream
			}
			return c.Evidence[i].EventID < c.Evidence[j].EventID
		})
		sort.Slice(c.Alerts, func(i, j int) bool { return c.Alerts[i].LineSHA < c.Alerts[j].LineSHA })
		manifest.Cases = append(manifest.Cases, *c)
	}
	sort.Slice(manifest.Cases, func(i, j int) bool { return manifest.Cases[i].ID < manifest.Cases[j].ID })
	return manifest, nil
}
