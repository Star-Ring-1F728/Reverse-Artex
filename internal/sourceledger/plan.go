// Package sourceledger prepares replay-verified evidence for a separately
// provisioned source namespace. It does not authenticate native sensors.
package sourceledger

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"reverse-artex/internal/evidence"
	"reverse-artex/internal/recovery"
	"sort"
)

var namespaceID = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)
var identityID = regexp.MustCompile(`^[A-Za-z0-9_.:/{}-]{1,128}$`)

type Record struct {
	Stream  string `json:"stream"`
	Asset   string `json:"asset_id"`
	Sensor  string `json:"sensor_id"`
	EventID string `json:"event_id"`
	LineSHA string `json:"line_sha256"`
}
type Occurrence struct {
	Record
	Ordinal       int    `json:"commit_ordinal"`
	EvaluationSHA string `json:"evaluation_sha256"`
	Result        string `json:"evaluation_result"`
}
type Plan struct {
	Schema      string                      `json:"schema_version"`
	Namespace   string                      `json:"source_namespace"`
	Tenant      string                      `json:"tenant_id"`
	SnapshotSHA string                      `json:"snapshot_sha256"`
	MetadataSHA string                      `json:"metadata_sha256"`
	Streams     []evidence.StreamCommitment `json:"streams"`
	Records     []Record                    `json:"records"`
	Occurrences []Occurrence                `json:"occurrences"`
}
type Review struct {
	Plan   Plan   `json:"plan"`
	SHA256 string `json:"plan_sha256"`
}

// Prepared is sealed: only Prepare creates importable data. Review returns a
// detached copy; JSON supplied by a caller is never accepted as replay proof.
type Prepared struct {
	plan Plan
	sha  string
}

func (p *Prepared) Review() Review {
	data, _ := json.Marshal(p.plan)
	var plan Plan
	json.Unmarshal(data, &plan)
	return Review{plan, p.sha}
}
func hash(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func key(r Record) string {
	b, _ := json.Marshal([]string{r.Stream, r.Asset, r.Sensor, r.EventID})
	return string(b)
}

func Prepare(namespace, tenant string, s *evidence.Snapshot) (*Prepared, error) {
	if !namespaceID.MatchString(namespace) || !identityID.MatchString(tenant) {
		return nil, errors.New("valid source namespace and tenant required")
	}
	if err := recovery.VerifySnapshot(s); err != nil {
		return nil, err
	}
	p := Plan{Schema: "source-ledger-plan/1", Namespace: namespace, Tenant: tenant, SnapshotSHA: s.SHA256(), MetadataSHA: hash(s.Metadata()), Streams: s.Commitments(), Records: []Record{}, Occurrences: []Occurrence{}}
	seen := map[string]Record{}
	for _, pair := range [][2]string{{"events", "evaluations"}, {"host-events", "host-evaluations"}} {
		var evaluations []struct{ sha, result string }
		if err := s.VisitRecords(pair[1], func(line []byte) error {
			var e recovery.Evaluation
			if err := json.Unmarshal(line, &e); err != nil {
				return err
			}
			evaluations = append(evaluations, struct{ sha, result string }{hash(line), e.Result})
			return nil
		}); err != nil {
			return nil, err
		}
		n := 0
		err := s.VisitRecords(pair[0], func(line []byte) error {
			var e struct {
				Tenant string `json:"tenant_id"`
				Asset  string `json:"asset_id"`
				Sensor string `json:"sensor_id"`
				ID     string `json:"event_id"`
			}
			if err := json.Unmarshal(line, &e); err != nil {
				return err
			}
			if e.Tenant != tenant || !identityID.MatchString(e.Asset) || !identityID.MatchString(e.Sensor) || !identityID.MatchString(e.ID) {
				return errors.New("snapshot outside registered tenant or invalid source identity")
			}
			if n >= len(evaluations) {
				return errors.New("missing source evaluation")
			}
			ev := evaluations[n]
			n++
			r := Record{pair[0], e.Asset, e.Sensor, e.ID, hash(line)}
			k := key(r)
			if previous, ok := seen[k]; ok && previous.LineSHA != r.LineSHA {
				return errors.New("ambiguous scoped source identity")
			}
			seen[k] = r
			p.Occurrences = append(p.Occurrences, Occurrence{r, n, ev.sha, ev.result})
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	if len(seen) == 0 {
		return nil, errors.New("nonempty single-tenant source required")
	}
	for _, r := range seen {
		p.Records = append(p.Records, r)
	}
	sort.Slice(p.Records, func(i, j int) bool { return key(p.Records[i]) < key(p.Records[j]) })
	data, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	return &Prepared{p, hash(data)}, nil
}
