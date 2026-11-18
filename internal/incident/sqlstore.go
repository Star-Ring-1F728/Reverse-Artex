package incident

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
)

var importID = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)
var projectionID = regexp.MustCompile(`^[A-Za-z0-9_.:/{}-]{1,128}$`)

const insertCase = `INSERT INTO ra_cases
 (case_id, tenant_id, asset_id, first_alert_at, last_alert_at)
 VALUES ($1,$2,$3,$4,$5)
 ON CONFLICT (case_id) DO UPDATE SET
 first_alert_at = LEAST(ra_cases.first_alert_at, EXCLUDED.first_alert_at),
 last_alert_at = GREATEST(ra_cases.last_alert_at, EXCLUDED.last_alert_at)
 WHERE ra_cases.tenant_id = EXCLUDED.tenant_id AND ra_cases.asset_id = EXCLUDED.asset_id`

const insertEvidence = `INSERT INTO ra_evidence_records
 (stream, tenant_id, asset_id, event_id, line_sha256, event_time)
 VALUES ($1,$2,$3,$4,decode($5,'hex'),$6)
 ON CONFLICT (stream, tenant_id, asset_id, event_id) DO UPDATE SET
 line_sha256 = EXCLUDED.line_sha256
 WHERE ra_evidence_records.line_sha256 = EXCLUDED.line_sha256
 AND ra_evidence_records.event_time = EXCLUDED.event_time`

const insertLink = `INSERT INTO ra_case_evidence
 (case_id, tenant_id, asset_id, stream, event_id)
 VALUES ($1,$2,$3,$4,$5) ON CONFLICT (case_id, stream, event_id) DO NOTHING`

const insertAlert = `INSERT INTO ra_case_alerts
 (stream, line_sha256, case_id, tenant_id, asset_id, rule_id, alert_time)
 VALUES ($1,decode($2,'hex'),$3,$4,$5,$6,$7)
 ON CONFLICT (stream, line_sha256) DO UPDATE SET rule_id = EXCLUDED.rule_id
 WHERE ra_case_alerts.case_id = EXCLUDED.case_id
 AND ra_case_alerts.tenant_id = EXCLUDED.tenant_id
 AND ra_case_alerts.asset_id = EXCLUDED.asset_id
 AND ra_case_alerts.rule_id = EXCLUDED.rule_id
 AND ra_case_alerts.alert_time = EXCLUDED.alert_time`

const insertImport = `INSERT INTO ra_projection_imports (source_id, manifest_sha256)
 VALUES ($1,decode($2,'hex'))
 ON CONFLICT (source_id) DO UPDATE SET manifest_sha256 = EXCLUDED.manifest_sha256
 WHERE ra_projection_imports.manifest_sha256 = EXCLUDED.manifest_sha256`

func validSHA(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

// Validate checks the bounded projection contract without writing to a database.
func Validate(m Manifest) error { return validateManifest("case-memory", m) }

func validateManifest(sourceID string, m Manifest) error {
	if !importID.MatchString(sourceID) || m.Version != 1 || len(m.Cases) > 100_000 {
		return errors.New("invalid incident import identity or version")
	}
	seenCases := map[string]bool{}
	for _, c := range m.Cases {
		if !projectionID.MatchString(c.ID) || !projectionID.MatchString(c.Tenant) || !projectionID.MatchString(c.Asset) ||
			c.First.IsZero() || c.Last.Before(c.First) || len(c.Evidence) > 100_000 || len(c.Alerts) > 100_000 || seenCases[c.ID] {
			return errors.New("invalid case projection")
		}
		seenCases[c.ID] = true
		refs := map[string]bool{}
		for _, e := range c.Evidence {
			if (e.Stream != "events" && e.Stream != "host-events") || e.Tenant != c.Tenant || e.Asset != c.Asset ||
				!projectionID.MatchString(e.EventID) || !validSHA(e.LineSHA) || e.Time.IsZero() {
				return errors.New("invalid case evidence")
			}
			k := key(e.Stream, e.Tenant, e.Asset, e.EventID)
			if refs[k] {
				return errors.New("repeated case evidence")
			}
			refs[k] = true
		}
		for _, a := range c.Alerts {
			if (a.Stream != "alerts" && a.Stream != "host-alerts") || !validSHA(a.LineSHA) ||
				!projectionID.MatchString(a.Rule) || a.Time.IsZero() || a.Time.Before(c.First) || a.Time.After(c.Last) ||
				len(a.Refs) == 0 || len(a.Refs) > 128 {
				return errors.New("invalid case alert")
			}
			stream := "events"
			if a.Stream == "host-alerts" {
				stream = "host-events"
			}
			for _, id := range a.Refs {
				if !refs[key(stream, c.Tenant, c.Asset, id)] {
					return errors.New("unresolved alert evidence")
				}
			}
		}
	}
	return nil
}

func checkedExec(ctx context.Context, tx *sql.Tx, statement string, args ...any) error {
	result, err := tx.ExecContext(ctx, statement, args...)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return errors.New("conflicting or missing PostgreSQL row")
	}
	return nil
}

// Import writes one complete, immutable projection in a serializable DB
// transaction. Existing keys with different source hashes fail closed.
// JSONL ACKs remain independent of DB availability; callers retry this import.
func Import(ctx context.Context, db *sql.DB, sourceID string, m Manifest) (string, error) {
	if db == nil {
		return "", errors.New("database required")
	}
	if err := validateManifest(sourceID, m); err != nil {
		return "", err
	}
	encoded, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	manifestSHA := hex.EncodeToString(sum[:])
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	for _, c := range m.Cases {
		if err := checkedExec(ctx, tx, insertCase, c.ID, c.Tenant, c.Asset, c.First, c.Last); err != nil {
			return "", fmt.Errorf("case import: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE ra_policy_history SET case_id=$1 WHERE source_case_id=$1 AND tenant_id=$2 AND asset_id=$3 AND case_id IS NULL`, c.ID, c.Tenant, c.Asset); err != nil {
			return "", fmt.Errorf("policy case link: %w", err)
		}
		for _, e := range c.Evidence {
			if err := checkedExec(ctx, tx, insertEvidence, e.Stream, e.Tenant, e.Asset, e.EventID, e.LineSHA, e.Time); err != nil {
				return "", fmt.Errorf("evidence import: %w", err)
			}
			if _, err := tx.ExecContext(ctx, insertLink, c.ID, c.Tenant, c.Asset, e.Stream, e.EventID); err != nil {
				return "", fmt.Errorf("evidence link: %w", err)
			}
		}
		for _, a := range c.Alerts {
			if err := checkedExec(ctx, tx, insertAlert, a.Stream, a.LineSHA, c.ID, c.Tenant, c.Asset, a.Rule, a.Time); err != nil {
				return "", fmt.Errorf("alert import: %w", err)
			}
		}
	}
	if err := checkedExec(ctx, tx, insertImport, sourceID, manifestSHA); err != nil {
		return "", fmt.Errorf("source import: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return manifestSHA, nil
}
