package incident

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reverse-artex/internal/control"
	"reverse-artex/internal/policy"
	"time"
)

type auditRow struct {
	Version   uint64         `json:"version"`
	Epoch     string         `json:"epoch"`
	Time      time.Time      `json:"time"`
	Operation string         `json:"operation"`
	Policy    *policy.Policy `json:"policy,omitempty"`
	Removed   []string       `json:"removed,omitempty"`
}

// ImportAudit projects a complete, validated control WAL snapshot. Source IDs
// are immutable; a changed WAL must use a new source ID and the shared
// (epoch,version) key proves that previously imported rows have identical bytes.
func ImportAudit(ctx context.Context, db *sql.DB, sourceID, path string) (string, int, error) {
	if db == nil || !importID.MatchString(sourceID) {
		return "", 0, errors.New("invalid audit import identity")
	}
	stat, err := os.Stat(path)
	if err != nil || stat.IsDir() || stat.Size() == 0 || stat.Size() > 128<<20 || filepath.Base(path) != "actions.jsonl" {
		return "", 0, errors.New("nonempty bounded actions.jsonl required")
	}
	if _, err := control.Open(filepath.Dir(path)); err != nil {
		return "", 0, fmt.Errorf("control WAL recovery refused: %w", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", 0, err
	}
	if len(raw) == 0 || raw[len(raw)-1] != '\n' {
		return "", 0, errors.New("incomplete control WAL")
	}
	sum := sha256.Sum256(raw)
	walSHA := hex.EncodeToString(sum[:])
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return "", 0, err
	}
	defer tx.Rollback()
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 4096), 1<<20)
	count := 0
	var epoch string
	for scanner.Scan() {
		line := scanner.Bytes()
		var r auditRow
		if err := json.Unmarshal(line, &r); err != nil || r.Version != uint64(count+1) || r.Time.IsZero() || (epoch != "" && epoch != r.Epoch) {
			return "", 0, errors.New("invalid control WAL row")
		}
		epoch = r.Epoch
		lineSum := sha256.Sum256(line)
		lineSHA := hex.EncodeToString(lineSum[:])
		var policyID any
		if r.Policy != nil {
			policyID = r.Policy.ID
			var linked sql.NullString
			err := tx.QueryRowContext(ctx, `SELECT case_id FROM ra_cases WHERE case_id=$1 AND tenant_id=$2 AND asset_id=$3`, r.Policy.CaseID, r.Policy.Tenant, r.Policy.Asset).Scan(&linked)
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				return "", 0, err
			}
			if err := checkedExec(ctx, tx, `INSERT INTO ra_policy_history(policy_id,source_case_id,case_id,tenant_id,asset_id,rule_version,issued_at,expires_at,last_operation)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,'issued') ON CONFLICT(policy_id) DO UPDATE SET last_operation='issued',case_id=COALESCE(ra_policy_history.case_id,EXCLUDED.case_id)
WHERE ra_policy_history.source_case_id=EXCLUDED.source_case_id AND ra_policy_history.tenant_id=EXCLUDED.tenant_id
AND ra_policy_history.asset_id=EXCLUDED.asset_id AND ra_policy_history.rule_version=EXCLUDED.rule_version
AND ra_policy_history.issued_at=EXCLUDED.issued_at AND ra_policy_history.expires_at=EXCLUDED.expires_at
AND (ra_policy_history.case_id IS NULL OR EXCLUDED.case_id IS NULL OR ra_policy_history.case_id=EXCLUDED.case_id)`,
				r.Policy.ID, r.Policy.CaseID, linked, r.Policy.Tenant, r.Policy.Asset, r.Policy.RuleVersion, r.Policy.Issued, r.Policy.Expires); err != nil {
				return "", 0, fmt.Errorf("policy history import: %w", err)
			}
		}
		operation := ""
		switch r.Operation {
		case "expire":
			operation = "expired"
		case "revoke":
			operation = "revoked"
		case "rollback":
			operation = "rolled_back"
		}
		if len(r.Removed) != 0 && operation == "" {
			return "", 0, errors.New("unknown policy removal operation")
		}
		for _, id := range r.Removed {
			if err := checkedExec(ctx, tx, `UPDATE ra_policy_history SET last_operation=$2 WHERE policy_id=$1`, id, operation); err != nil {
				return "", 0, fmt.Errorf("policy removal import: %w", err)
			}
		}
		if err := checkedExec(ctx, tx, `INSERT INTO ra_control_audit(epoch,version,operation,operation_at,line_sha256,policy_id)
VALUES($1,$2,$3,$4,decode($5,'hex'),$6) ON CONFLICT(epoch,version) DO UPDATE SET line_sha256=EXCLUDED.line_sha256
WHERE ra_control_audit.line_sha256=EXCLUDED.line_sha256 AND ra_control_audit.operation=EXCLUDED.operation
AND ra_control_audit.operation_at=EXCLUDED.operation_at AND ra_control_audit.policy_id IS NOT DISTINCT FROM EXCLUDED.policy_id`,
			r.Epoch, r.Version, r.Operation, r.Time, lineSHA, policyID); err != nil {
			return "", 0, fmt.Errorf("audit row import: %w", err)
		}
		count++
	}
	if err := scanner.Err(); err != nil {
		return "", 0, err
	}
	current, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(raw, current) {
		return "", 0, errors.New("control WAL changed during import")
	}
	if err := checkedExec(ctx, tx, `INSERT INTO ra_audit_imports(source_id,wal_sha256,row_count) VALUES($1,decode($2,'hex'),$3)
ON CONFLICT(source_id) DO UPDATE SET wal_sha256=EXCLUDED.wal_sha256
WHERE ra_audit_imports.wal_sha256=EXCLUDED.wal_sha256 AND ra_audit_imports.row_count=EXCLUDED.row_count`, sourceID, walSHA, count); err != nil {
		return "", 0, fmt.Errorf("audit source import: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return "", 0, err
	}
	return walSHA, count, nil
}
