package caseledger

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
)

func matchPolicyLegacy(ctx context.Context, tx *sql.Tx, review PolicyReview) error {
	b := review.Binding
	var same bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM public.ra_audit_imports WHERE source_id=$1 AND wal_sha256=decode($2,'hex') AND row_count=$3)`, b.AuditSource, b.WALSHA, b.WALRows).Scan(&same); err != nil {
		return err
	}
	if !same {
		return errors.New("imported policy WAL commitment missing or changed")
	}
	for _, line := range b.AuditRows {
		x, err := decodePolicyAudit(line)
		if err != nil {
			return err
		}
		var policyID any
		if x.Policy != nil {
			p := x.Policy
			policyID = p.ID
			if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM public.ra_policy_history WHERE policy_id=$1 AND source_case_id=$2 AND tenant_id=$3 AND asset_id=$4 AND rule_version=$5 AND issued_at=$6 AND expires_at=$7)`, p.ID, p.CaseID, p.Tenant, p.Asset, p.RuleVersion, p.Issued, p.Expires).Scan(&same); err != nil {
				return err
			}
			if !same {
				return errors.New("legacy policy commitment missing or changed")
			}
		}
		if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM public.ra_control_audit WHERE epoch=$1 AND version=$2 AND operation=$3 AND operation_at=$4 AND line_sha256=decode($5,'hex') AND policy_id IS NOT DISTINCT FROM $6::text)`, x.Epoch, int64(x.Version), x.Operation, x.Time, hash(line), policyID).Scan(&same); err != nil {
			return err
		}
		if !same {
			return errors.New("legacy audit commitment missing or changed")
		}
	}
	return nil
}

// Optional migration keeps pre-B05-D readers usable. Once installed, missing
// SELECT grants or inconsistent bindings fail closed rather than hiding data.
func readPolicyTx(ctx context.Context, tx *sql.Tx, s Stored) (*PolicyReview, error) {
	var exists bool
	if err := tx.QueryRowContext(ctx, `SELECT to_regclass('public.ra_case_policy_bindings') IS NOT NULL`).Scan(&exists); err != nil {
		return nil, err
	}
	if !exists {
		return nil, nil
	}
	var data, keysJSON []byte
	var sha, ns, snapshot, commit string
	err := tx.QueryRowContext(ctx, `SELECT canonical_binding,encode(binding_sha256,'hex'),source_namespace,encode(snapshot_sha256,'hex'),encode(commit_sha256,'hex'),to_json(audit_keys) FROM public.ra_case_policy_bindings WHERE tenant_id=$1 AND case_id=$2 AND revision=$3`, s.Head.Tenant, s.Head.CaseID, s.Head.Revision).Scan(&data, &sha, &ns, &snapshot, &commit, &keysJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var b PolicyBinding
	var keys []string
	if len(data) > MaxPolicyBinding || json.Unmarshal(data, &b) != nil || json.Unmarshal(keysJSON, &keys) != nil || !bytes.Equal(data, encoded(b)) || sha != hash(data) || b.Case != s.Head || ns != s.Head.Namespace || snapshot != s.Head.SnapshotSHA || commit != s.Head.CommitSHA || !reflect.DeepEqual(keys, policyAuditKeys(b)) {
		return nil, errInconsistent()
	}
	out := PolicyReview{b, sha}
	if _, err = ValidatePolicyHistory(s.Revisions[len(s.Revisions)-1], out); err != nil {
		return nil, err
	}
	if err = matchPolicyLegacy(ctx, tx, out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ImportPolicyHistory uses the same registered source writer and SERIALIZABLE
// head lock as case commits. A changed selection/as-of requires a new revision;
// identical retry is idempotent and never updates the frozen binding.
func ImportPolicyHistory(ctx context.Context, db *sql.DB, p *PreparedPolicyHistory, reviewed string) (PolicyReview, error) {
	if db == nil || p == nil || reviewed != p.sha || p.sha == "" || hash(p.data) != p.sha {
		return PolicyReview{}, errors.New("prepared policy binding and matching review required")
	}
	r := p.Review()
	b := r.Binding
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return PolicyReview{}, err
	}
	defer tx.Rollback()
	if err = setup(ctx, tx); err != nil {
		return PolicyReview{}, err
	}
	s, err := readTx(ctx, tx, b.Case.Tenant, b.Case.CaseID, true)
	if err != nil {
		return PolicyReview{}, err
	}
	if s.Head != b.Case {
		return PolicyReview{}, errors.New("policy binding requires current case commit")
	}
	v := s.Revisions[len(s.Revisions)-1]
	if err = writerAllowed(ctx, tx, v.Plan); err != nil {
		return PolicyReview{}, err
	}
	if _, err = ValidatePolicyHistory(v, r); err != nil {
		return PolicyReview{}, err
	}
	old, err := readPolicyTx(ctx, tx, s)
	if err != nil {
		return PolicyReview{}, err
	}
	if old != nil {
		if old.SHA256 != r.SHA256 {
			return PolicyReview{}, errors.New("immutable policy binding conflict")
		}
		if err = tx.Commit(); err != nil {
			return PolicyReview{}, err
		}
		return *old, nil
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO public.ra_case_policy_bindings(tenant_id,case_id,revision,source_namespace,snapshot_sha256,commit_sha256,binding_sha256,audit_keys,canonical_binding) VALUES($1,$2,$3,$4,decode($5,'hex'),decode($6,'hex'),decode($7,'hex'),$8,$9)`, b.Case.Tenant, b.Case.CaseID, b.Case.Revision, b.Case.Namespace, b.Case.SnapshotSHA, b.Case.CommitSHA, r.SHA256, policyAuditKeys(b), p.data)
	if err != nil {
		return PolicyReview{}, err
	}
	// Insertion admits only the selected removal keys under reader RLS. Verify
	// them before COMMIT; any missing/changed legacy row rolls the link back.
	if err = matchPolicyLegacy(ctx, tx, r); err != nil {
		return PolicyReview{}, err
	}
	if err = tx.Commit(); err != nil {
		return PolicyReview{}, err
	}
	return r, nil
}
