package caseledger

import (
	"context"
	"database/sql"
	"errors"

	"github.com/jackc/pgx/v5"
)

// ErrUnauthenticated never contains a credential, identity or database detail.
var ErrUnauthenticated = errors.New("case API authentication required")

// CheckAPIService requires a non-inheriting, non-owner login. Membership grants
// SET ROLE to dedicated readers, never ownership or administration privileges.
func CheckAPIService(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return errors.New("case API database required")
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = checkAPIServiceTx(ctx, tx); err != nil {
		return err
	}
	return tx.Commit()
}

func checkAPIServiceTx(ctx context.Context, tx *sql.Tx) error {
	if err := setup(ctx, tx); err != nil {
		return err
	}
	if err := safeRole(ctx, tx); err != nil {
		return err
	}
	var safe bool
	err := tx.QueryRowContext(ctx, `SELECT current_user=session_user AND NOT r.rolinherit AND NOT r.rolcreaterole AND NOT r.rolcreatedb AND NOT r.rolreplication AND NOT EXISTS(
 SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='public' AND c.relname IN ('ra_case_api_credentials','ra_reader_grants','ra_source_registry','ra_source_snapshots','ra_source_streams','ra_source_records','ra_source_occurrences','ra_case_heads','ra_case_revisions','ra_case_refs','ra_case_policy_bindings','ra_policy_history','ra_control_audit','ra_audit_imports')
 AND pg_has_role(r.oid,c.relowner,'MEMBER')) AND has_table_privilege(current_user,'public.ra_case_api_credentials','SELECT')
 FROM pg_roles r WHERE r.rolname=current_user`).Scan(&safe)
	if err != nil {
		return err
	}
	if !safe {
		return errors.New("restricted NOINHERIT case API service required")
	}
	return apiReadOnlyRole(ctx, tx)
}

// ReadBearer authenticates and verifies the entire ledger in one read-only,
// repeatable-read transaction. Token and tenant grants are never cached.
// Revocation affects requests whose DB snapshot begins after its commit;
// it does not retract data already admitted by an in-flight request.
func ReadBearer(ctx context.Context, db *sql.DB, tokenSHA [32]byte, tenant, caseID string) (Stored, error) {
	if db == nil || !identifier.MatchString(tenant) || !identifier.MatchString(caseID) {
		return Stored{}, errors.New("database and valid case identity required")
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return Stored{}, err
	}
	defer tx.Rollback()
	if err = checkAPIServiceTx(ctx, tx); err != nil {
		return Stored{}, err
	}
	var principal, role, scope string
	err = tx.QueryRowContext(ctx, `SELECT principal_id,reader_role::text,tenant_id FROM public.ra_case_api_credentials WHERE token_sha256=$1 AND enabled AND not_before<=clock_timestamp() AND expires_at>clock_timestamp()`, tokenSHA[:]).Scan(&principal, &role, &scope)
	if errors.Is(err, sql.ErrNoRows) {
		return Stored{}, ErrUnauthenticated
	}
	if err != nil {
		return Stored{}, err
	}
	if scope != tenant {
		return Stored{}, sql.ErrNoRows
	}
	// Role comes only from the operator-owned row, never an HTTP parameter.
	if _, err = tx.ExecContext(ctx, "SET LOCAL ROLE "+pgx.Identifier{role}.Sanitize()); err != nil {
		return Stored{}, err
	}
	if err = safeRole(ctx, tx); err != nil {
		return Stored{}, err
	}
	if err = apiReadOnlyRole(ctx, tx); err != nil {
		return Stored{}, err
	}
	var allowed bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM public.ra_reader_grants WHERE role_name=current_user AND tenant_id=$1)`, tenant).Scan(&allowed); err != nil {
		return Stored{}, err
	}
	if !allowed {
		return Stored{}, sql.ErrNoRows
	}
	var rows, size int64
	if err = tx.QueryRowContext(ctx, `SELECT count(*),COALESCE(sum(octet_length(canonical_plan)),0) FROM public.ra_case_revisions WHERE tenant_id=$1 AND case_id=$2`, tenant, caseID).Scan(&rows, &size); err != nil {
		return Stored{}, err
	}
	if rows == 0 {
		return Stored{}, sql.ErrNoRows
	}
	if rows > 64 || size > MaxPlan {
		return Stored{}, errors.New("case API history limit")
	}
	out, err := readTx(ctx, tx, tenant, caseID, false)
	if err != nil {
		return Stored{}, err
	}
	out.PolicyHistory, err = readPolicyTx(ctx, tx, out)
	if err != nil {
		return Stored{}, err
	}
	if err = tx.Commit(); err != nil {
		return Stored{}, err
	}
	return out, nil
}

func apiReadOnlyRole(ctx context.Context, tx *sql.Tx) error {
	var safe bool
	err := tx.QueryRowContext(ctx, `SELECT NOT r.rolcreaterole AND NOT r.rolcreatedb AND NOT r.rolreplication AND NOT EXISTS(
 SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='public' AND c.relname IN ('ra_case_api_credentials','ra_reader_grants','ra_source_registry','ra_source_snapshots','ra_source_streams','ra_source_records','ra_source_occurrences','ra_case_heads','ra_case_revisions','ra_case_refs','ra_case_policy_bindings','ra_policy_history','ra_control_audit','ra_audit_imports')
 AND (has_table_privilege(r.oid,c.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR has_any_column_privilege(r.oid,c.oid,'INSERT,UPDATE,REFERENCES')))
 FROM pg_roles r WHERE r.rolname=current_user`).Scan(&safe)
	if err != nil {
		return err
	}
	if !safe {
		return errors.New("case API role must have read-only privileges")
	}
	return nil
}
