package sourceledger

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// insertMatch never updates an immutable row. A conflicting key must have
// exactly the expected stored fields; otherwise the entire transaction fails.
func insertMatch(ctx context.Context, tx *sql.Tx, insert, match string, args ...any) error {
	r, err := tx.ExecContext(ctx, insert, args...)
	if err != nil {
		return err
	}
	n, err := r.RowsAffected()
	if err != nil {
		return err
	}
	if n == 1 {
		return nil
	}
	var same bool
	if err := tx.QueryRowContext(ctx, match, args...).Scan(&same); err != nil {
		return err
	}
	if !same {
		return errors.New("immutable source ledger conflict")
	}
	return nil
}

type Receipt struct {
	Namespace   string `json:"source_namespace"`
	Tenant      string `json:"tenant_id"`
	SnapshotSHA string `json:"snapshot_sha256"`
	PlanSHA     string `json:"plan_sha256"`
	Records     int    `json:"unique_records"`
	Occurrences int    `json:"occurrences"`
}

// Import commits one freshly replayed, explicitly reviewed snapshot. The DB
// owner separately provisions the source/tenant, exact metadata hash and writer.
// Retry serialization or uncertain commit outcomes with the same input/hash;
// each call rechecks registration. No automatic retry changes the source.
func Import(ctx context.Context, db *sql.DB, p *Prepared, reviewedSHA string) (Receipt, error) {
	if db == nil || p == nil || p.sha == "" || reviewedSHA != p.sha {
		return Receipt{}, errors.New("database, prepared source and matching reviewed plan SHA required")
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return Receipt{}, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `SET LOCAL search_path=pg_catalog,public`); err != nil {
		return Receipt{}, err
	}
	var safe bool
	err = tx.QueryRowContext(ctx, `SELECT NOT r.rolsuper AND NOT r.rolbypassrls AND NOT EXISTS (
 SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='public' AND c.relname IN ('ra_source_registry','ra_source_snapshots','ra_source_streams','ra_source_records','ra_source_occurrences') AND pg_has_role(r.oid,c.relowner,'USAGE'))
 FROM pg_roles r WHERE r.rolname=current_user`).Scan(&safe)
	if err != nil {
		return Receipt{}, err
	}
	if !safe {
		return Receipt{}, errors.New("non-owner source writer without RLS bypass required")
	}
	v := p.plan
	var allowed bool
	err = tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM public.ra_source_registry WHERE source_namespace=$1 AND tenant_id=$2 AND writer_role=current_user AND enabled AND metadata_sha256=decode($3,'hex'))`, v.Namespace, v.Tenant, v.MetadataSHA).Scan(&allowed)
	if err != nil {
		return Receipt{}, err
	}
	if !allowed {
		return Receipt{}, errors.New("source writer, tenant or metadata registration refused")
	}
	if err := insertMatch(ctx, tx,
		`INSERT INTO public.ra_source_snapshots(source_namespace,tenant_id,snapshot_sha256,metadata_sha256,plan_sha256) VALUES($1,$2,decode($3,'hex'),decode($4,'hex'),decode($5,'hex')) ON CONFLICT DO NOTHING`,
		`SELECT EXISTS(SELECT 1 FROM public.ra_source_snapshots WHERE source_namespace=$1 AND tenant_id=$2 AND snapshot_sha256=decode($3,'hex') AND metadata_sha256=decode($4,'hex') AND plan_sha256=decode($5,'hex'))`, v.Namespace, v.Tenant, v.SnapshotSHA, v.MetadataSHA, p.sha); err != nil {
		return Receipt{}, fmt.Errorf("snapshot: %w", err)
	}
	for _, s := range v.Streams {
		if err := insertMatch(ctx, tx,
			`INSERT INTO public.ra_source_streams(source_namespace,tenant_id,snapshot_sha256,stream,record_count,stream_sha256) VALUES($1,$2,decode($3,'hex'),$4,$5,decode($6,'hex')) ON CONFLICT DO NOTHING`,
			`SELECT EXISTS(SELECT 1 FROM public.ra_source_streams WHERE source_namespace=$1 AND tenant_id=$2 AND snapshot_sha256=decode($3,'hex') AND stream=$4 AND record_count=$5 AND stream_sha256=decode($6,'hex'))`, v.Namespace, v.Tenant, v.SnapshotSHA, s.Stream, s.Records, s.SHA256); err != nil {
			return Receipt{}, fmt.Errorf("stream: %w", err)
		}
	}
	for _, r := range v.Records {
		if err := insertMatch(ctx, tx,
			`INSERT INTO public.ra_source_records(source_namespace,tenant_id,stream,asset_id,sensor_id,event_id,line_sha256) VALUES($1,$2,$3,$4,$5,$6,decode($7,'hex')) ON CONFLICT DO NOTHING`,
			`SELECT EXISTS(SELECT 1 FROM public.ra_source_records WHERE source_namespace=$1 AND tenant_id=$2 AND stream=$3 AND asset_id=$4 AND sensor_id=$5 AND event_id=$6 AND line_sha256=decode($7,'hex'))`, v.Namespace, v.Tenant, r.Stream, r.Asset, r.Sensor, r.EventID, r.LineSHA); err != nil {
			return Receipt{}, fmt.Errorf("record: %w", err)
		}
	}
	for _, o := range v.Occurrences {
		if err := insertMatch(ctx, tx,
			`INSERT INTO public.ra_source_occurrences(source_namespace,tenant_id,snapshot_sha256,stream,commit_ordinal,asset_id,sensor_id,event_id,line_sha256,evaluation_sha256,evaluation_result) VALUES($1,$2,decode($3,'hex'),$4,$5,$6,$7,$8,decode($9,'hex'),decode($10,'hex'),$11) ON CONFLICT DO NOTHING`,
			`SELECT EXISTS(SELECT 1 FROM public.ra_source_occurrences WHERE source_namespace=$1 AND tenant_id=$2 AND snapshot_sha256=decode($3,'hex') AND stream=$4 AND commit_ordinal=$5 AND asset_id=$6 AND sensor_id=$7 AND event_id=$8 AND line_sha256=decode($9,'hex') AND evaluation_sha256=decode($10,'hex') AND evaluation_result=$11)`, v.Namespace, v.Tenant, v.SnapshotSHA, o.Stream, o.Ordinal, o.Asset, o.Sensor, o.EventID, o.LineSHA, o.EvaluationSHA, o.Result); err != nil {
			return Receipt{}, fmt.Errorf("occurrence: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return Receipt{}, err
	}
	return Receipt{v.Namespace, v.Tenant, v.SnapshotSHA, p.sha, len(v.Records), len(v.Occurrences)}, nil
}
