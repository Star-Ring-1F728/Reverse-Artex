package caseledger

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"reverse-artex/internal/casefile"
)

const timeWire = "2006-01-02T15:04:05.000000000Z"

type Receipt struct {
	Namespace         string `json:"source_namespace"`
	Tenant            string `json:"tenant_id"`
	CaseID            string `json:"case_id"`
	Revision          int    `json:"revision"`
	B03RevisionSHA    string `json:"b03_revision_sha256"`
	B03PreviousSHA    string `json:"b03_previous_revision_sha256"`
	CommitSHA         string `json:"commit_sha256"`
	PreviousCommitSHA string `json:"previous_commit_sha256"`
	PlanSHA           string `json:"plan_sha256"`
	SnapshotSHA       string `json:"snapshot_sha256"`
}
type Stored struct {
	// Raw WAL/source proofs are internal only. Tool routes emit masked rows.
	PolicyHistory *PolicyReview `json:"-"`
	Head          Receipt       `json:"head"`
	Revisions     []Review      `json:"revisions"`
}

func receipt(v Plan, sha string) Receipt {
	c := v.Commit
	h := v.Context.History.Entries[c.Revision-1]
	return Receipt{c.Namespace, c.Tenant, c.CaseID, c.Revision, h.SHA256, h.Previous, v.CommitSHA, c.Previous, sha, c.SnapshotSHA}
}
func errInconsistent() error { return errors.New("stored case/source ledger inconsistent") }

func setup(ctx context.Context, tx *sql.Tx) error {
	_, err := tx.ExecContext(ctx, `SET LOCAL search_path=pg_catalog,public`)
	return err
}
func safeRole(ctx context.Context, tx *sql.Tx) error {
	var safe bool
	err := tx.QueryRowContext(ctx, `SELECT NOT r.rolsuper AND NOT r.rolbypassrls AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname IN ('ra_reader_grants','ra_source_registry','ra_source_snapshots','ra_source_streams','ra_source_records','ra_source_occurrences','ra_case_heads','ra_case_revisions','ra_case_refs','ra_case_policy_bindings','ra_policy_history','ra_control_audit','ra_audit_imports') AND pg_has_role(r.oid,c.relowner,'USAGE')) FROM pg_roles r WHERE r.rolname=current_user`).Scan(&safe)
	if err != nil {
		return err
	}
	if !safe {
		return errors.New("non-owner case role without RLS bypass required")
	}
	return nil
}
func writerAllowed(ctx context.Context, tx *sql.Tx, v Plan) error {
	if err := safeRole(ctx, tx); err != nil {
		return err
	}
	var allowed bool
	err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM public.ra_source_registry WHERE source_namespace=$1 AND tenant_id=$2 AND enabled AND writer_role=current_user AND metadata_sha256=decode($3,'hex'))`, v.Commit.Namespace, v.Commit.Tenant, v.Source.MetadataSHA).Scan(&allowed)
	if err != nil {
		return err
	}
	if !allowed {
		return errors.New("case source writer registration refused")
	}
	return nil
}

// matchSource never inserts source rows. Every receipt binding belongs to the
// exact persisted namespace/tenant/snapshot and original evaluation ordinal.
func matchSource(ctx context.Context, tx *sql.Tx, v Plan) error {
	c, r := v.Commit, v.Source
	var same bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM public.ra_source_snapshots WHERE source_namespace=$1 AND tenant_id=$2 AND snapshot_sha256=decode($3,'hex') AND metadata_sha256=decode($4,'hex') AND plan_sha256=decode($5,'hex'))`, c.Namespace, c.Tenant, c.SnapshotSHA, r.MetadataSHA, c.SourcePlanSHA).Scan(&same); err != nil {
		return err
	}
	if !same {
		return errors.New("source snapshot commitment missing or changed")
	}
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM public.ra_source_streams WHERE source_namespace=$1 AND tenant_id=$2 AND snapshot_sha256=decode($3,'hex')`, c.Namespace, c.Tenant, c.SnapshotSHA).Scan(&n); err != nil {
		return err
	}
	if n != len(r.Streams) {
		return errInconsistent()
	}
	for _, s := range r.Streams {
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM public.ra_source_streams WHERE source_namespace=$1 AND tenant_id=$2 AND snapshot_sha256=decode($3,'hex') AND stream=$4 AND record_count=$5 AND stream_sha256=decode($6,'hex'))`, c.Namespace, c.Tenant, c.SnapshotSHA, s.Stream, s.Records, s.SHA256).Scan(&same); err != nil {
			return err
		}
		if !same {
			return errors.New("source stream commitment missing or changed")
		}
	}
	for _, b := range r.Bindings {
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM public.ra_source_occurrences o JOIN public.ra_source_records x USING(source_namespace,tenant_id,stream,asset_id,sensor_id,event_id,line_sha256) WHERE o.source_namespace=$1 AND o.tenant_id=$2 AND o.snapshot_sha256=decode($3,'hex') AND o.stream=$4 AND o.commit_ordinal=$5 AND o.asset_id=$6 AND o.sensor_id=$7 AND o.event_id=$8 AND o.line_sha256=decode($9,'hex') AND o.evaluation_sha256=decode($10,'hex') AND o.evaluation_result=$11)`, c.Namespace, c.Tenant, c.SnapshotSHA, b.Stream, b.Ordinal, b.Asset, b.Sensor, b.EventID, b.LineSHA, b.EvaluationSHA, b.Result).Scan(&same); err != nil {
			return err
		}
		if !same {
			return errors.New("source occurrence missing or changed")
		}
	}
	return nil
}

// readTx validates the complete persisted prefix, including every stored B03
// history and source/ref linkage. All callers use one consistent transaction.
func readTx(ctx context.Context, tx *sql.Tx, tenant, caseID string, lock bool) (Stored, error) {
	var ns, headSHA string
	var headNum int
	var assetsJSON []byte
	query := `SELECT source_namespace,revision,encode(commit_sha256,'hex'),to_json(asset_ids) FROM public.ra_case_heads WHERE tenant_id=$1 AND case_id=$2`
	if lock {
		query += ` FOR UPDATE`
	}
	if err := tx.QueryRowContext(ctx, query, tenant, caseID).Scan(&ns, &headNum, &headSHA, &assetsJSON); err != nil {
		return Stored{}, err
	}
	var assets []string
	if err := json.Unmarshal(assetsJSON, &assets); err != nil {
		return Stored{}, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT revision,source_namespace,to_json(asset_ids),encode(snapshot_sha256,'hex'),encode(commit_sha256,'hex'),encode(previous_commit_sha256,'hex'),observed_at,encode(plan_sha256,'hex'),canonical_plan FROM public.ra_case_revisions WHERE tenant_id=$1 AND case_id=$2 ORDER BY revision`, tenant, caseID)
	if err != nil {
		return Stored{}, err
	}
	var reviews []Review
	for rows.Next() {
		var num int
		var rowNS, snapshot, commit, parent, observed, sha string
		var assetBytes, data []byte
		if err = rows.Scan(&num, &rowNS, &assetBytes, &snapshot, &commit, &parent, &observed, &sha, &data); err != nil {
			rows.Close()
			return Stored{}, err
		}
		var v Plan
		var rowAssets []string
		if len(data) > MaxPlan || json.Unmarshal(data, &v) != nil || json.Unmarshal(assetBytes, &rowAssets) != nil || hash(data) != sha || !bytes.Equal(data, encoded(v)) || validate(v) != nil {
			rows.Close()
			return Stored{}, errInconsistent()
		}
		c := v.Commit
		if num != len(reviews)+1 || c.Tenant != tenant || c.CaseID != caseID || c.Namespace != ns || rowNS != ns || !reflect.DeepEqual(c.Assets, assets) || !reflect.DeepEqual(rowAssets, assets) || num != c.Revision || snapshot != c.SnapshotSHA || commit != v.CommitSHA || parent != c.Previous || observed != c.ObservedAt.UTC().Format(timeWire) {
			rows.Close()
			return Stored{}, errInconsistent()
		}
		if len(reviews) > 0 {
			prev := reviews[len(reviews)-1].Plan
			if parent != prev.CommitSHA || !reflect.DeepEqual(v.Context.History.Entries[:num-1], prev.Context.History.Entries) || c.ObservedAt.Before(prev.Commit.ObservedAt) {
				rows.Close()
				return Stored{}, errInconsistent()
			}
		}
		reviews = append(reviews, Review{v, sha})
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return Stored{}, err
	}
	rows.Close()
	if len(reviews) != headNum || headNum < 1 || headNum > casefile.MaxRevisions || reviews[len(reviews)-1].Plan.CommitSHA != headSHA {
		return Stored{}, errInconsistent()
	}
	// Queries run after closing the row stream: database/sql uses one connection
	// per transaction and cannot execute nested result sets on it.
	for _, review := range reviews {
		v := review.Plan
		if err = matchSource(ctx, tx, v); err != nil {
			return Stored{}, err
		}
		rows, err = tx.QueryContext(ctx, `SELECT ref_id,source_namespace,encode(snapshot_sha256,'hex'),stream,commit_ordinal FROM public.ra_case_refs WHERE tenant_id=$1 AND case_id=$2 AND revision=$3 ORDER BY ref_id`, tenant, caseID, v.Commit.Revision)
		if err != nil {
			return Stored{}, err
		}
		n := 0
		for rows.Next() {
			var id, rowNS, snapshot, stream string
			var ordinal int
			if err = rows.Scan(&id, &rowNS, &snapshot, &stream, &ordinal); err != nil {
				rows.Close()
				return Stored{}, err
			}
			if n >= len(v.Source.Bindings) {
				rows.Close()
				return Stored{}, errInconsistent()
			}
			b := v.Source.Bindings[n]
			if id != b.RefID || rowNS != ns || snapshot != v.Commit.SnapshotSHA || stream != b.Stream || ordinal != b.Ordinal {
				rows.Close()
				return Stored{}, errInconsistent()
			}
			n++
		}
		if err = rows.Err(); err != nil {
			rows.Close()
			return Stored{}, err
		}
		rows.Close()
		if n != len(v.Source.Bindings) {
			return Stored{}, errInconsistent()
		}
	}
	last := reviews[len(reviews)-1]
	return Stored{Head: receipt(last.Plan, last.SHA256), Revisions: reviews}, nil
}

func Read(ctx context.Context, db *sql.DB, tenant, caseID string) (Stored, error) {
	if db == nil || !identifier.MatchString(tenant) || !identifier.MatchString(caseID) {
		return Stored{}, errors.New("database and valid case identity required")
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return Stored{}, err
	}
	defer tx.Rollback()
	if err = setup(ctx, tx); err != nil {
		return Stored{}, err
	}
	if err = safeRole(ctx, tx); err != nil {
		return Stored{}, err
	}
	var allowed bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM public.ra_reader_grants WHERE role_name=current_user AND tenant_id=$1) OR EXISTS(SELECT 1 FROM public.ra_source_registry WHERE writer_role=current_user AND tenant_id=$1 AND enabled)`, tenant).Scan(&allowed); err != nil {
		return Stored{}, err
	}
	if !allowed {
		return Stored{}, sql.ErrNoRows
	}
	out, err := readTx(ctx, tx, tenant, caseID, false)
	if err != nil {
		return Stored{}, err
	}
	if err = tx.Commit(); err != nil {
		return Stored{}, err
	}
	return out, nil
}

// Import performs head lock, current writer/source validation, full prior
// history validation and head CAS in one SERIALIZABLE transaction. Retry the
// exact input/review on serialization or uncertain commit; never reset parents.
func Import(ctx context.Context, db *sql.DB, p *Prepared, reviewed string) (Receipt, error) {
	if db == nil || p == nil || p.sha == "" || reviewed != p.sha || hash(p.data) != p.sha {
		return Receipt{}, errors.New("database, prepared case and matching review SHA required")
	}
	var v Plan
	if err := json.Unmarshal(p.data, &v); err != nil {
		return Receipt{}, err
	}
	if err := validate(v); err != nil {
		return Receipt{}, err
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return Receipt{}, err
	}
	defer tx.Rollback()
	if err = setup(ctx, tx); err != nil {
		return Receipt{}, err
	}
	if err = writerAllowed(ctx, tx, v); err != nil {
		return Receipt{}, err
	}
	c := v.Commit
	prior, readErr := readTx(ctx, tx, c.Tenant, c.CaseID, true)
	if readErr != nil && !errors.Is(readErr, sql.ErrNoRows) {
		return Receipt{}, readErr
	}
	if readErr == nil {
		head := prior.Head
		if c.Revision == head.Revision {
			if head.CommitSHA != v.CommitSHA {
				return Receipt{}, errors.New("same case revision conflict")
			}
			if err = tx.Commit(); err != nil {
				return Receipt{}, err
			}
			return head, nil
		}
		last := prior.Revisions[len(prior.Revisions)-1].Plan
		if c.Revision != head.Revision+1 || c.Previous != head.CommitSHA || c.Namespace != head.Namespace || !reflect.DeepEqual(c.Assets, last.Commit.Assets) || c.ObservedAt.Before(last.Commit.ObservedAt) || !reflect.DeepEqual(v.Context.History.Entries[:c.Revision-1], last.Context.History.Entries) {
			return Receipt{}, errors.New("case head, scope or history conflict")
		}
	} else if c.Revision != 1 || c.Previous != "" {
		return Receipt{}, errors.New("new case requires first revision")
	}
	if err = matchSource(ctx, tx, v); err != nil {
		return Receipt{}, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO public.ra_case_revisions(tenant_id,case_id,revision,source_namespace,asset_ids,snapshot_sha256,commit_sha256,previous_commit_sha256,observed_at,plan_sha256,canonical_plan) VALUES($1,$2,$3,$4,$5,decode($6,'hex'),decode($7,'hex'),decode($8,'hex'),$9,decode($10,'hex'),$11)`, c.Tenant, c.CaseID, c.Revision, c.Namespace, c.Assets, c.SnapshotSHA, v.CommitSHA, c.Previous, c.ObservedAt.UTC().Format(timeWire), p.sha, p.data); err != nil {
		return Receipt{}, err
	}
	for _, b := range v.Source.Bindings {
		if _, err = tx.ExecContext(ctx, `INSERT INTO public.ra_case_refs(tenant_id,case_id,revision,ref_id,source_namespace,snapshot_sha256,stream,commit_ordinal) VALUES($1,$2,$3,$4,$5,decode($6,'hex'),$7,$8)`, c.Tenant, c.CaseID, c.Revision, b.RefID, c.Namespace, c.SnapshotSHA, b.Stream, b.Ordinal); err != nil {
			return Receipt{}, fmt.Errorf("case ref: %w", err)
		}
	}
	if readErr != nil {
		_, err = tx.ExecContext(ctx, `INSERT INTO public.ra_case_heads(tenant_id,case_id,source_namespace,asset_ids,revision,commit_sha256) VALUES($1,$2,$3,$4,$5,decode($6,'hex'))`, c.Tenant, c.CaseID, c.Namespace, c.Assets, c.Revision, v.CommitSHA)
	} else {
		var result sql.Result
		result, err = tx.ExecContext(ctx, `UPDATE public.ra_case_heads SET revision=$3,commit_sha256=decode($4,'hex') WHERE tenant_id=$1 AND case_id=$2 AND revision=$5 AND commit_sha256=decode($6,'hex')`, c.Tenant, c.CaseID, c.Revision, v.CommitSHA, c.Revision-1, c.Previous)
		if err == nil {
			var n int64
			n, err = result.RowsAffected()
			if err == nil && n != 1 {
				err = errors.New("case head CAS conflict")
			}
		}
	}
	if err != nil {
		return Receipt{}, err
	}
	if err = tx.Commit(); err != nil {
		return Receipt{}, err
	}
	return receipt(v, p.sha), nil
}
