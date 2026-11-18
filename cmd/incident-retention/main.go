// incident-retention reports database retention candidates. It never deletes.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"log"
	"os"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

type result struct {
	Mode                        string    `json:"mode"`
	AsOf                        time.Time `json:"as_of"`
	EventDaysProposal           int       `json:"event_days_proposal"`
	CaseDaysProposal            int       `json:"case_days_proposal"`
	OldClosedCasesWithoutHold   int64     `json:"old_closed_cases_without_hold"`
	OldUnreferencedEvidenceRows int64     `json:"old_unreferenced_evidence_rows"`
	OldOpenCases                int64     `json:"old_open_cases"`
	ActiveHolds                 int64     `json:"active_holds"`
	DeletionAuthorized          bool      `json:"deletion_authorized"`
	SegmentAndAckChecked        bool      `json:"segment_and_ack_checked"`
}

func main() {
	asOfFlag := flag.String("as-of", "", "fixed RFC3339 review time; defaults to current UTC")
	flag.Parse()
	asOf := time.Now().UTC()
	if *asOfFlag != "" {
		var err error
		asOf, err = time.Parse(time.RFC3339, *asOfFlag)
		if err != nil {
			log.Fatal(err)
		}
	}
	dsn := os.Getenv("RA_INCIDENT_DATABASE_URL")
	if dsn == "" {
		log.Fatal("RA_INCIDENT_DATABASE_URL required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		log.Fatal("database configuration invalid")
	}
	defer db.Close()
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		log.Fatal("database unavailable")
	}
	defer tx.Rollback()
	r := result{Mode: "dry-run", AsOf: asOf, EventDaysProposal: 7, CaseDaysProposal: 30}
	queries := []struct {
		out   *int64
		query string
		args  []any
	}{
		{&r.OldClosedCasesWithoutHold, `SELECT count(*) FROM ra_cases c WHERE c.state='closed' AND c.last_alert_at < $1 AND NOT EXISTS (SELECT 1 FROM ra_retention_holds h WHERE h.case_id=c.case_id AND h.released_at IS NULL)`, []any{asOf.AddDate(0, 0, -30)}},
		{&r.OldUnreferencedEvidenceRows, `SELECT count(*) FROM ra_evidence_records e WHERE e.event_time < $1 AND NOT EXISTS (SELECT 1 FROM ra_case_evidence l WHERE l.stream=e.stream AND l.tenant_id=e.tenant_id AND l.asset_id=e.asset_id AND l.event_id=e.event_id)`, []any{asOf.AddDate(0, 0, -7)}},
		{&r.OldOpenCases, `SELECT count(*) FROM ra_cases WHERE state <> 'closed' AND last_alert_at < $1`, []any{asOf.AddDate(0, 0, -30)}},
		{&r.ActiveHolds, `SELECT count(*) FROM ra_retention_holds WHERE released_at IS NULL`, nil},
	}
	for _, q := range queries {
		if err := tx.QueryRowContext(ctx, q.query, q.args...).Scan(q.out); err != nil {
			log.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		log.Fatal(err)
	}
	if err := json.NewEncoder(os.Stdout).Encode(r); err != nil {
		log.Fatal(err)
	}
}
