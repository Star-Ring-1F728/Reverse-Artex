// incident-export reads one tenant's case timeline from PostgreSQL.
package main

import (
	"context"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"
	"unicode"

	_ "github.com/jackc/pgx/v5/stdlib"
)

type row struct {
	CaseID string    `json:"case_id"`
	Tenant string    `json:"tenant_id"`
	Asset  string    `json:"asset_id"`
	Kind   string    `json:"kind"`
	Stream string    `json:"stream"`
	ID     string    `json:"id"`
	Rule   string    `json:"rule_id,omitempty"`
	Time   time.Time `json:"time"`
}

const timeline = `SELECT c.case_id,c.tenant_id,c.asset_id,'alert',a.stream,encode(a.line_sha256,'hex'),a.rule_id,a.alert_time
FROM ra_cases c JOIN ra_case_alerts a ON a.case_id=c.case_id AND a.tenant_id=c.tenant_id AND a.asset_id=c.asset_id
WHERE c.tenant_id=$1 AND ($2='' OR c.case_id=$2)
UNION ALL
SELECT c.case_id,c.tenant_id,c.asset_id,'evidence',e.stream,e.event_id,'',e.event_time
FROM ra_cases c JOIN ra_case_evidence l ON l.case_id=c.case_id AND l.tenant_id=c.tenant_id AND l.asset_id=c.asset_id
JOIN ra_evidence_records e ON e.stream=l.stream AND e.tenant_id=l.tenant_id AND e.asset_id=l.asset_id AND e.event_id=l.event_id
WHERE c.tenant_id=$1 AND ($2='' OR c.case_id=$2)
UNION ALL
SELECT c.case_id,c.tenant_id,c.asset_id,'policy','control',p.policy_id,p.rule_version,p.issued_at
FROM ra_cases c JOIN ra_policy_history p ON p.case_id=c.case_id AND p.tenant_id=c.tenant_id AND p.asset_id=c.asset_id
WHERE c.tenant_id=$1 AND ($2='' OR c.case_id=$2)
UNION ALL
SELECT c.case_id,c.tenant_id,c.asset_id,'control-audit',a.operation,a.epoch || ':' || a.version::text,p.rule_version,a.operation_at
FROM ra_cases c JOIN ra_policy_history p ON p.case_id=c.case_id AND p.tenant_id=c.tenant_id AND p.asset_id=c.asset_id
JOIN ra_control_audit a ON a.policy_id=p.policy_id
WHERE c.tenant_id=$1 AND ($2='' OR c.case_id=$2)
ORDER BY 8,1,4,6 LIMIT 10001`

func safeCSV(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, s)
	s = strings.TrimLeftFunc(s, func(r rune) bool { return unicode.IsSpace(r) || r == '\ufeff' || r == '\u200b' })
	if s != "" && strings.ContainsRune("=+-@", rune(s[0])) {
		return "'" + s
	}
	return s
}

func main() {
	tenant := flag.String("tenant", "", "tenant identifier granted to the caller")
	caseID := flag.String("case", "", "optional case identifier")
	format := flag.String("format", "json", "json or csv")
	flag.Parse()
	if *tenant == "" || (*format != "json" && *format != "csv") {
		log.Fatal("-tenant and -format json|csv required")
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
	var grantedTenant string
	if err := tx.QueryRowContext(ctx, `SELECT tenant_id FROM ra_reader_grants WHERE role_name=current_user`).Scan(&grantedTenant); err != nil || grantedTenant != *tenant {
		log.Fatal("database reader role is not granted this tenant")
	}
	rows, err := tx.QueryContext(ctx, timeline, *tenant, *caseID)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()
	items := []row{}
	for rows.Next() {
		var item row
		if err := rows.Scan(&item.CaseID, &item.Tenant, &item.Asset, &item.Kind, &item.Stream, &item.ID, &item.Rule, &item.Time); err != nil {
			log.Fatal(err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		log.Fatal(err)
	}
	if len(items) > 10000 {
		log.Fatal("timeline exceeds 10000 rows; narrow -case")
	}
	if err := tx.Commit(); err != nil {
		log.Fatal(err)
	}
	if *format == "json" {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetEscapeHTML(true)
		if err := encoder.Encode(items); err != nil {
			log.Fatal(err)
		}
		return
	}
	writer := csv.NewWriter(os.Stdout)
	if err := writer.Write([]string{"case_id", "tenant_id", "asset_id", "kind", "stream", "id", "rule_id", "time"}); err != nil {
		log.Fatal(err)
	}
	for _, item := range items {
		fields := []string{item.CaseID, item.Tenant, item.Asset, item.Kind, item.Stream, item.ID, item.Rule, item.Time.Format(time.RFC3339Nano)}
		for i := range fields {
			fields[i] = safeCSV(fields[i])
		}
		if err := writer.Write(fields); err != nil {
			log.Fatal(err)
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		log.Fatal(fmt.Errorf("CSV export: %w", err))
	}
}
