// control-audit-sync projects one immutable control WAL snapshot into PostgreSQL.
package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"log"
	"os"
	"reverse-artex/internal/incident"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func main() {
	path := flag.String("wal", "", "recovery-checked actions.jsonl path")
	sourceID := flag.String("source-id", "", "immutable WAL snapshot identifier")
	flag.Parse()
	if *path == "" || *sourceID == "" {
		log.Fatal("-wal and -source-id required")
	}
	dsn := os.Getenv("RA_INCIDENT_DATABASE_URL")
	if dsn == "" {
		log.Fatal("RA_INCIDENT_DATABASE_URL required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		log.Fatal("database configuration invalid")
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	sha, count, err := incident.ImportAudit(ctx, db, *sourceID, *path)
	if err != nil {
		log.Fatalf("control audit import refused: %v", err)
	}
	fmt.Printf("control audit import committed: rows=%d wal_sha256=%s\n", count, sha)
}
