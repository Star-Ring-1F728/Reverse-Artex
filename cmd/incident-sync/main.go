// incident-sync imports a reviewed, immutable case projection into PostgreSQL.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"reflect"
	"reverse-artex/internal/evidence"
	"reverse-artex/internal/incident"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func main() {
	path := flag.String("manifest", "", "reviewed incident projection JSON")
	source := flag.String("evidence", "", "recovery-checked source evidence directory")
	sourceID := flag.String("source-id", "", "immutable source identifier")
	flag.Parse()
	if *path == "" || *source == "" || *sourceID == "" {
		log.Fatal("-manifest, -evidence and -source-id required")
	}
	dsn := os.Getenv("RA_INCIDENT_DATABASE_URL")
	if dsn == "" {
		log.Fatal("RA_INCIDENT_DATABASE_URL required")
	}
	file, err := os.Open(*path)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || info.Size() > 32<<20 {
		log.Fatal("incident manifest exceeds 32 MiB")
	}
	var m incident.Manifest
	decoder := json.NewDecoder(io.LimitReader(file, 32<<20+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&m); err != nil {
		log.Fatal(err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		log.Fatal("single manifest required")
	}
	info, err = os.Stat(*source)
	if err != nil || !info.IsDir() {
		log.Fatal("existing evidence directory required")
	}
	store, err := evidence.New(*source, 64<<20)
	if err != nil {
		log.Fatal(err)
	}
	rebuilt, err := incident.Build(store)
	if err != nil || !reflect.DeepEqual(m, rebuilt) {
		log.Fatal("manifest does not match current evidence")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		log.Fatal("incident database configuration invalid")
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if err := db.PingContext(ctx); err != nil {
		log.Fatal("incident database unavailable")
	}
	sha, err := incident.Import(ctx, db, *sourceID, m)
	if err != nil {
		log.Fatalf("incident import refused: %v", err)
	}
	fmt.Printf("incident import committed: cases=%d manifest_sha256=%s\n", len(m.Cases), sha)
}
