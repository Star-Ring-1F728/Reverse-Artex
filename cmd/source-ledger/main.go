// source-ledger reviews or imports one replay-verified offline evidence snapshot.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"reverse-artex/internal/evidence"
	"reverse-artex/internal/sourceledger"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func run(args []string, stdout, stderr io.Writer) error {
	f := flag.NewFlagSet("source-ledger", flag.ContinueOnError)
	f.SetOutput(stderr)
	source := f.String("evidence", "", "offline unchanged detector evidence directory")
	namespace := f.String("source-id", "", "separately provisioned source namespace")
	tenant := f.String("tenant", "", "registered tenant; not caller authentication")
	planOnly := f.Bool("plan", false, "read-only plan and hash, no DB connection")
	reviewed := f.String("review-sha", "", "required reviewed plan SHA for import")
	if err := f.Parse(args); err != nil {
		return err
	}
	if *source == "" || *namespace == "" || *tenant == "" || f.NArg() != 0 || (*planOnly && *reviewed != "") || (!*planOnly && *reviewed == "") {
		return errors.New("evidence, source-id, tenant and either -plan or -review-sha required")
	}
	s, err := evidence.Capture(*source)
	if err != nil {
		return err
	}
	p, err := sourceledger.Prepare(*namespace, *tenant, s)
	if err != nil {
		return err
	}
	var output any = p.Review()
	if !*planOnly {
		if p.Review().SHA256 != *reviewed {
			return errors.New("reviewed plan does not match current source")
		}
		dsn := os.Getenv("RA_SOURCE_DATABASE_URL")
		if dsn == "" {
			return errors.New("RA_SOURCE_DATABASE_URL required")
		}
		db, err := sql.Open("pgx", dsn)
		if err != nil {
			return errors.New("source database configuration invalid")
		}
		defer db.Close()
		db.SetMaxOpenConns(1)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		receipt, err := sourceledger.Import(ctx, db, p, *reviewed)
		if err != nil {
			return fmt.Errorf("source import refused: %w", err)
		}
		output = receipt
	}
	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	n, err := stdout.Write(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	return err
}
func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "source-ledger refused:", err)
		os.Exit(2)
	}
}
