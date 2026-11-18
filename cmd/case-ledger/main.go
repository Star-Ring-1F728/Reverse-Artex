// case-ledger reviews/imports replayed case history or verifies persisted history.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	_ "github.com/jackc/pgx/v5/stdlib"
	"io"
	"os"
	"reverse-artex/internal/casefile"
	"reverse-artex/internal/caseledger"
	"reverse-artex/internal/evidence"
	"strings"
	"time"
)

func regular(path string, max int64) (*os.File, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Size() > max {
		return nil, errors.New("bounded regular input required")
	}
	return os.Open(path)
}
func run(args []string, stdout, stderr io.Writer) error {
	f := flag.NewFlagSet("case-ledger", flag.ContinueOnError)
	f.SetOutput(stderr)
	input := f.String("input", "", "bounded case-context fixture")
	source := f.String("evidence", "", "unchanged offline detector evidence")
	ns := f.String("source-id", "", "provisioned source namespace")
	tenant := f.String("tenant", "", "tenant scope; not caller authentication")
	previous := f.String("previous", "", "B03 predecessor ContextResult file")
	expected := f.String("expected-head", "", "predecessor DB commit SHA; distinct from B03 parent")
	at := f.String("at", "", "explicit RFC3339Nano as-of; not online freshness")
	plan := f.Bool("plan", false, "read-only plan without DB connection")
	review := f.String("review-sha", "", "review SHA required for import")
	read := f.String("read-case", "", "verify and read persisted case history")
	wal := f.String("policy-wal", "", "offline actions.jsonl to bind to an existing case head")
	auditSource := f.String("audit-source", "", "existing legacy audit import identity")
	policyIDs := f.String("policy-ids", "", "comma-separated explicit policy selection")
	policyAt := f.String("policy-at", "", "explicit historical policy snapshot cutoff")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 || *tenant == "" {
		return errors.New("tenant and valid mode required")
	}
	var out any
	if (*wal != "" && (*auditSource == "" || *policyIDs == "" || *policyAt == "" || *read != "")) || (*wal == "" && (*auditSource != "" || *policyIDs != "" || *policyAt != "")) {
		return errors.New("policy binding requires WAL, audit-source, policy-ids and policy-at")
	}
	if *read != "" {
		if *input != "" || *source != "" || *ns != "" || *previous != "" || *expected != "" || *at != "" || *plan || *review != "" {
			return errors.New("read-case cannot combine with write/plan inputs")
		}
	} else {
		now, err := time.Parse(time.RFC3339Nano, *at)
		if err != nil || *input == "" || *source == "" || *ns == "" || (*plan && *review != "") || (!*plan && *review == "") {
			return errors.New("input, evidence, source-id, at and either plan or review-sha required")
		}
		file, err := regular(*input, casefile.MaxBundle)
		if err != nil {
			return err
		}
		b, err := casefile.DecodeContext(file)
		file.Close()
		if err != nil {
			return err
		}
		var prior *casefile.ContextResult
		if *previous != "" {
			file, err := regular(*previous, casefile.MaxPrevious)
			if err != nil {
				return err
			}
			p, err := casefile.DecodePrevious(file)
			file.Close()
			if err != nil {
				return err
			}
			prior = &p
		}
		snapshot, err := evidence.Capture(*source)
		if err != nil {
			return err
		}
		p, err := caseledger.Prepare(*ns, *tenant, b, prior, *expected, now, snapshot)
		if err != nil {
			return err
		}
		if *wal != "" {
			cut, err := time.Parse(time.RFC3339Nano, *policyAt)
			if err != nil {
				return errors.New("valid policy cutoff required")
			}
			h, err := caseledger.PreparePolicyHistory(p, snapshot, *wal, *auditSource, strings.Split(*policyIDs, ","), cut)
			if err != nil {
				return err
			}
			if *plan {
				out = h.Review()
			} else {
				db, err := openDB()
				if err != nil {
					return err
				}
				defer db.Close()
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				r, err := caseledger.ImportPolicyHistory(ctx, db, h, *review)
				if err != nil {
					return err
				}
				out = struct {
					SHA  string             `json:"binding_sha256"`
					Case caseledger.Receipt `json:"case"`
					AsOf time.Time          `json:"as_of"`
				}{r.SHA256, r.Binding.Case, r.Binding.AsOf}
			}
		} else if *plan {
			out = p.Review()
		} else {
			if p.Review().SHA256 != *review {
				return errors.New("reviewed plan does not match current case/source")
			}
			db, err := openDB()
			if err != nil {
				return err
			}
			defer db.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			out, err = caseledger.Import(ctx, db, p, *review)
			if err != nil {
				return fmt.Errorf("case import refused: %w", err)
			}
		}
	}
	if *read != "" {
		db, err := openDB()
		if err != nil {
			return err
		}
		defer db.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		out, err = caseledger.Read(ctx, db, *tenant, *read)
		if err != nil {
			return fmt.Errorf("case read refused: %w", err)
		}
	}
	data, err := json.MarshalIndent(out, "", "  ")
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
func openDB() (*sql.DB, error) {
	dsn := os.Getenv("RA_CASE_DATABASE_URL")
	if dsn == "" {
		return nil, errors.New("RA_CASE_DATABASE_URL required")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, errors.New("case database configuration invalid")
	}
	db.SetMaxOpenConns(1)
	return db, nil
}
func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "case-ledger refused:", err)
		os.Exit(2)
	}
}
