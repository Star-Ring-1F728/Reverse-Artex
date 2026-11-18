// action-execute connects explicit signed approvals to authenticated case reads
// and a configured policy-control writer. It never invokes a model or signer.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"reverse-artex/internal/actionapproval"
	"reverse-artex/internal/actionproposal"
)

func bounded(path string, limit int) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > int64(limit) {
		return nil, errors.New("bounded regular input required")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, int64(limit+1)))
	if err != nil || len(raw) > limit {
		return nil, errors.New("input read failed or exceeded bound")
	}
	return raw, nil
}
func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	f := flag.NewFlagSet("action-execute", flag.ContinueOnError)
	f.SetOutput(stderr)
	op := f.String("operation", "inspect", "inspect, execute, observe or release")
	enabled := f.Bool("execute", false, "explicit opt-in to real policy-control mutations")
	state := f.String("state", "", "approval ledger path")
	trustPath := f.String("trust", "", "original pinned ledger trust policy")
	authority := f.String("authority", "", "operator-owned current grants/configuration file")
	caseOrigin := f.String("case-api", "", "case service literal-IP origin")
	controlOrigin := f.String("policy-control", "", "control service literal-IP origin")
	request := f.String("request", "", "original proposal request")
	authorization := f.String("authorization", "", "signed exact approval")
	entry := f.String("entry", "", "existing execution entry for observe/release")
	out := f.String("out", "", "optional new receipt path, also used for unconfirmed outcomes")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 || *state == "" || *trustPath == "" || (*op != "inspect" && *op != "execute" && *op != "observe" && *op != "release") || ((*op == "execute" || *op == "release") && !*enabled) {
		return errors.New("explicit operation/state/trust and mutation opt-in required")
	}
	if *out != "" {
		if _, err := os.Lstat(*out); !os.IsNotExist(err) {
			return errors.New("new receipt path required")
		}
	}
	raw, err := bounded(*trustPath, 16<<10)
	if err != nil {
		return err
	}
	trust, err := actionapproval.DecodeTrust(raw)
	if err != nil {
		return err
	}
	// Validate all service/input settings before opening/creating the ledger.
	var services *actionapproval.ExecutionServices
	var req actionproposal.Request
	var auth actionapproval.Signed
	if *op != "inspect" {
		services, err = actionapproval.NewExecutionServices(*caseOrigin, *controlOrigin, os.Getenv("RA_ACTION_CASE_TOKEN"), os.Getenv("RA_ACTION_ADMIN_TOKEN"), os.Getenv("RA_ACTION_READER_TOKEN"), *authority)
		if err != nil {
			return err
		}
		defer services.Close()
		if *op == "execute" {
			raw, err = bounded(*request, actionproposal.MaxRequest)
			if err != nil {
				return err
			}
			req, err = actionproposal.DecodeRequest(raw)
			if err != nil {
				return err
			}
			raw, err = bounded(*authorization, 8<<10)
			if err != nil {
				return err
			}
			auth, err = actionapproval.DecodeSigned(raw)
			if err != nil {
				return err
			}
		} else if *entry == "" {
			return errors.New("entry required for observe/release")
		}
	}
	l, err := actionapproval.Open(*state, trust, time.Now().UTC())
	if err != nil {
		return err
	}
	defer l.Close()
	var result any
	var operationErr error
	switch *op {
	case "inspect":
		result = l.Inspect()
	case "execute":
		result, operationErr = l.RunExecution(ctx, req, auth, services)
	case "observe":
		result, operationErr = l.ObserveExecution(ctx, *entry, services)
	case "release":
		result, operationErr = l.ReleaseExecution(ctx, *entry, services)
	}
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return errors.Join(operationErr, err)
	}
	data = append(data, '\n')
	var dest io.Writer = stdout
	var file *os.File
	if *out != "" {
		file, err = os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return errors.Join(operationErr, err)
		}
		dest = file
	}
	n, err := dest.Write(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	if file != nil {
		if err == nil {
			err = file.Sync()
		}
		err = errors.Join(err, file.Close())
	}
	return errors.Join(operationErr, err)
}
func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "action-execute:", err)
		os.Exit(2)
	}
}
