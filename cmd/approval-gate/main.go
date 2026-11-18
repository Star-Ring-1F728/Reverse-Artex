// approval-gate operates an offline signed intent ledger. It has no signer,
// private-key input, network transport or policy execution operation.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"reverse-artex/internal/actionapproval"
	"reverse-artex/internal/actionproposal"
)

func bounded(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	s, err := f.Stat()
	if err != nil || !s.Mode().IsRegular() || s.Size() > limit {
		return nil, errors.New("bounded regular input file required")
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, errors.New("input byte limit")
	}
	return raw, nil
}

func run(args []string, stdout, stderr io.Writer) error {
	f := flag.NewFlagSet("approval-gate", flag.ContinueOnError)
	f.SetOutput(stderr)
	action := f.String("action", "status", "status | consume | command (offline only)")
	state := f.String("state", "", "explicit owned append-only ledger path")
	trust := f.String("trust", "", "operator-pinned public-key trust policy JSON")
	signed := f.String("authorization", "", "signed authorization JSON; no signing occurs here")
	request := f.String("request", "", "original proposal request, only for consume")
	asOf := f.String("as-of", "", "explicit RFC3339 offline validation time")
	out := f.String("out", "", "optional new report file; never overwrites")
	if err := f.Parse(args); err != nil {
		return err
	}
	now, err := time.Parse(time.RFC3339Nano, *asOf)
	if err != nil || now.IsZero() || *state == "" || *trust == "" || f.NArg() != 0 ||
		(*action != "status" && *action != "consume" && *action != "command") ||
		(*action == "consume") != (*request != "") || (*action != "status") != (*signed != "") {
		return errors.New("explicit state/trust/as-of and action-specific inputs required")
	}
	if *out != "" {
		if _, err := os.Lstat(*out); !os.IsNotExist(err) {
			return errors.New("new report path required")
		}
	}
	raw, err := bounded(*trust, 16<<10)
	if err != nil {
		return err
	}
	policy, err := actionapproval.DecodeTrust(raw)
	if err != nil {
		return err
	}
	var authorization actionapproval.Signed
	if *signed != "" {
		raw, err := bounded(*signed, 8<<10)
		if err != nil {
			return err
		}
		authorization, err = actionapproval.DecodeSigned(raw)
		if err != nil {
			return err
		}
	}
	var original actionproposal.Request
	if *request != "" {
		raw, err := bounded(*request, actionproposal.MaxRequest)
		if err != nil {
			return err
		}
		original, err = actionproposal.DecodeRequest(raw)
		if err != nil {
			return err
		}
	}
	l, err := actionapproval.Open(*state, policy, now)
	if err != nil {
		return err
	}
	defer l.Close()
	switch *action {
	case "consume":
		_, err = l.Consume(original, authorization, now)
	case "command":
		err = l.Apply(authorization, now)
	}
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(l.Inspect(), "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if *out == "" {
		n, err := stdout.Write(data)
		if err == nil && n != len(data) {
			err = io.ErrShortWrite
		}
		return err
	}
	dest, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	n, err := dest.Write(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = dest.Sync()
	}
	closeErr := dest.Close()
	if err == nil {
		err = closeErr
	}
	return err
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "approval-gate refused:", err)
		os.Exit(2)
	}
}
