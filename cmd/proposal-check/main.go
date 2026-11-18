// proposal-check validates a declared offline context and emits a shadow draft.
// It never connects to a case service, model, approver or policy writer.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"reverse-artex/internal/actionproposal"
)

func run(args []string, stdout, stderr io.Writer) error {
	f := flag.NewFlagSet("proposal-check", flag.ContinueOnError)
	f.SetOutput(stderr)
	input := f.String("input", "", "bounded offline proposal request JSON")
	asOf := f.String("as-of", "", "explicit RFC3339 validation time; offline replay only")
	out := f.String("out", "", "optional new JSON report; never overwrites")
	if err := f.Parse(args); err != nil {
		return err
	}
	now, err := time.Parse(time.RFC3339Nano, *asOf)
	if err != nil || now.IsZero() || *input == "" || f.NArg() != 0 {
		return errors.New("input and explicit RFC3339 as-of time required")
	}
	file, err := os.Open(*input)
	if err != nil {
		return err
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil || !stat.Mode().IsRegular() || stat.Size() > actionproposal.MaxRequest {
		return errors.New("bounded regular request file required")
	}
	raw, err := io.ReadAll(io.LimitReader(file, actionproposal.MaxRequest+1))
	if err != nil {
		return err
	}
	req, err := actionproposal.DecodeRequest(raw)
	if err != nil {
		return err
	}
	review, err := actionproposal.Build(req, now)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(review, "", "  ")
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
	destination, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	n, err := destination.Write(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = destination.Sync()
	}
	closeErr := destination.Close()
	if err == nil {
		err = closeErr
	}
	return err
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "proposal-check refused:", err)
		os.Exit(2)
	}
}
