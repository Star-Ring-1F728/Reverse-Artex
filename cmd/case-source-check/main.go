// case-source-check binds an offline context fixture to replayed detector
// evidence. It never authenticates a sensor or connects to a live database.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"reverse-artex/internal/casefile"
	"reverse-artex/internal/evidence"
	"time"
)

func run(args []string, stdout, stderr io.Writer) error {
	f := flag.NewFlagSet("case-source-check", flag.ContinueOnError)
	f.SetOutput(stderr)
	input := f.String("input", "", "case-context/1 fixture")
	source := f.String("evidence", "", "offline, unchanged detector evidence directory")
	at := f.String("at", "", "explicit RFC3339Nano as-of time")
	out := f.String("out", "", "optional new output file; never overwrites")
	if err := f.Parse(args); err != nil {
		return err
	}
	now, err := time.Parse(time.RFC3339Nano, *at)
	if err != nil || *input == "" || *source == "" || f.NArg() != 0 {
		return errors.New("input, evidence and explicit as-of time required")
	}
	if *out != "" {
		if _, err := os.Lstat(*out); !os.IsNotExist(err) {
			return errors.New("new output path required")
		}
	}
	st, err := os.Lstat(*input)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() || st.Size() > casefile.MaxBundle {
		return errors.New("bounded regular fixture required")
	}
	file, err := os.Open(*input)
	if err != nil {
		return err
	}
	b, decodeErr := casefile.DecodeContext(file)
	if err := errors.Join(decodeErr, file.Close()); err != nil {
		return err
	}
	snapshot, err := evidence.Capture(*source)
	if err != nil {
		return err
	}
	result, err := casefile.CheckSource(b, now, snapshot)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(result, "", "  ")
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
	file, err = os.OpenFile(*out, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	n, err := file.Write(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = file.Sync()
	}
	return errors.Join(err, file.Close())
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "case-source-check refused:", err)
		os.Exit(2)
	}
}
