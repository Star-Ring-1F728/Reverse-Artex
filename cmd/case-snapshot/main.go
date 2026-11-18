// case-snapshot derives one offline case envelope. It does not read a live
// incident DB, enqueue assistance, authenticate sensors or mutate policies.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"reverse-artex/internal/casefile"
	"time"
)

func run(args []string, stdout, stderr io.Writer) error {
	f := flag.NewFlagSet("case-snapshot", flag.ContinueOnError)
	f.SetOutput(stderr)
	input := f.String("input", "", "bounded offline case fixture JSON")
	at := f.String("at", "", "required RFC3339Nano as-of time; not an online freshness claim")
	out := f.String("out", "", "optional new output file; never overwrites")
	withContext := f.Bool("context", false, "case-context/1 with offline revision history")
	previous := f.String("previous", "", "trusted previous context result, read only; requires -context")
	if err := f.Parse(args); err != nil {
		return err
	}
	now, err := time.Parse(time.RFC3339Nano, *at)
	if err != nil || *input == "" || f.NArg() != 0 || (!*withContext && *previous != "") {
		return errors.New("explicit input and valid as-of time required")
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
	handle, err := os.Open(*input)
	if err != nil {
		return err
	}
	defer handle.Close()
	var doc any
	if *withContext {
		b, decodeErr := casefile.DecodeContext(handle)
		if decodeErr != nil {
			return decodeErr
		}
		var prior *casefile.ContextResult
		if *previous != "" {
			st, err := os.Lstat(*previous)
			if err != nil {
				return err
			}
			if !st.Mode().IsRegular() || st.Size() > casefile.MaxPrevious {
				return errors.New("bounded regular predecessor required")
			}
			f, err := os.Open(*previous)
			if err != nil {
				return err
			}
			defer f.Close()
			p, err := casefile.DecodePrevious(f)
			if err != nil {
				return err
			}
			prior = &p
		}
		doc, err = casefile.Advance(prior, b, now)
	} else {
		b, decodeErr := casefile.Decode(handle)
		if decodeErr != nil {
			return decodeErr
		}
		doc, err = casefile.Build(b, now)
	}
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(doc, "", "  ")
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
	file, err := os.OpenFile(*out, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
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
		fmt.Fprintln(os.Stderr, "case-snapshot refused:", err)
		os.Exit(2)
	}
}
