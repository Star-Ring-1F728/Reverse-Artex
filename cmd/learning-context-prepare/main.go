// learning-context-prepare exports an unsigned review request from a stopped
// collector and an existing verified-label journal; it cannot issue signatures.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reverse-artex/internal/actioncontext"
	"reverse-artex/internal/casememory"
	"reverse-artex/internal/contextfeedback"
	"reverse-artex/internal/contractjson"
	"reverse-artex/internal/evidence"
	"time"
)

func read(path string, target any) error {
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() || st.Size() > 2<<20 {
		return fmt.Errorf("bounded regular public contract required")
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, (2<<20)+1))
	if err != nil {
		return err
	}
	return contractjson.Decode(raw, target, 2<<20, 8192)
}

func run(args []string) error {
	f := flag.NewFlagSet("learning-context-prepare", flag.ContinueOnError)
	root := f.String("evidence", "", "stopped collector or immutable offline evidence")
	journal := f.String("case-memory", "", "existing current signed-label journal")
	trustPath := f.String("context-trust", "", "operator-pinned sensor/issuer public trust")
	requestPath := f.String("request", "", "dataset recipe and exact case/family/source annotations")
	out := f.String("out", "", "new output directory")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 || *root == "" || *journal == "" || *trustPath == "" || *requestPath == "" || *out == "" {
		return fmt.Errorf("explicit evidence, existing case journal, trust, request and new output required")
	}
	if _, err := os.Lstat(*out); !os.IsNotExist(err) {
		return fmt.Errorf("output must be a new directory")
	}
	st, err := os.Lstat(*journal)
	if err != nil || !st.Mode().IsRegular() {
		return fmt.Errorf("existing regular case journal required")
	}
	var trust actioncontext.Trust
	var request contextfeedback.Request
	if err := read(*trustPath, &trust); err != nil {
		return err
	}
	if err := read(*requestPath, &request); err != nil {
		return err
	}
	snapshot, err := evidence.Capture(*root)
	if err != nil {
		return err
	}
	memory, err := casememory.Open(*journal)
	if err != nil {
		return err
	}
	defer memory.Close()
	prepared, err := contextfeedback.Prepare(snapshot, memory, trust, request, time.Now().UTC())
	if err != nil {
		return err
	}
	if err := os.Mkdir(*out, 0700); err != nil {
		return err
	}
	for _, item := range []struct {
		name  string
		value any
	}{
		{"inputs.json", prepared.Inputs}, {"gold.json", prepared.Gold},
		{"review-template.json", prepared.Review}, {"review-trust.json", prepared.Trust},
		{"preparation.json", prepared},
	} {
		raw, err := json.MarshalIndent(item.value, "", "  ")
		if err != nil {
			return err
		}
		h, err := os.OpenFile(filepath.Join(*out, item.name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		_, writeErr := h.Write(append(raw, '\n'))
		syncErr, closeErr := h.Sync(), h.Close()
		if writeErr != nil {
			return writeErr
		}
		if syncErr != nil {
			return syncErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
