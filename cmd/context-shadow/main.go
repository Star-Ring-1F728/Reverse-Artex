// context-shadow reads a stopped collector snapshot. It never reads gold.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reverse-artex/internal/actioncontext"
	"reverse-artex/internal/casememory"
	"reverse-artex/internal/contextlearning"
	"reverse-artex/internal/contextshadow"
	"reverse-artex/internal/contractjson"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func read(path string, v any) error {
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() || st.Size() > 2<<20 {
		return contextlearning.ErrInvalid
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, (2<<20)+1))
	if err != nil {
		return err
	}
	return contractjson.Decode(b, v, 2<<20, 8192)
}
func run(args []string) error {
	flags := flag.NewFlagSet("context-shadow", flag.ContinueOnError)
	candidate := flags.String("candidate", "", "frozen v2 candidate JSON")
	expected := flags.String("expected-candidate-sha256", "", "candidate digest delivered separately")
	authorities := flags.String("review-trust", "", "public review authorities matching candidate")
	trust := flags.String("context-trust", "", "public sensor/issuer trust matching candidate and snapshot")
	evidence := flags.String("evidence", "", "stopped collector evidence or offline copy")
	out := flags.String("out", "", "new receipt outside source evidence directory")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *candidate == "" || *expected == "" || *authorities == "" || *trust == "" || *evidence == "" || *out == "" {
		return errors.New("explicit candidate pin, public trusts, offline evidence and new output required")
	}
	// Resolve parents to prevent writing through a symlink into source evidence.
	source, err := filepath.EvalSymlinks(*evidence)
	if err != nil {
		return err
	}
	source, err = filepath.Abs(source)
	if err != nil {
		return err
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(*out))
	if err != nil {
		return err
	}
	parent, err = filepath.Abs(parent)
	if err != nil {
		return err
	}
	sourceInfo, err := os.Stat(source)
	if err != nil {
		return err
	}
	for p := parent; ; p = filepath.Dir(p) {
		info, statErr := os.Stat(p)
		if statErr != nil {
			return statErr
		}
		if os.SameFile(info, sourceInfo) {
			return errors.New("receipt must be outside evidence directory")
		}
		if filepath.Dir(p) == p {
			break
		}
	}
	var c contextlearning.Candidate
	var a casememory.LearningTrust
	var t actioncontext.Trust
	for _, item := range []struct {
		path string
		v    any
	}{{*candidate, &c}, {*authorities, &a}, {*trust, &t}} {
		if err := read(item.path, item.v); err != nil {
			return err
		}
	}
	receipt, err := contextshadow.Observe(source, c, *expected, a, t)
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.OpenFile(*out, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(append(b, '\n'))
	return errors.Join(writeErr, f.Sync(), f.Close())
}
