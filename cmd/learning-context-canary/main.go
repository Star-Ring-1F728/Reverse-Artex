package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"reverse-artex/internal/casememory"
	"reverse-artex/internal/contextevaluation"
	"reverse-artex/internal/evidence"
	"time"
)

func main() {
	if e := run(os.Args[1:]); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func writeNew(path string, value any) error {
	raw, e := json.MarshalIndent(value, "", "  ")
	if e != nil {
		return e
	}
	raw = append(raw, '\n')
	if len(raw) > 2<<20 {
		return contextevaluation.ErrInvalid
	}
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	n, e := f.Write(raw)
	if e == nil && n != len(raw) {
		e = io.ErrShortWrite
	}
	return errors.Join(e, f.Sync(), f.Close())
}
func run(args []string) error {
	f := flag.NewFlagSet("learning-context-canary", flag.ContinueOnError)
	action := f.String("action", "assess", "freeze or assess; no model activation")
	profile := f.String("profile", "", "installed canary release profile")
	release := f.String("release-sha256", "", "exact signed release version")
	source := f.String("evidence", "", "stopped collector evidence directory")
	memory := f.String("case-memory", "", "current case-memory journal with signed later labels")
	plan := f.String("expected-plan-sha256", "", "operator-retained frozen plan pin")
	out := f.String("out", "", "new public output; never overwrites")
	if e := f.Parse(args); e != nil {
		return e
	}
	if f.NArg() != 0 || *out == "" || *profile == "" || *release == "" || *source == "" {
		return contextevaluation.ErrInvalid
	}
	allowed := map[string]bool{"action": true, "profile": true, "release-sha256": true, "evidence": true, "out": true}
	switch *action {
	case "freeze":
	case "assess":
		allowed["case-memory"], allowed["expected-plan-sha256"] = true, true
		if *memory == "" || *plan == "" {
			return contextevaluation.ErrInvalid
		}
	default:
		return contextevaluation.ErrInvalid
	}
	bad := false
	f.Visit(func(flag *flag.Flag) {
		if !allowed[flag.Name] {
			bad = true
		}
	})
	if bad {
		return contextevaluation.ErrInvalid
	}
	if _, e := os.Lstat(*out); e == nil {
		return os.ErrExist
	} else if !os.IsNotExist(e) {
		return e
	}
	s, e := contextevaluation.Open(*profile, *release)
	if e != nil {
		return e
	}
	defer s.Close()
	snapshot, e := evidence.Capture(*source)
	if e != nil {
		return e
	}
	now := time.Now().UTC()
	if *action == "freeze" {
		p, e := s.Freeze(snapshot, now)
		if e != nil {
			return e
		}
		return writeNew(*out, p)
	}
	st, e := os.Lstat(*memory)
	if e != nil || !st.Mode().IsRegular() || st.Size() > casememory.MaxJournal {
		return contextevaluation.ErrInvalid
	}
	labels, e := casememory.Open(*memory)
	if e != nil {
		return e
	}
	defer labels.Close()
	report, e := s.Assess(snapshot, labels, *plan, now)
	if e != nil {
		return e
	}
	return writeNew(*out, report)
}
