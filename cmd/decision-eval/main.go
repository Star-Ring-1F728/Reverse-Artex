// decision-eval is a local-only public synthetic classifier comparison tool.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"reverse-artex/internal/decisions"
)

func run(args []string, out, errout io.Writer) error {
	f := flag.NewFlagSet("decision-eval", flag.ContinueOnError)
	f.SetOutput(errout)
	action := f.String("action", "compare", "questions | compare")
	manifest := f.String("manifest", "", "explicit public synthetic manifest")
	pin := f.String("expected-manifest-sha256", "", "optional independently saved manifest digest")
	output := f.String("out", "", "optional new JSON report file")
	if e := f.Parse(args); e != nil {
		return e
	}
	if f.NArg() != 0 || (*action != "questions" && *action != "compare") || (*action == "compare") != (*manifest != "") || (*action == "questions" && *pin != "") {
		return errors.New("invalid action or manifest")
	}
	var value any
	if *action == "questions" {
		value = decisions.QuestionDocument()
	} else {
		d, e := decisions.LoadDataset(*manifest, *pin)
		if e != nil {
			return e
		}
		reports := []decisions.EvaluationReport{}
		for _, candidate := range []string{"rules-v1", "scripted-v1", "forced-benign", "refused", "timeout", "rate_limited", "invalid", "stale", "error"} {
			r, e := decisions.Evaluate(d, candidate)
			if e != nil {
				return e
			}
			reports = append(reports, r)
		}
		value = struct {
			Schema  string                       `json:"schema"`
			Reports []decisions.EvaluationReport `json:"reports"`
		}{"decision-offline-comparison/1", reports}
	}
	data, e := json.MarshalIndent(value, "", "  ")
	if e != nil {
		return e
	}
	data = append(data, '\n')
	if *output == "" {
		n, e := out.Write(data)
		if e == nil && n != len(data) {
			e = io.ErrShortWrite
		}
		return e
	}
	fh, e := os.OpenFile(*output, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	defer fh.Close()
	n, e := fh.Write(data)
	if e == nil && n != len(data) {
		e = io.ErrShortWrite
	}
	if e == nil {
		e = fh.Sync()
	}
	return e
}
func main() {
	if e := run(os.Args[1:], os.Stdout, os.Stderr); e != nil {
		fmt.Fprintln(os.Stderr, "decision-eval refused:", e)
		os.Exit(2)
	}
}
