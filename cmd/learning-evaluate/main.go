// learning-evaluate executes public feature inputs without gold, or separately
// scores in the evaluator's private environment. It never signs attestations.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"reverse-artex/internal/casememory"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func readDocument(path string, target any) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() > 2<<20 {
		return casememory.ErrInvalid
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
	return casememory.DecodeLearningDocument(raw, target, 2<<20, 4096)
}
func run(args []string) error {
	flags := flag.NewFlagSet("learning-evaluate", flag.ContinueOnError)
	expectedCapsule := flags.String("expected-capsule-sha256", "", "capsule pin received through trusted handoff")
	action := flags.String("action", "run", "run (no labels), score, or diagnose (scorer only)")
	capsule := flags.String("capsule", "", "frozen capsule")
	inputs := flags.String("inputs", "", "sealed public inputs")
	predictions := flags.String("predictions", "", "saved runtime output for score only")
	gold := flags.String("gold", "", "private evaluator labels, score only")
	prior := flags.String("quality-report", "", "completed quality report for posthoc diagnostics only")
	output := flags.String("out", "", "new output path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *expectedCapsule == "" || *output == "" || (*action != "run" && *action != "score" && *action != "diagnose") {
		return errors.New("explicit run/score and new output path required")
	}
	if *action == "run" && (*gold != "" || *predictions != "" || *prior != "") {
		return errors.New("label-free runtime refuses gold or scorer inputs")
	}
	if (*action == "diagnose" && (*gold == "" || *prior == "" || *predictions != "")) || (*action == "score" && *prior != "") {
		return errors.New("diagnostics require gold and completed quality report; predictions are score only")
	}
	var c casememory.QualityCapsule
	var in casememory.QualityInputs
	if err := readDocument(*capsule, &c); err != nil {
		return err
	}
	if c.SHA != *expectedCapsule {
		return casememory.ErrConflict
	}
	if err := readDocument(*inputs, &in); err != nil {
		return err
	}
	var result any
	if *action == "run" {
		v, err := casememory.RunQuality(c, in)
		if err != nil {
			return err
		}
		result = v
	} else if *action == "diagnose" {
		var labels casememory.QualityGold
		var previous casememory.QualityReport
		if err := readDocument(*gold, &labels); err != nil {
			return err
		}
		if err := readDocument(*prior, &previous); err != nil {
			return err
		}
		v, err := casememory.DiagnoseQualityFeatures(c, in, labels, previous)
		if err != nil {
			return err
		}
		result = v
	} else {
		var out casememory.QualityPredictions
		var labels casememory.QualityGold
		if err := readDocument(*predictions, &out); err != nil {
			return err
		}
		if err := readDocument(*gold, &labels); err != nil {
			return err
		}
		v, err := casememory.ScoreQuality(c, in, out, labels)
		if err != nil {
			return err
		}
		result = v
	}
	raw, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.OpenFile(*output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(append(raw, '\n'))
	syncErr := f.Sync()
	closeErr := f.Close()
	if writeErr != nil {
		return writeErr
	}
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}
