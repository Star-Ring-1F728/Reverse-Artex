// learning-context isolates v2 training, label-free inference and private scoring.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"reverse-artex/internal/casememory"
	"reverse-artex/internal/contextlearning"
	"reverse-artex/internal/contractjson"
)

func main() {
	if e := run(os.Args[1:]); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func read(path string, v any) error {
	st, e := os.Lstat(path)
	if e != nil {
		return e
	}
	if !st.Mode().IsRegular() || st.Size() > 2<<20 {
		return contextlearning.ErrInvalid
	}
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, (2<<20)+1))
	if e != nil {
		return e
	}
	return contractjson.Decode(b, v, 2<<20, 8192)
}
func run(args []string) error {
	flags := flag.NewFlagSet("learning-context", flag.ContinueOnError)
	action := flags.String("action", "run", "train, update from reviewed feedback, run without labels, score, or boundary-bytes")
	capsule := flags.String("capsule", "", "")
	expected := flags.String("expected-capsule-sha256", "", "")
	inputs := flags.String("inputs", "", "")
	gold := flags.String("gold", "", "")
	review := flags.String("review", "", "")
	trust := flags.String("review-trust", "", "")
	expectedTrust := flags.String("expected-review-trust-sha256", "", "")
	previous := flags.String("previous-candidate", "", "prior quarantined candidate for cumulative feedback")
	boundary := flags.String("training-boundary", "", "custodian-signed reserved holdout membership hashes")
	preds := flags.String("predictions", "", "")
	out := flags.String("out", "", "")
	if e := flags.Parse(args); e != nil {
		return e
	}
	if flags.NArg() != 0 || *out == "" {
		return errors.New("explicit action and new output required")
	}
	if *action == "run" && (*gold != "" || *review != "" || *trust != "" || *expectedTrust != "" || *preds != "" || *previous != "" || *boundary != "") {
		return errors.New("label-free v2 runtime refuses gold/training/scorer inputs")
	}
	if *action == "boundary-bytes" {
		if *boundary == "" || *inputs != "" || *gold != "" || *review != "" || *trust != "" || *expectedTrust != "" || *preds != "" || *previous != "" || *capsule != "" || *expected != "" {
			return contextlearning.ErrInvalid
		}
		var b contextlearning.TrainingBoundary
		if err := read(*boundary, &b); err != nil {
			return err
		}
		return writeNew(*out, contextlearning.TrainingBoundaryBytes(b))
	}
	if *action != "train" && *action != "update" && *action != "run" && *action != "score" {
		return errors.New("unknown v2 action")
	}
	if *action != "update" && (*previous != "" || *boundary != "") || *action == "update" && (*previous == "" || *boundary == "") {
		return contextlearning.ErrInvalid
	}
	var in contextlearning.Inputs
	if e := read(*inputs, &in); e != nil {
		return e
	}
	var result any
	if *action == "train" || *action == "update" {
		if *capsule != "" || *preds != "" || *expectedTrust == "" {
			return contextlearning.ErrInvalid
		}
		var g contextlearning.Gold
		var r contextlearning.Review
		var t casememory.LearningTrust
		for _, d := range []struct {
			p string
			v any
		}{{*gold, &g}, {*review, &r}, {*trust, &t}} {
			if e := read(d.p, d.v); e != nil {
				return e
			}
		}
		if casememory.LearningTrustDigest(t) != *expectedTrust {
			return contextlearning.ErrInvalid
		}
		if *action == "update" {
			var prior contextlearning.Candidate
			var reserved contextlearning.TrainingBoundary
			if err := read(*previous, &prior); err != nil {
				return err
			}
			if err := read(*boundary, &reserved); err != nil {
				return err
			}
			v, err := contextlearning.Update(prior, in, g, r, t, reserved)
			if err != nil {
				return err
			}
			result = v
		} else {
			c, err := contextlearning.Train(in, g, r, t)
			if err != nil {
				return err
			}
			result = c
		}
	} else {
		if *expected == "" || *review != "" || *trust != "" {
			return contextlearning.ErrInvalid
		}
		var c contextlearning.Capsule
		if e := read(*capsule, &c); e != nil {
			return e
		}
		if c.SHA != *expected {
			return contextlearning.ErrInvalid
		}
		if *action == "run" {
			v, e := contextlearning.Run(c, in)
			if e != nil {
				return e
			}
			result = v
		} else {
			var g contextlearning.Gold
			var p contextlearning.Predictions
			if e := read(*gold, &g); e != nil {
				return e
			}
			if e := read(*preds, &p); e != nil {
				return e
			}
			v, e := contextlearning.Score(c, in, g, p)
			if e != nil {
				return e
			}
			result = v
		}
	}
	b, e := json.MarshalIndent(result, "", "  ")
	if e != nil {
		return e
	}
	return writeNew(*out, append(b, '\n'))
}

func writeNew(path string, b []byte) error {
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	_, e = f.Write(b)
	syncErr := f.Sync()
	closeErr := f.Close()
	if e != nil {
		return e
	}
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}
