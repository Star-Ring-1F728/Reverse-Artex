// learning-context-quality checks public v2 quality evidence without reading
// gold, training rows, private keys or changing any runtime/model pointer.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"reverse-artex/internal/actioncontext"
	"reverse-artex/internal/casememory"
	"reverse-artex/internal/contextadmission"
	"reverse-artex/internal/contextlearning"
	"reverse-artex/internal/contractjson"
	"time"
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
		return contextadmission.ErrInvalid
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(st, opened) {
		return contextadmission.ErrInvalid
	}
	raw, err := io.ReadAll(io.LimitReader(f, (2<<20)+1))
	if err != nil {
		return err
	}
	return contractjson.Decode(raw, v, 2<<20, 8192)
}

func run(args []string) error {
	flags := flag.NewFlagSet("learning-context-quality", flag.ContinueOnError)
	action := flags.String("action", "check", "check, policy-template, or endorsement-bytes")
	policyPath := flags.String("policy", "", "operator-installed admission policy")
	policyPin := flags.String("expected-policy-sha256", "", "independently delivered canonical policy SHA")
	capsulePath := flags.String("capsule", "", "public v2 capsule")
	capsulePin := flags.String("expected-capsule-sha256", "", "independently delivered capsule SHA")
	authoritiesPath := flags.String("authority-trust", "", "current operator-installed authority keys")
	contextPath := flags.String("context-trust", "", "current sensor/issuer public trust")
	endorsementPath := flags.String("endorsement", "", "independent evaluator's signed public envelope")
	tenant := flags.String("tenant", "", "policy-template tenant")
	out := flags.String("out", "", "new output file")
	// Unsupported label/private-key options are rejected here, before any input
	// file is opened, including in the signing-bytes helper.
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *out == "" {
		return errors.New("exact action and new output required")
	}
	if *action != "check" && *action != "policy-template" && *action != "endorsement-bytes" {
		return contextadmission.ErrInvalid
	}
	var result any
	var raw []byte
	if *action == "endorsement-bytes" {
		if *endorsementPath == "" || *policyPath != "" || *policyPin != "" || *capsulePath != "" || *capsulePin != "" || *authoritiesPath != "" || *contextPath != "" || *tenant != "" {
			return contextadmission.ErrInvalid
		}
		var e contextadmission.Endorsement
		if err := read(*endorsementPath, &e); err != nil {
			return err
		}
		raw = contextadmission.SigningBytes(e)
	} else {
		if *authoritiesPath == "" || *contextPath == "" {
			return contextadmission.ErrInvalid
		}
		var a casememory.LearningTrust
		var context actioncontext.Trust
		if err := read(*authoritiesPath, &a); err != nil {
			return err
		}
		if err := read(*contextPath, &context); err != nil {
			return err
		}
		if *action == "policy-template" {
			if *tenant == "" || *policyPath != "" || *policyPin != "" || *capsulePath != "" || *capsulePin != "" || *endorsementPath != "" {
				return contextadmission.ErrInvalid
			}
			p, err := contextadmission.PolicyTemplate(*tenant, a, context)
			if err != nil {
				return err
			}
			result = p
		} else {
			if *policyPath == "" || *policyPin == "" || *capsulePath == "" || *capsulePin == "" || *endorsementPath == "" || *tenant != "" {
				return contextadmission.ErrInvalid
			}
			var p contextadmission.Policy
			var c contextlearning.Capsule
			var e contextadmission.Endorsement
			if err := read(*policyPath, &p); err != nil {
				return err
			}
			if contextlearning.Digest(p) != *policyPin {
				return contextadmission.ErrInvalid
			}
			if err := read(*capsulePath, &c); err != nil {
				return err
			}
			if c.SHA != *capsulePin {
				return contextadmission.ErrInvalid
			}
			if err := read(*endorsementPath, &e); err != nil {
				return err
			}
			d, err := contextadmission.Assess(p, c, e, a, context, time.Now().UTC())
			if err != nil {
				return err
			}
			result = d
		}
	}
	if raw == nil {
		var err error
		raw, err = json.MarshalIndent(result, "", "  ")
		if err != nil {
			return err
		}
		raw = append(raw, '\n')
	}
	f, err := os.OpenFile(*out, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	n, writeErr := f.Write(raw)
	if writeErr == nil && n != len(raw) {
		writeErr = io.ErrShortWrite
	}
	return errors.Join(writeErr, f.Sync(), f.Close())
}
