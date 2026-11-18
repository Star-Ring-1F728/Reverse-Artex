// v2-journal-check is an offline, read-only verifier. It has no management,
// model, policy mutation or network credentials and never starts a writer.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reverse-artex/internal/protection"
	"reverse-artex/internal/responsev2"
	"strings"
)

func main() { os.Exit(run()) }
func run() int {
	state := flag.String("state", "", "stopped owned V2 journal or retention marker")
	profile := flag.String("protection-registry", "", "same public protection manifest")
	export := flag.String("responses", "", "optional NEW external JSONL output of verified response bindings")
	backup := flag.String("backup-dir", "", "optional NEW directory for a verified stopped retained journal copy")
	flag.Parse()
	if *state == "" || *profile == "" || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "state and protection-registry required")
		return 2
	}
	if *backup != "" && *export != "" {
		fmt.Fprintln(os.Stderr, "backup-dir and responses are separate operations")
		return 2
	}
	profileFile, err := os.Open(*profile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "invalid protection registry file")
		return 2
	}
	raw, err := io.ReadAll(io.LimitReader(profileFile, (64<<10)+1))
	profileFile.Close()
	if err != nil || len(raw) > 64<<10 {
		fmt.Fprintln(os.Stderr, "invalid protection registry file")
		return 2
	}
	reg, err := protection.Parse(raw)
	if err != nil {
		fmt.Fprintln(os.Stderr, "invalid protection registry")
		return 2
	}
	if *backup != "" {
		result, err := responsev2.BackupRetainedJournal(*state, reg, *backup)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		if err = json.NewEncoder(os.Stdout).Encode(result); err != nil {
			return 1
		}
		return 0
	}
	var file *os.File
	if *export != "" {
		destination, e := filepath.Abs(*export)
		if e != nil {
			return 2
		}
		original, e := filepath.Abs(*state)
		if e != nil {
			return 2
		}
		destinationParent, e := filepath.EvalSymlinks(filepath.Dir(destination))
		if e != nil {
			return 2
		}
		originalParent, e := filepath.EvalSymlinks(filepath.Dir(original))
		if e != nil {
			return 2
		}
		destination = filepath.Join(destinationParent, filepath.Base(destination))
		original = filepath.Join(originalParent, filepath.Base(original))
		relative, relativeErr := filepath.Rel(original+".retained", destination)
		if relativeErr != nil {
			return 2
		}
		if relative != ".." && !strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
			fmt.Fprintln(os.Stderr, "response export must be outside original retained evidence")
			return 2
		}
		file, err = os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			fmt.Fprintln(os.Stderr, "new response export required")
			return 2
		}
		defer file.Close()
	}
	count := 0
	emit := func(row responsev2.VerifiedResponse) error {
		count++
		if file == nil {
			return nil
		}
		return json.NewEncoder(file).Encode(row)
	}
	result, err := responsev2.VerifyJournal(*state, reg, emit)
	if file != nil {
		if e := file.Sync(); e != nil && err == nil {
			err = e
		}
		if e := file.Close(); e != nil && err == nil {
			err = e
		}
	}
	if err != nil {
		result.Passed = false
	}
	envelope := map[string]any{"verification": result, "exported_responses": count, "response_export_complete": err == nil, "error": nil}
	if err != nil {
		envelope["error"] = err.Error()
	}
	json.NewEncoder(os.Stdout).Encode(envelope)
	if err != nil {
		return 1
	}
	return 0
}
