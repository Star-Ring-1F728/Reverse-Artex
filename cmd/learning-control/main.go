// learning-control manages verified labels and local advisory-model releases.
// It owns the same journal lock as the collector; stop the collector first.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"reverse-artex/internal/casememory"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(args []string, out io.Writer) error {
	flags := flag.NewFlagSet("learning-control", flag.ContinueOnError)
	action := flags.String("action", "status", "trust, label-template/import/bytes, select, candidate, advisory-change/bytes, production-policy/template, quality-prepare/status/import/bytes, cohort-import/bytes, production-change/stop/status/bytes, status")
	journal := flags.String("journal", "", "explicit case-memory journal; collector must be stopped")
	tenant := flags.String("tenant", "", "configured tenant")
	input := flags.String("input", "", "strict JSON input (public policy or externally signed request)")
	id := flags.String("case-id", "", "case ID for label-template")
	value := flags.String("value", "uncertain", "reviewed label for template")
	reason := flags.String("reason", "", "review basis for label-template")
	keyID := flags.String("key-id", "", "reviewer key ID for template")
	candidateID := flags.String("candidate-id", "", "frozen verified candidate")
	planID := flags.String("plan-id", "", "quality plan")
	expected := flags.Int("expected-revision", 0, "production pointer CAS for emergency stop")
	selection := flags.String("selection-sha256", "", "exact saved verified selection for candidate")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	read := func(target any) error {
		f, err := os.Open(*input)
		if err != nil {
			return err
		}
		defer f.Close()
		info, err := f.Stat()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Size() > 32768 {
			return casememory.ErrInvalid
		}
		raw, err := io.ReadAll(io.LimitReader(f, 32769))
		if err != nil {
			return err
		}
		return casememory.DecodeLearningJSON(raw, target)
	}
	emit := func(v any) error { enc := json.NewEncoder(out); enc.SetIndent("", "  "); return enc.Encode(v) }
	// Signing byte export never opens or creates a journal and never loads keys.
	switch *action {
	case "cohort-bytes":
		var q casememory.CohortSeal
		if err := read(&q); err != nil {
			return err
		}
		_, err := out.Write(casememory.CohortSigningBytes(q))
		return err
	case "quality-bytes":
		var q casememory.SignedQualityReport
		if err := read(&q); err != nil {
			return err
		}
		_, err := out.Write(casememory.QualitySigningBytes(q))
		return err
	case "production-bytes":
		var q casememory.SignedProductionChange
		if err := read(&q); err != nil {
			return err
		}
		_, err := out.Write(casememory.ProductionSigningBytes(q))
		return err
	}
	if *action == "label-bytes" {
		var q casememory.SignedLabel
		if err := read(&q); err != nil {
			return err
		}
		_, err := out.Write(casememory.LabelSigningBytes(q))
		return err
	}
	if *action == "advisory-bytes" {
		var q casememory.SignedAdvisory
		if err := read(&q); err != nil {
			return err
		}
		_, err := out.Write(casememory.AdvisorySigningBytes(q))
		return err
	}
	if *journal == "" || *tenant == "" {
		return errors.New("explicit -journal and -tenant required")
	}
	// A misspelled path must not silently create a new empty memory.
	if info, err := os.Lstat(*journal); err != nil {
		return err
	} else if !info.Mode().IsRegular() {
		return casememory.ErrInvalid
	}
	switch *action {
	case "candidate-diagnostics", "trust", "label-template", "label-import", "select", "candidate", "advisory-change", "status", "production-policy-template", "production-policy", "quality-prepare", "quality-status", "cohort-import", "quality-import", "production-change", "production-stop", "production-status":
	default:
		return errors.New("unknown action")
	}
	store, err := casememory.Open(*journal)
	if err != nil {
		return err
	}
	defer store.Close()
	switch *action {
	case "candidate-diagnostics":
		v, err := store.CandidateFeatureDiagnostics(*tenant, *candidateID)
		if err != nil {
			return err
		}
		return emit(v)
	case "production-policy-template":
		trust, err := store.LearningTrust(*tenant)
		if err != nil {
			return err
		}
		return emit(casememory.DefaultProductionPolicy(*tenant, casememory.LearningTrustDigest(trust)))
	case "production-policy":
		var q casememory.ProductionPolicy
		if err := read(&q); err != nil {
			return err
		}
		if q.Tenant != *tenant {
			return casememory.ErrInvalid
		}
		sha, err := store.SetProductionPolicy(q)
		if err != nil {
			return err
		}
		return emit(map[string]string{"production_policy_sha256": sha})
	case "quality-prepare":
		v, err := store.PrepareQuality(*tenant, *candidateID)
		if err != nil {
			return err
		}
		return emit(v)
	case "quality-status":
		v, err := store.Quality(*tenant, *planID)
		if err != nil {
			return err
		}
		return emit(v)
	case "cohort-import":
		var q casememory.CohortSeal
		if err := read(&q); err != nil {
			return err
		}
		v, err := store.AdmitQualityCohort(*tenant, q)
		if err != nil {
			return err
		}
		return emit(v)
	case "quality-import":
		var q casememory.SignedQualityReport
		if err := read(&q); err != nil {
			return err
		}
		v, err := store.ImportQuality(*tenant, q)
		if err != nil {
			return err
		}
		return emit(v)
	case "production-change":
		var q casememory.SignedProductionChange
		if err := read(&q); err != nil {
			return err
		}
		v, err := store.ChangeProduction(*tenant, q)
		if err != nil {
			return err
		}
		return emit(v)
	case "production-stop":
		v, err := store.StopProduction(*tenant, *expected, *reason)
		if err != nil {
			return err
		}
		return emit(v)
	case "production-status":
		v, err := store.Production(*tenant)
		if err != nil {
			return err
		}
		return emit(v)
	case "trust":
		var p casememory.LearningTrust
		if err := read(&p); err != nil {
			return err
		}
		if p.Tenant != *tenant {
			return casememory.ErrInvalid
		}
		sha, err := store.SetLearningTrust(p)
		if err != nil {
			return err
		}
		return emit(map[string]string{"trust_sha256": sha})
	case "label-template":
		policy, err := store.LearningTrust(*tenant)
		if err != nil {
			return err
		}
		view, err := store.Get(*tenant, *id)
		if err != nil {
			return err
		}
		previous := ""
		if len(view.Labels) > 0 {
			previous = view.Labels[len(view.Labels)-1].SHA
		}
		now := time.Now().UTC()
		// Evidence SHA is the canonical digest already exposed in the selection.
		selected, err := store.Select(*tenant, false)
		if err != nil {
			return err
		}
		evidence := ""
		for _, b := range selected.Items {
			if b.CaseID == *id {
				evidence = b.EvidenceSHA
			}
		}
		return emit(casememory.SignedLabel{TrustSHA: casememory.LearningTrustDigest(policy), Schema: "case-verified-label/1", Tenant: *tenant, CaseID: *id, Expected: len(view.Labels), Previous: previous, CaseSHA: view.Current.SHA, SourceSHA: view.Current.Source, EvidenceSHA: evidence, Value: *value, Reason: *reason, Basis: "evidence_review", KeyID: *keyID, IssuedAt: now, ExpiresAt: now.Add(time.Hour)})
	case "label-import":
		var q casememory.SignedLabel
		if err := read(&q); err != nil {
			return err
		}
		v, err := store.ImportVerifiedLabel(*tenant, q)
		if err != nil {
			return err
		}
		return emit(v)
	case "select":
		v, err := store.SelectVerified(*tenant, true)
		if err != nil {
			return err
		}
		return emit(v)
	case "candidate":
		v, err := store.SavedSelection(*tenant, *selection)
		if err != nil {
			return err
		}
		if v.Selection.TrustSHA == "" {
			return casememory.ErrInvalid
		}
		candidate, err := store.CreateCandidate(*tenant, *selection)
		if err != nil {
			return err
		}
		return emit(candidate)
	case "advisory-change":
		var q casememory.SignedAdvisory
		if err := read(&q); err != nil {
			return err
		}
		v, err := store.ChangeSignedAdvisory(*tenant, q)
		if err != nil {
			return err
		}
		return emit(v)
	case "status":
		p, err := store.LearningTrust(*tenant)
		if err != nil {
			return err
		}
		v, err := store.SelectVerified(*tenant, false)
		if err != nil {
			return err
		}
		a, err := store.Advisory(*tenant)
		if err != nil {
			return err
		}
		production, err := store.Production(*tenant)
		if err != nil {
			return err
		}
		return emit(map[string]any{"trust": p, "trust_sha256": casememory.LearningTrustDigest(p), "selection": v, "advisory": a, "production": production, "production_deployment_allowed": production.RuntimeEnabled})
	}
	return nil
}
