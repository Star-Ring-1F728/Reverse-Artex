package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"reverse-artex/internal/actioncontext"
	"reverse-artex/internal/detect"
	"reverse-artex/internal/evidence"
	"reverse-artex/internal/hostguard"
	"reverse-artex/internal/recovery"
	"sort"
)

const recoveryVersion = recovery.Version
const recoveryRuleset = recovery.Ruleset
const maxRecoveryRecords = recovery.MaxRecords

type recoveryMeta = recovery.Metadata
type evaluationRecord = recovery.Evaluation

func checkOfflineOutput(dir string) error {
	_, err := os.Stat(filepath.Join(dir, "recovery.meta.json"))
	if err == nil {
		return errors.New("offline replay cannot write into a live recovery directory")
	}
	if !os.IsNotExist(err) {
		return err
	}
	return nil
}

func restoreState(store *evidence.Store, dir string, correlation string, canaries []string, httpEngine *detect.Engine, hostEngine *hostguard.Engine, contextTrust ...*actioncontext.Trust) error {
	ids := append([]string(nil), canaries...)
	sort.Strings(ids)
	ids = dedupStrings(ids)
	want := recoveryMeta{Version: recoveryVersion, Ruleset: recoveryRuleset, Correlation: correlation, Canaries: ids}
	if len(contextTrust) > 1 {
		return errors.New("one context trust profile required")
	}
	if len(contextTrust) == 1 {
		want.ContextTrust = contextTrust[0]
		if want.ContextTrust != nil {
			if err := want.ContextTrust.Validate(); err != nil {
				return err
			}
		}
	}
	want.TenantFairness = httpEngine.FairnessProfile()
	if httpEngine.CriticalReserveEnabled() {
		want.CriticalReserve = detect.CriticalReserveVersion
	}
	if endpoint := os.Getenv("RA_POLICY_CONTROL_URL"); endpoint != "" {
		fingerprint := sha256.Sum256([]byte(endpoint))
		want.PolicyControl = fmt.Sprintf("%x", fingerprint[:])
	}
	path := filepath.Join(dir, "recovery.meta.json")
	if info, err := os.Stat(path); err == nil && info.Size() > 4096 {
		return errors.New("recovery metadata exceeds size limit")
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		// An unversioned evidence directory cannot prove its correlation mode or
		// whether the last cross-stream transaction finished.
		for _, name := range []string{"events", "evaluations", "alerts", "host-events", "host-evaluations", "host-alerts", "policy-delivery-acks"} {
			count := 0
			if err := store.VisitRecords(name, func([]byte) error { count++; return nil }); err != nil {
				return err
			}
			if count != 0 {
				return errors.New("unversioned evidence requires explicit migration or a new output directory")
			}
		}
		encoded, _ := json.Marshal(want)
		encoded = append(encoded, '\n')
		if len(encoded) > 4096 {
			return errors.New("recovery metadata exceeds size limit")
		}
		return store.CreateMetadata("recovery.meta.json", encoded)
	}
	if err != nil {
		return err
	}
	var got recoveryMeta
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&got); err != nil {
		return fmt.Errorf("invalid recovery metadata: %w", err)
	}
	var extra any
	if d.Decode(&extra) != io.EOF || !reflect.DeepEqual(got, want) {
		return errors.New("recovery metadata or rule/configuration version mismatch")
	}
	if err := recovery.HTTPWithContext(store, httpEngine, want.ContextTrust); err != nil {
		return fmt.Errorf("HTTP recovery refused: %w", err)
	}
	if err := recovery.Host(store, hostEngine); err != nil {
		return fmt.Errorf("host recovery refused: %w", err)
	}
	return nil
}

func dedupStrings(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if len(out) == 0 || out[len(out)-1] != s {
			out = append(out, s)
		}
	}
	return out
}

func readEvaluations(store *evidence.Store, stream string) ([]evaluationRecord, error) {
	return recovery.ReadEvaluations(store, stream)
}
