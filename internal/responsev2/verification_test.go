//go:build linux

package responsev2

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func evidenceHashes(t *testing.T, path string) map[string]string {
	t.Helper()
	result := map[string]string{}
	for _, root := range []string{path, path + ".owner", path + ".retained"} {
		if _, err := os.Stat(root); os.IsNotExist(err) {
			continue
		}
		if err := filepath.Walk(root, func(name string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.Mode().IsRegular() {
				raw, err := os.ReadFile(name)
				if err != nil {
					return err
				}
				result[name] = digestBytes(raw)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	return result
}
func TestReadOnlyVerificationRejectsLiveWriterAndLeavesEvidenceUnchanged(t *testing.T) {
	s, reg, key, path := retainedFixture(t, DefaultRetentionConfig())
	responseFixture(t, s, reg, key, "verified-one", "own", "allow", true)
	if _, err := VerifyJournal(path, reg, nil); err == nil {
		t.Fatal("reader raced an active writer")
	}
	if err := s.Checkpoint(); err != nil {
		t.Fatal(err)
	}
	head, sequence := s.head, s.sequence
	s.Close()
	before := evidenceHashes(t, path)
	rows := []VerifiedResponse{}
	result, err := VerifyJournal(path, reg, func(row VerifiedResponse) error { rows = append(rows, row); return nil })
	if err != nil || !result.Passed || !result.ReadOnly || !result.AuditAvailable || result.Head != head || result.Sequence != sequence || result.TotalObservations != 1 || len(rows) != 1 {
		t.Fatal(result, err)
	}
	if rows[0].RequestID != "verified-one" || rows[0].Observation.Write.Complete != true || rows[0].Attempt.EvidenceID != rows[0].EvidenceID {
		t.Fatal(rows)
	}
	if after := evidenceHashes(t, path); !reflect.DeepEqual(before, after) {
		t.Fatal("offline verification changed original evidence")
	}
}
func TestReadOnlyVerificationNeverCompletesInterruptedPublication(t *testing.T) {
	s, reg, key, path := retainedFixture(t, DefaultRetentionConfig())
	responseFixture(t, s, reg, key, "before", "own", "allow", true)
	s.retentionHook = func(stage string) error {
		if stage == "checkpoint-published" {
			return errors.New("interrupted")
		}
		return nil
	}
	if err := s.Checkpoint(); err == nil {
		t.Fatal("expected interruption")
	}
	s.Close()
	before := evidenceHashes(t, path)
	if result, err := VerifyJournal(path, reg, nil); err == nil || result.Passed {
		t.Fatal("read-only verification silently recovered writer state")
	}
	if after := evidenceHashes(t, path); !reflect.DeepEqual(before, after) {
		t.Fatal("read-only verifier wrote recovery files")
	}
	reopened, err := OpenRetained(path, reg, DefaultRetentionConfig())
	if err != nil {
		t.Fatal(err)
	}
	reopened.Close()
	if result, err := VerifyJournal(path, reg, nil); err != nil || !result.Passed {
		t.Fatal(result, err)
	}
}
func TestReadOnlyVerificationPropagatesExportFailureWithoutChangingInputs(t *testing.T) {
	s, reg, key, path := retainedFixture(t, DefaultRetentionConfig())
	responseFixture(t, s, reg, key, "one", "own", "allow", true)
	s.Close()
	before := evidenceHashes(t, path)
	if result, err := VerifyJournal(path, reg, func(VerifiedResponse) error { return errors.New("derived output unavailable") }); err == nil || result.Passed {
		t.Fatal("partial export reported complete")
	}
	if after := evidenceHashes(t, path); !reflect.DeepEqual(before, after) {
		t.Fatal("failed export changed original state")
	}
}
