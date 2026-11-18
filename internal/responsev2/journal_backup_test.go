//go:build linux

package responsev2

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestRetainedBackupLocksWriterAndPreservesCommittedHistory(t *testing.T) {
	s, reg, key, path := retainedFixture(t, DefaultRetentionConfig())
	responseFixture(t, s, reg, key, "backup-complete", "own", "allow", true)
	dst := filepath.Join(t.TempDir(), "recovery")
	if _, err := BackupRetainedJournal(path, reg, dst); err == nil {
		t.Fatal("live writer was not fenced")
	}
	if _, err := os.Lstat(dst); !os.IsNotExist(err) {
		t.Fatal("a blocked backup created output", err)
	}
	if err := s.Checkpoint(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := BackupRetainedJournal(path, reg, filepath.Join(path+".retained", "backup")); err == nil {
		t.Fatal("created backup inside the protected source")
	}
	b, err := BackupRetainedJournal(path, reg, dst)
	if err != nil || !b.Verification.Passed || b.Verification.TotalObservations != 1 || !b.Verification.AuditAvailable {
		t.Fatal(b, err)
	}
	manifest, err := os.ReadFile(filepath.Join(dst, "backup.json"))
	if err != nil {
		t.Fatal(err)
	}
	var recorded JournalBackup
	if err = json.Unmarshal(manifest, &recorded); err != nil || recorded.Verification.Head != b.Verification.Head || len(recorded.Files) != len(b.Files) {
		t.Fatal("backup receipt does not bind the verified copy", err)
	}
	for _, item := range b.Files {
		bytes, err := os.ReadFile(filepath.Join(dst, item.Path))
		if err != nil || int64(len(bytes)) != item.Bytes || digestBytes(bytes) != item.SHA256 {
			t.Fatal("manifest integrity", item.Path, err)
		}
	}
	if _, err = BackupRetainedJournal(path, reg, dst); err == nil {
		t.Fatal("existing backup was overwritten")
	}
	copyPath := filepath.Join(dst, b.Journal)
	reopened, err := OpenRetained(copyPath, reg, DefaultRetentionConfig())
	if err != nil {
		t.Fatal(err)
	}
	if reopened.sequence != b.Verification.Sequence+1 || reopened.totalObservations != 1 {
		t.Fatal("recovered writer did not preserve the stopped state")
	}
	if err = reopened.Close(); err != nil {
		t.Fatal(err)
	}
	old, err := VerifyJournal(path, reg, nil)
	if err != nil || old.Head != b.Verification.Head {
		t.Fatal("read-only backup changed original", old, err)
	}
}

func TestRetainedBackupRefusesUnresolvedOutcome(t *testing.T) {
	s, reg, key, path := retainedFixture(t, DefaultRetentionConfig())
	combinedResponseFixture(t, s, reg, key, "unknown-outcome", "own", "allow")
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "recovery")
	if _, err := BackupRetainedJournal(path, reg, dst); err == nil {
		t.Fatal("unresolved write was accepted for promotion")
	}
	if _, err := os.Lstat(dst); !os.IsNotExist(err) {
		t.Fatal("unresolved write created a recovery artifact", err)
	}
}
