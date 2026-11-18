package responsev2

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reverse-artex/internal/protection"
)

type JournalBackup struct {
	Schema       string              `json:"schema"`
	Registry     string              `json:"registry_digest"`
	Journal      string              `json:"journal"`
	Verification JournalVerification `json:"verification"`
	Files        []JournalBackupFile `json:"files"`
}

type JournalBackupFile struct {
	Path   string `json:"path"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

// BackupRetainedJournal exports committed files from a stopped writer.
// While copying it holds the same read lock as VerifyJournal, then verifies the
// copy before writing its manifest. A partial export is left for inspection;
// require a successful exit. Promotion on another machine requires fencing the
// original writer; the lock only protects the source directory.
func BackupRetainedJournal(path string, registry *protection.Registry, destination string) (JournalBackup, error) {
	var result JournalBackup
	if !retentionSupported() || registry == nil {
		return result, ErrUnavailable
	}
	source, err := canonicalJournalPath(path)
	if err != nil {
		return result, err
	}
	target, err := canonicalJournalPath(destination)
	if err != nil {
		return result, err
	}
	if err = validateRetentionPath(source); err != nil {
		return result, err
	}
	if err = validateRetentionPath(target); err != nil {
		return result, err
	}
	if relative, relErr := filepath.Rel(source+".retained", target); relErr == nil && filepath.IsLocal(relative) {
		return result, errors.New("backup destination must be outside the journal directory")
	}
	owner, err := openJournalReadLock(source)
	if err != nil {
		return result, err
	}
	defer owner.Close()
	defer unlockRetentionRead(owner)
	if !retainedRootPresent(source) {
		return result, errors.New("backup requires a retained journal")
	}
	verified, err := verifyStoppedJournal(source, registry, nil)
	if err != nil {
		return result, err
	}
	if !verified.AuditAvailable || verified.Pending != 0 {
		return result, errors.New("resolve unavailable audit state before creating a recovery backup")
	}
	generation, ok := verified.Retention["generation"].(int)
	if !ok || generation < 1 || generation > 1024 {
		return result, ErrUnavailable
	}
	if err = os.Mkdir(target, 0700); err != nil {
		return result, err
	}
	const journalName = "v2.jsonl"
	result = JournalBackup{Schema: "retained-journal-backup/1", Registry: registry.Digest(), Journal: journalName, Verification: verified}
	data := filepath.Join(target, journalName+".retained")
	if err = os.Mkdir(data, 0700); err != nil {
		return result, err
	}
	copyFile := func(from, relative string, limit int64) error {
		row, copyErr := copyBackupFile(from, target, relative, limit)
		if copyErr == nil {
			result.Files = append(result.Files, row)
		}
		return copyErr
	}
	if err = copyFile(source, journalName, 16<<10); err != nil {
		return result, err
	}
	for _, name := range []string{"IDENTITY.json", "CURRENT"} {
		if err = copyFile(filepath.Join(source+".retained", name), filepath.Join(journalName+".retained", name), 16<<10); err != nil {
			return result, err
		}
	}
	for i := 0; i <= generation; i++ {
		name := segmentName(i)
		if err = copyFile(filepath.Join(source+".retained", name), filepath.Join(journalName+".retained", name), 64<<20); err != nil {
			return result, err
		}
		if i > 0 {
			name = checkpointName(i)
			if err = copyFile(filepath.Join(source+".retained", name), filepath.Join(journalName+".retained", name), retainedCheckpointLimit); err != nil {
				return result, err
			}
		}
	}
	if err = writeBackupFile(filepath.Join(target, journalName+".owner"), func(io.Writer) error { return nil }); err != nil {
		return result, err
	}
	result.Files = append(result.Files, JournalBackupFile{Path: journalName + ".owner", SHA256: digestBytes(nil)})
	// Verify the copied bytes independently, including the genesis and every
	// checkpoint. A verified prefix alone cannot qualify as this backup.
	copied, err := VerifyJournal(filepath.Join(target, journalName), registry, nil)
	if err != nil {
		return result, err
	}
	if !copied.Passed || !copied.AuditAvailable || copied.Head != verified.Head || copied.Sequence != verified.Sequence {
		return result, errors.New("backup differs from the stopped writer")
	}
	if err = syncRetentionDirectory(data); err != nil {
		return result, err
	}
	if err = syncRetentionDirectory(target); err != nil {
		return result, err
	}
	if err = syncRetentionDirectory(filepath.Dir(target)); err != nil {
		return result, err
	}
	if err = writeBackupFile(filepath.Join(target, "backup.json"), func(w io.Writer) error {
		return json.NewEncoder(w).Encode(result)
	}); err != nil {
		return result, err
	}
	return result, syncRetentionDirectory(target)
}

func canonicalJournalPath(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(absolute))
	if err != nil {
		return "", err
	}
	return filepath.Join(parent, filepath.Base(absolute)), nil
}

func writeBackupFile(path string, write func(io.Writer) error) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if err = write(f); err == nil {
		err = f.Sync()
	}
	return errors.Join(err, f.Close())
}

func copyBackupFile(source, target, relative string, limit int64) (JournalBackupFile, error) {
	row := JournalBackupFile{Path: filepath.ToSlash(relative)}
	info, err := os.Lstat(source)
	if err != nil {
		return row, err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return row, ErrLimit
	}
	file, err := os.Open(source)
	if err != nil {
		return row, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return row, ErrUnavailable
	}
	digest := sha256.New()
	err = writeBackupFile(filepath.Join(target, relative), func(w io.Writer) error {
		n, err := io.Copy(io.MultiWriter(w, digest), io.LimitReader(file, limit+1))
		if err == nil && (n != info.Size() || n > limit) {
			return ErrUnavailable
		}
		row.Bytes = n
		return err
	})
	row.SHA256 = hex.EncodeToString(digest.Sum(nil))
	return row, err
}
