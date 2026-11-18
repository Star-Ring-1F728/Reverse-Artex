package contextshadow

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const MaxArchiveSegments = 8
const MaxTotalHistoryBytes = 256 << 20

// Limits apply to regular file lengths, including archive seals. They do not
// claim a filesystem allocation quota or protection against unrelated writers.
type StorageLimits struct {
	ActiveAttempts  int `json:"active_attempts"`
	ActiveBytes     int `json:"active_bytes"`
	ArchiveSegments int `json:"archive_segments"`
	TotalBytes      int `json:"total_bytes"`
}

func DefaultStorageLimits() StorageLimits {
	return StorageLimits{MaxAttempts, MaxHistoryBytes, MaxArchiveSegments, MaxTotalHistoryBytes}
}
func (l StorageLimits) valid() bool {
	return l.ActiveAttempts >= 4 && l.ActiveAttempts <= MaxAttempts && l.ActiveBytes >= 64<<10 && l.ActiveBytes <= MaxHistoryBytes && l.ArchiveSegments >= 0 && l.ArchiveSegments <= MaxArchiveSegments && l.TotalBytes >= l.ActiveBytes+(64<<10) && l.TotalBytes <= MaxTotalHistoryBytes
}

type HistoryStorage struct {
	State            string        `json:"state"`
	ActiveAttempts   int           `json:"active_attempts"`
	ArchivedAttempts int           `json:"archived_attempts"`
	ArchiveSegments  int           `json:"archive_segments"`
	ActiveBytes      int           `json:"active_bytes"`
	TotalBytes       int           `json:"total_bytes"`
	UnsavedChecks    int           `json:"unsaved_checks"`
	Limits           StorageLimits `json:"limits"`
}
type ArchiveEntry struct {
	Sequence   int       `json:"sequence"`
	Bytes      int       `json:"bytes"`
	FileSHA    string    `json:"file_sha256"`
	AttemptSHA string    `json:"attempt_sha256"`
	FinishedAt time.Time `json:"finished_at"`
	Error      string    `json:"error,omitempty"`
}
type ArchiveSeal struct {
	Schema       string         `json:"schema"`
	Index        int            `json:"index"`
	Tenant       string         `json:"tenant_id"`
	CandidateSHA string         `json:"candidate_sha256"`
	PreviousSHA  string         `json:"previous_seal_sha256"`
	Entries      []ArchiveEntry `json:"entries"`
	SHA          string         `json:"seal_sha256"`
}

func sealSHA(a ArchiveSeal) string { a.SHA = ""; b, _ := json.Marshal(a); return fileSHA(b) }
func fileSHA(b []byte) string      { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func attemptName(n int) string     { return fmt.Sprintf("attempt-%06d.json", n) }
func segmentName(n int) string     { return fmt.Sprintf("segment-%06d", n) }
func sealName(n int) string        { return fmt.Sprintf("seal-%06d.json", n) }
func (s *Live) validateAttempt(record Attempt, n int) error {
	if record.Schema != "case-context-live-attempt/2" || record.Sequence != n || record.Tenant != s.c.Tenant || record.CandidateSHA != s.c.SHA || record.SHA != attemptSHA(record) || record.FinishedAt.Before(record.StartedAt) || (record.Receipt == nil) == (record.Error == "") {
		return errors.New("invalid shadow attempt")
	}
	if v := record.Receipt; v != nil && (v.SHA != ReceiptSHA(*v) || v.CandidateSHA != s.c.SHA || v.Tenant != s.c.Tenant || v.DeploymentAllowed) {
		return errors.New("invalid shadow receipt")
	}
	return nil
}
func (s *Live) remember(a Attempt) {
	s.latest = &a
	s.summaries = append(s.summaries, AttemptSummary{a.Sequence, a.FinishedAt, a.Error, a.SHA})
}
func (s *Live) restoreHistory() error {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return err
	}
	allowed := map[string]bool{"owner.lock": true, "capacity.json": true, "observer.state.json": true}
	previous := ""
	for n := 1; ; n++ {
		path := filepath.Join(s.dir, sealName(n))
		if _, err := os.Lstat(path); os.IsNotExist(err) {
			break
		} else if err != nil {
			return err
		}
		if n > s.limits.ArchiveSegments {
			return ErrLimit
		}
		var seal ArchiveSeal
		if err := ReadPublic(path, &seal); err != nil {
			return err
		}
		if seal.Schema != "case-context-shadow-archive/1" || seal.Index != n || seal.Tenant != s.c.Tenant || seal.CandidateSHA != s.c.SHA || seal.PreviousSHA != previous || len(seal.Entries) == 0 || len(seal.Entries) > s.limits.ActiveAttempts || seal.SHA != sealSHA(seal) {
			return errors.New("invalid shadow archive seal")
		}
		dir := filepath.Join(s.dir, segmentName(n))
		st, err := os.Lstat(dir)
		if err != nil || !st.IsDir() {
			return errors.New("regular shadow archive directory required")
		}
		members, err := os.ReadDir(dir)
		if err != nil || len(members) != len(seal.Entries) {
			return errors.New("shadow archive member mismatch")
		}
		countBytes := 0
		for index, e := range seal.Entries {
			if e.Sequence != s.baseSequence+index+1 || e.Bytes < 1 || e.Bytes > 2<<20 || members[index].Name() != attemptName(e.Sequence) {
				return errors.New("shadow archive sequence mismatch")
			}
			path := filepath.Join(dir, attemptName(e.Sequence))
			st, err := os.Lstat(path)
			if err != nil || !st.Mode().IsRegular() || st.Size() != int64(e.Bytes) {
				return errors.New("shadow archive file mismatch")
			}
			raw, err := os.ReadFile(path)
			if err != nil || fileSHA(raw) != e.FileSHA {
				return errors.New("shadow archive checksum mismatch")
			}
			var a Attempt
			if err := ReadPublic(path, &a); err != nil {
				return err
			}
			if s.validateAttempt(a, e.Sequence) != nil || a.SHA != e.AttemptSHA || !a.FinishedAt.Equal(e.FinishedAt) || a.Error != e.Error {
				return errors.New("shadow archive content mismatch")
			}
			s.remember(a)
			countBytes += len(raw)
		}
		if countBytes > s.limits.ActiveBytes {
			return ErrLimit
		}
		s.baseSequence += len(seal.Entries)
		st, err = os.Stat(path)
		if err != nil {
			return err
		}
		s.totalBytes += countBytes + int(st.Size())
		s.archives = append(s.archives, seal)
		previous = seal.SHA
		allowed[sealName(n)] = true
		allowed[segmentName(n)] = true
	}
	for _, e := range entries {
		if allowed[e.Name()] {
			continue
		}
		n := s.baseSequence + len(s.attempts) + 1
		if e.Name() != attemptName(n) || len(s.attempts) >= s.limits.ActiveAttempts {
			return errors.New("unexpected or unfinished shadow history member")
		}
		st, err := e.Info()
		if err != nil || !st.Mode().IsRegular() || st.Size() > 2<<20 {
			return errors.New("regular bounded shadow attempt required")
		}
		var a Attempt
		if err := ReadPublic(filepath.Join(s.dir, e.Name()), &a); err != nil {
			return err
		}
		if err := s.validateAttempt(a, n); err != nil {
			return err
		}
		s.bytes += int(st.Size())
		s.totalBytes += int(st.Size())
		s.attempts = append(s.attempts, a)
		s.remember(a)
	}
	if raw, e := os.ReadFile(filepath.Join(s.dir, "capacity.json")); e == nil {
		var marker CapacityMarker
		if e = ReadPublic(filepath.Join(s.dir, "capacity.json"), &marker); e != nil {
			return e
		}
		if marker.Schema != "context-shadow-capacity/1" || marker.Tenant != s.c.Tenant || marker.CandidateSHA != s.c.SHA || marker.LastSequence != s.baseSequence+len(s.attempts) || marker.SHA != capacitySHA(marker) || s.latest == nil || marker.LastSHA != s.latest.SHA {
			return errors.New("invalid shadow capacity marker")
		}
		s.totalBytes += len(raw)
		s.storageFull = true
		s.unsavedChecks = marker.Unsaved
		s.status.Error = ErrLimit.Error()
	} else if !os.IsNotExist(e) {
		return e
	}
	if info, e := os.Lstat(filepath.Join(s.dir, "observer.state.json")); e == nil {
		if !info.Mode().IsRegular() || info.Size() != observerStateBytes {
			return errors.New("invalid observer state file")
		}
		s.totalBytes += int(info.Size())
	} else if !os.IsNotExist(e) {
		return e
	}
	if s.bytes > s.limits.ActiveBytes || s.totalBytes > s.limits.TotalBytes {
		return ErrLimit
	}
	return nil
}
func (s *Live) canRotate() bool {
	return len(s.attempts) > 0 && len(s.archives) < s.limits.ArchiveSegments && s.totalBytes+(64<<10) < s.limits.TotalBytes
}

// Rotation never deletes audit files. An immutable synced intent pins all
// original bytes before same-root renames. Any interruption keeps the intent
// and blocks reopening; there is no automatic partial-move recovery.
func (s *Live) rotateHistory() error {
	if !s.canRotate() {
		return ErrLimit
	}
	seal := ArchiveSeal{Schema: "case-context-shadow-archive/1", Index: len(s.archives) + 1, Tenant: s.c.Tenant, CandidateSHA: s.c.SHA, Entries: []ArchiveEntry{}}
	if len(s.archives) > 0 {
		seal.PreviousSHA = s.archives[len(s.archives)-1].SHA
	}
	for _, a := range s.attempts {
		path := filepath.Join(s.dir, attemptName(a.Sequence))
		st, err := os.Lstat(path)
		if err != nil || !st.Mode().IsRegular() || st.Size() > 2<<20 {
			return errors.New("shadow rotation source mismatch")
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var verified Attempt
		if err = ReadPublic(path, &verified); err != nil {
			return err
		}
		if s.validateAttempt(verified, a.Sequence) != nil || verified.SHA != a.SHA {
			return errors.New("shadow rotation attempt changed")
		}
		seal.Entries = append(seal.Entries, ArchiveEntry{a.Sequence, len(raw), fileSHA(raw), a.SHA, a.FinishedAt, a.Error})
	}
	seal.SHA = sealSHA(seal)
	b, err := json.Marshal(seal)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if len(b) > 64<<10 || s.totalBytes+len(b) > s.limits.TotalBytes {
		return ErrLimit
	}
	intent := filepath.Join(s.dir, "rotation.pending.json")
	if err = writeNewHistoryFile(intent, b); err != nil {
		return err
	}
	dir := filepath.Join(s.dir, segmentName(seal.Index))
	if err = os.Mkdir(dir, 0700); err != nil {
		return err
	}
	for _, e := range seal.Entries {
		if err = os.Rename(filepath.Join(s.dir, attemptName(e.Sequence)), filepath.Join(dir, attemptName(e.Sequence))); err != nil {
			return err
		}
	}
	if err = os.Rename(intent, filepath.Join(s.dir, sealName(seal.Index))); err != nil {
		return err
	}
	s.baseSequence += len(s.attempts)
	s.attempts = nil
	s.bytes = 0
	s.totalBytes += len(b)
	s.archives = append(s.archives, seal)
	return nil
}
func writeNewHistoryFile(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	n, e := f.Write(b)
	if e == nil && n != len(b) {
		e = errors.New("short shadow history write")
	}
	return errors.Join(e, f.Sync(), f.Close())
}
func (s *Live) storageStatus() HistoryStorage {
	state := "ready"
	if s.storageFull {
		state = "full"
	}
	if s.storageFailed {
		state = "failed"
	}
	return HistoryStorage{state, len(s.attempts), s.baseSequence, len(s.archives), s.bytes, s.totalBytes, s.unsavedChecks, s.limits}
}

type CapacityMarker struct {
	Schema       string    `json:"schema"`
	Tenant       string    `json:"tenant_id"`
	CandidateSHA string    `json:"candidate_sha256"`
	LastSequence int       `json:"last_sequence"`
	LastSHA      string    `json:"last_attempt_sha256"`
	Unsaved      int       `json:"unsaved_checks"`
	CreatedAt    time.Time `json:"created_at"`
	SHA          string    `json:"sha256"`
}

func capacitySHA(m CapacityMarker) string { m.SHA = ""; b, _ := json.Marshal(m); return fileSHA(b) }
func (s *Live) pauseCapacity() {
	s.status.Enabled = false
	s.status.Queued = false
	s.storageFull = true
	s.status.Error = ErrLimit.Error()
	if s.latest == nil {
		s.storageFailed = true
		return
	}
	m := CapacityMarker{Schema: "context-shadow-capacity/1", Tenant: s.c.Tenant, CandidateSHA: s.c.SHA, LastSequence: s.baseSequence + len(s.attempts), LastSHA: s.latest.SHA, Unsaved: s.unsavedChecks, CreatedAt: time.Now().UTC()}
	m.SHA = capacitySHA(m)
	b, _ := json.Marshal(m)
	b = append(b, '\n')
	path := filepath.Join(s.dir, "capacity.json")
	if _, err := os.Lstat(path); err == nil {
		return
	}
	if len(b) > 4096 || s.totalBytes+len(b) > s.limits.TotalBytes {
		s.storageFailed = true
		s.status.Error = "no reserved space for shadow capacity marker"
		return
	}
	if err := writeNewHistoryFile(path, b); err != nil {
		s.storageFailed = true
		s.status.Error = err.Error()
	} else {
		s.totalBytes += len(b)
	}
}
