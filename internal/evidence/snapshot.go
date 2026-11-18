package evidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const MaxSnapshotBytes = 32 << 20
const MaxSnapshotRecords = 100000

var snapshotStreams = []string{"events", "evaluations", "alerts", "host-events", "host-evaluations", "host-alerts"}

type StreamCommitment struct {
	Stream  string `json:"stream"`
	Records int    `json:"records"`
	SHA256  string `json:"sha256"`
}

// Snapshot is a bounded, immutable copy of six detector streams and metadata.
// It excludes policy delivery ACKs, control WAL and database state.
type Snapshot struct {
	metadata    []byte
	rows        map[string][][]byte
	commitments []StreamCommitment
	digest      string
}

func (s *Snapshot) Metadata() []byte { return bytes.Clone(s.metadata) }
func (s *Snapshot) SHA256() string   { return s.digest }
func (s *Snapshot) Commitments() []StreamCommitment {
	return append([]StreamCommitment(nil), s.commitments...)
}
func (s *Snapshot) VisitRecords(stream string, visit func([]byte) error) error {
	rows, ok := s.rows[stream]
	if !ok {
		return errors.New("stream outside detector snapshot")
	}
	for _, row := range rows {
		if err := visit(bytes.Clone(row)); err != nil {
			return err
		}
	}
	return nil
}

// Capture requires an offline source. Equal consecutive reads detect ordinary
// concurrent changes; they do not implement a writer lock or atomic filesystem
// snapshot. Verification and selection subsequently use only the frozen bytes.
// Unlike New, this never creates directories, metadata, budget files or handles
// for writing. Missing metadata and non-regular source files are rejected.
func Capture(dir string) (*Snapshot, error) {
	a, err := capture(dir)
	if err != nil {
		return nil, err
	}
	b, err := capture(dir)
	if err != nil {
		return nil, err
	}
	if a.digest != b.digest {
		return nil, errors.New("evidence changed during snapshot capture")
	}
	return a, nil
}

// CaptureLocked performs one bounded read while the caller serializes every
// evidence writer and rotation with its commit mutex. Unlike Capture this has
// no second-read drift check and must never be used by an offline CLI or a
// caller without exclusive writer ownership. Replay still verifies all commits.
func CaptureLocked(dir string) (*Snapshot, error) { return capture(dir) }

func capture(dir string) (*Snapshot, error) {
	st, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() {
		return nil, errors.New("existing evidence directory required")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	if len(entries) > 4096 {
		return nil, errors.New("snapshot directory entry limit")
	}
	var physical int64
	segments := map[string]bool{}
	for _, entry := range entries {
		relevant := entry.Name() == "recovery.meta.json"
		for _, name := range snapshotStreams {
			relevant = relevant || strings.HasPrefix(entry.Name(), name+".")
			if strings.HasPrefix(entry.Name(), name+".") && entry.Name() != name+".jsonl" {
				parts := strings.SplitN(strings.TrimPrefix(entry.Name(), name+"."), ".", 2)
				if len(parts) != 2 {
					return nil, errors.New("invalid snapshot segment")
				}
				n, err := strconv.Atoi(parts[0])
				if err != nil || n < 1 {
					return nil, errors.New("invalid snapshot segment sequence")
				}
				key := fmt.Sprintf("%s:%d:%s", name, n, parts[1])
				if segments[key] {
					return nil, errors.New("aliased snapshot segment")
				}
				segments[key] = true
			}
		}
		if relevant {
			info, err := entry.Info()
			if err != nil {
				return nil, err
			}
			if !info.Mode().IsRegular() {
				return nil, errors.New("regular evidence files required")
			}
			physical += info.Size()
			if physical > 2*MaxSnapshotBytes {
				return nil, errors.New("snapshot source byte limit")
			}
		}
	}
	f, err := os.Open(filepath.Join(dir, "recovery.meta.json"))
	if err != nil {
		return nil, err
	}
	meta, readErr := io.ReadAll(io.LimitReader(f, 4097))
	err = errors.Join(readErr, f.Close())
	if err != nil {
		return nil, err
	}
	if len(meta) == 0 || len(meta) > 4096 {
		return nil, errors.New("bounded recovery metadata required")
	}
	return snapshotFromReader(meta, &Store{dir: dir, readLimit: MaxSnapshotBytes})
}
func snapshotFromReader(meta []byte, reader *Store) (*Snapshot, error) {
	s := &Snapshot{metadata: meta, rows: map[string][][]byte{}}
	total, count := len(meta), 0
	for _, name := range snapshotStreams {
		s.rows[name] = [][]byte{}
		h := sha256.New()
		err := reader.VisitRecords(name, func(line []byte) error {
			total += len(line) + 1
			count++
			if total > MaxSnapshotBytes || count > MaxSnapshotRecords {
				return errors.New("detector snapshot limit exceeded")
			}
			s.rows[name] = append(s.rows[name], bytes.Clone(line))
			h.Write(line)
			h.Write([]byte{'\n'})
			return nil
		})
		if err != nil {
			return nil, err
		}
		s.commitments = append(s.commitments, StreamCommitment{name, len(s.rows[name]), hex.EncodeToString(h.Sum(nil))})
	}
	metaSHA := sha256.Sum256(meta)
	encoded, _ := json.Marshal(struct {
		Schema      string             `json:"schema_version"`
		MetadataSHA string             `json:"metadata_sha256"`
		Streams     []StreamCommitment `json:"streams"`
	}{"detector-snapshot/1", hex.EncodeToString(metaSHA[:]), s.commitments})
	digest := sha256.Sum256(encoded)
	s.digest = hex.EncodeToString(digest[:])
	return s, nil
}
