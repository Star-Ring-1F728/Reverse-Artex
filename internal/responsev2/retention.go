package responsev2

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reverse-artex/internal/casememory"
	"reverse-artex/internal/decisions"
	"reverse-artex/internal/protection"
	"sort"
	"strings"
	"time"
)

const retainedCheckpointLimit = 64 << 20
const completionReserve = 2048

type RetentionConfig struct {
	SegmentBytes   int64 `json:"segment_bytes"`
	MaxBytes       int64 `json:"max_storage_bytes"`
	MaxGenerations int   `json:"max_generations"`
}

func DefaultRetentionConfig() RetentionConfig { return RetentionConfig{16 << 20, 8 << 30, 256} }
func (c RetentionConfig) Validate() error {
	if c.SegmentBytes < 64<<10 || c.SegmentBytes > 64<<20 || c.MaxBytes < c.SegmentBytes*4 || c.MaxBytes > 64<<30 || c.MaxGenerations < 2 || c.MaxGenerations > 1024 {
		return ErrLimit
	}
	return nil
}

type retentionRoot struct {
	Schema      string          `json:"schema"`
	ID          string          `json:"store_id"`
	Registry    string          `json:"registry_digest"`
	Config      RetentionConfig `json:"limits"`
	LegacySHA   string          `json:"legacy_sha256"`
	LegacyBytes int64           `json:"legacy_bytes"`
	Genesis     string          `json:"genesis_checkpoint_sha256"`
}
type retentionPointer struct {
	Schema        string `json:"schema"`
	ID            string `json:"store_id"`
	Generation    int    `json:"generation"`
	CheckpointSHA string `json:"checkpoint_sha256"`
	SHA           string `json:"sha256"`
}
type retainedCheckpoint struct {
	Schema             string                        `json:"schema"`
	ID                 string                        `json:"store_id"`
	Registry           string                        `json:"registry_digest"`
	Generation         int                           `json:"generation"`
	PreviousCheckpoint string                        `json:"previous_checkpoint_sha256"`
	At                 time.Time                     `json:"at"`
	Sequence           int                           `json:"sequence"`
	Head               string                        `json:"journal_head_sha256"`
	Segment            string                        `json:"sealed_segment"`
	SegmentSHA         string                        `json:"segment_sha256"`
	SegmentBytes       int64                         `json:"segment_bytes"`
	State              retainedState                 `json:"state"`
	Completions        map[string]retainedCompletion `json:"archived_completion_digests"`
	CompletionKeys     []uint64                      `json:"completion_keys"`
	ArchivedRequests   map[string]string             `json:"archived_requests"`
	RequestKeys        []uint64                      `json:"request_keys"`
	SHA                string                        `json:"sha256"`
}
type checkpointInfo struct {
	generation     int
	sha            string
	completionKeys []uint64
	requestKeys    []uint64
}
type retainedJournal struct {
	path, dir, id string
	config        RetentionConfig
	generation    int
	checkpointSHA string
	bytes         int64
	checkpoints   []checkpointInfo
}

func digestBytes(raw []byte) string             { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }
func checkpointSHA(c retainedCheckpoint) string { c.SHA = ""; return decisions.Hash(c) }
func pointerSHA(p retentionPointer) string      { p.SHA = ""; return decisions.Hash(p) }
func segmentName(generation int) string         { return fmt.Sprintf("segment-%06d.jsonl", generation) }
func checkpointName(generation int) string      { return fmt.Sprintf("checkpoint-%06d.json", generation) }
func retainedRootPresent(path string) bool {
	st, err := os.Lstat(path)
	if err != nil || !st.Mode().IsRegular() || st.Size() > 16<<10 || st.Size() == 0 {
		return false
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var head struct {
		Schema string `json:"schema"`
	}
	return json.Unmarshal(raw, &head) == nil && head.Schema == "response-retention-root/1"
}
func readRetainedFile(path string, limit int64) ([]byte, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Size() > limit {
		return nil, ErrLimit
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(st, opened) {
		return nil, ErrUnavailable
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, ErrLimit
	}
	return raw, nil
}

// hashRetainedFile hashes the complete bounded file without materializing a
// growing copy of the segment. Keep the same file identity and size guards as
// readRetainedFile; checkpoints still bind every byte of the sealed predecessor.
func hashRetainedFile(path string, limit int64) (string, int64, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return "", 0, err
	}
	if !st.Mode().IsRegular() || st.Size() > limit {
		return "", 0, ErrLimit
	}
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(st, opened) {
		return "", 0, ErrUnavailable
	}
	digest := sha256.New()
	var buffer [64 << 10]byte
	n, err := io.CopyBuffer(digest, io.LimitReader(f, limit+1), buffer[:])
	if err != nil {
		return "", n, err
	}
	if n > limit {
		return "", n, ErrLimit
	}
	return hex.EncodeToString(digest.Sum(nil)), n, nil
}

func (r *retainedJournal) usage() (int64, error) {
	entries, err := os.ReadDir(r.dir)
	if err != nil {
		return 0, err
	}
	if len(entries) > r.config.MaxGenerations*4+32 {
		return 0, ErrLimit
	}
	total := int64(16 << 10) // root/pointer metadata and an atomic replacement reserve
	for _, entry := range entries {
		info, err := os.Lstat(filepath.Join(r.dir, entry.Name()))
		if err != nil {
			return 0, err
		}
		if !info.Mode().IsRegular() {
			return 0, ErrUnavailable
		}
		name := entry.Name()
		if name != "IDENTITY.json" && name != "CURRENT" && !strings.HasPrefix(name, "segment-") && !strings.HasPrefix(name, "checkpoint-") && !strings.HasPrefix(name, ".pending-") {
			return 0, ErrUnavailable
		}
		total += info.Size()
		if total > r.config.MaxBytes {
			return 0, ErrLimit
		}
	}
	return total, nil
}
func (s *Store) retentionStage(stage string) error {
	if s.retentionHook != nil {
		return s.retentionHook(stage)
	}
	return nil
}
func (s *Store) retainedFile(name string, raw []byte, replace bool) error {
	r := s.retained
	destination := filepath.Join(r.dir, name)
	if filepath.IsAbs(name) {
		destination = name
	}
	if !replace {
		existing, err := readRetainedFile(destination, retainedCheckpointLimit)
		if err == nil {
			if !bytes.Equal(existing, raw) {
				return ErrUnavailable
			}
			return nil
		}
		if !os.IsNotExist(err) {
			return err
		}
	}
	used, err := r.usage()
	if err != nil {
		return err
	}
	if used+int64(len(raw))+int64(len(s.attempts)-len(s.observations))*completionReserve > r.config.MaxBytes {
		return ErrLimit
	}
	temporary := filepath.Join(r.dir, ".pending-"+newBootID())
	f, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	good := false
	defer func() {
		f.Close()
		if good {
			_ = os.Remove(temporary)
		}
	}()
	n, err := f.Write(raw)
	if err != nil || n != len(raw) {
		return ErrUnavailable
	}
	if err = s.syncFile(f); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if replace {
		if err = publishRetentionPointer(temporary, destination); err != nil {
			return err
		}
	} else {
		if err = os.Link(temporary, destination); err != nil {
			return err
		}
		if err = syncRetentionDirectory(r.dir); err != nil {
			return err
		}
	}
	good = true
	return nil
}
func (s *Store) writeCheckpoint(c retainedCheckpoint) error {
	raw, err := json.Marshal(c)
	if err != nil {
		return err
	}
	if len(raw) > retainedCheckpointLimit {
		return ErrLimit
	}
	return s.retainedFile(checkpointName(c.Generation), append(raw, '\n'), false)
}
func (s *Store) publishCurrent(c retainedCheckpoint) error {
	p := retentionPointer{Schema: "response-retention-current/1", ID: s.retained.id, Generation: c.Generation, CheckpointSHA: c.SHA}
	p.SHA = pointerSHA(p)
	raw, _ := json.Marshal(p)
	return s.retainedFile("CURRENT", append(raw, '\n'), true)
}
func readPointer(r *retainedJournal) (retentionPointer, error) {
	raw, err := readRetainedFile(filepath.Join(r.dir, "CURRENT"), 16<<10)
	if err != nil {
		return retentionPointer{}, err
	}
	var p retentionPointer
	if decisions.DecodeStrict(raw, &p, 16<<10) != nil || p.Schema != "response-retention-current/1" || p.ID != r.id || p.Generation < 1 || p.Generation > r.config.MaxGenerations || p.SHA != pointerSHA(p) || !decisions.ValidHash(p.CheckpointSHA) {
		return p, ErrUnavailable
	}
	return p, nil
}
func (s *Store) readCheckpoint(generation int) (retainedCheckpoint, error) {
	raw, err := readRetainedFile(filepath.Join(s.retained.dir, checkpointName(generation)), retainedCheckpointLimit)
	if err != nil {
		return retainedCheckpoint{}, err
	}
	var c retainedCheckpoint
	if decisions.DecodeStrict(raw, &c, retainedCheckpointLimit) != nil || c.Schema != "response-checkpoint/1" || c.ID != s.retained.id || c.Registry != s.registry.Digest() || c.Generation != generation || c.SHA != checkpointSHA(c) {
		return c, ErrUnavailable
	}
	return c, nil
}
func retainedFingerprint(id string) uint64 {
	sum := sha256.Sum256([]byte(id))
	return binary.BigEndian.Uint64(sum[:8])
}
func sortedFingerprints[T any](entries map[string]T) []uint64 {
	keys := make([]uint64, 0, len(entries))
	for id := range entries {
		keys = append(keys, retainedFingerprint(id))
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	return keys
}
func hasFingerprint(keys []uint64, hash uint64) bool {
	i := sort.Search(len(keys), func(i int) bool { return keys[i] >= hash })
	return i < len(keys) && keys[i] == hash
}
func (s *Store) buildCheckpoint(generation int, segmentSHA string, segmentBytes int64) (retainedCheckpoint, error) {
	state, completed, requests, err := s.compactedState()
	if err != nil {
		return retainedCheckpoint{}, err
	}
	c := retainedCheckpoint{Schema: "response-checkpoint/1", ID: s.retained.id, Registry: s.registry.Digest(), Generation: generation, PreviousCheckpoint: s.retained.checkpointSHA, At: s.high, Sequence: s.sequence, Head: s.head,
		Segment: segmentName(generation - 1), SegmentSHA: segmentSHA, SegmentBytes: segmentBytes, State: state, Completions: completed, CompletionKeys: sortedFingerprints(completed), ArchivedRequests: requests, RequestKeys: sortedFingerprints(requests)}
	c.SHA = checkpointSHA(c)
	return c, nil
}
func (s *Store) rememberCheckpoint(c retainedCheckpoint) {
	s.retained.generation = c.Generation
	s.retained.checkpointSHA = c.SHA
	s.retained.checkpoints = append(s.retained.checkpoints, checkpointInfo{c.Generation, c.SHA, append([]uint64(nil), c.CompletionKeys...), append([]uint64(nil), c.RequestKeys...)})
	s.installRetainedState(c.State)
}

// OpenRetained explicitly opts into a durable, segmented journal. The
// original legacy prefix is preserved and the original path becomes a marker,
// so an unaware old binary cannot reopen an earlier generation as current.
func OpenRetained(path string, registry *protection.Registry, config RetentionConfig) (*Store, error) {
	return openRetained(path, registry, config, nil)
}
func openRetained(path string, registry *protection.Registry, config RetentionConfig, hook func(string) error) (*Store, error) {
	return openRetainedUsingClock(path, registry, config, hook, time.Now)
}

// Tests may seed an explicit past authority clock without changing the host.
// The live wrapper samples time.Now at the original post-replay fence below.
func openRetainedUsingClock(path string, registry *protection.Registry, config RetentionConfig, hook func(string) error, clock func() time.Time) (*Store, error) {
	if !retentionSupported() {
		return nil, errors.New("retained V2 journal requires Linux or local Windows NTFS")
	}
	if err := validateRetentionPath(path); err != nil {
		return nil, err
	}
	if registry == nil {
		return nil, ErrUnavailable
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	var s *Store
	var err error
	if !retainedRootPresent(path) {
		s, err = openLegacy(path, registry, true)
		if err != nil {
			return nil, err
		}
		s.retentionHook = hook
		if err = s.activateRetention(path, config); err != nil {
			s.Close()
			return nil, err
		}
	} else {
		raw, e := readRetainedFile(path, 16<<10)
		if e != nil {
			return nil, e
		}
		var root retentionRoot
		if decisions.DecodeStrict(raw, &root, 16<<10) != nil || root.Schema != "response-retention-root/1" || root.Registry != registry.Digest() || root.Config != config || len(root.ID) != 32 || !decisions.ValidHash(root.Genesis) {
			return nil, ErrUnavailable
		}
		owner, e := casememory.Open(path + ".owner")
		if e != nil {
			return nil, e
		}
		s, e = newStore(nil, owner, registry)
		if e != nil {
			owner.Close()
			return nil, e
		}
		s.retentionHook = hook
		s.retained = &retainedJournal{path: path, dir: path + ".retained", id: root.ID, config: config}
		if e = s.replayRetained(root, true); e != nil {
			s.Close()
			return nil, e
		}
	}
	now := clock()
	if now.Before(s.high) {
		s.Close()
		return nil, errors.New("v2 journal clock rollback; operator recovery required")
	}
	s.restoreDeadlines(now)
	if err = s.commit(record{Operation: "writer-started", WriterBoot: s.bootID, At: now.UTC()}); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}
func (s *Store) activateRetention(path string, config RetentionConfig) error {
	legacy, err := readRetainedFile(path, 64<<20)
	if err != nil {
		return err
	}
	directory := path + ".retained"
	if err = os.Mkdir(directory, 0700); err != nil && !os.IsExist(err) {
		return err
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ErrUnavailable
	}
	identityPath := filepath.Join(directory, "IDENTITY.json")
	identity := retentionRoot{Schema: "response-retention-preparation/1", ID: newBootID(), Registry: s.registry.Digest(), Config: config, LegacySHA: digestBytes(legacy), LegacyBytes: int64(len(legacy))}
	if raw, e := readRetainedFile(identityPath, 16<<10); e == nil {
		var old retentionRoot
		if decisions.DecodeStrict(raw, &old, 16<<10) != nil || old.Schema != identity.Schema || old.Registry != identity.Registry || old.Config != config || old.LegacySHA != identity.LegacySHA || old.LegacyBytes != identity.LegacyBytes || len(old.ID) != 32 || old.Genesis != "" {
			return ErrUnavailable
		}
		identity = old
	} else if !os.IsNotExist(e) {
		return e
	}
	s.retained = &retainedJournal{path: path, dir: directory, id: identity.ID, config: config}
	raw, _ := json.Marshal(identity)
	if err = s.retainedFile("IDENTITY.json", append(raw, '\n'), false); err != nil {
		return err
	}
	if err = s.retainedFile(segmentName(0), legacy, false); err != nil {
		return err
	}
	c, err := s.buildCheckpoint(1, identity.LegacySHA, int64(len(legacy)))
	if err != nil {
		return err
	}
	if err = s.writeCheckpoint(c); err != nil {
		return err
	}
	if err = s.retainedFile(segmentName(1), nil, false); err != nil {
		return err
	}
	if current, e := readPointer(s.retained); e == nil {
		if current.Generation != 1 || current.CheckpointSHA != c.SHA {
			return ErrUnavailable
		}
	} else if !os.IsNotExist(e) {
		return e
	}
	if err = s.publishCurrent(c); err != nil {
		return err
	}
	if err = s.retentionStage("initial-files-synced"); err != nil {
		return err
	}
	root := identity
	root.Schema = "response-retention-root/1"
	root.Genesis = c.SHA
	raw, _ = json.Marshal(root)
	if err = s.file.Close(); err != nil {
		return err
	}
	s.file = nil
	absolute, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	if err = s.retainedFile(absolute, append(raw, '\n'), true); err != nil {
		return err
	}
	if err = s.retentionStage("root-published"); err != nil {
		return err
	}
	s.rememberCheckpoint(c)
	s.size = 0
	s.file, err = os.OpenFile(filepath.Join(directory, segmentName(1)), os.O_RDWR|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	s.retained.bytes, err = s.retained.usage()
	return err
}
func (s *Store) replayRetained(root retentionRoot, recover bool) error {
	r := s.retained
	directory, err := os.Lstat(r.dir)
	if err != nil || !directory.IsDir() || directory.Mode()&os.ModeSymlink != 0 {
		return ErrUnavailable
	}
	identityRaw, identityErr := readRetainedFile(filepath.Join(r.dir, "IDENTITY.json"), 16<<10)
	var identity retentionRoot
	if identityErr != nil || decisions.DecodeStrict(identityRaw, &identity, 16<<10) != nil || identity.Schema != "response-retention-preparation/1" || identity.ID != root.ID || identity.Registry != root.Registry || identity.Config != root.Config || identity.LegacySHA != root.LegacySHA || identity.LegacyBytes != root.LegacyBytes || identity.Genesis != "" {
		return ErrUnavailable
	}
	if r.bytes, err = r.usage(); err != nil {
		return err
	}
	pointer, err := readPointer(r)
	if err != nil {
		return err
	}
	if err = validateRetainedLayout(r, pointer.Generation); err != nil {
		return err
	}
	for generation := 0; generation <= pointer.Generation; generation++ {
		path := filepath.Join(r.dir, segmentName(generation))
		st, e := os.Lstat(path)
		if e != nil || !st.Mode().IsRegular() {
			return ErrUnavailable
		}
		limit := r.config.SegmentBytes
		if generation == 0 {
			limit = 64 << 20
		}
		if st.Size() > limit {
			return ErrLimit
		}
		f, e := os.Open(path)
		if e != nil {
			return e
		}
		digest := sha256.New()
		reader := bufio.NewReaderSize(io.TeeReader(f, digest), 64<<10)
		size := int64(0)
		for {
			raw, readErr := reader.ReadSlice('\n')
			if readErr == io.EOF && len(raw) == 0 {
				break
			}
			if readErr != nil || len(raw) > 64<<10 {
				f.Close()
				return errors.New("incomplete retained V2 journal")
			}
			if e = s.replayRecord(raw); e != nil {
				f.Close()
				return e
			}
			size += int64(len(raw))
		}
		if e = f.Close(); e != nil {
			return e
		}
		if generation < pointer.Generation {
			c, e := s.readCheckpoint(generation + 1)
			if e != nil {
				return e
			}
			if generation == 0 {
				if c.SegmentSHA != root.LegacySHA || c.SegmentBytes != root.LegacyBytes {
					return errors.New("retained genesis differs from original legacy journal")
				}
				s.markInterrupted()
			}
			expected, e := s.buildCheckpoint(generation+1, hex.EncodeToString(digest.Sum(nil)), size)
			if e != nil {
				return e
			}
			if expected.SHA != c.SHA || (generation == 0 && c.SHA != root.Genesis) {
				return errors.New("retained checkpoint differs from full signed journal replay")
			}
			s.rememberCheckpoint(c)
		} else {
			s.size = size
		}
	}
	if r.checkpointSHA != pointer.CheckpointSHA {
		return ErrUnavailable
	}
	// Complete an interrupted publication only when the successor is empty and
	// the sealed predecessor reproduces every checkpoint field exactly.
	next, err := s.readCheckpoint(r.generation + 1)
	if err == nil {
		if !recover {
			return errors.New("incomplete checkpoint publication requires writer recovery before read-only verification")
		}
		if err = s.recoverSuccessor(next); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	currentPath := filepath.Join(r.dir, segmentName(r.generation))
	if recover {
		s.file, err = os.OpenFile(currentPath, os.O_RDWR|os.O_APPEND, 0600)
	} else {
		s.file, err = os.Open(currentPath)
	}
	return err
}
func (s *Store) recoverSuccessor(c retainedCheckpoint) error {
	r := s.retained
	if c.Generation > r.config.MaxGenerations {
		return ErrLimit
	}
	raw, err := readRetainedFile(filepath.Join(r.dir, segmentName(r.generation)), r.config.SegmentBytes)
	if err != nil {
		return err
	}
	expected, err := s.buildCheckpoint(c.Generation, digestBytes(raw), int64(len(raw)))
	if err != nil {
		return err
	}
	if expected.SHA != c.SHA {
		return ErrUnavailable
	}
	if err = s.retainedFile(segmentName(c.Generation), nil, false); err != nil {
		return err
	}
	if err = s.publishCurrent(c); err != nil {
		return err
	}
	s.rememberCheckpoint(c)
	s.size = 0
	r.bytes, err = r.usage()
	return err
}
func (s *Store) rotateRetained() (err error) {
	defer s.timingEnd(timingRotation, s.timingStart())
	// A checkpoint must never capture the batch coordinator's provisional view.
	if err = s.flushJournalBatch(); err != nil {
		return err
	}
	r := s.retained
	if r == nil || s.closed || s.failed {
		return ErrUnavailable
	}
	if r.generation >= r.config.MaxGenerations {
		return ErrLimit
	}
	if err = s.syncFile(s.file); err != nil {
		s.failed = true
		return err
	}
	if err = s.retentionStage("predecessor-synced"); err != nil {
		return err
	}
	readStarted := s.timingStart()
	segmentSHA, segmentBytes, err := hashRetainedFile(filepath.Join(r.dir, segmentName(r.generation)), r.config.SegmentBytes)
	s.timingEnd(timingRotationRead, readStarted)
	if err != nil || segmentBytes != s.size {
		s.failed = true
		if err == nil {
			err = ErrUnavailable
		}
		return err
	}
	buildStarted := s.timingStart()
	c, err := s.buildCheckpoint(r.generation+1, segmentSHA, segmentBytes)
	s.timingEnd(timingRotationBuild, buildStarted)
	if err != nil {
		return err
	}
	marshalStarted := s.timingStart()
	data, marshalErr := json.Marshal(c)
	s.timingEnd(timingRotationMarshal, marshalStarted)
	if marshalErr != nil {
		return marshalErr
	}
	if len(data) > retainedCheckpointLimit {
		return ErrLimit
	}
	used, usageErr := r.usage()
	if usageErr != nil {
		return usageErr
	}
	if used+int64(2*len(data))+int64(len(s.attempts)-len(s.observations))*completionReserve+(32<<10) > r.config.MaxBytes {
		return ErrLimit
	}
	defer func() {
		if err != nil {
			s.failed = true
		}
	}()
	publishStarted := s.timingStart()
	defer s.timingEnd(timingRotationPublish, publishStarted)
	// Publish the exact encoding already checked against the checkpoint and
	// storage limits above. The store lock keeps this checkpoint immutable;
	// re-encoding it here adds work without changing the durable bytes.
	if err = s.retainedFile(checkpointName(c.Generation), append(data, '\n'), false); err != nil {
		return err
	}
	if err = s.retentionStage("checkpoint-published"); err != nil {
		return err
	}
	if err = s.retainedFile(segmentName(c.Generation), nil, false); err != nil {
		return err
	}
	if err = s.retentionStage("successor-synced"); err != nil {
		return err
	}
	if err = s.file.Close(); err != nil {
		return err
	}
	s.file = nil
	if err = s.publishCurrent(c); err != nil {
		return err
	}
	if err = s.retentionStage("current-published"); err != nil {
		return err
	}
	s.rememberCheckpoint(c)
	s.size = 0
	if err = s.retentionStage("state-installed"); err != nil {
		return err
	}
	s.file, err = os.OpenFile(filepath.Join(r.dir, segmentName(r.generation)), os.O_RDWR|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	r.bytes, err = r.usage()
	return err
}
func (s *Store) prepareRetainedAppend(bytes int64, rec record) error {
	r := s.retained
	pending := len(s.attempts) - len(s.observations)
	if rec.Attempt != nil {
		pending++
	}
	if rec.Observation != nil {
		pending--
	}
	reserve := int64(pending) * completionReserve
	// Admission leaves room for every accepted response's separate write record.
	if s.size+bytes+reserve > r.config.SegmentBytes {
		if bytes+reserve > r.config.SegmentBytes {
			return ErrLimit
		}
		if err := s.rotateRetained(); err != nil {
			return err
		}
	}
	if r.bytes+bytes+reserve > r.config.MaxBytes {
		return ErrLimit
	}
	return nil
}
func (s *Store) archivedCompletion(id string) (retainedCompletion, bool, error) {
	if !decisions.ValidHash(id) {
		return retainedCompletion{}, false, nil
	}
	r := s.retained
	for i := len(r.checkpoints) - 1; i >= 0; i-- {
		info := r.checkpoints[i]
		if !hasFingerprint(info.completionKeys, retainedFingerprint(id)) {
			continue
		}
		c, err := s.readCheckpoint(info.generation)
		if err != nil {
			return retainedCompletion{}, false, err
		}
		if c.SHA != info.sha {
			return retainedCompletion{}, false, ErrUnavailable
		}
		if old, ok := c.Completions[id]; ok {
			return old, true, nil
		}
	}
	return retainedCompletion{}, false, nil
}

func (s *Store) archivedRequest(id string) (string, bool, error) {
	r := s.retained
	hash := retainedFingerprint(id)
	for i := len(r.checkpoints) - 1; i >= 0; i-- {
		info := r.checkpoints[i]
		if !hasFingerprint(info.requestKeys, hash) {
			continue
		}
		c, err := s.readCheckpoint(info.generation)
		if err != nil {
			return "", false, err
		}
		if c.SHA != info.sha {
			return "", false, ErrUnavailable
		}
		if evidence, ok := c.ArchivedRequests[id]; ok {
			return evidence, true, nil
		}
	}
	return "", false, nil
}

func validateRetainedLayout(r *retainedJournal, current int) error {
	entries, err := os.ReadDir(r.dir)
	if err != nil {
		return err
	}
	nextCheckpoint := false
	nextSegment := false
	for _, entry := range entries {
		name := entry.Name()
		generation := 0
		if strings.HasPrefix(name, "checkpoint-") {
			if _, err := fmt.Sscanf(name, "checkpoint-%d.json", &generation); err != nil || name != checkpointName(generation) || generation < 1 || generation > current+1 {
				return ErrUnavailable
			}
			if generation == current+1 {
				nextCheckpoint = true
			}
		} else if strings.HasPrefix(name, "segment-") {
			if _, err := fmt.Sscanf(name, "segment-%d.jsonl", &generation); err != nil || name != segmentName(generation) || generation < 0 || generation > current+1 {
				return ErrUnavailable
			}
			if generation == current+1 {
				nextSegment = true
			}
		}
	}
	if nextSegment && !nextCheckpoint {
		return errors.New("successor journal without its durable checkpoint; preserve recovery evidence")
	}
	return nil
}
