package evidence

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// VisitRecords reads a stream in archive, pending, active order without
// modifying evidence. A torn line, missing segment, or conflicting pending
// copy is an error; callers must not rebuild detector state from a prefix.
func (s *Store) VisitRecords(name string, visit func([]byte) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.visitRecords(name, visit)
}

func (s *Store) visitRecords(name string, visit func([]byte) error) error {
	if name != "events" && name != "alerts" && name != "evaluations" && name != "host-events" && name != "host-alerts" && name != "host-evaluations" && name != "policy-delivery-acks" {
		return errors.New("invalid replay stream")
	}
	entries, err := s.replayEntries()
	if err != nil {
		return err
	}
	type segment struct{ archive, pending, tmp string }
	segments := map[int]*segment{}
	for _, entry := range entries {
		file := entry.Name()
		if !strings.HasPrefix(file, name+".") || file == name+".jsonl" {
			continue
		}
		tail := strings.TrimPrefix(file, name+".")
		parts := strings.SplitN(tail, ".", 2)
		if len(parts) != 2 {
			return fmt.Errorf("unexpected evidence file %s", file)
		}
		seq, err := strconv.Atoi(parts[0])
		if err != nil || seq < 1 {
			return fmt.Errorf("invalid evidence sequence %s", file)
		}
		seg := segments[seq]
		if seg == nil {
			seg = &segment{}
			segments[seq] = seg
		}
		switch parts[1] {
		case "jsonl.gz":
			seg.archive = file
		case "pending":
			seg.pending = file
		case "jsonl.gz.tmp":
			seg.tmp = file
		default:
			return fmt.Errorf("unexpected evidence suffix %s", file)
		}
	}
	seqs := make([]int, 0, len(segments))
	for seq := range segments {
		seqs = append(seqs, seq)
	}
	sort.Ints(seqs)
	for index, seq := range seqs {
		if seq != index+1 {
			return fmt.Errorf("missing evidence segment before %d", seq)
		}
		seg := segments[seq]
		if seg.archive == "" && seg.pending == "" {
			return fmt.Errorf("temporary segment without source: %d", seq)
		}
		if seg.archive != "" && seg.pending != "" && !s.sameReplayContents(seg.pending, seg.archive) {
			return fmt.Errorf("conflicting pending segment: %d", seq)
		}
		file := seg.archive
		if file == "" {
			file = seg.pending
		}
		if err := s.visitReplayFile(file, seg.archive != "", visit); err != nil {
			return err
		}
	}
	active := name + ".jsonl"
	if _, err := s.replayStat(active); err == nil {
		return s.visitReplayFile(active, false, visit)
	} else if !os.IsNotExist(err) {
		return err
	}
	return nil
}

func visitFile(path string, compressed bool, visit func([]byte) error) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return visitSource(f, path, compressed, visit)
}
func visitSource(f io.Reader, path string, compressed bool, visit func([]byte) error) error {
	var source io.Reader = f
	if compressed {
		g, err := gzip.NewReader(f)
		if err != nil {
			return err
		}
		defer g.Close()
		source = g
	}
	r := bufio.NewReaderSize(source, 1<<20)
	for {
		line, err := r.ReadSlice('\n')
		if err == io.EOF {
			if len(line) != 0 {
				return fmt.Errorf("torn evidence line in %s", path)
			}
			return nil
		}
		if err != nil {
			return err
		}
		if len(line) <= 1 {
			return fmt.Errorf("empty evidence line in %s", path)
		}
		if err := visit(line[:len(line)-1]); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
	}
}

func (s *Store) replayEntries() ([]fs.DirEntry, error) {
	if s.snapshotFS != nil {
		return fs.ReadDir(s.snapshotFS, ".")
	}
	return os.ReadDir(s.dir)
}
func (s *Store) replayStat(name string) (fs.FileInfo, error) {
	if s.snapshotFS != nil {
		return fs.Stat(s.snapshotFS, name)
	}
	return os.Stat(filepath.Join(s.dir, name))
}
func (s *Store) visitReplayFile(name string, compressed bool, visit func([]byte) error) error {
	if s.snapshotFS == nil {
		return visitFile(filepath.Join(s.dir, name), compressed, visit)
	}
	f, err := s.snapshotFS.Open(name)
	if err != nil {
		return err
	}
	defer f.Close()
	return visitSource(f, filepath.Join(s.dir, name), compressed, visit)
}
func (s *Store) sameReplayContents(pending, archive string) bool {
	if s.snapshotFS == nil {
		return sameContentsLimit(filepath.Join(s.dir, pending), filepath.Join(s.dir, archive), s.readLimit)
	}
	p, e := s.snapshotFS.Open(pending)
	if e != nil {
		return false
	}
	defer p.Close()
	a, e := s.snapshotFS.Open(archive)
	if e != nil {
		return false
	}
	defer a.Close()
	g, e := gzip.NewReader(a)
	if e != nil {
		return false
	}
	defer g.Close()
	hp, ha := sha256.New(), sha256.New()
	np, ep := io.Copy(hp, io.LimitReader(p, s.readLimit+1))
	na, ea := io.Copy(ha, io.LimitReader(g, s.readLimit+1))
	return ep == nil && ea == nil && np <= s.readLimit && na <= s.readLimit && bytes.Equal(hp.Sum(nil), ha.Sum(nil))
}
