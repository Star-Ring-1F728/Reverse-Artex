package evidence

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// FrozenSource holds the actual current on-disk bytes, not a process mirror.
// All opens/reads finish while the caller owns the ingestion commit mutex.
// Later rotations, appends or file tampering cannot mutate this captured set.
type FrozenSource struct {
	files  frozenTree
	origin string
}

func CaptureFilesLocked(dir string) (*FrozenSource, error) {
	st, err := os.Lstat(dir)
	if err != nil || !st.IsDir() {
		return nil, errors.New("regular source directory required")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	if len(entries) > 4096 {
		return nil, errors.New("snapshot directory entry limit")
	}
	tree := frozenTree{}
	physical := int64(0)
	aliases := map[string]bool{}
	for _, entry := range entries {
		name := entry.Name()
		relevant := name == "recovery.meta.json"
		for _, stream := range snapshotStreams {
			if !strings.HasPrefix(name, stream+".") {
				continue
			}
			relevant = true
			if name != stream+".jsonl" {
				parts := strings.SplitN(strings.TrimPrefix(name, stream+"."), ".", 2)
				if len(parts) != 2 {
					return nil, errors.New("invalid snapshot segment")
				}
				n, e := strconv.Atoi(parts[0])
				if e != nil || n < 1 {
					return nil, errors.New("invalid snapshot segment sequence")
				}
				key := fmt.Sprintf("%s:%d:%s", stream, n, parts[1])
				if aliases[key] {
					return nil, errors.New("aliased snapshot segment")
				}
				aliases[key] = true
			}
		}
		if !relevant {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() || info.Size() < 0 {
			return nil, errors.New("regular source file required")
		}
		physical += info.Size()
		if physical > 2*MaxSnapshotBytes {
			return nil, errors.New("snapshot source byte limit")
		}
		if name == "recovery.meta.json" && (info.Size() == 0 || info.Size() > 4096) {
			return nil, errors.New("bounded recovery metadata required")
		}
		f, err := os.Open(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		raw := make([]byte, int(info.Size()))
		_, readErr := io.ReadFull(f, raw)
		var extra [1]byte
		n, end := f.Read(extra[:])
		closeErr := f.Close()
		if readErr != nil || closeErr != nil {
			return nil, errors.Join(readErr, closeErr)
		}
		if n != 0 || end != io.EOF {
			return nil, errors.New("source changed outside commit ownership")
		}
		tree[name] = raw
	}
	if _, ok := tree["recovery.meta.json"]; !ok {
		return nil, errors.New("recovery metadata required")
	}
	return &FrozenSource{tree, dir}, nil
}

// Snapshot expands compressed segments and hashes/parses lines outside the
// collector commit lock, enforcing the original logical 32MiB/record bounds.
func (s *FrozenSource) Snapshot() (*Snapshot, error) {
	if s == nil {
		return nil, errors.New("frozen source required")
	}
	return snapshotFromReader(bytes.Clone(s.files["recovery.meta.json"]), &Store{dir: s.origin, readLimit: MaxSnapshotBytes, snapshotFS: s.files})
}

type frozenTree map[string][]byte
type frozenInfo struct {
	name string
	size int64
	mode fs.FileMode
}

func (i frozenInfo) Name() string       { return i.name }
func (i frozenInfo) Size() int64        { return i.size }
func (i frozenInfo) Mode() fs.FileMode  { return i.mode }
func (i frozenInfo) ModTime() time.Time { return time.Time{} }
func (i frozenInfo) IsDir() bool        { return i.mode.IsDir() }
func (i frozenInfo) Sys() any           { return nil }

type frozenEntry struct{ frozenInfo }

func (e frozenEntry) Type() fs.FileMode          { return e.mode.Type() }
func (e frozenEntry) Info() (fs.FileInfo, error) { return e.frozenInfo, nil }

type frozenFile struct {
	*bytes.Reader
	info frozenInfo
}

func (f *frozenFile) Close() error               { return nil }
func (f *frozenFile) Stat() (fs.FileInfo, error) { return f.info, nil }
func (t frozenTree) Open(name string) (fs.File, error) {
	b, ok := t[name]
	if !ok {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}
	return &frozenFile{bytes.NewReader(b), frozenInfo{name, int64(len(b)), 0600}}, nil
}
func (t frozenTree) Stat(name string) (fs.FileInfo, error) {
	if name == "." {
		return frozenInfo{".", 0, fs.ModeDir | 0700}, nil
	}
	b, ok := t[name]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return frozenInfo{name, int64(len(b)), 0600}, nil
}
func (t frozenTree) ReadDir(name string) ([]fs.DirEntry, error) {
	if name != "." {
		return nil, fs.ErrNotExist
	}
	entries := []fs.DirEntry{}
	for n, b := range t {
		entries = append(entries, frozenEntry{frozenInfo{n, int64(len(b)), 0600}})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	return entries, nil
}
