package evidence

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const storageSchema = "reverse-artex-storage/1"

// Budget serializes cooperating local writers, including Python's SQLite app.
// It measures regular file lengths, not filesystem allocation or device space.
type Budget struct {
	root  string
	limit int64
	mu    sync.Mutex
}

type storageContract struct {
	Schema string `json:"schema"`
	Limit  int64  `json:"limit_bytes"`
}

func readSmall(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 4097))
	if err == nil && len(raw) > 4096 {
		err = errors.New("storage metadata too large")
	}
	return raw, err
}

func parseStorage(raw []byte) (storageContract, error) {
	var contract storageContract
	d := json.NewDecoder(bytes.NewReader(raw))
	first, err := d.Token()
	if err != nil || first != json.Delim('{') {
		return contract, errors.New("invalid storage configuration")
	}
	seen := map[string]bool{}
	for d.More() {
		token, err := d.Token()
		if err != nil {
			return contract, err
		}
		key, ok := token.(string)
		if !ok || seen[key] {
			return contract, errors.New("duplicate storage configuration field")
		}
		seen[key] = true
		switch key {
		case "schema":
			err = d.Decode(&contract.Schema)
		case "limit_bytes":
			err = d.Decode(&contract.Limit)
		default:
			return contract, errors.New("unknown storage configuration field")
		}
		if err != nil {
			return contract, err
		}
	}
	if _, err = d.Token(); err != nil || len(seen) != 2 {
		return contract, errors.New("incomplete storage configuration")
	}
	if _, err = d.Token(); err != io.EOF {
		return contract, errors.New("trailing storage configuration")
	}
	return contract, nil
}

func unlinked(path string) error {
	for p := path; ; p = filepath.Dir(p) {
		st, err := os.Lstat(p)
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		if err == nil && st.Mode()&os.ModeSymlink != 0 {
			return errors.New("linked storage path refused")
		}
		if filepath.Dir(p) == p {
			return nil
		}
	}
}

func NewBudget(root string, limit int64) (*Budget, error) {
	if os.Getenv("RA_STORAGE_ROOT") != "" || os.Getenv("RA_STORAGE_LIMIT") != "" {
		return nil, errors.New("choose one shared storage profile")
	}
	if limit < 65536 || limit > 16<<30 {
		return nil, errors.New("bounded shared storage limit required")
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if err = unlinked(root); err != nil {
		return nil, err
	}
	b := &Budget{root: root, limit: limit}
	if err = b.checkScope(); err != nil {
		return nil, err
	}
	if err = os.MkdirAll(root, 0700); err != nil {
		return nil, err
	}
	err = b.locked(func() error {
		path := filepath.Join(root, ".storage-budget.json")
		if err := b.check(0); err != nil {
			return err
		}
		raw, err := readSmall(path)
		if err == nil {
			contract, err := parseStorage(raw)
			if err != nil {
				return err
			}
			if contract.Schema != storageSchema || contract.Limit != limit {
				return errors.New("shared storage configuration mismatch")
			}
			return nil
		}
		if !os.IsNotExist(err) {
			return err
		}
		if err = b.check(4096); err != nil {
			return err
		}
		raw, _ = json.Marshal(storageContract{Schema: storageSchema, Limit: limit})
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		_, err = f.Write(append(raw, '\n'))
		if err == nil {
			err = f.Sync()
		}
		return errors.Join(err, f.Close())
	})
	return b, err
}

// Overlapping roots have different locks and cannot share an admission budget.
// Recheck ancestors for existing writers as well as during initialization.
func (b *Budget) checkScope() error {
	for parent := b.root; ; parent = filepath.Dir(parent) {
		if _, err := os.Lstat(filepath.Join(parent, ".runtime-budget", "config.json")); err == nil || !os.IsNotExist(err) {
			return errors.New("runtime storage profile already bound")
		}
		if parent != b.root {
			if _, err := os.Lstat(filepath.Join(parent, ".storage-budget.json")); err == nil || !os.IsNotExist(err) {
				return errors.New("nested shared storage root refused")
			}
		}
		if filepath.Dir(parent) == parent {
			break
		}
	}
	return nil
}

func (b *Budget) Contains(path string) error {
	path, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	if err = unlinked(path); err != nil {
		return err
	}
	rel, err := filepath.Rel(b.root, path)
	if err != nil || rel == "." || rel == ".." || len(rel) >= 3 && rel[:3] == ".."+string(filepath.Separator) {
		return errors.New("managed path must be inside shared storage root")
	}
	return nil
}

// ServiceLease is independent of data directories so offline restore can move
// those directories while excluding both writers and concurrent startup.
func (b *Budget) ServiceLease(name string) (*os.File, error) {
	if name != "app" && name != "collector" {
		return nil, errors.New("invalid service lease")
	}
	path := filepath.Join(b.root, ".lifecycle", name+".lock")
	if err := unlinked(path); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err == nil && st.Size() > 1 {
		err = errors.New("invalid service lease")
	}
	if err == nil {
		err = lockStorage(f)
	}
	if err != nil {
		f.Close()
		return nil, errors.New("service is running")
	}
	return f, nil
}

func (b *Budget) used() (int64, error) {
	var used int64
	count := 0
	err := filepath.WalkDir(b.root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		count++
		if count > 32769 {
			return errors.New("shared storage entry limit exceeded")
		}
		if strings.EqualFold(entry.Name(), ".storage-budget.json") && filepath.Dir(path) != b.root {
			return errors.New("nested shared storage root refused")
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("linked storage entry refused")
		}
		if entry.IsDir() {
			if strings.EqualFold(entry.Name(), ".runtime-budget") {
				return errors.New("runtime storage profile overlaps flag-based pool")
			}
			return nil
		}
		st, err := entry.Info()
		if err != nil {
			return err
		}
		if !st.Mode().IsRegular() {
			return errors.New("nonregular storage entry refused")
		}
		if err := regularStorageFile(path, st); err != nil {
			return err
		}
		used += st.Size()
		return nil
	})
	return used, err
}

func (b *Budget) remaining() (int64, error) {
	used, err := b.used()
	if err != nil {
		return 0, err
	}
	return b.limit - used, nil
}

// check/remaining are called only while the cross-process lock is held.
func (b *Budget) check(growth int64) error {
	remaining, err := b.remaining()
	if err != nil {
		return err
	}
	if growth < 0 || growth > remaining {
		return errors.New("shared storage budget exhausted")
	}
	return nil
}

func (b *Budget) locked(fn func() error) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	path := filepath.Join(b.root, ".storage-budget.lock")
	if err := unlinked(path); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if st.Size() > 1 {
		return errors.New("invalid storage lock")
	}
	deadline := time.Now().Add(time.Second)
	for {
		if err = lockStorage(f); err == nil {
			break
		}
		if time.Now().After(deadline) {
			return errors.New("shared storage lock busy")
		}
		time.Sleep(10 * time.Millisecond)
	}
	defer unlockStorage(f)
	if err := b.checkScope(); err != nil {
		return err
	}
	return fn()
}

func (b *Budget) Stats() map[string]any {
	var used int64
	err := b.locked(func() error { var err error; used, err = b.used(); return err })
	return map[string]any{"schema": storageSchema, "used_bytes": used, "limit_bytes": b.limit,
		"scan_error": err != nil, "over_budget": err == nil && used > b.limit,
		"scope": "all regular file lengths under dedicated local root; cooperative writers"}
}

// UseBudget must precede recovery/listen. Binding also prevents a later startup
// from silently dropping the shared quota flags.
func (s *Store) UseBudget(b *Budget) error {
	if s.shared != nil {
		return errors.New("choose one shared storage profile")
	}
	if err := b.Contains(s.dir); err != nil {
		return err
	}
	err := b.locked(func() error {
		if err := b.check(0); err != nil {
			return err
		}
		path := filepath.Join(s.dir, ".storage-binding.json")
		binding, _ := json.Marshal(struct {
			Root  string `json:"root"`
			Limit int64  `json:"limit_bytes"`
		}{b.root, b.limit})
		raw, err := readSmall(path)
		if err == nil {
			if string(raw) != string(binding) {
				return errors.New("collector storage binding mismatch")
			}
			return nil
		}
		if !os.IsNotExist(err) {
			return err
		}
		if err := b.check(int64(len(binding))); err != nil {
			return err
		}
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		n, err := f.Write(binding)
		if err == nil && n != len(binding) {
			err = io.ErrShortWrite
		}
		if err == nil {
			err = f.Sync()
		}
		return errors.Join(err, f.Close())
	})
	if err == nil {
		s.budget = b
	}
	return err
}
