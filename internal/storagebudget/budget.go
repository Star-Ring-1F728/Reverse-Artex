// Package storagebudget serializes cooperating writers across processes.
// It caps file lengths in one explicit root, not allocated blocks or OS quotas.
package storagebudget

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

const Schema = "ra-runtime-storage/1"
const Meta = ".runtime-budget"
const MaxFiles = 8192

var ErrFull = errors.New("shared storage budget exhausted")
var ErrScope = errors.New("invalid shared storage scope")
var local sync.Mutex

type Budget struct {
	Root  string
	Limit int64
}
type Lease struct {
	budget         *Budget
	prepaid        *int64
	inventoryAfter bool
}
type Status struct {
	Schema    string `json:"schema"`
	Used      int64  `json:"used_bytes"`
	Limit     int64  `json:"limit_bytes"`
	Remaining int64  `json:"remaining_bytes"`
}

func clean(path string) (string, error) {
	for _, part := range strings.FieldsFunc(path, func(r rune) bool { return r == '/' || r == 92 }) {
		if part == ".." {
			return "", ErrScope
		}
	}
	p, e := filepath.Abs(path)
	if e != nil {
		return "", e
	}
	for q := p; ; q = filepath.Dir(q) {
		info, err := os.Lstat(q)
		if err == nil && info.Mode()&os.ModeSymlink != 0 {
			return "", ErrScope
		}
		if err != nil && !os.IsNotExist(err) {
			return "", err
		}
		if filepath.Dir(q) == q {
			break
		}
	}
	return filepath.Clean(p), nil
}
func (b *Budget) Contains(path string) error {
	p, e := clean(path)
	if e != nil {
		return e
	}
	rel, e := filepath.Rel(b.Root, p)
	if e != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return ErrScope
	}
	if strings.ToLower(rel) == Meta || strings.HasPrefix(strings.ToLower(rel), Meta+string(filepath.Separator)) {
		return ErrScope
	}
	return nil
}
func policy(path string) bool {
	p, _ := filepath.Abs(path)
	for q := p; ; q = filepath.Dir(q) {
		if _, e := os.Stat(filepath.Join(q, Meta, "config.json")); e == nil {
			return true
		}
		if filepath.Dir(q) == q {
			return false
		}
	}
}
func FromEnv(path string) (*Budget, error) {
	root := os.Getenv("RA_STORAGE_ROOT")
	raw := os.Getenv("RA_STORAGE_LIMIT")
	if root == "" {
		if raw != "" || policy(path) {
			return nil, ErrScope
		}
		return nil, nil
	}
	limit, e := strconv.ParseInt(raw, 10, 64)
	if e != nil || limit < 1<<20 || limit > 1<<30 {
		return nil, ErrScope
	}
	root, e = clean(root)
	if e != nil {
		return nil, e
	}
	for q := root; ; q = filepath.Dir(q) {
		if _, err := os.Lstat(filepath.Join(q, ".storage-budget.json")); err == nil || !os.IsNotExist(err) {
			return nil, ErrScope
		}
		if filepath.Dir(q) == q {
			break
		}
	}
	// Nested policies would use different locks for overlapping inventories.
	for q := filepath.Dir(root); q != root; q = filepath.Dir(q) {
		if _, err := os.Stat(filepath.Join(q, Meta, "config.json")); err == nil {
			return nil, ErrScope
		} else if !os.IsNotExist(err) {
			return nil, err
		}
		if filepath.Dir(q) == q {
			break
		}
	}
	b := &Budget{Root: root, Limit: limit}
	if e = b.Contains(path); e != nil {
		return nil, e
	}
	if e = b.initialize(); e != nil {
		return nil, e
	}
	return b, nil
}
func (b *Budget) config() []byte {
	data, _ := json.Marshal(map[string]any{"schema": Schema, "limit": b.Limit})
	return append(data, 10)
}
func (b *Budget) locked(fn func() error) error {
	local.Lock()
	defer local.Unlock()
	lockPath, e := clean(filepath.Join(b.Root, Meta, "quota.lock"))
	if e != nil {
		return e
	}
	f, e := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return e
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil {
		return e
	}
	if st.Size() > 1 {
		return ErrScope
	}
	if st.Size() == 0 {
		if _, e = f.WriteAt([]byte{0}, 0); e != nil {
			return e
		}
	}
	if e = lock(f); e != nil {
		return e
	}
	defer unlock(f)
	return fn()
}
func (b *Budget) initialize() error {
	if _, e := os.Stat(filepath.Join(b.Root, Meta, "config.json")); os.IsNotExist(e) {
		if _, e := os.Stat(b.Root); e == nil {
			used, e := b.scan()
			if e != nil {
				return e
			}
			if used+4096 > b.Limit {
				return ErrFull
			}
		}
	} else if e == nil {
		if _, e = os.Stat(filepath.Join(b.Root, Meta, "quota.lock")); e != nil {
			return ErrScope
		}
	}
	if _, e := clean(filepath.Join(b.Root, Meta)); e != nil {
		return e
	}
	if e := os.MkdirAll(filepath.Join(b.Root, Meta), 0700); e != nil {
		return e
	}
	return b.locked(func() error {
		path := filepath.Join(b.Root, Meta, "config.json")
		raw, e := b.readPolicy()
		if os.IsNotExist(e) {
			used, e := b.scan()
			if e != nil {
				return e
			}
			data := b.config()
			if used+int64(len(data)) > b.Limit {
				return ErrFull
			}
			f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if e != nil {
				return e
			}
			n, e := f.Write(data)
			if e == nil && n != len(data) {
				e = errors.New("short shared policy write")
			}
			if e == nil {
				e = f.Sync()
			}
			return errors.Join(e, f.Close())
		}
		if e != nil {
			return e
		}
		if !bytes.Equal(raw, b.config()) {
			return ErrScope
		}
		used, e := b.scan()
		if e != nil {
			return e
		}
		if used > b.Limit {
			return ErrFull
		}
		return nil
	})
}
func (b *Budget) scan() (int64, error) {
	var used int64
	files, dirs := 0, 0
	e := filepath.WalkDir(b.Root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return ErrScope
		}
		if entry.IsDir() {
			if strings.EqualFold(entry.Name(), Meta) {
				rel, err := filepath.Rel(b.Root, path)
				if err != nil || !strings.EqualFold(rel, Meta) {
					return ErrScope
				}
			}
			dirs++
			if dirs > MaxFiles {
				return ErrScope
			}
			return nil
		}
		files++
		if strings.EqualFold(entry.Name(), ".storage-budget.json") {
			return ErrScope
		}
		if files > MaxFiles {
			return ErrScope
		}
		info, e := entry.Info()
		if e != nil {
			return e
		}
		if !info.Mode().IsRegular() {
			return ErrScope
		}
		if e = regular(path, info); e != nil {
			return e
		}
		used += info.Size()
		if used > 1<<40 {
			return ErrScope
		}
		return nil
	})
	return used, e
}
func (b *Budget) With(fn func(*Lease) error) error {
	if b == nil {
		return fn(nil)
	}
	return b.locked(func() error {
		raw, e := b.readPolicy()
		if e != nil {
			return e
		}
		if !bytes.Equal(raw, b.config()) {
			return ErrScope
		}
		e = fn(&Lease{budget: b})
		used, scanErr := b.scan()
		if scanErr == nil && used > b.Limit {
			scanErr = ErrFull
		}
		return errors.Join(e, scanErr)
	})
}
func (l *Lease) Allow(growth int64) error {
	if l == nil {
		return nil
	}
	if growth < 0 {
		return ErrScope
	}
	if l.prepaid != nil {
		if growth > *l.prepaid {
			return ErrFull
		}
		return nil
	}
	used, e := l.budget.scan()
	if e != nil {
		return e
	}
	if growth > l.budget.Limit-used {
		return ErrFull
	}
	return nil
}
func (b *Budget) Stats() (out Status, err error) {
	if b == nil {
		return out, nil
	}
	err = b.With(func(l *Lease) error {
		used, e := b.scan()
		out = Status{Schema, used, b.Limit, b.Limit - used}
		return e
	})
	return
}
func (b *Budget) WriteFile(path string, data []byte) error {
	if b == nil {
		return os.WriteFile(path, data, 0600)
	}
	if e := b.Contains(path); e != nil {
		return e
	}
	return b.With(func(l *Lease) error {
		old := int64(0)
		if info, e := os.Stat(path); e == nil {
			old = info.Size()
		} else if !os.IsNotExist(e) {
			return e
		}
		growth := int64(len(data)) - old
		if growth < 0 {
			growth = 0
		}
		if e := l.Allow(growth); e != nil {
			return e
		}
		f, e := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
		if e != nil {
			return e
		}
		n, e := f.Write(data)
		if e == nil && n != len(data) {
			e = errors.New("short shared write")
		}
		if e == nil {
			e = f.Sync()
		}
		return errors.Join(e, f.Close())
	})
}

func (b *Budget) readPolicy() ([]byte, error) {
	path, e := clean(filepath.Join(b.Root, Meta, "config.json"))
	if e != nil {
		return nil, e
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil {
		return nil, e
	}
	if !info.Mode().IsRegular() || info.Size() > 4096 {
		return nil, ErrScope
	}
	if e = regular(path, info); e != nil {
		return nil, e
	}
	data, e := io.ReadAll(io.LimitReader(f, 4097))
	if len(data) > 4096 {
		return nil, ErrScope
	}
	return data, e
}
