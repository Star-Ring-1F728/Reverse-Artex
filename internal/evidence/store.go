package evidence

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reverse-artex/internal/storagebudget"
	"sync"
	"sync/atomic"
	"time"
)

// Store has a per-file disk budget. Exhaustion is an explicit ingestion failure.
type Store struct {
	appendTimings         atomic.Pointer[appendTimingMetrics]
	snapshotFS            fs.FS // immutable raw-file capture; ordinary store reads remain native
	budget                *Budget
	shared                *storagebudget.Budget
	lease                 *storagebudget.Lease
	deferredSync          *[]groupSync
	groupSyncOutsideLease uint64
	groupTiming           map[string]groupDuration
	mu                    sync.Mutex
	dir                   string
	limit                 int64
	segment               int64
	streams               map[string]*streamState
	write                 func(*os.File, []byte) (int, error)
	sync                  func(*os.File) error
	files                 map[string]*os.File
	sizes                 map[string]int64
	closed                bool
	ownedStream           string
	recordLimit           int
	records               map[string]int
	readLimit             int64 // offline snapshot pending/archive comparison only
}

// NewPersistentRotating requires one live writer per stream. It reuses stream
// handles, but still Syncs every complete record before reporting success.
func NewPersistentRotating(dir string, limit, segment int64) (*Store, error) {
	s, err := NewRotating(dir, limit, segment)
	if err == nil {
		s.files = map[string]*os.File{}
		s.sizes = map[string]int64{}
	}
	return s, err
}

// NewPersistentStream owns exactly one stream. Different streams may have
// independent writers without serializing their durable Sync operations.
func NewPersistentStream(dir string, limit, segment int64, name string) (*Store, error) {
	if !validStream(name) {
		return nil, errors.New("invalid evidence stream")
	}
	s, err := NewPersistentRotating(dir, limit, segment)
	if err == nil {
		s.ownedStream = name
	}
	return s, err
}

func validStream(name string) bool {
	switch name {
	case "events", "alerts", "actions", "evaluations", "host-events", "host-alerts", "host-evaluations", "policy-delivery-acks":
		return true
	}
	return false
}

func (s *Store) closePath(path string) error {
	if f := s.files[path]; f != nil {
		delete(s.files, path)
		delete(s.sizes, path)
		return f.Close()
	}
	return nil
}

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	var err error
	for path := range s.files {
		err = errors.Join(err, s.closePath(path))
	}
	return err
}

func New(dir string, limit int64) (*Store, error) {
	shared, err := storagebudget.FromEnv(dir)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	return &Store{dir: dir, limit: limit, shared: shared}, nil
}
func (s *Store) Append(name string, v any) error {
	return s.AppendBatch(name, []any{v})
}

// AppendBatch commits a bounded sequence of complete JSONL records with one
// Sync. No record in the batch is reported successful before that Sync, and a
// write/Sync failure rolls the entire batch back to its preceding boundary.
func (s *Store) AppendBatch(name string, values []any) error {
	if len(values) == 0 || len(values) > 64 {
		return errors.New("invalid evidence batch size")
	}
	defer s.appendTimingEnd(appendTimingTotal, s.appendTimingStart())
	started := time.Now()
	lockStarted := s.appendTimingStart()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.appendTimingEnd(appendTimingLockWait, lockStarted)
	s.timeGroup("append_store_wait", started)
	if s.closed {
		return errors.New("evidence store closed")
	}
	if !validStream(name) || s.ownedStream != "" && name != s.ownedStream {
		return errors.New("invalid evidence stream")
	}
	admissionStarted := s.appendTimingStart()
	admissionErr := s.admitRecords(name, len(values))
	s.appendTimingEnd(appendTimingRecordAdmission, admissionStarted)
	if admissionErr != nil {
		return admissionErr
	}
	serializeStarted := s.appendTimingStart()
	var b []byte
	for _, v := range values {
		line, err := json.Marshal(v)
		if err != nil {
			s.appendTimingEnd(appendTimingSerialize, serializeStarted)
			return err
		}
		b = append(b, line...)
		b = append(b, '\n')
	}
	s.appendTimingEnd(appendTimingSerialize, serializeStarted)
	budgetStarted := s.appendTimingStart()
	var budgetExitStarted time.Time
	budgetEntered := false
	appendData := func() error {
		return s.shared.With(func(lease *storagebudget.Lease) error {
			budgetEntered = true
			s.appendTimingEnd(appendTimingBudgetEnter, budgetStarted)
			s.lease = lease
			defer func() {
				s.lease = nil
				budgetExitStarted = s.appendTimingStart()
			}()
			if s.segment > 0 {
				return s.appendRotating(name, b)
			}
			return s.appendLine(filepath.Join(s.dir, name+".jsonl"), b, s.limit)
		})
	}
	var err error
	if s.budget != nil {
		err = s.budget.locked(func() error {
			if err := s.budget.check(0); err != nil {
				return err
			}
			return appendData()
		})
	} else {
		err = appendData()
	}
	if budgetEntered {
		s.appendTimingEnd(appendTimingBudgetExit, budgetExitStarted)
	} else {
		s.appendTimingEnd(appendTimingBudgetEnter, budgetStarted)
	}
	if err == nil && s.records != nil {
		s.records[name] += len(values)
	}
	return err
}

// appendLine syncs before return except the bounded persistent AppendGroup path,
// whose caller holds Store.mu and finishes all queued Syncs before returning.
// A failed or short write is rolled back to the previous complete JSONL line.
// The caller must treat any error, including a failed rollback, as uncertain.
func (s *Store) appendLine(path string, b []byte, maxSize int64) error {
	if s.budget != nil {
		budgetStarted := s.appendTimingStart()
		err := s.budget.check(int64(len(b)))
		s.appendTimingEnd(appendTimingBudgetCheck, budgetStarted)
		if err != nil {
			return err
		}
	}
	fileStarted := s.appendTimingStart()
	f := s.files[path]
	if f == nil {
		var err error
		f, err = os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			s.appendTimingEnd(appendTimingFilePrepare, fileStarted)
			return err
		}
		if s.files != nil {
			s.files[path] = f
		}
	}
	closeFile := func() error {
		if s.files != nil {
			delete(s.files, path)
			delete(s.sizes, path)
		}
		return f.Close()
	}
	size, known := s.sizes[path]
	if !known {
		st, err := f.Stat()
		if err != nil {
			closeFile()
			s.appendTimingEnd(appendTimingFilePrepare, fileStarted)
			return err
		}
		size = st.Size()
	}
	if size+int64(len(b)) > maxSize {
		closeFile()
		s.appendTimingEnd(appendTimingFilePrepare, fileStarted)
		return errors.New("evidence disk budget exceeded")
	}
	s.appendTimingEnd(appendTimingFilePrepare, fileStarted)
	write := s.write
	if write == nil {
		write = (*os.File).Write
	}
	syncFile := s.sync
	if syncFile == nil {
		syncFile = (*os.File).Sync
	}
	allowStarted := s.appendTimingStart()
	allowErr := s.lease.Allow(int64(len(b)))
	s.appendTimingEnd(appendTimingLeaseAllow, allowStarted)
	if allowErr != nil {
		closeFile()
		return allowErr
	}
	writeStarted := time.Now()
	writeTimingStarted := s.appendTimingStart()
	n, err := write(f, b)
	s.appendTimingEnd(appendTimingWrite, writeTimingStarted)
	s.timeGroup(filepath.Base(path)+".write", writeStarted)
	s.lease.Written(int64(n))
	if err == nil && n != len(b) {
		err = errors.New("short evidence write")
	}
	if err == nil {
		if s.deferredSync != nil {
			*s.deferredSync = append(*s.deferredSync, groupSync{path: path, file: f, before: size})
		} else {
			syncStarted := time.Now()
			syncTimingStarted := s.appendTimingStart()
			err = syncFile(f)
			s.appendTimingEnd(appendTimingSync, syncTimingStarted)
			s.timeGroup(filepath.Base(path)+".sync", syncStarted)
		}
	}
	if err != nil {
		rollbackStarted := s.appendTimingStart()
		closeErr := closeFile()
		rollbackErr := os.Truncate(path, size)
		if rollbackErr == nil {
			rollback, openErr := os.OpenFile(path, os.O_RDWR, 0600)
			if openErr != nil {
				rollbackErr = openErr
			} else {
				rollbackErr = errors.Join(rollback.Sync(), rollback.Close())
			}
		}
		s.appendTimingEnd(appendTimingRollback, rollbackStarted)
		return errors.Join(err, closeErr, rollbackErr)
	}
	if s.files != nil {
		s.sizes[path] = size + int64(len(b))
		return nil
	}
	return closeFile()
}

// CreateMetadata creates a bounded recovery file under the selected quota.
func (s *Store) CreateMetadata(name string, data []byte) error {
	if name != "recovery.meta.json" || len(data) > 4096 {
		return errors.New("invalid recovery metadata")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("evidence store closed")
	}
	write := func() error {
		if s.budget != nil {
			if err := s.budget.check(int64(len(data))); err != nil {
				return err
			}
		}
		return s.shared.With(func(l *storagebudget.Lease) error {
			if err := l.Allow(int64(len(data))); err != nil {
				return err
			}
			f, err := os.OpenFile(filepath.Join(s.dir, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if err != nil {
				return err
			}
			n, err := f.Write(data)
			if err == nil && n != len(data) {
				err = errors.New("short recovery metadata write")
			}
			if err == nil {
				err = f.Sync()
			}
			return errors.Join(err, f.Close())
		})
	}
	if s.budget != nil {
		return s.budget.locked(write)
	}
	return write()
}
