package evidence

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reverse-artex/internal/storagebudget"
	"time"
)

type groupDuration struct {
	Calls   uint64    `json:"calls"`
	TotalMS float64   `json:"total_ms"`
	MaxMS   float64   `json:"max_ms"`
	Slow    uint64    `json:"over_250ms"`
	Buckets [9]uint64 `json:"buckets_le_1_5_20_100_500_1000_5000_60000_inf_ms"`
}

// Called under Store.mu; the fixed phase names bound memory usage.
func (s *Store) timeGroup(phase string, started time.Time) {
	if s.groupTiming == nil {
		s.groupTiming = make(map[string]groupDuration)
	}
	duration := float64(time.Since(started)) / float64(time.Millisecond)
	value := s.groupTiming[phase]
	value.Calls++
	value.TotalMS += duration
	value.MaxMS = max(value.MaxMS, duration)
	index := 8
	for j, limit := range [...]float64{1, 5, 20, 100, 500, 1000, 5000, 60000} {
		if duration <= limit {
			index = j
			break
		}
	}
	value.Buckets[index]++
	if duration >= 250 {
		value.Slow++
	}
	s.groupTiming[phase] = value
}

// BudgetEnabled selects cross-stream admission only for the opt-in shared pool.
func (s *Store) BudgetEnabled() bool { return s.shared != nil }

// AppendGroup admits all file growth under the shared lock, then may Sync
// stable persistent streams outside that lock while retaining exclusive Store.mu.
// No successful return precedes every stream Sync.
// A conservative compression bound is reserved before any stream is changed.
// Actual I/O failures remain uncertain and require the existing recovery path.
func (s *Store) AppendGroup(values map[string][]any) error {
	started := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.timeGroup("store_wait", started)
	defer s.timeGroup("total", started)
	if s.closed {
		return errors.New("evidence store closed")
	}
	order := []string{"events", "alerts", "evaluations", "host-events", "host-alerts", "host-evaluations"}
	encoded := map[string][][]byte{}
	for name, rows := range values {
		if !validStream(name) || s.ownedStream != "" && s.ownedStream != name {
			return errors.New("invalid evidence stream")
		}
		found := false
		for _, allowed := range order {
			found = found || name == allowed
		}
		if !found {
			return errors.New("unsupported evidence group stream")
		}
		if err := s.admitRecords(name, len(rows)); err != nil {
			return err
		}
		for len(rows) > 0 {
			n := min(64, len(rows))
			var b []byte
			for _, row := range rows[:n] {
				line, e := json.Marshal(row)
				if e != nil {
					return e
				}
				b = append(b, line...)
				b = append(b, '\n')
			}
			if s.segment > 0 && int64(len(b)) > s.segment {
				return errors.New("evidence record exceeds segment budget")
			}
			encoded[name] = append(encoded[name], b)
			rows = rows[n:]
		}
	}
	namespaceChanges := false
	singleChunk := true
	for _, chunks := range encoded {
		if len(chunks) > 1 {
			singleChunk = false
		}
	}
	var pending []groupSync
	defer func() { s.deferredSync = nil }()
	compoundStarted := time.Now()
	err := s.shared.Compound(func() (int64, error) {
		// Includes OS/local lease acquisition and policy validation; inventory
		// and writes are accounted for by the complete compound duration.
		s.timeGroup("lease_and_policy", compoundStarted)
		var growth int64
		for _, name := range order {
			if len(encoded[name]) == 0 {
				continue
			}
			path := filepath.Join(s.dir, name+".jsonl")
			var active int64
			if info, e := os.Stat(path); e == nil {
				active = info.Size()
			} else if !os.IsNotExist(e) {
				return 0, e
			} else {
				namespaceChanges = true
			}
			var extra, archives int64
			if s.segment > 0 {
				st, e := s.state(name)
				if e != nil {
					return 0, e
				}
				archives = st.archiveBytes
				if st.pending != "" {
					namespaceChanges = true
					info, e := os.Stat(filepath.Join(s.dir, st.pending))
					if e != nil {
						return 0, e
					}
					// RFC1951 stored blocks grow by much less than 2*n+1024, including gzip framing.
					extra += 2*info.Size() + 1024
				}
			}
			initial := active
			for _, b := range encoded[name] {
				size := int64(len(b))
				extra += size
				if s.segment > 0 && active > 0 && active+size > s.segment {
					namespaceChanges = true
					extra += 2*active + 1024
					active = 0
				}
				active += size
			}
			// Also prevent a known per-stream limit from failing halfway through a group.
			if archives+initial+extra > s.limit {
				return 0, errors.New("evidence group disk budget exceeded")
			}
			growth += extra
		}
		return growth, nil
	}, func(lease *storagebudget.Lease) error {
		if namespaceChanges {
			lease.InventoryAfter()
		}
		s.lease = lease
		defer func() { s.lease = nil }()
		if !namespaceChanges && singleChunk && s.shared != nil && s.files != nil {
			s.deferredSync = &pending
		}
		for _, name := range order {
			for _, b := range encoded[name] {
				var e error
				if s.segment > 0 {
					e = s.appendRotating(name, b)
				} else {
					e = s.appendLine(filepath.Join(s.dir, name+".jsonl"), b, s.limit)
				}
				if e != nil {
					return e
				}
			}
		}
		return nil
	})
	s.timeGroup("compound", compoundStarted)
	s.deferredSync = nil
	if err == nil {
		syncStarted := time.Now()
		syncFile := s.sync
		if syncFile == nil {
			syncFile = (*os.File).Sync
		}
		for _, entry := range pending {
			if err = syncFile(entry.file); err != nil {
				break
			}
		}
		if len(pending) > 0 {
			s.timeGroup("deferred_sync", syncStarted)
		}
	}
	if err != nil {
		return errors.Join(err, s.rollbackGroup(pending))
	}
	if len(pending) > 0 {
		s.groupSyncOutsideLease++
	}
	if s.records != nil {
		for name, rows := range values {
			s.records[name] += len(rows)
		}
	}
	return nil
}

type groupSync struct {
	path   string
	file   *os.File
	before int64
}

func (s *Store) rollbackGroup(pending []groupSync) error {
	var result error
	for _, entry := range pending {
		// Windows append-only handles cannot truncate. Drop cached state and
		// reopen the existing single-owner file without CREATE or APPEND.
		closeErr := s.closePath(entry.path)
		file, err := os.OpenFile(entry.path, os.O_RDWR, 0600)
		if err == nil {
			info, statErr := file.Stat()
			err = statErr
			if err == nil {
				if info.Size() < entry.before {
					err = errors.New("evidence rollback would grow file")
				} else {
					err = file.Truncate(entry.before)
				}
			}
			if err == nil {
				err = file.Sync()
			}
			err = errors.Join(err, file.Close())
		}
		result = errors.Join(result, closeErr, err)
	}
	return result
}
