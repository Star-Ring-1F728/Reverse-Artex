package evidence

import (
	"compress/gzip"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reverse-artex/internal/storagebudget"
	"strconv"
	"strings"
)

type streamState struct {
	sequence     int
	archiveBytes int64
	rotations    uint64
	pending      string
}

// NewRotating keeps sealed gzip segments plus an active JSONL under the same
// per-stream budget. No evidence is evicted: exhaustion remains an explicit error.
// Compression needs temporary space within that budget, including the pending file.
func NewRotating(dir string, limit, segment int64) (*Store, error) {
	if limit <= 0 || segment <= 0 || segment > limit/4 {
		return nil, errors.New("invalid evidence rotation budget")
	}
	s, err := New(dir, limit)
	if err != nil {
		return nil, err
	}
	s.segment = segment
	s.streams = map[string]*streamState{}
	return s, nil
}

func (s *Store) state(name string) (*streamState, error) {
	defer s.appendTimingEnd(appendTimingStreamState, s.appendTimingStart())
	if st := s.streams[name]; st != nil {
		return st, nil
	}
	st := &streamState{}
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		n := e.Name()
		if !strings.HasPrefix(n, name+".") {
			continue
		}
		tail := strings.TrimPrefix(n, name+".")
		parts := strings.SplitN(tail, ".", 2)
		if len(parts) != 2 {
			continue
		}
		seq, err := strconv.Atoi(parts[0])
		if err != nil || seq < 1 {
			continue
		}
		if parts[1] != "jsonl.gz" && parts[1] != "pending" {
			continue
		}
		if seq > st.sequence {
			st.sequence = seq
		}
		if parts[1] == "pending" {
			if st.pending != "" {
				return nil, errors.New("multiple pending evidence segments")
			}
			st.pending = n
		} else {
			info, err := e.Info()
			if err != nil {
				return nil, err
			}
			st.archiveBytes += info.Size()
		}
	}
	s.streams[name] = st
	return st, nil
}

type budgetWriter struct {
	shared    *storagebudget.Lease
	w         io.Writer
	remaining int64
}

func (w *budgetWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > w.remaining {
		return 0, errors.New("evidence compression budget exceeded")
	}
	if err := w.shared.Allow(int64(len(p))); err != nil {
		return 0, err
	}
	n, err := w.w.Write(p)
	w.shared.Written(int64(n))
	w.remaining -= int64(n)
	return n, err
}

func sameContents(pending, archive string) bool {
	return sameContentsLimit(pending, archive, 0)
}

func sameContentsLimit(pending, archive string, limit int64) bool {
	p, err := os.Open(pending)
	if err != nil {
		return false
	}
	defer p.Close()
	a, err := os.Open(archive)
	if err != nil {
		return false
	}
	defer a.Close()
	g, err := gzip.NewReader(a)
	if err != nil {
		return false
	}
	defer g.Close()
	hp, ha := sha256.New(), sha256.New()
	var pr, ar io.Reader = p, g
	if limit > 0 {
		pr, ar = io.LimitReader(p, limit+1), io.LimitReader(g, limit+1)
	}
	np, ep := io.Copy(hp, pr)
	na, ea := io.Copy(ha, ar)
	if limit > 0 && (np > limit || na > limit) {
		return false
	}
	return ep == nil && ea == nil && string(hp.Sum(nil)) == string(ha.Sum(nil))
}

func (s *Store) seal(name string, st *streamState) error {
	defer s.appendTimingEnd(appendTimingSeal, s.appendTimingStart())
	pending := filepath.Join(s.dir, st.pending)
	archive := strings.TrimSuffix(pending, ".pending") + ".jsonl.gz"
	// Recovery after rename but before pending-file removal must not duplicate records.
	if _, err := os.Stat(archive); err == nil {
		if !sameContents(pending, archive) {
			return errors.New("pending evidence differs from sealed archive")
		}
		if err := os.Remove(pending); err != nil {
			return err
		}
		st.pending = ""
		return nil
	}
	p, err := os.Open(pending)
	if err != nil {
		return err
	}
	defer p.Close()
	info, err := p.Stat()
	if err != nil {
		return err
	}
	activeBytes := int64(0)
	if a, err := os.Stat(filepath.Join(s.dir, name+".jsonl")); err == nil {
		activeBytes = a.Size()
	}
	tmp := archive + ".tmp"
	// Only this store's incomplete compression file is replaced during recovery.
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer os.Remove(tmp)
	bw := &budgetWriter{shared: s.lease, w: f, remaining: s.limit - st.archiveBytes - info.Size() - activeBytes}
	if s.budget != nil {
		remaining, err := s.budget.remaining()
		if err != nil {
			f.Close()
			return err
		}
		if remaining < bw.remaining {
			bw.remaining = remaining
		}
	}
	g, err := gzip.NewWriterLevel(bw, gzip.BestSpeed)
	if err != nil {
		f.Close()
		return err
	}
	_, err = io.Copy(g, p)
	if closeErr := g.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	compressed, err := os.Stat(tmp)
	if err != nil {
		return err
	}
	if err = os.Rename(tmp, archive); err != nil {
		return err
	}
	st.archiveBytes += compressed.Size()
	st.rotations++
	p.Close()
	if err = os.Remove(pending); err != nil {
		return err
	}
	st.pending = ""
	return nil
}

func (s *Store) appendRotating(name string, b []byte) error {
	if int64(len(b)) > s.segment {
		return errors.New("evidence record exceeds segment budget")
	}
	st, err := s.state(name)
	if err != nil {
		return err
	}
	if st.pending != "" {
		if err = s.seal(name, st); err != nil {
			return err
		}
	}
	path := filepath.Join(s.dir, name+".jsonl")
	size := int64(0)
	if cached, ok := s.sizes[path]; ok {
		// Only the persistent single writer uses cached active-file sizes.
		size = cached
	} else if info, err := os.Stat(path); err == nil {
		size = info.Size()
	} else if !os.IsNotExist(err) {
		return err
	}
	if size > 0 && size+int64(len(b)) > s.segment {
		// Windows cannot rename an active file while our writer handle is open.
		if err = s.closePath(path); err != nil {
			return err
		}
		st.sequence++
		st.pending = fmt.Sprintf("%s.%08d.pending", name, st.sequence)
		if err = os.Rename(path, filepath.Join(s.dir, st.pending)); err != nil {
			st.pending = ""
			return err
		}
		if err = s.seal(name, st); err != nil {
			return err
		}
		size = 0
	}
	if st.archiveBytes+size+int64(len(b)) > s.limit {
		return errors.New("evidence disk budget exceeded")
	}
	return s.appendLine(path, b, s.limit-st.archiveBytes)
}

func (s *Store) Stats() map[string]any {
	lockStarted := s.appendTimingStart()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.appendTimingEnd(appendTimingStatsLockWait, lockStarted)
	inventoryStarted := s.appendTimingStart()
	streams := map[string]any{}
	entries, scanErr := os.ReadDir(s.dir)
	for _, name := range []string{"events", "alerts", "actions", "evaluations", "host-events", "host-alerts", "host-evaluations", "policy-delivery-acks"} {
		var bytes int64
		segments := 0
		pending := false
		statError := scanErr != nil
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), name+".") {
				if info, err := e.Info(); err == nil {
					bytes += info.Size()
				} else {
					statError = true
				}
				if strings.HasSuffix(e.Name(), ".gz") {
					segments++
				}
				pending = pending || strings.HasSuffix(e.Name(), ".pending")
			}
		}
		streams[name] = map[string]any{"stored_bytes": bytes, "sealed_segments": segments, "pending_segment": pending, "limit_bytes": s.limit, "scan_error": statError}
	}
	s.appendTimingEnd(appendTimingStatsInventory, inventoryStarted)
	result := map[string]any{"segment_bytes": s.segment, "retention_evicted_records": 0, "streams": streams, "group_sync_outside_lease": s.groupSyncOutsideLease}
	if s.records != nil {
		counts := make(map[string]int, len(s.records))
		for name, count := range s.records {
			counts[name] = count
		}
		result["record_counts"], result["record_limit"] = counts, s.recordLimit
	}
	if len(s.groupTiming) > 0 {
		timing := make(map[string]groupDuration, len(s.groupTiming))
		for phase, value := range s.groupTiming {
			timing[phase] = value
		}
		result["group_timing"] = timing
	}
	if s.shared != nil {
		value, err := s.shared.Stats()
		result["shared_storage"] = map[string]any{"status": value, "scan_error": err != nil}
	}
	if s.budget != nil {
		result["shared_storage"] = s.budget.Stats()
	}
	return result
}
