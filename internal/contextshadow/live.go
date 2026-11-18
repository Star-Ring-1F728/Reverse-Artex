package contextshadow

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reverse-artex/internal/actioncontext"
	"reverse-artex/internal/casememory"
	"reverse-artex/internal/contextlearning"
	"reverse-artex/internal/contractjson"
	"reverse-artex/internal/evidence"
	"sync"
	"time"
)

var ErrConflict = errors.New("shadow observation busy or closed")
var ErrLimit = errors.New("shadow history full; collector continues; preserve archives and configure a new history profile")

const MaxAttempts = 128
const MaxHistoryBytes = 32 << 20

// Paths are installed by the filesystem operator, never supplied by the web API.
type Profile struct {
	Storage         *StorageLimits `json:"storage,omitempty"`
	CandidatePath   string         `json:"candidate_path"`
	CandidateSHA    string         `json:"candidate_sha256"`
	AuthoritiesPath string         `json:"review_trust_path"`
}

func ReadPublic(path string, v any) error {
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() || st.Size() > 2<<20 {
		return contextlearning.ErrInvalid
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, (2<<20)+1))
	if err != nil {
		return err
	}
	return contractjson.Decode(b, v, 2<<20, 8192)
}
func LoadProfile(path string, trust actioncontext.Trust) (contextlearning.Candidate, casememory.LearningTrust, error) {
	var p Profile
	var c contextlearning.Candidate
	var a casememory.LearningTrust
	if err := ReadPublic(path, &p); err != nil {
		return c, a, err
	}
	resolve := func(s string) string {
		if filepath.IsAbs(s) {
			return s
		}
		return filepath.Join(filepath.Dir(path), s)
	}
	if err := ReadPublic(resolve(p.CandidatePath), &c); err != nil {
		return c, a, err
	}
	if err := ReadPublic(resolve(p.AuthoritiesPath), &a); err != nil {
		return c, a, err
	}
	return c, a, ValidateCandidate(c, p.CandidateSHA, a, trust)
}

type Attempt struct {
	Schema       string    `json:"schema"`
	Sequence     int       `json:"sequence"`
	Tenant       string    `json:"tenant_id"`
	CandidateSHA string    `json:"candidate_sha256"`
	StartedAt    time.Time `json:"started_at"`
	FinishedAt   time.Time `json:"finished_at"`
	Error        string    `json:"error,omitempty"`
	Receipt      *Receipt  `json:"receipt,omitempty"`
	SHA          string    `json:"attempt_sha256"`
}

func attemptSHA(a Attempt) string { a.SHA = ""; return contextlearning.Digest(a) }

type AttemptSummary struct {
	Sequence   int       `json:"sequence"`
	FinishedAt time.Time `json:"finished_at"`
	Error      string    `json:"error,omitempty"`
	SHA        string    `json:"attempt_sha256"`
}
type LiveStatus struct {
	Storage           HistoryStorage   `json:"storage"`
	Configured        bool             `json:"configured"`
	Tenant            string           `json:"tenant_id"`
	CandidateSHA      string           `json:"candidate_sha256"`
	Enabled           bool             `json:"enabled"`
	Busy              bool             `json:"busy"`
	Queued            bool             `json:"queued"`
	Checks            int              `json:"checks"`
	LastChecked       time.Time        `json:"last_checked"`
	Error             string           `json:"error,omitempty"`
	Latest            *Attempt         `json:"latest,omitempty"`
	History           []AttemptSummary `json:"history"`
	IntervalSeconds   int              `json:"interval_seconds"`
	DeploymentAllowed bool             `json:"deployment_allowed"`
}
type Live struct {
	mu            sync.Mutex
	c             contextlearning.Candidate
	a             casememory.LearningTrust
	trust         actioncontext.Trust
	capture       func(context.Context) (*evidence.Snapshot, error)
	dir           string
	owner         *os.File
	stateFile     *os.File
	bytes         int
	attempts      []Attempt
	status        LiveStatus
	wake          chan struct{}
	done          chan struct{}
	ctx           context.Context
	cancel        context.CancelFunc
	attemptCancel context.CancelFunc
	closed        bool
	storageFailed bool
	storageFull   bool
	unsavedChecks int
	limits        StorageLimits
	totalBytes    int
	baseSequence  int
	archives      []ArchiveSeal
	summaries     []AttemptSummary
	latest        *Attempt
	generation    int
}

func OpenLive(dir string, c contextlearning.Candidate, a casememory.LearningTrust, trust actioncontext.Trust, capture func(context.Context) (*evidence.Snapshot, error)) (*Live, error) {
	return OpenLiveWithStorage(dir, c, a, trust, capture, DefaultStorageLimits())
}
func OpenLiveWithStorage(dir string, c contextlearning.Candidate, a casememory.LearningTrust, trust actioncontext.Trust, capture func(context.Context) (*evidence.Snapshot, error), limits StorageLimits) (*Live, error) {
	if !limits.valid() {
		return nil, errors.New("invalid bounded shadow storage limits")
	}

	if capture == nil || ValidateCandidate(c, c.SHA, a, trust) != nil {
		return nil, contextlearning.ErrInvalid
	}
	// Retain private copies: caller mutations cannot change a running profile.
	b, _ := json.Marshal(c)
	var cc contextlearning.Candidate
	json.Unmarshal(b, &cc)
	c = cc
	b, _ = json.Marshal(a)
	var aa casememory.LearningTrust
	json.Unmarshal(b, &aa)
	a = aa
	b, _ = json.Marshal(trust)
	var tt actioncontext.Trust
	json.Unmarshal(b, &tt)
	trust = tt
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	st, err := os.Lstat(dir)
	if err != nil || !st.IsDir() {
		return nil, contextlearning.ErrInvalid
	}
	lockPath := filepath.Join(dir, "owner.lock")
	if st, e := os.Lstat(lockPath); e == nil && !st.Mode().IsRegular() {
		return nil, contextlearning.ErrInvalid
	}
	owner, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = lockOwner(owner); err != nil {
		owner.Close()
		return nil, err
	}
	success := false
	defer func() {
		if !success {
			unlockOwner(owner)
			owner.Close()
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	s := &Live{limits: limits, c: c, a: a, trust: trust, capture: capture, dir: dir, owner: owner, wake: make(chan struct{}, 1), done: make(chan struct{}), ctx: ctx, cancel: cancel, status: LiveStatus{Configured: true, Tenant: c.Tenant, CandidateSHA: c.SHA, History: []AttemptSummary{}, IntervalSeconds: 2}}
	if err := s.restoreHistory(); err != nil {
		cancel()
		return nil, err
	}
	if err := s.openObserverState(); err != nil {
		cancel()
		return nil, err
	}
	if s.latest != nil {
		s.status.Error = s.latest.Error
		s.status.LastChecked = s.latest.FinishedAt
	}
	if len(s.attempts) >= s.limits.ActiveAttempts && !s.canRotate() {
		s.storageFull = true
		s.status.Error = ErrLimit.Error()
	}
	success = true
	go s.loop()
	return s, nil
}
func (s *Live) Tenant() string { return s.c.Tenant }
func (s *Live) Status() LiveStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.statusLocked()
}
func (s *Live) statusLocked() LiveStatus {
	v := s.status
	v.Storage = s.storageStatus()
	v.History = []AttemptSummary{}
	for i := len(s.summaries) - 1; i >= 0 && len(v.History) < 16; i-- {
		v.History = append(v.History, s.summaries[i])
	}
	v.Latest = s.latest
	b, _ := json.Marshal(v)
	var copy LiveStatus
	json.Unmarshal(b, &copy)
	return copy
}
func (s *Live) History(sequence int) (Attempt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sequence < 1 || sequence > s.baseSequence+len(s.attempts) {
		return Attempt{}, contextlearning.ErrInvalid
	}
	var a Attempt
	if sequence > s.baseSequence {
		a = s.attempts[sequence-s.baseSequence-1]
	} else {
		found := false
		for _, seal := range s.archives {
			for _, e := range seal.Entries {
				if e.Sequence == sequence {
					path := filepath.Join(s.dir, segmentName(seal.Index), attemptName(sequence))
					raw, err := os.ReadFile(path)
					if err != nil || len(raw) != e.Bytes || fileSHA(raw) != e.FileSHA {
						return Attempt{}, errors.New("archived history changed")
					}
					if err := ReadPublic(path, &a); err != nil {
						return Attempt{}, err
					}
					if s.validateAttempt(a, sequence) != nil || a.SHA != e.AttemptSHA {
						return Attempt{}, contextlearning.ErrInvalid
					}
					found = true
					break
				}
			}
		}
		if !found {
			return Attempt{}, contextlearning.ErrInvalid
		}
	}
	b, _ := json.Marshal(a)
	var copy Attempt
	json.Unmarshal(b, &copy)
	return copy, nil
}
func (s *Live) Request(pin string, continuous bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.requestLocked(pin, continuous)
}

// RequestWithStatus captures admission state before the worker can acquire the
// storage lock. HTTP acceptance must not wait for observation/rotation I/O.
func (s *Live) RequestWithStatus(pin string, continuous bool) (LiveStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.requestLocked(pin, continuous); err != nil {
		return LiveStatus{}, err
	}
	return s.statusLocked(), nil
}
func (s *Live) requestLocked(pin string, continuous bool) error {
	if pin != s.c.SHA {
		return contextlearning.ErrInvalid
	}
	if s.closed || s.storageFailed || s.status.Busy || s.status.Queued {
		return ErrConflict
	}
	if s.storageFull || (len(s.attempts) >= s.limits.ActiveAttempts && !s.canRotate()) {
		s.pauseCapacity()
		return ErrLimit
	}
	s.status.Enabled = continuous || s.status.Enabled
	s.status.Queued = true
	s.status.Error = ""
	select {
	case s.wake <- struct{}{}:
	default:
	}
	return nil
}
func (s *Live) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status.Enabled = false
	s.status.Queued = false
	s.generation++
	if s.attemptCancel != nil {
		s.attemptCancel()
	}
}
func (s *Live) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.mu.Unlock()
	s.Stop()
	s.cancel()
	<-s.done
	if s.stateFile != nil {
		s.stateFile.Close()
	}
	unlockOwner(s.owner)
	s.owner.Close()
}
func (s *Live) loop() {
	defer close(s.done)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
		case <-s.wake:
		}
		s.mu.Lock()
		if !s.status.Queued && !s.status.Enabled {
			s.mu.Unlock()
			continue
		}
		if err := s.writeObserverState(true); err != nil {
			s.storageFailed = true
			s.status.Enabled = false
			s.status.Queued = false
			s.status.Error = "shadow admission intent unverified: " + err.Error()
			s.mu.Unlock()
			continue
		}
		if len(s.attempts) >= s.limits.ActiveAttempts {
			if e := s.rotateHistory(); e != nil {
				s.status.Enabled = false
				s.status.Queued = false
				s.status.Error = e.Error()
				if errors.Is(e, ErrLimit) {
					s.pauseCapacity()
				} else {
					s.storageFailed = true
				}
				s.finishObserverState()
				s.mu.Unlock()
				continue
			}
		}
		s.status.Queued = false
		s.status.Busy = true
		generation := s.generation
		ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
		s.attemptCancel = cancel
		s.mu.Unlock()
		started := time.Now().UTC()
		snapshot, err := s.capture(ctx)
		var receipt Receipt
		if err == nil {
			if err = ctx.Err(); err == nil {
				receipt, err = ObserveSnapshot(snapshot, s.c, s.c.SHA, s.a, s.trust)
			}
		}
		if err == nil {
			err = ctx.Err()
		}
		cancel()
		s.mu.Lock()
		s.attemptCancel = nil
		s.status.Checks++
		s.status.LastChecked = time.Now().UTC()
		s.status.Busy = false
		if generation != s.generation {
			err = context.Canceled
		}
		// Unchanged snapshots reuse the immutable receipt; they are not new samples.
		unchanged := false
		if err == nil && s.latest != nil {
			last := *s.latest
			unchanged = last.Receipt != nil && last.Receipt.SourceSHA == receipt.SourceSHA
		}
		if !unchanged {
			record := Attempt{Schema: "case-context-live-attempt/2", Sequence: s.baseSequence + len(s.attempts) + 1, Tenant: s.c.Tenant, CandidateSHA: s.c.SHA, StartedAt: started, FinishedAt: time.Now().UTC()}
			if err != nil {
				record.Error = err.Error()
			} else {
				record.Receipt = &receipt
			}
			record.SHA = attemptSHA(record)
			if saveErr := s.save(record); saveErr != nil {
				if errors.Is(saveErr, ErrLimit) {
					s.unsavedChecks++
					s.pauseCapacity()
				} else {
					s.unsavedChecks++
					s.storageFailed = true
				}
				s.status.Error = saveErr.Error()
				s.status.Enabled = false
			} else {
				s.attempts = append(s.attempts, record)
				s.remember(record)
				if err != nil {
					s.status.Error = err.Error()
					s.status.Enabled = false
				}
			}
		}
		s.finishObserverState()
		s.mu.Unlock()
	}
}
func (s *Live) save(a Attempt) error {
	b, err := json.Marshal(a)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if len(b) > 2<<20 {
		return ErrLimit
	}
	if len(s.attempts) >= s.limits.ActiveAttempts || s.bytes+len(b) > s.limits.ActiveBytes {
		if err := s.rotateHistory(); err != nil {
			return err
		}
	}
	if s.totalBytes+len(b)+4096 > s.limits.TotalBytes {
		return ErrLimit
	}
	if err := writeNewHistoryFile(filepath.Join(s.dir, attemptName(a.Sequence)), b); err != nil {
		return err
	}
	s.bytes += len(b)
	s.totalBytes += len(b)
	return nil
}
