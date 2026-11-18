package contextrelease

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"path/filepath"
	"reverse-artex/internal/contextlearning"
	"reverse-artex/internal/contextshadow"
	"reverse-artex/internal/evidence"
	"reverse-artex/internal/incident"
	"sync"
	"time"
)

const (
	MinCadence     = 2 * time.Second
	MaxCadence     = 300 * time.Second
	DefaultCadence = 120 * time.Second
)

// RuntimeService is the common read, stop, and close surface for canary
// services. The cadence implementation does not change the signed release
// contract pinned by SourceSHA.
type RuntimeService interface {
	Tenant() string
	Status() Status
	Stop(expected int, reason string) (View, error)
	Advice(c incident.Case, sourceSHA string) *Advice
	Close() error
}

// CadencedService performs one observation immediately and asks the live
// observer for later one-shot checks on the operator-selected interval.
type CadencedService struct {
	*Service
	interval  time.Duration
	candidate string
	cancel    context.CancelFunc
	done      chan struct{}
	mu        sync.Mutex
	closed    bool
	stopped   bool
}

//go:embed cadence.go
var cadenceSource embed.FS

// CadenceSourceSHA independently pins this wrapper and its frozen release
// dependencies without changing the existing signed SourceSHA.
func CadenceSourceSHA() string {
	raw, _ := cadenceSource.ReadFile("cadence.go")
	sum := sha256.Sum256(raw)
	return contextlearning.Digest([]string{"reverse-artex/context-canary-cadence/1", SourceSHA(), "cadence.go", hex.EncodeToString(sum[:])})
}

func cadenceValid(interval time.Duration) bool {
	return interval >= MinCadence && interval <= MaxCadence && interval%time.Second == 0
}

// OpenCadencedProfileService owns the same signed journal and observation
// history as OpenProfileService, but uses bounded one-shot requests instead
// of the frozen service's two-second continuous observer.
func OpenCadencedProfileService(profile, expectedContext string, interval time.Duration, capture func(context.Context) (*evidence.Snapshot, error)) (*CadencedService, error) {
	if !cadenceValid(interval) {
		return nil, ErrInvalid
	}
	c, path, err := LoadProfile(profile)
	if err != nil || contextlearning.Digest(c.Context) != expectedContext {
		return nil, ErrInvalid
	}
	store, err := Open(path)
	if err != nil {
		return nil, err
	}
	provider := func() (Config, error) {
		next, journal, err := LoadProfile(profile)
		if err != nil || journal != path || next.Policy.Tenant != c.Policy.Tenant || contextlearning.Digest(next.Context) != expectedContext {
			return Config{}, ErrInvalid
		}
		return next, nil
	}
	service, err := openCadencedService(store, provider, capture, interval)
	if err != nil {
		return nil, errors.Join(err, store.Close())
	}
	return service, nil
}

func openCadencedService(store *Store, provider func() (Config, error), capture func(context.Context) (*evidence.Snapshot, error), interval time.Duration) (*CadencedService, error) {
	if store == nil || provider == nil || capture == nil || !cadenceValid(interval) {
		return nil, ErrInvalid
	}
	c, err := provider()
	if err != nil || ValidateConfig(c) != nil {
		return nil, ErrInvalid
	}
	base := &Service{store: store, provider: provider, tenant: c.Policy.Tenant}
	r, b, err := store.Current(c, time.Now().UTC())
	if err != nil {
		return newCadencedService(base, interval, ""), nil
	}
	base.release = r.SHA
	limits := contextshadow.StorageLimits{ActiveAttempts: 64, ActiveBytes: 8 << 20, ArchiveSegments: 2, TotalBytes: 32 << 20}
	base.live, err = contextshadow.OpenLiveWithStorage(filepath.Join(store.path+".observations", r.Approval.Request.BundleSHA), b.Capsule.Candidate, c.Authorities, c.Context, func(ctx context.Context) (*evidence.Snapshot, error) {
		if err := base.gate(); err != nil {
			return nil, err
		}
		snapshot, err := capture(ctx)
		if err != nil {
			return nil, err
		}
		if err = base.gate(); err != nil {
			return nil, err
		}
		return snapshot, nil
	}, limits)
	if err != nil {
		base.openError = "preserve canary history; observation recovery requires review: " + err.Error()
		return newCadencedService(base, interval, ""), nil
	}
	if err = base.live.Request(b.Capsule.Candidate.SHA, false); err != nil {
		base.openError = err.Error()
	}
	return newCadencedService(base, interval, b.Capsule.Candidate.SHA), nil
}

func newCadencedService(base *Service, interval time.Duration, candidate string) *CadencedService {
	ctx, cancel := context.WithCancel(context.Background())
	s := &CadencedService{Service: base, interval: interval, candidate: candidate, cancel: cancel, done: make(chan struct{})}
	if base.live == nil || candidate == "" {
		close(s.done)
		return s
	}
	go s.schedule(ctx)
	return s
}

func (s *CadencedService) schedule(ctx context.Context) {
	defer close(s.done)
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.mu.Lock()
			if s.closed || s.stopped {
				s.mu.Unlock()
				return
			}
			if s.Service.gate() == nil {
				_ = s.live.Request(s.candidate, false)
			}
			s.mu.Unlock()
		}
	}
}

// Status reports the one-shot scheduler as running while the signed canary is
// active; the underlying live observer correctly remains non-continuous.
func (s *CadencedService) Status() Status {
	status := s.Service.Status()
	s.mu.Lock()
	schedulerRunning := !s.closed && !s.stopped && s.live != nil && s.candidate != ""
	s.mu.Unlock()
	status.Running = schedulerRunning && status.Release.State == "CANARY_OBSERVATION"
	return status
}

// Stop only disables scheduling after the store CAS succeeds. A stale revision
// or failed append leaves both the service and scheduler available for retry.
func (s *CadencedService) Stop(expected int, reason string) (View, error) {
	s.mu.Lock()
	if s.closed || s.stopped {
		s.mu.Unlock()
		return View{}, ErrConflict
	}
	view, err := s.store.Stop(s.tenant, expected, reason, time.Now().UTC())
	if err != nil {
		s.mu.Unlock()
		return View{}, err
	}
	s.stopped = true
	s.Service.mu.Lock()
	s.Service.stopped = true
	s.Service.mu.Unlock()
	if s.live != nil {
		s.live.Stop()
	}
	s.cancel()
	s.mu.Unlock()
	<-s.done
	return view, nil
}

// Close joins the cadence goroutine before the embedded service releases the
// live history and journal owners.
func (s *CadencedService) Close() error {
	s.mu.Lock()
	if !s.closed {
		s.closed = true
		s.cancel()
	}
	s.mu.Unlock()
	<-s.done
	return s.Service.Close()
}

var _ RuntimeService = (*Service)(nil)
var _ RuntimeService = (*CadencedService)(nil)
