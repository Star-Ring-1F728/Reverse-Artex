package contextrelease

import (
	"context"
	"errors"
	"path/filepath"
	"reverse-artex/internal/contextlearning"
	"reverse-artex/internal/contextshadow"
	"reverse-artex/internal/evidence"
	"reverse-artex/internal/incident"
	"sort"
	"sync"
	"time"
)

type Status struct {
	Release           View   `json:"release"`
	Configured        bool   `json:"configured"`
	Running           bool   `json:"running"`
	Busy              bool   `json:"busy"`
	Checks            int    `json:"checks"`
	LastError         string `json:"last_error"`
	LatestAttemptSHA  string `json:"latest_attempt_sha256"`
	Observed          int    `json:"observed"`
	Unavailable       int    `json:"unavailable"`
	DeploymentAllowed bool   `json:"deployment_allowed"`
}
type Service struct {
	mu        sync.Mutex
	store     *Store
	provider  func() (Config, error)
	live      *contextshadow.Live
	release   string
	tenant    string
	closed    bool
	stopped   bool
	openError string
}

// OpenService holds the release journal owner until Close. Offline approval
// commands therefore cannot change a running collector's version underneath it.
func OpenService(store *Store, provider func() (Config, error), capture func(context.Context) (*evidence.Snapshot, error)) (*Service, error) {
	if store == nil || provider == nil || capture == nil {
		return nil, ErrInvalid
	}
	c, e := provider()
	if e != nil || ValidateConfig(c) != nil {
		return nil, ErrInvalid
	}
	s := &Service{store: store, provider: provider, tenant: c.Policy.Tenant}
	r, b, e := store.Current(c, time.Now().UTC())
	if e != nil {
		return s, nil
	}
	s.release = r.SHA
	// A package has one bounded history even across rollback/restart. A fresh
	// signed release never discards an unfinished observation intent.
	limits := contextshadow.StorageLimits{ActiveAttempts: 64, ActiveBytes: 8 << 20, ArchiveSegments: 2, TotalBytes: 32 << 20}
	s.live, e = contextshadow.OpenLiveWithStorage(filepath.Join(store.path+".observations", r.Approval.Request.BundleSHA), b.Capsule.Candidate, c.Authorities, c.Context, func(ctx context.Context) (*evidence.Snapshot, error) {
		if e := s.gate(); e != nil {
			return nil, e
		}
		snapshot, e := capture(ctx)
		if e != nil {
			return nil, e
		}
		if e = s.gate(); e != nil {
			return nil, e
		}
		return snapshot, nil
	}, limits)
	if e != nil {
		s.openError = "preserve canary history; observation recovery requires review: " + e.Error()
		return s, nil
	}
	if e = s.live.Request(b.Capsule.Candidate.SHA, true); e != nil {
		s.openError = e.Error()
	}
	return s, nil
}
func (s *Service) gate() error {
	s.mu.Lock()
	off := s.closed || s.stopped
	s.mu.Unlock()
	if off {
		return ErrUnavailable
	}
	c, e := s.provider()
	if e != nil {
		return ErrUnavailable
	}
	r, _, e := s.store.Current(c, time.Now().UTC())
	if e != nil || r.SHA != s.release {
		return ErrUnavailable
	}
	return nil
}
func (s *Service) Tenant() string { return s.tenant }
func (s *Service) Status() Status {
	c, e := s.provider()
	v := s.store.View(c, time.Now().UTC())
	if e != nil && v.State != "STOPPED" {
		v.State = "BLOCKED"
		v.Blockers = append(v.Blockers, "current_configuration_unavailable")
	}
	status := Status{Release: v, Configured: true, LastError: s.openError}
	if s.openError != "" && status.Release.State != "STOPPED" {
		status.Release.State = "BLOCKED"
		status.Release.Blockers = append(status.Release.Blockers, "observation_history_requires_review")
	}
	if s.live != nil {
		live := s.live.Status()
		status.Running = live.Enabled && status.Release.State == "CANARY_OBSERVATION"
		status.Busy = live.Busy
		status.Checks = live.Checks
		if live.Error != "" {
			status.LastError = live.Error
		}
		if live.Latest != nil {
			status.LatestAttemptSHA = live.Latest.SHA
			if live.Latest.Receipt != nil {
				status.Observed = live.Latest.Receipt.Observed
				status.Unavailable = live.Latest.Receipt.Unavailable
			}
		}
	}
	return status
}
func (s *Service) Stop(expected int, reason string) (View, error) {
	// Stop the worker even if persisting stop subsequently fails. No old advice
	// is exposed after an uncertain stop, and the store retains its owner lock.
	s.mu.Lock()
	s.store.mu.Lock()
	valid := s.store.available() == nil && expected == len(s.store.changes) && reasonValid(reason)
	s.store.mu.Unlock()
	if !valid || s.closed {
		s.mu.Unlock()
		return View{}, ErrConflict
	}
	s.stopped = true
	s.mu.Unlock()
	if s.live != nil {
		s.live.Stop()
	}
	return s.store.Stop(s.tenant, expected, reason, time.Now().UTC())
}
func (s *Service) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()
	if s.live != nil {
		s.live.Close()
	}
	return s.store.Close()
}

// Advice is a read-only projection of an already synced shadow receipt. It
// never creates inference samples on GET, nor exposes candidate predictions on
// the reference branch. It does not qualify samples for production activation.
func (s *Service) Advice(c incident.Case, sourceSHA string) *Advice {
	if c.Tenant != s.tenant || s.live == nil || s.gate() != nil {
		return nil
	}
	cfg, e := s.provider()
	if e != nil {
		return nil
	}
	r, b, e := s.store.Current(cfg, time.Now().UTC())
	if e != nil || r.SHA != s.release {
		return nil
	}
	status := s.live.Status()
	a := status.Latest
	if a == nil || a.Receipt == nil || a.Error != "" || a.StartedAt.Before(r.At) || a.Receipt.SourceSHA != sourceSHA || a.Receipt.CandidateSHA != b.Capsule.Candidate.SHA {
		return nil
	}
	for _, row := range a.Receipt.Rows {
		if row.CaseID != c.ID || row.CaseSHA != contextlearning.Digest(c) {
			continue
		}
		out := &Advice{Schema: "case-context-canary-advice/2", Mode: "canary_observation", ReleaseSHA: r.SHA, CandidateSHA: b.Capsule.Candidate.SHA, ModelSHA: b.Capsule.Candidate.ModelSHA, CaseID: c.ID, CaseSHA: row.CaseSHA, SourceSHA: sourceSHA, AttemptSHA: a.SHA, Branch: "excluded", Prediction: "unknown", InferredAt: a.FinishedAt, ValidUntil: r.Approval.Request.Until, MandatoryReviewPreserved: true}
		if row.Status != "observed" {
			out.Exclusion = row.Reason
		} else if contains(r.Baseline.Cases, c.ID) {
			out.Exclusion = "pre_release_case"
		} else {
			for _, key := range row.EvidenceKeys {
				if contains(r.Baseline.Evidence, key) {
					out.Exclusion = "pre_release_evidence_overlap"
					break
				}
			}
			if out.Exclusion == "" {
				out.Eligible = true
				out.Branch = branch(out.CandidateSHA, c.Tenant, c.ID, r.Approval.Request.Percent)
				out.Prediction = "suspicious"
				if out.Branch == "candidate" {
					out.Prediction = row.Prediction
				}
			}
		}
		if s.gate() != nil {
			return nil
		}
		return out
	}
	return nil
}
func contains(values []string, value string) bool {
	i := sort.SearchStrings(values, value)
	return i < len(values) && values[i] == value
}

func OpenProfileService(profile, expectedContext string, capture func(context.Context) (*evidence.Snapshot, error)) (*Service, error) {
	c, path, e := LoadProfile(profile)
	if e != nil || contextlearning.Digest(c.Context) != expectedContext {
		return nil, ErrInvalid
	}
	store, e := Open(path)
	if e != nil {
		return nil, e
	}
	provider := func() (Config, error) {
		next, journal, e := LoadProfile(profile)
		if e != nil || journal != path || next.Policy.Tenant != c.Policy.Tenant || contextlearning.Digest(next.Context) != expectedContext {
			return Config{}, ErrInvalid
		}
		return next, nil
	}
	s, e := OpenService(store, provider, capture)
	if e != nil {
		return nil, errors.Join(e, store.Close())
	}
	return s, nil
}
