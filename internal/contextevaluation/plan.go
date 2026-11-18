package contextevaluation

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"reverse-artex/internal/casememory"
	"reverse-artex/internal/contextlearning"
	"reverse-artex/internal/contextrelease"
	"reverse-artex/internal/contextshadow"
	"reverse-artex/internal/evidence"
	"reverse-artex/internal/recovery"
	"sort"
	"time"
)

var pin = regexp.MustCompile(`^[a-f0-9]{64}$`)
var identifier = regexp.MustCompile(`^[A-Za-z0-9_.:/{}-]{1,128}$`)

type Session struct {
	profile, journal string
	cfg              contextrelease.Config
	store            *contextrelease.Store
	version          contextrelease.EvaluationRelease
}

// Open holds the replay-verified release owner for the entire offline read.
func Open(profile, releaseSHA string) (*Session, error) {
	if !pin.MatchString(releaseSHA) {
		return nil, ErrInvalid
	}
	cfg, path, e := contextrelease.LoadProfile(profile)
	if e != nil {
		return nil, e
	}
	st, e := os.Lstat(path)
	if e != nil || !st.Mode().IsRegular() {
		return nil, ErrInvalid
	}
	store, e := contextrelease.Open(path)
	if e != nil {
		return nil, e
	}
	version, e := store.ReadEvaluationRelease(releaseSHA)
	if e != nil {
		store.Close()
		return nil, e
	}
	if version.Release.Config == nil || contextlearning.Digest(cfg) != contextlearning.Digest(*version.Release.Config) {
		store.Close()
		return nil, ErrConflict
	}
	return &Session{profile, path, cfg, store, version}, nil
}
func (s *Session) Close() error { return s.store.Close() }
func (s *Session) fresh() error {
	cfg, path, e := contextrelease.LoadProfile(s.profile)
	if e != nil || path != s.journal || contextlearning.Digest(cfg) != contextlearning.Digest(s.cfg) {
		return ErrConflict
	}
	v, e := s.store.ReadEvaluationRelease(s.version.Release.SHA)
	if e != nil || v.JournalHead != s.version.JournalHead {
		return ErrConflict
	}
	return nil
}
func (s *Session) history() (contextshadow.HistorySnapshot, error) {
	return contextshadow.ReadHistory(s.version.HistoryPath, s.version.Bundle.Capsule.Candidate, s.cfg.Authorities, s.cfg.Context, contextshadow.StorageLimits{ActiveAttempts: 64, ActiveBytes: 8 << 20, ArchiveSegments: 2, TotalBytes: 32 << 20})
}
func (s *Session) verifySnapshot(snapshot *evidence.Snapshot) error {
	if snapshot == nil || recovery.VerifySnapshot(snapshot) != nil {
		return ErrInvalid
	}
	var meta recovery.Metadata
	if json.Unmarshal(snapshot.Metadata(), &meta) != nil || meta.ContextTrust == nil || contextlearning.Digest(*meta.ContextTrust) != contextlearning.Digest(s.cfg.Context) {
		return ErrInvalid
	}
	return nil
}
func defaultCriteria(tenant, trust string) casememory.CanaryCriteria {
	return casememory.DefaultProductionPolicy(tenant, trust).Canary
}
func (s *Session) validPlan(p Plan) bool {
	r := s.version.Release
	if p.Schema != "case-context-canary-evaluation-plan/2" || p.SHA != PlanSHA(p) || p.Tenant != r.Tenant || p.ReleaseSHA != r.SHA || p.BundleSHA != r.Approval.Request.BundleSHA || p.ConfigSHA != contextlearning.Digest(s.cfg) || p.EvaluationSHA != SourceSHA() || p.LabelTrustSHA != casememory.LearningTrustDigest(s.cfg.Authorities) || p.Criteria != defaultCriteria(p.Tenant, p.LabelTrustSHA) || p.CreatedAt.Before(r.At) || !p.CreatedAt.Before(p.Until) || !p.Until.Equal(r.Approval.Request.Until) || p.HistorySequence < 0 || p.HistorySequence > 192 || p.HistorySequence == 0 && p.HistoryHead != "" || p.HistorySequence > 0 && !pin.MatchString(p.HistoryHead) {
		return false
	}
	b := p.Baseline
	if !pin.MatchString(b.SourceSHA) || b.Cases == nil || b.Evidence == nil || len(b.Cases) > 512 || len(b.Evidence) > 4096 || !sort.StringsAreSorted(b.Cases) || !sort.StringsAreSorted(b.Evidence) {
		return false
	}
	for i, v := range b.Cases {
		if !identifier.MatchString(v) || i > 0 && v == b.Cases[i-1] {
			return false
		}
	}
	for i, v := range b.Evidence {
		if !pin.MatchString(v) || i > 0 && v == b.Evidence[i-1] {
			return false
		}
	}
	return true
}
func verifyPrefix(p Plan, h contextshadow.HistorySnapshot) error {
	if h.SHA != contextshadow.HistorySnapshotSHA(h) || len(h.Attempts) < p.HistorySequence {
		return ErrConflict
	}
	if p.HistorySequence > 0 && h.Attempts[p.HistorySequence-1].SHA != p.HistoryHead {
		return ErrConflict
	}
	return nil
}
func (s *Session) loadPlan(expected string) (Plan, error) {
	var p Plan
	if !pin.MatchString(expected) {
		return p, ErrInvalid
	}
	if e := contextshadow.ReadPublic(s.version.PlanPath, &p); e != nil {
		return p, e
	}
	if p.SHA != expected || !s.validPlan(p) {
		return p, ErrConflict
	}
	return p, nil
}
func writeNew(path string, value any) error {
	raw, e := json.MarshalIndent(value, "", "  ")
	if e != nil {
		return e
	}
	raw = append(raw, '\n')
	if len(raw) > 512<<10 {
		return ErrInvalid
	}
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	n, e := f.Write(raw)
	if e == nil && n != len(raw) {
		e = io.ErrShortWrite
	}
	return errors.Join(e, f.Sync(), f.Close())
}

// Freeze persists one immutable plan per signed release before future samples.
// A retry returns the original plan, including its original baseline and time.
func (s *Session) Freeze(snapshot *evidence.Snapshot, at time.Time) (Plan, error) {
	if at.IsZero() || s.fresh() != nil {
		return Plan{}, ErrConflict
	}
	h, e := s.history()
	if e != nil {
		return Plan{}, e
	}
	if _, e = os.Lstat(s.version.PlanPath); e == nil {
		var p Plan
		if e = contextshadow.ReadPublic(s.version.PlanPath, &p); e != nil {
			return p, e
		}
		if !s.validPlan(p) || verifyPrefix(p, h) != nil {
			return p, ErrConflict
		}
		return p, nil
	} else if !os.IsNotExist(e) {
		return Plan{}, e
	}
	current, _, e := s.store.Current(s.cfg, at)
	if e != nil || current.SHA != s.version.Release.SHA {
		return Plan{}, ErrConflict
	}
	if e = s.verifySnapshot(snapshot); e != nil {
		return Plan{}, e
	}
	baseline, e := contextrelease.CaptureBaseline(snapshot, s.cfg.Policy.Tenant)
	if e != nil {
		return Plan{}, e
	}
	p := Plan{Schema: "case-context-canary-evaluation-plan/2", Tenant: s.cfg.Policy.Tenant, ReleaseSHA: current.SHA, BundleSHA: current.Approval.Request.BundleSHA, ConfigSHA: contextlearning.Digest(s.cfg), EvaluationSHA: SourceSHA(), LabelTrustSHA: casememory.LearningTrustDigest(s.cfg.Authorities), Criteria: defaultCriteria(current.Tenant, casememory.LearningTrustDigest(s.cfg.Authorities)), CreatedAt: at.UTC(), Until: current.Approval.Request.Until, Baseline: baseline, HistorySequence: len(h.Attempts)}
	if len(h.Attempts) > 0 {
		last := h.Attempts[len(h.Attempts)-1]
		if last.FinishedAt.After(at) {
			return Plan{}, ErrInvalid
		}
		p.HistoryHead = last.SHA
	}
	p.SHA = PlanSHA(p)
	if !s.validPlan(p) {
		return Plan{}, ErrInvalid
	}
	for _, dir := range []string{filepath.Dir(filepath.Dir(s.version.PlanPath)), filepath.Dir(s.version.PlanPath)} {
		if e = os.Mkdir(dir, 0700); e != nil && !os.IsExist(e) {
			return Plan{}, e
		}
		st, err := os.Lstat(dir)
		if err != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
			return Plan{}, ErrInvalid
		}
	}
	if e = writeNew(s.version.PlanPath, p); e != nil {
		return Plan{}, e
	}
	return p, nil
}
