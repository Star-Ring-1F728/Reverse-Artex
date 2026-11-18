package contextrelease

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reverse-artex/internal/casememory"
	"reverse-artex/internal/contextlearning"
	"reverse-artex/internal/contractjson"
	"reverse-artex/internal/evidence"
	"reverse-artex/internal/recovery"
	"sync"
	"time"
)

type Store struct {
	mu       sync.Mutex
	path     string
	file     *os.File
	owner    *casememory.Store
	changes  []Change
	packages map[string]Bundle
	size     int
	failed   bool
	syncFile func(*os.File) error
}

func Open(path string) (*Store, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	owner, err := casememory.Open(path + ".owner")
	if err != nil {
		return nil, err
	}
	good := false
	defer func() {
		if !good {
			owner.Close()
		}
	}()
	if st, e := os.Lstat(path); e == nil && !st.Mode().IsRegular() {
		return nil, ErrInvalid
	} else if e != nil && !os.IsNotExist(e) {
		return nil, e
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0600)
	if err != nil {
		return nil, err
	}
	s := &Store{path: path, file: f, owner: owner, changes: []Change{}, packages: map[string]Bundle{}, syncFile: (*os.File).Sync}
	defer func() {
		if !good {
			f.Close()
		}
	}()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if st.Size() > MaxJournal {
		return nil, ErrLimit
	}
	r := bufio.NewReaderSize(f, MaxRecord+1)
	for {
		raw, e := r.ReadSlice('\n')
		if e == io.EOF && len(raw) == 0 {
			break
		}
		if e != nil || len(raw) > MaxRecord {
			return nil, ErrUnavailable
		}
		var row Change
		if contractjson.Decode(raw, &row, MaxRecord, 8192) != nil || row.SHA != changeSHA(row) || s.validate(row) != nil {
			return nil, ErrUnavailable
		}
		s.apply(row)
		s.size += len(raw)
	}
	good = true
	return s, nil
}
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file == nil {
		return nil
	}
	e := s.file.Close()
	s.file = nil
	return errors.Join(e, s.owner.Close())
}
func (s *Store) available() error {
	if s.file == nil || s.failed {
		return ErrUnavailable
	}
	return nil
}
func (s *Store) head() string {
	if len(s.changes) == 0 {
		return ""
	}
	return s.changes[len(s.changes)-1].SHA
}
func (s *Store) last() *Change {
	if len(s.changes) == 0 {
		return nil
	}
	return &s.changes[len(s.changes)-1]
}
func (s *Store) apply(r Change) {
	s.changes = append(s.changes, clone(r))
	if r.Bundle != nil {
		s.packages[BundleSHA(*r.Bundle)] = clone(*r.Bundle)
	}
}

func (s *Store) policyFloor(c Config) bool {
	for _, old := range s.changes {
		if old.Config == nil {
			continue
		}
		p := old.Config.Policy
		if c.Policy.Revision < p.Revision || c.Policy.Revision == p.Revision && contextlearning.Digest(c.Policy) != contextlearning.Digest(p) {
			return false
		}
		if c.Admission.Revision < old.Config.Admission.Revision || c.Admission.Revision == old.Config.Admission.Revision && contextlearning.Digest(c.Admission) != contextlearning.Digest(old.Config.Admission) {
			return false
		}
	}
	return true
}
func (s *Store) cohortUsed(b Bundle) bool {
	n := b.Capsule.Cohort
	for _, old := range s.packages {
		o := old.Capsule.Cohort
		if b.Capsule.Plan.ID == old.Capsule.Plan.ID || n.DatasetID == o.DatasetID || n.InputsSHA == o.InputsSHA || n.GoldSHA == o.GoldSHA || n.SourceSHA == o.SourceSHA || n.MembershipSHA == o.MembershipSHA || b.Endorsement.Report.PredictionsSHA == old.Endorsement.Report.PredictionsSHA {
			return true
		}
	}
	return false
}
func (s *Store) validate(r Change) error {
	if r.Schema != "context-canary-journal/2" || r.Revision != len(s.changes)+1 || r.Previous != s.head() || r.SourceSHA != SourceSHA() || !id.MatchString(r.Tenant) || r.At.IsZero() || !reasonValid(r.Reason) || len(s.changes) >= MaxChanges {
		return ErrInvalid
	}
	if old := s.last(); old != nil && (r.Tenant != old.Tenant || r.At.Before(old.At)) {
		return ErrInvalid
	}
	if r.Action == "stop" {
		if r.Config != nil || r.Bundle != nil || r.Baseline != nil || r.Approval != nil {
			return ErrInvalid
		}
		return nil
	}
	if r.Action != "canary" && r.Action != "rollback" || r.Config == nil || r.Baseline == nil || r.Approval == nil || !validBaseline(*r.Baseline) || !s.policyFloor(*r.Config) {
		return ErrInvalid
	}
	a := *r.Approval
	q := a.Request
	if q.Expected != len(s.changes) || q.Previous != s.head() || q.Action != r.Action || a.Tenant != r.Tenant || r.Config.Policy.Tenant != r.Tenant || r.Reason != q.Reason {
		return ErrConflict
	}
	for _, old := range s.changes {
		if old.Approval != nil && old.Approval.Request.Nonce == q.Nonce {
			return ErrConflict
		}
	}
	var b Bundle
	if r.Action == "canary" {
		if r.Bundle == nil || len(s.packages) >= MaxPackages {
			return ErrLimit
		}
		b = *r.Bundle
		if _, ok := s.packages[BundleSHA(b)]; ok || s.cohortUsed(b) {
			return ErrConflict
		}
	} else {
		if r.Bundle != nil {
			return ErrInvalid
		}
		var ok bool
		b, ok = s.packages[q.BundleSHA]
		if !ok {
			return ErrInvalid
		}
		if old := s.last(); old != nil && old.Approval != nil && old.Approval.Request.BundleSHA == q.BundleSHA {
			return ErrConflict
		}
	}
	return verifyApproval(*r.Config, b, *r.Baseline, a, r.At)
}
func (s *Store) commit(r Change) error {
	if s.available() != nil {
		return ErrUnavailable
	}
	r = clone(r)
	if err := s.validate(r); err != nil {
		return err
	}
	r.SHA = changeSHA(r)
	raw, _ := jsonBytes(r)
	reserve, slots := 0, 0
	if r.Action != "stop" {
		reserve, slots = stopReserve, 1
	}
	if len(raw) > MaxRecord || s.size+len(raw)+reserve > MaxJournal || len(s.changes)+1+slots > MaxChanges {
		return ErrLimit
	}
	n, err := s.file.Write(raw)
	if err == nil && n != len(raw) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = s.syncFile(s.file)
	}
	if err != nil {
		s.failed = true
		return ErrUnavailable
	}
	s.apply(r)
	s.size += len(raw)
	return nil
}
func jsonBytes(v any) ([]byte, error) { raw, err := json.Marshal(v); return append(raw, '\n'), err }

func baselineFor(c Config, snapshot *evidence.Snapshot) (Baseline, error) {
	if snapshot == nil {
		return Baseline{}, ErrInvalid
	}
	var meta recovery.Metadata
	if json.Unmarshal(snapshot.Metadata(), &meta) != nil || meta.ContextTrust == nil || contextlearning.Digest(*meta.ContextTrust) != contextlearning.Digest(c.Context) {
		return Baseline{}, ErrInvalid
	}
	return CaptureBaseline(snapshot, c.Policy.Tenant)
}

// Prepare returns public signing material. It neither admits a package nor
// consumes a nonce. Callers must recapture source when submitting the approval.
func (s *Store) Prepare(c Config, b Bundle, snapshot *evidence.Snapshot, action string, percent int, until time.Time, nonce, reason string, at time.Time) (Request, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.available() != nil {
		return Request{}, ErrUnavailable
	}
	d, e := assess(c, b, at)
	if e != nil {
		return Request{}, e
	}
	base, e := baselineFor(c, snapshot)
	if e != nil {
		return Request{}, e
	}
	if action != "canary" && action != "rollback" || percent < 1 || percent > 50 || !pin.MatchString(nonce) || !reasonValid(reason) || !at.Before(until) || until.After(d.ValidUntil) || !s.policyFloor(c) {
		return Request{}, ErrInvalid
	}
	if action == "rollback" {
		if _, ok := s.packages[BundleSHA(b)]; !ok {
			return Request{}, ErrInvalid
		}
	} else if s.cohortUsed(b) {
		return Request{}, ErrConflict
	}
	return Request{Expected: len(s.changes), Previous: s.head(), Action: action, BundleSHA: BundleSHA(b), PolicySHA: contextlearning.Digest(c.Policy), BaselineSHA: contextlearning.Digest(base), Percent: percent, Until: until, Nonce: nonce, Reason: reason}, nil
}
func (s *Store) Approve(c Config, b Bundle, snapshot *evidence.Snapshot, a Approval, at time.Time) (Version, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.available() != nil {
		return Version{}, ErrUnavailable
	}
	for _, old := range s.changes {
		if old.Approval != nil && old.Approval.Request.Nonce == a.Request.Nonce {
			if contextlearning.Digest(*old.Approval) == contextlearning.Digest(a) {
				return s.version(old), nil
			}
			return Version{}, ErrConflict
		}
	}
	if a.Request.BundleSHA != BundleSHA(b) {
		return Version{}, ErrInvalid
	}
	base, e := baselineFor(c, snapshot)
	if e != nil {
		return Version{}, e
	}
	r := Change{Schema: "context-canary-journal/2", Revision: len(s.changes) + 1, Previous: s.head(), SourceSHA: SourceSHA(), Tenant: c.Policy.Tenant, Action: a.Request.Action, At: at.UTC(), Reason: a.Request.Reason, Config: &c, Baseline: &base, Approval: &a}
	if r.Action == "canary" {
		r.Bundle = &b
	} else if r.Action == "rollback" {
		known, ok := s.packages[BundleSHA(b)]
		if !ok || contextlearning.Digest(known) != contextlearning.Digest(b) {
			return Version{}, ErrInvalid
		}
	}
	if e = s.commit(r); e != nil {
		return Version{}, e
	}
	return s.version(*s.last()), nil
}
func (s *Store) Stop(tenant string, expected int, reason string, at time.Time) (View, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.available() != nil {
		return View{}, ErrUnavailable
	}
	if !id.MatchString(tenant) || expected != len(s.changes) || !reasonValid(reason) {
		return View{}, ErrConflict
	}
	if old := s.last(); old != nil && old.Action == "stop" && old.Tenant == tenant {
		return s.view(Config{}, at), nil
	}
	r := Change{Schema: "context-canary-journal/2", Revision: len(s.changes) + 1, Previous: s.head(), SourceSHA: SourceSHA(), Tenant: tenant, Action: "stop", At: at.UTC(), Reason: reason}
	if e := s.commit(r); e != nil {
		return View{}, e
	}
	return s.view(Config{}, at), nil
}
func (s *Store) version(r Change) Version {
	v := Version{Revision: r.Revision, SHA: r.SHA, Action: r.Action, At: r.At, Reason: r.Reason}
	if r.Approval != nil {
		q := r.Approval.Request
		v.BundleSHA = q.BundleSHA
		v.Percent = q.Percent
		v.Until = q.Until
		if b, ok := s.packages[q.BundleSHA]; ok {
			v.CandidateSHA = b.Capsule.Candidate.SHA
		}
	}
	return v
}
func (s *Store) current(c Config, at time.Time) (Change, Bundle, error) {
	if s.available() != nil {
		return Change{}, Bundle{}, ErrUnavailable
	}
	r := s.last()
	if r == nil || r.Action == "stop" {
		return Change{}, Bundle{}, ErrUnavailable
	}
	if at.Before(r.At) || r.Config == nil || contextlearning.Digest(c) != contextlearning.Digest(*r.Config) || !s.policyFloor(c) || !at.Before(r.Approval.Request.Until) {
		return Change{}, Bundle{}, ErrInvalid
	}
	b, ok := s.packages[r.Approval.Request.BundleSHA]
	if !ok {
		return Change{}, Bundle{}, ErrInvalid
	}
	if _, e := assess(c, b, at); e != nil {
		return Change{}, Bundle{}, e
	}
	return clone(*r), clone(b), nil
}
func (s *Store) Current(c Config, at time.Time) (Change, Bundle, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.current(c, at)
}
func (s *Store) View(c Config, at time.Time) View {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.view(c, at)
}
func (s *Store) view(c Config, at time.Time) View {
	v := View{Revision: len(s.changes), Head: s.head(), State: "STOPPED", History: []Version{}, Blockers: []string{}}
	for i := len(s.changes) - 1; i >= 0 && len(v.History) < 16; i-- {
		v.History = append(v.History, s.version(s.changes[i]))
	}
	if r := s.last(); r != nil {
		v.Tenant = r.Tenant
		version := s.version(*r)
		v.Current = &version
		if r.Action != "stop" {
			v.State = "CANARY_OBSERVATION"
			if _, _, e := s.current(c, at); e != nil {
				v.State = "BLOCKED"
				v.Blockers = append(v.Blockers, "current_quality_policy_keys_or_lease_unavailable")
			}
		}
	}
	if s.available() != nil {
		v.State = "UNAVAILABLE"
		v.Blockers = append(v.Blockers, "journal_unavailable")
	}
	return v
}
func (s *Store) Package(sha string) (Bundle, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.available() != nil {
		return Bundle{}, ErrUnavailable
	}
	b, ok := s.packages[sha]
	if !ok {
		return Bundle{}, ErrInvalid
	}
	return clone(b), nil
}
