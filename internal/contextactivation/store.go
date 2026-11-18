package contextactivation

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reverse-artex/internal/casememory"
	"reverse-artex/internal/contextevaluation"
	"reverse-artex/internal/contextlearning"
	"reverse-artex/internal/contextshadow"
	"reverse-artex/internal/contractjson"
	"reverse-artex/internal/evidence"
	"sync"
	"time"
)

// Checked can only be obtained by replaying the current canary, evidence and
// signed-label journals. It retains their owners through approval persistence.
type Checked struct {
	eval     *contextevaluation.Session
	memory   *casememory.Store
	basis    Basis
	snapshot *evidence.Snapshot
	plan     string
}

func OpenCheck(profile, release, plan, source, memory string, at time.Time) (*Checked, error) {
	e, e1 := contextevaluation.Open(profile, release)
	if e1 != nil {
		return nil, e1
	}
	m, e1 := casememory.Open(memory)
	if e1 != nil {
		e.Close()
		return nil, e1
	}
	snapshot, e1 := evidence.Capture(source)
	if e1 != nil {
		m.Close()
		e.Close()
		return nil, e1
	}
	x := &Checked{eval: e, memory: m, snapshot: snapshot, plan: plan}
	if e1 = x.refresh(at); e1 != nil {
		x.Close()
		return nil, e1
	}
	return x, nil
}
func (c *Checked) refresh(at time.Time) error {
	if c == nil || c.eval == nil || c.memory == nil {
		return ErrInvalid
	}
	r, e := c.eval.Assess(c.snapshot, c.memory, c.plan, at)
	if e != nil {
		return e
	}
	cfg, v, e := c.eval.ApprovalBinding()
	if e != nil {
		return e
	}
	c.basis = Basis{Config: cfg, Version: v, Report: r}
	_, e = validateBasis(c.basis, at)
	return e
}
func (c *Checked) Basis() Basis { return clone(c.basis) }
func (c *Checked) Close() error {
	var e1, e2 error
	if c.memory != nil {
		e1 = c.memory.Close()
		c.memory = nil
	}
	if c.eval != nil {
		e2 = c.eval.Close()
		c.eval = nil
	}
	return errors.Join(e1, e2)
}

type Store struct {
	mu       sync.Mutex
	path     string
	file     *os.File
	owner    *casememory.Store
	changes  []Change
	size     int
	failed   bool
	syncFile func(*os.File) error
}

func Open(path string) (*Store, error) {
	path, e := filepath.Abs(path)
	if e != nil {
		return nil, e
	}
	if e = os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return nil, e
	}
	owner, e := casememory.Open(path + ".owner")
	if e != nil {
		return nil, e
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
	f, e := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	s := &Store{path: path, file: f, owner: owner, changes: []Change{}, syncFile: (*os.File).Sync}
	defer func() {
		if !good {
			f.Close()
		}
	}()
	st, e := f.Stat()
	if e != nil {
		return nil, e
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
		var c Change
		if contractjson.Decode(raw, &c, MaxRecord, 32768) != nil || c.SHA != changeSHA(c) || s.validate(c) != nil {
			return nil, ErrUnavailable
		}
		s.changes = append(s.changes, c)
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
func (s *Store) last() *Change {
	if len(s.changes) == 0 {
		return nil
	}
	return &s.changes[len(s.changes)-1]
}
func (s *Store) head() string {
	if c := s.last(); c != nil {
		return c.SHA
	}
	return ""
}
func (s *Store) floor(p Policy) bool {
	for _, c := range s.changes {
		if c.Policy != nil && (p.Revision < c.Policy.Revision || p.Revision == c.Policy.Revision && contextlearning.Digest(p) != contextlearning.Digest(*c.Policy)) {
			return false
		}
	}
	return true
}
func (s *Store) known(release, candidate string) bool {
	for _, c := range s.changes {
		if c.Approval != nil && c.Approval.Request.ReleaseSHA == release && c.Approval.Request.CandidateSHA == candidate {
			return true
		}
	}
	return false
}
func (s *Store) validate(c Change) error {
	if c.Schema != "context-production-journal/2" || c.Revision != len(s.changes)+1 || c.Previous != s.head() || c.SourceSHA != SourceSHA() || !identifier.MatchString(c.Tenant) || c.At.IsZero() || !reasonValid(c.Reason) || len(s.changes) >= MaxChanges {
		return ErrInvalid
	}
	if old := s.last(); old != nil && (old.Tenant != c.Tenant || c.At.Before(old.At)) {
		return ErrInvalid
	}
	if c.Action == "stop" {
		if c.Policy != nil || c.Basis != nil || c.Approval != nil {
			return ErrInvalid
		}
		return nil
	}
	if c.Action != "activate" && c.Action != "rollback" || c.Policy == nil || c.Basis == nil || c.Approval == nil || !s.floor(*c.Policy) {
		return ErrInvalid
	}
	a := *c.Approval
	q := a.Request
	if a.Tenant != c.Tenant || q.Action != c.Action || q.Expected != len(s.changes) || q.Previous != s.head() || q.Reason != c.Reason {
		return ErrConflict
	}
	for _, old := range s.changes {
		if old.Approval != nil && old.Approval.Request.Nonce == q.Nonce {
			return ErrConflict
		}
	}
	if c.Action == "rollback" && !s.known(q.ReleaseSHA, q.CandidateSHA) {
		return ErrInvalid
	}
	if old := s.last(); old != nil && old.Action != "stop" && old.Approval != nil && old.Approval.Request.CandidateSHA == q.CandidateSHA {
		return ErrConflict
	}
	return verifyApproval(*c.Policy, *c.Basis, a, c.At)
}
func (s *Store) commit(c Change) error {
	if s.available() != nil {
		return ErrUnavailable
	}
	if e := s.validate(c); e != nil {
		return e
	}
	c = clone(c)
	c.SHA = changeSHA(c)
	raw, _ := json.Marshal(c)
	raw = append(raw, '\n')
	reserve, slots := 0, 0
	if c.Action != "stop" {
		reserve, slots = stopReserve, 1
	}
	if len(raw) > MaxRecord || s.size+len(raw)+reserve > MaxJournal || len(s.changes)+1+slots > MaxChanges {
		return ErrLimit
	}
	n, e := s.file.Write(raw)
	if e == nil && n != len(raw) {
		e = io.ErrShortWrite
	}
	if e == nil {
		e = s.syncFile(s.file)
	}
	if e != nil {
		s.failed = true
		return ErrUnavailable
	}
	s.changes = append(s.changes, c)
	s.size += len(raw)
	return nil
}
func (s *Store) Prepare(p Policy, c *Checked, action string, until time.Time, nonce, reason string, at time.Time) (Request, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.available() != nil {
		return Request{}, ErrUnavailable
	}
	if e := c.refresh(at); e != nil {
		return Request{}, e
	}
	b := c.basis
	limit, e := validateBasis(b, at)
	if e != nil || ValidatePolicy(p, b.Config) != nil || !p.Enabled || !s.floor(p) || action != "activate" && action != "rollback" || !at.Before(until) || until.After(limit) || !pin.MatchString(nonce) || !reasonValid(reason) {
		return Request{}, ErrInvalid
	}
	if action == "rollback" && !s.known(b.Report.ReleaseSHA, b.Report.CandidateSHA) {
		return Request{}, ErrInvalid
	}
	return Request{Expected: len(s.changes), Previous: s.head(), Action: action, PolicySHA: contextlearning.Digest(p), BasisSHA: BasisSHA(b), ReviewSHA: ReviewSHA(b.Report), ReleaseSHA: b.Report.ReleaseSHA, CandidateSHA: b.Report.CandidateSHA, PlanSHA: b.Report.PlanSHA, Until: until, Nonce: nonce, Reason: reason}, nil
}
func (s *Store) Approve(p Policy, c *Checked, a Approval, at time.Time) (View, error) {
	return s.ApproveCurrent(c, a, at, func() (Policy, error) { return p, nil })
}

// ApproveCurrent reloads operator policy after the potentially long review,
// immediately before validating and committing the signed request.
func (s *Store) ApproveCurrent(c *Checked, a Approval, at time.Time, policy func() (Policy, error)) (View, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.available() != nil {
		return View{}, ErrUnavailable
	}
	for _, old := range s.changes {
		if old.Approval != nil && old.Approval.Request.Nonce == a.Request.Nonce {
			if contextlearning.Digest(*old.Approval) == contextlearning.Digest(a) {
				return s.view(), nil
			}
			return View{}, ErrConflict
		}
	}
	if e := c.refresh(at); e != nil {
		return View{}, e
	}
	if policy == nil {
		return View{}, ErrInvalid
	}
	p, err := policy()
	if err != nil {
		return View{}, err
	}
	b := c.basis
	row := Change{Schema: "context-production-journal/2", Revision: len(s.changes) + 1, Previous: s.head(), SourceSHA: SourceSHA(), Tenant: p.Tenant, Action: a.Request.Action, At: at.UTC(), Reason: a.Request.Reason, Policy: &p, Basis: &b, Approval: &a}
	if e := s.commit(row); e != nil {
		return View{}, e
	}
	return s.view(), nil
}
func (s *Store) Stop(tenant string, expected int, reason string, at time.Time) (View, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.available() != nil {
		return View{}, ErrUnavailable
	}
	if !identifier.MatchString(tenant) || expected != len(s.changes) || !reasonValid(reason) {
		return View{}, ErrConflict
	}
	if old := s.last(); old != nil && old.Action == "stop" && old.Tenant == tenant {
		return s.view(), nil
	}
	c := Change{Schema: "context-production-journal/2", Revision: len(s.changes) + 1, Previous: s.head(), SourceSHA: SourceSHA(), Tenant: tenant, Action: "stop", At: at.UTC(), Reason: reason}
	if e := s.commit(c); e != nil {
		return View{}, e
	}
	return s.view(), nil
}
func (s *Store) view() View {
	v := View{Revision: len(s.changes), Head: s.head(), State: "STOPPED", MandatoryReviewPreserved: true}
	if c := s.last(); c != nil {
		v.Tenant = c.Tenant
		copy := clone(*c)
		v.Current = &copy
		if c.Action != "stop" {
			v.State = "REVALIDATION_REQUIRED"
		}
	}
	if s.available() != nil {
		v.State = "UNAVAILABLE"
	}
	return v
}
func (s *Store) View() View { s.mu.Lock(); defer s.mu.Unlock(); return s.view() }
func (s *Store) Current(p Policy, at time.Time) (Change, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.available() != nil {
		return Change{}, ErrUnavailable
	}
	c := s.last()
	if c == nil || c.Action == "stop" || c.Policy == nil || c.Basis == nil || c.Approval == nil || at.Before(c.At) || !at.Before(c.Approval.Request.Until) || contextlearning.Digest(p) != contextlearning.Digest(*c.Policy) || !s.floor(p) {
		return Change{}, ErrInvalid
	}
	if ValidatePolicy(p, c.Basis.Config) != nil || !p.Enabled {
		return Change{}, ErrInvalid
	}
	if _, e := validateBasis(*c.Basis, at); e != nil {
		return Change{}, e
	}
	return clone(*c), nil
}

// ReadPublic is shared by the offline CLI; unknown/duplicate JSON fields fail.
func ReadPublic(path string, v any) error { return contextshadow.ReadPublic(path, v) }
