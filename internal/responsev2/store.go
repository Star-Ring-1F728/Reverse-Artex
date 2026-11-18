package responsev2

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reverse-artex/internal/casememory"
	"reverse-artex/internal/decisions"
	"reverse-artex/internal/protection"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

type Store struct {
	responseBatcher                               *ResponseBatcher // registered once; protected by mu
	commitBatch                                   *journalBatch    // private provisional view; mu stays locked through Sync/rollback
	timings                                       atomic.Pointer[timingMetrics]
	outcomeFacts                                  map[string]outcomeFacts
	retained                                      *retainedJournal
	retentionHook                                 func(string) error
	replayObserver                                func(record) error
	totalEvents, totalAttempts, totalObservations int

	histories              map[string]PolicyHistory
	bindings               map[string]PolicyBinding
	attempts               map[string]ResponseAttempt
	observations           map[string]ResponseObservation
	pendingCases           map[string]int // unresolved response count by case; derived from the journal
	l3Runs                 map[string]L3Run
	bootID                 string
	outcomeFailed          bool
	mu                     sync.Mutex
	file                   *os.File
	owner                  *casememory.Store
	registry               *protection.Registry
	cases                  map[string]Case
	events                 map[string]Evidence
	requests               map[string]string
	leases                 map[string]Lease
	intents                map[string]string
	receipts               map[string]Receipt
	jobs                   map[string]Job
	deadlines              map[string]time.Time
	head                   string
	sequence, epoch        int
	paused, failed, closed bool
	size                   int64
	high                   time.Time
	syncFile               func(*os.File) error
}

func Open(path string, r *protection.Registry) (*Store, error) { return openLegacy(path, r, false) }
func openLegacy(path string, r *protection.Registry, allowPrepared bool) (*Store, error) {
	if !allowPrepared {
		if _, err := os.Lstat(path + ".retained"); err == nil {
			return nil, errors.New("retained journal directory requires explicit retention mode")
		} else if !os.IsNotExist(err) {
			return nil, err
		}
	}

	if retainedRootPresent(path) {
		return nil, errors.New("retained V2 journal requires explicit retention mode")
	}
	if r == nil {
		return nil, ErrUnavailable
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	owner, err := casememory.Open(path + ".owner")
	if err != nil {
		return nil, err
	}
	if st, e := os.Lstat(path); e == nil && !st.Mode().IsRegular() {
		owner.Close()
		return nil, ErrUnavailable
	} else if e != nil && !os.IsNotExist(e) {
		owner.Close()
		return nil, e
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		owner.Close()
		return nil, err
	}
	s, err := newStore(f, owner, r)
	if err != nil {
		f.Close()
		owner.Close()
		return nil, err
	}
	good := false
	defer func() {
		if !good {
			s.Close()
		}
	}()
	st, err := f.Stat()
	if err != nil || st.Size() > 64<<20 {
		return nil, ErrLimit
	}
	reader := bufio.NewReaderSize(f, 64<<10)
	for {
		raw, e := reader.ReadSlice('\n')
		if e == io.EOF && len(raw) == 0 {
			break
		}
		if e != nil || len(raw) > 64<<10 {
			return nil, errors.New("incomplete v2 journal")
		}
		// A legacy reader preserves its historical contract, but retention
		// migration must validate the stricter clock rule before publishing
		// any retained root or checkpoint over the original legacy path.
		if err := s.replayRecordWithClockFence(raw, allowPrepared); err != nil {
			return nil, err
		}
		s.size += int64(len(raw))
	}
	if _, err = f.Seek(0, io.SeekEnd); err != nil {
		return nil, err
	}
	now := time.Now()
	if now.Before(s.high) {
		return nil, errors.New("v2 journal clock rollback; operator recovery required")
	}
	s.restoreDeadlines(now)
	s.markInterrupted()
	good = true
	return s, nil
}
func (s *Store) Close() error {
	s.mu.Lock()
	var batchErr error
	if s.responseBatcher != nil {
		batcher := s.responseBatcher
		s.mu.Unlock()
		batchErr = batcher.Close()
		s.mu.Lock()
	}
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	var fileErr error
	if s.file != nil {
		fileErr = s.file.Close()
	}
	return errors.Join(batchErr, fileErr, s.owner.Close())
}
func (s *Store) apply(r record) {
	s.sequence = r.Sequence
	s.head = r.SHA
	if r.At.After(s.high) {
		s.high = r.At
	}
	if r.Operation == "writer-started" {
		s.markInterrupted()
	}
	if r.Event != nil {
		s.totalEvents++
		s.events[r.Event.ID] = *r.Event
		s.requests[r.Event.Request] = r.Event.ID
	}
	if r.RetiredCase != nil {
		delete(s.cases, r.RetiredCase.ID)
	}
	if r.Case != nil {
		s.cases[r.Case.ID] = *r.Case
	}
	if r.Lease != nil {
		l := *r.Lease
		old, exists := s.leases[l.ID]
		s.leases[l.ID] = l
		if !exists || !old.Expires.Equal(l.Expires) {
			s.deadlines[l.ID] = time.Now().Add(time.Until(l.Expires))
		}
	}
	if r.CommandID != "" {
		s.intents[r.CommandID] = r.CommandSHA
	}
	if r.Intent != nil {
		s.intents[r.Intent.ID] = decisions.Hash(*r.Intent)
	}
	if r.Receipt != nil {
		s.receipts[r.Receipt.Intent] = *r.Receipt
	}
	if r.Epoch != nil {
		s.epoch = *r.Epoch
	}
	if r.Paused != nil {
		s.paused = *r.Paused
	}
	if r.Job != nil {
		s.jobs[r.Job.ID] = *r.Job
	}
	s.applyExtension(r)
}
func (s *Store) commit(r record) error {
	if s.closed || s.failed {
		return ErrUnavailable
	}
	// Every committed timestamp must satisfy the same high-water fence as
	// replay. In particular a completed response must not make a retained
	// journal permanently unreplayable after a wall-clock step backwards.
	if r.At.IsZero() {
		r.At = time.Now().UTC()
	}
	if r.At.Before(s.high) {
		return fmt.Errorf("%w: journal timestamp rollback: record %s precedes high-water %s by %s", ErrUnavailable, r.At.Format(time.RFC3339Nano), s.high.Format(time.RFC3339Nano), s.high.Sub(r.At))
	}
	batchable := s.commitBatch != nil && batchableResponseRecord(r)
	if s.commitBatch != nil && !batchable {
		if err := s.flushJournalBatch(); err != nil {
			return err
		}
	}
	marshalStarted := s.timingStart()
	r.Schema = "response-journal/2"
	r.Sequence = s.sequence + 1
	r.Previous = s.head
	r.Registry = s.registry.Digest()
	r.SHA = recordSHA(r)
	raw, err := json.Marshal(r)
	s.timingEnd(timingMarshal, marshalStarted)
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	if len(raw) > 64<<10 {
		return ErrLimit
	}
	if s.retained != nil {
		if err = s.prepareRetainedAppend(int64(len(raw)), r); err != nil {
			return err
		}
	} else if s.size+int64(len(raw)) > 64<<20 {
		return ErrLimit
	}
	if batchable {
		return s.stageJournalRecord(r, raw)
	}
	writeStarted := s.timingStart()
	n, err := s.file.Write(raw)
	s.timingEnd(timingWrite, writeStarted)
	if err != nil || n != len(raw) {
		s.failed = true
		return ErrUnavailable
	}
	syncStarted := s.timingStart()
	err = s.syncFile(s.file)
	s.timingEnd(timingSync, syncStarted)
	if err != nil {
		s.failed = true
		return ErrUnavailable
	}
	s.apply(r)
	s.size += int64(n)
	if s.retained != nil {
		s.retained.bytes += int64(n)
	}
	if s.commitBatch != nil {
		s.commitBatch.durableSequence = s.sequence
	}
	return nil
}
func (s *Store) check(now time.Time) error {
	if s.closed || s.failed || s.outcomeFailed || now.Before(s.high) {
		return ErrUnavailable
	}
	return nil
}
func clone[T any](v T) T { raw, _ := json.Marshal(v); var out T; json.Unmarshal(raw, &out); return out }
func evidenceKind(p protection.Proof) string {
	if p.Decision == "deny" {
		return "prevented_unauthorized_access"
	}
	if p.Decision == "allow" {
		return "authorized_representation"
	}
	if p.Decision == "unauthenticated" {
		return "authentication_rejected"
	}
	if p.Decision == "not_found" {
		return "object_not_found"
	}
	return "unknown"
}
func (s *Store) Observe(raw string, b protection.RequestBinding, status int, body []byte, now time.Time) (GateResult, error) {
	started := s.timingStart()
	s.mu.Lock()
	s.timingEnd(timingObserveWait, started)
	defer s.mu.Unlock()
	return s.observeLocked(raw, b, status, body, now)
}

// ObserveCurrent samples the live authority time after taking the journal
// lock. A timestamp captured by a concurrent HTTP request before the lock can
// precede a later request's committed high-water mark without a clock rollback.
// Explicit-time Observe remains strict for replay and deterministic fixtures.
func (s *Store) ObserveCurrent(raw string, b protection.RequestBinding, status int, body []byte) (GateResult, error) {
	started := s.timingStart()
	s.mu.Lock()
	s.timingEnd(timingObserveWait, started)
	defer s.mu.Unlock()
	return s.observeLocked(raw, b, status, body, time.Now())
}

func (s *Store) observeLocked(raw string, b protection.RequestBinding, status int, body []byte, now time.Time) (GateResult, error) {
	g, rec, err := s.observationRecordLocked(raw, b, status, body, now)
	if err != nil {
		return GateResult{}, err
	}
	if rec != nil {
		if err = s.commit(*rec); err != nil {
			return GateResult{}, err
		}
	}
	return g, nil
}

// Build an observation without publishing it. Callers commit the returned
// record under the same lock; failed preparation cannot publish half a gate.
func (s *Store) observationRecordLocked(raw string, b protection.RequestBinding, status int, body []byte, now time.Time) (GateResult, *record, error) {
	if err := s.check(now); err != nil {
		return GateResult{}, nil, err
	}
	verifyStarted := s.timingStart()
	p, err := s.registry.Verify(raw, b, status, body, now)
	s.timingEnd(timingObservationVerify, verifyStarted)
	if err != nil {
		return GateResult{}, nil, err
	}
	id := decisions.Hash(raw)
	sc := scope(p, s.registry)
	cid := caseID(sc)
	if prior, ok := s.requests[p.RequestID]; ok {
		if prior != id {
			return GateResult{}, nil, ErrStale
		}
		c := s.cases[cid]
		if c.ID == "" {
			return GateResult{}, nil, ErrStale
		}
		return s.gateEvidence(c, s.events[id], now), nil, nil
	}
	if s.retained != nil {
		if _, found, err := s.archivedRequest(p.RequestID); err != nil {
			s.failed = true
			return GateResult{}, nil, err
		} else if found {
			return GateResult{}, nil, ErrStale
		}
	}
	if err := s.ensureHotCapacity(true, false); err != nil {
		return GateResult{}, nil, err
	}
	if len(s.events) >= 8192 {
		return GateResult{}, nil, ErrLimit
	}
	c, exists := s.cases[cid]
	var retired *caseRetirement
	if !exists && len(s.cases) >= s.caseLimit() {
		retired = s.cleanCaseToRetire(now)
		if retired == nil {
			return GateResult{}, nil, ErrLimit
		}
	}
	e := Evidence{Schema: "authorization-adjudication/2", ID: id, Request: p.RequestID, Scope: sc, Kind: evidenceKind(p), At: now.UTC(), Proof: raw, Binding: b, Status: status, BodyLength: len(body), BodySHA: protection.BodyHash(body)}
	c = caseWithEvidence(c, e)
	return s.gateEvidence(c, e, now), &record{At: now.UTC(), Operation: "adjudicate-and-publish", Event: &e, Case: &c, RetiredCase: retired}, nil
}

func caseWithEvidence(c Case, e Evidence) Case {
	if c.ID == "" {
		c = Case{Schema: "case-evidence-view/2", ID: caseID(e.Scope), Tenant: e.Scope.Tenant, Asset: e.Scope.Asset, Refs: []string{}}
	}
	c.Revision++
	c.Refs = append(append([]string{}, c.Refs...), e.ID)
	if len(c.Refs) > 32 {
		c.Refs = c.Refs[len(c.Refs)-32:]
	}
	c.Updated = e.At
	c.SHA = caseSHA(c)
	return c
}

// Authentication failures, missing objects and unavailable reads are not policy
// targets. Preserve their signed status even when an older lease still exists.
func (s *Store) gateEvidence(c Case, e Evidence, now time.Time) GateResult {
	if e.Status != 200 && e.Status != 403 {
		return GateResult{CaseID: c.ID, CaseSHA: c.SHA}
	}
	return s.gate(c, e.Scope, now)
}
func (s *Store) gate(c Case, sc Scope, now time.Time) GateResult {
	g := GateResult{CaseID: c.ID, CaseSHA: c.SHA}
	if l, ok := s.leases[scopeID(sc)]; ok && len(l.Claims) > 0 && now.Before(l.Expires) && now.Before(s.deadlines[l.ID]) {
		g.Deny = true
		g.PolicyID = l.ID
	}
	return g
}
func (s *Store) viewLocked(tenant, id string, now time.Time) (CaseView, error) {
	c, ok := s.cases[id]
	if !ok || c.Tenant != tenant {
		return CaseView{}, ErrStale
	}
	c.Refs = append([]string(nil), c.Refs...)
	v := CaseView{Case: c, Evidence: []Evidence{}, Candidates: []Candidate{}, PendingReview: false, Coverage: "registered SDK/edge observations only"}
	resources := map[string]bool{}
	eligible := []Evidence{}
	for _, ref := range c.Refs {
		e := s.events[ref]
		// Evidence, Scope and RequestBinding contain immutable strings and
		// value fields only. A value copy is detached without JSON roundtrips
		// for every signed proof on the native request path.
		v.Evidence = append(v.Evidence, e)
		if e.Kind == "unknown" {
			v.PendingReview = true
		}
		if e.Kind == "prevented_unauthorized_access" {
			v.PendingReview = true
		}
		if e.Kind == "prevented_unauthorized_access" && !e.At.Before(now.Add(-time.Minute)) && !e.At.After(now) {
			eligible = append(eligible, e)
			resources[e.Scope.Resource] = true
		}
	}
	if len(eligible) >= 2 && len(resources) >= 2 {
		latest := map[string]Evidence{}
		for _, e := range eligible {
			k := scopeID(e.Scope)
			if prior, ok := latest[k]; !ok || e.At.After(prior.At) {
				latest[k] = e
			}
		}
		for _, e := range latest {
			v.Candidates = append(v.Candidates, Candidate{ID: decisions.Hash([]string{c.SHA, e.ID}), EvidenceID: e.ID, Scope: e.Scope})
		}
	}
	sort.Slice(v.Candidates, func(i, j int) bool { return v.Candidates[i].ID < v.Candidates[j].ID })
	return v, nil
}
func (s *Store) Case(tenant, id string) (CaseView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.check(time.Now()); err != nil {
		return CaseView{}, err
	}
	return s.viewLocked(tenant, id, time.Now())
}
func (s *Store) Cases(tenant string) []Case {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []Case{}
	for _, c := range s.cases {
		if c.Tenant == tenant {
			out = append(out, clone(c))
		}
	}
	return out
}

func newStore(f *os.File, owner *casememory.Store, r *protection.Registry) (*Store, error) {
	s := &Store{file: f, owner: owner, registry: r, cases: map[string]Case{}, events: map[string]Evidence{}, requests: map[string]string{}, leases: map[string]Lease{}, intents: map[string]string{}, receipts: map[string]Receipt{}, jobs: map[string]Job{}, deadlines: map[string]time.Time{}, epoch: 1, syncFile: (*os.File).Sync}
	s.outcomeFacts = map[string]outcomeFacts{}
	s.histories = map[string]PolicyHistory{}
	s.bindings = map[string]PolicyBinding{}
	s.attempts = map[string]ResponseAttempt{}
	s.observations = map[string]ResponseObservation{}
	s.pendingCases = map[string]int{}
	s.l3Runs = map[string]L3Run{}
	s.bootID = newBootID()
	if s.bootID == "" {
		return nil, ErrUnavailable
	}
	return s, nil
}

func (s *Store) replayRecord(raw []byte) error {
	return s.replayRecordWithClockFence(raw, s.retained != nil)
}

func (s *Store) replayRecordWithClockFence(raw []byte, strictClock bool) error {
	var rec record
	if decisions.DecodeStrict(raw, &rec, 64<<10) != nil || rec.Schema != "response-journal/2" || rec.Registry != s.registry.Digest() || rec.Sequence != s.sequence+1 || rec.Previous != s.head || rec.SHA != recordSHA(rec) {
		return errors.New("invalid v2 journal binding or hash chain")
	}
	allowed := map[string]bool{"adjudicate-and-publish": true, "consume-and-install": true, "release-owned-claim": true, "cancel-epoch": true, "reserve-decisions-budget": true, "decisions-not-dispatched": true, "decisions-dispatch-fence": true, "decisions-suppressed": true, "decisions-result": true, "response-prepared": true, "response-observed": true, "l3-reserved": true, "l3-progress": true, "l3-cancelled": true}
	allowed["adjudicate-and-prepare"] = true
	allowed["writer-started"] = true
	if !allowed[rec.Operation] || rec.At.IsZero() {
		return errors.New("invalid v2 operation")
	}
	if rec.CommandID != "" && !decisions.ValidHash(rec.CommandSHA) {
		return errors.New("invalid command binding")
	}
	if strictClock && rec.At.Before(s.high) {
		return fmt.Errorf("retained journal timestamp rollback at sequence %d (%s): record %s precedes high-water %s by %s", rec.Sequence, rec.Operation, rec.At.Format(time.RFC3339Nano), s.high.Format(time.RFC3339Nano), s.high.Sub(rec.At))
	}
	if rec.Event != nil {
		e := rec.Event
		if s.retained != nil {
			if !e.At.Equal(rec.At) {
				return ErrUnavailable
			}
			if _, exists := s.requests[e.Request]; exists {
				return errors.New("duplicate retained SDK request")
			}
			if _, found, err := s.archivedRequest(e.Request); err != nil {
				return err
			} else if found {
				return errors.New("replayed archived SDK request")
			}
		}
		p, err := s.registry.VerifyRecorded(e.Proof, e.Binding, e.Status, e.BodyLength, e.BodySHA, e.At)
		if err != nil || e.ID != decisions.Hash(e.Proof) || e.Scope != scope(p, s.registry) || e.Request != p.RequestID || e.Schema != "authorization-adjudication/2" || e.Kind != evidenceKind(p) {
			return errors.New("invalid signed v2 evidence")
		}
	}
	if rec.Case != nil && rec.Case.SHA != caseSHA(*rec.Case) {
		return errors.New("invalid v2 case revision")
	}
	if err := s.validateExtension(rec); err != nil {
		return err
	}
	if s.replayObserver != nil {
		if err := s.replayObserver(rec); err != nil {
			return err
		}
	}
	s.apply(rec)
	return nil
}
