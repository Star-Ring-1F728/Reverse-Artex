// Package casememory stores local operator case history and label revisions.
// Offline candidate training is isolated from runtime policies and providers.
package casememory

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"reverse-artex/internal/incident"
)

const MaxJournal = 32 << 20
const MaxRecord = 2 << 20
const MaxCases = 512
const MaxHistory = 64

var (
	ErrInvalid     = errors.New("invalid case memory request")
	ErrConflict    = errors.New("case or label revision changed; reload the case")
	ErrNotFound    = errors.New("case memory item not found")
	ErrUnavailable = errors.New("case memory unavailable")
	ErrLimit       = errors.New("case memory capacity reached")
	identity       = regexp.MustCompile(`^[A-Za-z0-9_.:/{}-]{1,128}$`)
	digest         = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

type Revision struct {
	Revision int           `json:"revision"`
	SHA      string        `json:"case_sha256"`
	Source   string        `json:"source_snapshot_sha256"`
	At       time.Time     `json:"saved_at"`
	Case     incident.Case `json:"case"`
}

type Label struct {
	Tenant       string      `json:"tenant_id"`
	CaseID       string      `json:"case_id"`
	Revision     int         `json:"revision"`
	Previous     string      `json:"previous_sha256"`
	CaseSHA      string      `json:"case_sha256"`
	Value        string      `json:"value"`
	Reason       string      `json:"reason"`
	Actor        string      `json:"actor"`
	At           time.Time   `json:"created_at"`
	SHA          string      `json:"label_sha256"`
	Verification *LabelProof `json:"verification,omitempty"`
}

type Entry struct {
	Revisions []Revision `json:"case_revisions"`
	Labels    []Label    `json:"label_history"`
}

type View struct {
	Production   *RuntimeReceipt `json:"production_inference,omitempty"`
	Current      Revision        `json:"current"`
	Labels       []Label         `json:"label_history"`
	History      []Revision      `json:"case_revisions,omitempty"`
	LabelCurrent bool            `json:"label_current"`
}

type LabelRequest struct {
	Expected int    `json:"expected_label_revision"`
	CaseSHA  string `json:"case_sha256"`
	Value    string `json:"value"`
	Reason   string `json:"reason"`
}

type Binding struct {
	CaseID      string `json:"case_id"`
	CaseSHA     string `json:"case_sha256"`
	LabelSHA    string `json:"label_sha256"`
	Label       string `json:"label"`
	EvidenceSHA string `json:"evidence_sha256"`
	Exclusion   string `json:"exclusion_reason,omitempty"`
}

type Selection struct {
	TrustSHA string    `json:"label_trust_sha256,omitempty"`
	Schema   string    `json:"schema"`
	Tenant   string    `json:"tenant_id"`
	Items    []Binding `json:"items"`
	Eligible int       `json:"eligible"`
	Excluded int       `json:"excluded"`
	Total    int       `json:"total"`
	SHA      string    `json:"selection_sha256"`
}

type SelectionView struct {
	Selection    Selection `json:"selection"`
	Reevaluation bool      `json:"reevaluation_required"`
	Changed      []string  `json:"changed_cases"`
}

type record struct {
	ProductionPolicy *ProductionPolicy  `json:"production_policy,omitempty"`
	QualityPlan      *QualityPlan       `json:"quality_plan,omitempty"`
	QualityCohort    *CohortRecord      `json:"quality_cohort,omitempty"`
	QualityProof     *QualityRecord     `json:"quality_proof,omitempty"`
	ProductionChange *ProductionChange  `json:"production_change,omitempty"`
	RuntimeBatch     *RuntimeBatch      `json:"runtime_batch,omitempty"`
	LearningTrust    *LearningTrust     `json:"learning_trust,omitempty"`
	Schema           string             `json:"schema"`
	Sequence         int                `json:"sequence"`
	Previous         string             `json:"previous_sha256"`
	Cases            []Revision         `json:"cases,omitempty"`
	Label            *Label             `json:"label,omitempty"`
	Selection        *Selection         `json:"selection,omitempty"`
	Candidate        *LearningCandidate `json:"learning_candidate,omitempty"`
	ShadowPlan       *ShadowPlan        `json:"shadow_plan,omitempty"`
	ShadowSnapshot   *ShadowSnapshot    `json:"shadow_snapshot,omitempty"`
	ReviewPlan       *ReviewPlan        `json:"review_plan,omitempty"`
	ReviewDecision   *ReviewDecision    `json:"review_decision,omitempty"`
	AutoControl      *AutoControl       `json:"shadow_auto_control,omitempty"`
	AdvisoryChange   *AdvisoryChange    `json:"advisory_change,omitempty"`
	SHA              string             `json:"record_sha256"`
}

type Store struct {
	productionPolicies map[string]ProductionPolicy
	qualityPlans       map[string]QualityPlan
	cohorts            map[string]CohortRecord
	qualityProofs      map[string]QualityRecord
	production         map[string][]ProductionChange
	runtimeReceipts    map[string]RuntimeReceipt
	runtimeLatest      map[string]map[string]RuntimeReceipt
	trust              map[string]LearningTrust
	trustHistory       map[string]LearningTrust
	mu                 sync.Mutex
	file               *os.File
	cases              map[string]Entry
	selections         map[string]Selection
	candidates         map[string]LearningCandidate
	shadows            map[string]shadowState
	reviews            map[string]reviewState
	automatic          map[string][]AutoControl
	advisory           map[string][]AdvisoryChange
	head               string
	sequence           int
	size               int64
	failed             bool
}

func hash(v any) string {
	b, _ := json.Marshal(v)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func caseKey(tenant, id string) string { return hash([]string{tenant, id}) }
func labelHash(l Label) string         { l.SHA = ""; return hash(l) }
func selectionHash(s Selection) string { s.SHA = ""; return hash(s) }
func recordHash(r record) string       { r.SHA = ""; return hash(r) }

// Open owns an exclusive OS lock on the journal until Close. A torn or altered
// journal is refused, never truncated or silently repaired.
func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
		return nil, ErrInvalid
	} else if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = lockOwner(f); err != nil {
		f.Close()
		return nil, errors.New("case memory is already owned or cannot be locked")
	}
	s := &Store{productionPolicies: map[string]ProductionPolicy{}, qualityPlans: map[string]QualityPlan{}, cohorts: map[string]CohortRecord{}, qualityProofs: map[string]QualityRecord{}, production: map[string][]ProductionChange{}, runtimeReceipts: map[string]RuntimeReceipt{}, runtimeLatest: map[string]map[string]RuntimeReceipt{}, trust: map[string]LearningTrust{}, trustHistory: map[string]LearningTrust{}, file: f, cases: map[string]Entry{}, selections: map[string]Selection{}, candidates: map[string]LearningCandidate{}, shadows: map[string]shadowState{}, reviews: map[string]reviewState{}, automatic: map[string][]AutoControl{}, advisory: map[string][]AdvisoryChange{}}
	good := false
	defer func() {
		if !good {
			s.Close()
		}
	}()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() > MaxJournal {
		return nil, ErrLimit
	}
	reader := bufio.NewReaderSize(f, MaxRecord+1)
	for {
		line, err := reader.ReadSlice('\n')
		if err == io.EOF && len(line) == 0 {
			break
		}
		if err != nil || len(line) > MaxRecord {
			return nil, errors.New("incomplete or oversized case memory journal record")
		}
		var r record
		d := json.NewDecoder(bytes.NewReader(line))
		d.DisallowUnknownFields()
		if d.Decode(&r) != nil || d.Decode(new(any)) != io.EOF || r.Schema != "case-memory/1" || r.Sequence != s.sequence+1 || r.Previous != s.head || r.SHA != recordHash(r) {
			return nil, errors.New("invalid case memory hash chain")
		}
		if err := s.validate(r); err != nil {
			return nil, err
		}
		s.apply(r)
		s.size += int64(len(line))
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
	// Closing the locked descriptor atomically releases ownership.
	err := s.file.Close()
	s.file = nil
	return err
}

func (s *Store) available() error {
	if s.failed || s.file == nil {
		return ErrUnavailable
	}
	return nil
}

func (s *Store) append(r record) error {
	if err := s.available(); err != nil {
		return err
	}
	if s.sequence >= 8192 {
		return ErrLimit
	}
	r = clone(r)
	r.Schema, r.Sequence, r.Previous = "case-memory/1", s.sequence+1, s.head
	if err := s.validate(r); err != nil {
		return err
	}
	r.SHA = recordHash(r)
	b, _ := json.Marshal(r)
	b = append(b, '\n')
	if len(b) > MaxRecord || s.size+int64(len(b)) > MaxJournal {
		return ErrLimit
	}
	// Every enabled observer/advisory keeps a sequence and enough bytes for its
	// maximum-size stop record. Unrelated writes cannot consume those slots.
	stops := s.stopReservationsAfter(r)
	if s.sequence+1+stops > 8192 || s.size+int64(len(b))+int64(stops*stopReserveBytes) > MaxJournal {
		return ErrLimit
	}
	n, err := s.file.Write(b)
	if err == nil && n != len(b) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = s.file.Sync()
	}
	if err != nil {
		s.failed = true
		return ErrUnavailable
	}
	s.apply(r)
	s.size += int64(len(b))
	return nil
}

func (s *Store) validate(r record) error {
	kinds := 0
	if r.ProductionPolicy != nil {
		kinds++
	}
	if r.QualityPlan != nil {
		kinds++
	}
	if r.QualityCohort != nil {
		kinds++
	}
	if r.QualityProof != nil {
		kinds++
	}
	if r.ProductionChange != nil {
		kinds++
	}
	if r.RuntimeBatch != nil {
		kinds++
	}
	if r.LearningTrust != nil {
		kinds++
	}
	if len(r.Cases) > 0 {
		kinds++
	}
	if r.Label != nil {
		kinds++
	}
	if r.Selection != nil {
		kinds++
	}
	if r.Candidate != nil {
		kinds++
	}
	if r.ShadowPlan != nil {
		kinds++
	}
	if r.ShadowSnapshot != nil {
		kinds++
	}
	if r.ReviewPlan != nil {
		kinds++
	}
	if r.ReviewDecision != nil {
		kinds++
	}
	if r.AutoControl != nil {
		kinds++
	}
	if r.AdvisoryChange != nil {
		kinds++
	}
	if r.LearningTrust != nil {
		if err := s.validateLearningTrust(*r.LearningTrust); err != nil {
			return err
		}
	}
	if r.ProductionPolicy != nil {
		if err := s.validateProductionPolicy(*r.ProductionPolicy); err != nil {
			return err
		}
	}
	if r.QualityPlan != nil {
		if err := s.validateQualityPlan(*r.QualityPlan); err != nil {
			return err
		}
	}
	if r.QualityCohort != nil {
		if err := s.validateCohort(*r.QualityCohort); err != nil {
			return err
		}
	}
	if r.QualityProof != nil {
		if err := s.validateQualityProof(*r.QualityProof); err != nil {
			return err
		}
	}
	if r.ProductionChange != nil {
		if err := s.validateProductionChange(*r.ProductionChange); err != nil {
			return err
		}
	}
	if r.RuntimeBatch != nil {
		if err := s.validateRuntimeBatch(*r.RuntimeBatch); err != nil {
			return err
		}
	}
	if kinds != 1 {
		return ErrInvalid
	}
	if len(r.Cases) > 0 {
		seen := map[string]bool{}
		added := 0
		manifest := incident.Manifest{Version: 1, Cases: []incident.Case{}}
		for _, rev := range r.Cases {
			c := rev.Case
			k := caseKey(c.Tenant, c.ID)
			e := s.cases[k]
			if seen[k] || rev.Revision != len(e.Revisions)+1 || rev.Revision > MaxHistory || rev.SHA != hash(c) || !digest.MatchString(rev.Source) || rev.At.IsZero() {
				return ErrInvalid
			}
			if len(c.Evidence) == 0 || len(c.Alerts) == 0 || len(c.Evidence) > 1024 || len(c.Alerts) > 1024 {
				return ErrInvalid
			}
			if len(e.Revisions) > 0 {
				old := e.Revisions[len(e.Revisions)-1]
				if rev.SHA == old.SHA || rev.At.Before(old.At) || !extends(old.Case, c) {
					return ErrConflict
				}
			} else {
				added++
			}
			seen[k] = true
			manifest.Cases = append(manifest.Cases, c)
		}
		if len(s.cases)+added > MaxCases {
			return ErrLimit
		}
		if incident.Validate(manifest) != nil {
			return ErrInvalid
		}
	}
	if l := r.Label; l != nil {
		e, ok := s.cases[caseKey(l.Tenant, l.CaseID)]
		if !ok {
			return ErrNotFound
		}
		if l.Revision != len(e.Labels)+1 || l.Revision > MaxHistory || l.CaseSHA != e.Revisions[len(e.Revisions)-1].SHA {
			return ErrConflict
		}
		prev := ""
		if len(e.Labels) > 0 {
			prev = e.Labels[len(e.Labels)-1].SHA
		}
		if l.Previous != prev || l.SHA != labelHash(*l) || !validLabel(l.Value) || strings.TrimSpace(l.Reason) == "" || utf8.RuneCountInString(l.Reason) > 1000 || (l.Verification == nil && l.Actor != "local-operator") || l.At.IsZero() {
			return ErrInvalid
		}
		if l.Verification != nil {
			if err := s.validateLabelProof(*l, e.Revisions[len(e.Revisions)-1]); err != nil {
				return err
			}
		}
		if len(e.Labels) > 0 && l.At.Before(e.Labels[len(e.Labels)-1].At) {
			return ErrInvalid
		}
	}
	if x := r.Selection; x != nil {
		if len(s.selections) >= 256 {
			return ErrLimit
		}
		if x.TrustSHA != "" && (!validTrust(s.trust[x.Tenant]) || x.TrustSHA != hash(s.trust[x.Tenant])) {
			return ErrConflict
		}
		want := s.selectionFor(*x)
		if !identity.MatchString(x.Tenant) || !reflect.DeepEqual(want, *x) {
			return ErrConflict
		}
		if _, exists := s.selections[x.SHA]; exists {
			return ErrConflict
		}
	}
	if c := r.Candidate; c != nil {
		if len(s.candidates) >= MaxCandidates {
			return ErrLimit
		}
		if _, exists := s.candidates[c.ID]; exists || c.CreatedAt.IsZero() || !digest.MatchString(c.TrainerSHA) {
			return ErrInvalid
		}
		dataset, err := s.dataset(c.Tenant, c.Selection.SHA)
		if err != nil {
			return err
		}
		want := trainCandidate(dataset, c.CreatedAt, c.TrainerSHA)
		if !reflect.DeepEqual(want, *c) {
			return ErrInvalid
		}
	}
	if p := r.ShadowPlan; p != nil {
		if len(s.shadows) >= MaxShadowRuns {
			return ErrLimit
		}
		if _, exists := s.shadows[p.ID]; exists || p.StartedAt.IsZero() || !digest.MatchString(p.ObserverSHA) {
			return ErrInvalid
		}
		candidate, ok := s.candidates[p.CandidateID]
		if !ok || candidate.Tenant != p.Tenant {
			return ErrNotFound
		}
		if candidate.TrainingStatus != "fit_complete" || len(s.trainingChanges(candidate)) > 0 {
			return ErrConflict
		}
		want := s.shadowPlan(candidate, p.StartedAt, p.ObserverSHA)
		if !reflect.DeepEqual(want, *p) {
			return ErrInvalid
		}
	}
	if snapshot := r.ShadowSnapshot; snapshot != nil {
		state, ok := s.shadows[snapshot.RunID]
		if !ok {
			return ErrNotFound
		}
		if len(state.Snapshots) >= MaxShadowSnapshots {
			return ErrLimit
		}
		candidate := s.candidates[state.Plan.CandidateID]
		if len(s.trainingChanges(candidate)) > 0 {
			return ErrConflict
		}
		if snapshot.At.IsZero() || snapshot.At.Before(state.Plan.StartedAt) ||
			(len(state.Snapshots) > 0 && snapshot.At.Before(state.Snapshots[len(state.Snapshots)-1].At)) {
			return ErrInvalid
		}
		want, err := s.shadowSnapshot(state, candidate, snapshot.At)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(want, *snapshot) {
			return ErrInvalid
		}
	}
	if p := r.ReviewPlan; p != nil {
		if err := s.validateReviewPlan(*p); err != nil {
			return err
		}
	}
	if d := r.ReviewDecision; d != nil {
		if err := s.validateReviewDecision(*d); err != nil {
			return err
		}
	}
	if c := r.AutoControl; c != nil {
		if err := s.validateAuto(*c); err != nil {
			return err
		}
	}
	if c := r.AdvisoryChange; c != nil {
		if err := s.validateAdvisory(*c); err != nil {
			return err
		}
	}
	return nil
}

func extends(old, next incident.Case) bool {
	if old.ID != next.ID || old.Tenant != next.Tenant || old.Asset != next.Asset || next.First.After(old.First) || next.Last.Before(old.Last) {
		return false
	}
	refs := map[string]bool{}
	alerts := map[string]bool{}
	for _, e := range next.Evidence {
		refs[hash(e)] = true
	}
	for _, a := range next.Alerts {
		alerts[hash(a)] = true
	}
	for _, e := range old.Evidence {
		if !refs[hash(e)] {
			return false
		}
	}
	for _, a := range old.Alerts {
		if !alerts[hash(a)] {
			return false
		}
	}
	return true
}

func (s *Store) apply(r record) {
	if p := r.ProductionPolicy; p != nil {
		s.productionPolicies[p.Tenant] = *p
	}
	if p := r.QualityPlan; p != nil {
		s.qualityPlans[p.ID] = *p
	}
	if p := r.QualityCohort; p != nil {
		s.cohorts[p.Statement.PlanID] = *p
	}
	if p := r.QualityProof; p != nil {
		s.qualityProofs[p.Statement.Report.PlanID] = *p
	}
	if p := r.ProductionChange; p != nil {
		s.production[p.Tenant] = append(s.production[p.Tenant], *p)
	}
	if b := r.RuntimeBatch; b != nil {
		if s.runtimeLatest[b.Tenant] == nil {
			s.runtimeLatest[b.Tenant] = map[string]RuntimeReceipt{}
		}
		for _, receipt := range b.Rows {
			s.runtimeReceipts[runtimeKey(receipt.ReleaseSHA, receipt.CaseSHA)] = receipt
			s.runtimeLatest[b.Tenant][receipt.CaseID] = receipt
		}
	}
	if r.LearningTrust != nil {
		s.trust[r.LearningTrust.Tenant] = *r.LearningTrust
		s.trustHistory[hash(*r.LearningTrust)] = *r.LearningTrust
	}
	for _, rev := range r.Cases {
		k := caseKey(rev.Case.Tenant, rev.Case.ID)
		e := s.cases[k]
		e.Revisions = append(e.Revisions, rev)
		if e.Labels == nil {
			e.Labels = []Label{}
		}
		s.cases[k] = e
	}
	if l := r.Label; l != nil {
		k := caseKey(l.Tenant, l.CaseID)
		e := s.cases[k]
		e.Labels = append(e.Labels, *l)
		s.cases[k] = e
	}
	if x := r.Selection; x != nil {
		s.selections[x.SHA] = *x
	}
	if c := r.Candidate; c != nil {
		s.candidates[c.ID] = *c
	}
	if p := r.ShadowPlan; p != nil {
		s.shadows[p.ID] = shadowState{Plan: *p}
	}
	if snapshot := r.ShadowSnapshot; snapshot != nil {
		state := s.shadows[snapshot.RunID]
		state.Snapshots = append(state.Snapshots, *snapshot)
		s.shadows[snapshot.RunID] = state
	}
	if p := r.ReviewPlan; p != nil {
		s.reviews[p.RunID] = reviewState{Plan: *p}
	}
	if d := r.ReviewDecision; d != nil {
		state := s.reviews[d.RunID]
		state.Decisions = append(state.Decisions, *d)
		s.reviews[d.RunID] = state
	}
	if c := r.AutoControl; c != nil {
		s.automatic[c.RunID] = append(s.automatic[c.RunID], *c)
	}
	if c := r.AdvisoryChange; c != nil {
		s.advisory[c.Tenant] = append(s.advisory[c.Tenant], *c)
	}
	s.head, s.sequence = r.SHA, r.Sequence
}

// Sync imports an atomic set of changed projections from a verified snapshot.
// Re-importing unchanged cases creates no record and never invalidates labels.
func (s *Store) Sync(m incident.Manifest, source string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return 0, err
	}
	if !digest.MatchString(source) || incident.Validate(m) != nil {
		return 0, ErrInvalid
	}
	present := map[string]bool{}
	for _, c := range m.Cases {
		present[caseKey(c.Tenant, c.ID)] = true
	}
	for key := range s.cases {
		if !present[key] {
			return 0, ErrConflict
		}
	}
	changes := []Revision{}
	at := time.Now().UTC()
	for _, c := range m.Cases {
		e := s.cases[caseKey(c.Tenant, c.ID)]
		sha := hash(c)
		if len(e.Revisions) > 0 && e.Revisions[len(e.Revisions)-1].SHA == sha {
			continue
		}
		changes = append(changes, Revision{len(e.Revisions) + 1, sha, source, at, c})
	}
	if len(changes) == 0 {
		return 0, s.captureLearningLocked()
	}
	if err := s.append(record{Cases: changes}); err != nil {
		return 0, err
	}
	return len(changes), s.captureLearningLocked()
}

func makeView(e Entry, history bool) View {
	v := View{Current: e.Revisions[len(e.Revisions)-1], Labels: e.Labels}
	if history {
		v.History = e.Revisions
	}
	v.LabelCurrent = len(e.Labels) > 0 && e.Labels[len(e.Labels)-1].CaseSHA == v.Current.SHA
	return v
}

// Return detached data so callers cannot change the journal-backed state.
func clone[T any](value T) T {
	b, _ := json.Marshal(value)
	var out T
	_ = json.Unmarshal(b, &out)
	return out
}

func (s *Store) List(tenant string) ([]View, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return nil, err
	}
	out := []View{}
	for _, e := range s.cases {
		if e.Revisions[0].Case.Tenant == tenant {
			out = append(out, s.attachRuntime(makeView(e, false)))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Current.Case.ID < out[j].Current.Case.ID })
	return clone(out), nil
}

func (s *Store) Get(tenant, id string) (View, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return View{}, err
	}
	e, ok := s.cases[caseKey(tenant, id)]
	if !ok {
		return View{}, ErrNotFound
	}
	return clone(s.attachRuntime(makeView(e, true))), nil
}

func validLabel(v string) bool {
	return v == "confirmed_attack" || v == "confirmed_benign" || v == "uncertain" || v == "disputed"
}

func (s *Store) SetLabel(tenant, id string, q LabelRequest) (Label, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return Label{}, err
	}
	e, ok := s.cases[caseKey(tenant, id)]
	if !ok {
		return Label{}, ErrNotFound
	}
	if q.Expected != len(e.Labels) || q.CaseSHA != e.Revisions[len(e.Revisions)-1].SHA {
		return Label{}, ErrConflict
	}
	previous := ""
	if len(e.Labels) > 0 {
		previous = e.Labels[len(e.Labels)-1].SHA
	}
	l := Label{Tenant: tenant, CaseID: id, Revision: q.Expected + 1, Previous: previous, CaseSHA: q.CaseSHA, Value: q.Value, Reason: strings.TrimSpace(q.Reason), Actor: "local-operator", At: time.Now().UTC()}
	l.SHA = labelHash(l)
	// Freeze any newly synced automatic predictions before a label can be written.
	if err := s.captureAutomaticLocked(); err != nil {
		return Label{}, err
	}
	l.At = time.Now().UTC()
	l.SHA = labelHash(l)
	if err := s.append(record{Label: &l}); err != nil {
		return Label{}, err
	}
	return l, s.captureAutomaticLocked()
}

func (s *Store) selectCases(tenant string) Selection {
	x := Selection{Schema: "case-learning-selection/1", Tenant: tenant, Items: []Binding{}}
	refs := map[string][]int{}
	keys := []string{}
	for k, e := range s.cases {
		if e.Revisions[0].Case.Tenant == tenant {
			keys = append(keys, k)
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		return s.cases[keys[i]].Revisions[0].Case.ID < s.cases[keys[j]].Revisions[0].Case.ID
	})
	for _, k := range keys {
		e := s.cases[k]
		rev := e.Revisions[len(e.Revisions)-1]
		b := Binding{CaseID: rev.Case.ID, CaseSHA: rev.SHA, EvidenceSHA: hash(rev.Case.Evidence), Exclusion: "unlabeled"}
		if len(e.Labels) > 0 {
			l := e.Labels[len(e.Labels)-1]
			b.LabelSHA, b.Label = l.SHA, l.Value
			switch {
			case l.CaseSHA != rev.SHA:
				b.Exclusion = "stale_label"
			case l.Value == "uncertain" || l.Value == "disputed":
				b.Exclusion = l.Value
			default:
				b.Exclusion = ""
			}
		}
		index := len(x.Items)
		{
			for _, ref := range rev.Case.Evidence {
				key := hash([]string{ref.Stream, ref.Tenant, ref.Asset, ref.EventID, ref.LineSHA})
				refs[key] = append(refs[key], index)
			}
		}
		x.Items = append(x.Items, b)
	}
	// Shared source records must never be counted as independent training
	// samples. Exclude every overlapping case, and retain conflict reasons.
	for _, indices := range refs {
		if len(indices) < 2 {
			continue
		}
		reason := "duplicate_evidence"
		labels := map[string]bool{}
		for _, i := range indices {
			if x.Items[i].Label != "" {
				labels[x.Items[i].Label] = true
			}
		}
		if len(labels) > 1 {
			reason = "conflicting_labels"
		}
		for _, i := range indices {
			if x.Items[i].Exclusion == "" || x.Items[i].Exclusion == "duplicate_evidence" {
				x.Items[i].Exclusion = reason
			}
		}
	}
	for _, b := range x.Items {
		if b.Exclusion == "" {
			x.Eligible++
		} else {
			x.Excluded++
		}
	}
	x.Total = len(x.Items)
	x.SHA = selectionHash(x)
	return x
}

func (s *Store) Select(tenant string, save bool) (Selection, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return Selection{}, err
	}
	if !identity.MatchString(tenant) {
		return Selection{}, ErrInvalid
	}
	x := s.selectCases(tenant)
	if save {
		if _, ok := s.selections[x.SHA]; !ok {
			if err := s.append(record{Selection: &x}); err != nil {
				return Selection{}, err
			}
		}
	}
	return clone(x), nil
}

func (s *Store) SavedSelection(tenant, sha string) (SelectionView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return SelectionView{}, err
	}
	old, ok := s.selections[sha]
	if !ok || old.Tenant != tenant {
		return SelectionView{}, ErrNotFound
	}
	current := s.selectionFor(old)
	bindings := map[string]Binding{}
	for _, b := range old.Items {
		bindings[b.CaseID] = b
	}
	changed := []string{}
	for _, b := range current.Items {
		if previous, ok := bindings[b.CaseID]; !ok || previous != b {
			changed = append(changed, b.CaseID)
		}
	}
	return clone(SelectionView{old, old.SHA != current.SHA, changed}), nil
}

type Summary struct {
	ID           string    `json:"case_id"`
	Tenant       string    `json:"tenant_id"`
	Asset        string    `json:"asset_id"`
	Revision     int       `json:"revision"`
	Evidence     int       `json:"evidence_count"`
	Alerts       int       `json:"alert_count"`
	Last         time.Time `json:"last_alert_at"`
	Label        *Label    `json:"label,omitempty"`
	LabelCurrent bool      `json:"label_current"`
}

func (s *Store) Summaries(tenant string) ([]Summary, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return nil, err
	}
	out := []Summary{}
	for _, e := range s.cases {
		rev := e.Revisions[len(e.Revisions)-1]
		c := rev.Case
		if c.Tenant != tenant {
			continue
		}
		summary := Summary{ID: c.ID, Tenant: c.Tenant, Asset: c.Asset, Revision: rev.Revision, Evidence: len(c.Evidence), Alerts: len(c.Alerts), Last: c.Last}
		if len(e.Labels) > 0 {
			l := e.Labels[len(e.Labels)-1]
			summary.Label = &l
			summary.LabelCurrent = l.CaseSHA == rev.SHA
		}
		out = append(out, summary)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return clone(out), nil
}
