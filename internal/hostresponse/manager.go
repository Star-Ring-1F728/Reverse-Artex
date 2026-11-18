// Package hostresponse separates observation from operator-approved workload
// actions. Simulation is the default; a separately deployed Linux namespace
// adapter requires explicit operator configuration and transport credentials.
package hostresponse

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reverse-artex/internal/evidence"
	"reverse-artex/internal/hostguard"
	"sort"
	"sync"
	"time"
)

type Lease struct {
	ID               string    `json:"action_id"`
	CaseID           string    `json:"case_id"`
	Workload         string    `json:"workload_id"`
	Tenant           string    `json:"tenant_id"`
	Asset            string    `json:"asset_id"`
	Issued           time.Time `json:"issued_at"`
	Expires          time.Time `json:"expires_at"`
	State            string    `json:"state"`
	Key              string    `json:"idempotency_key"`
	Hash             string    `json:"command_hash"`
	ReleaseRequested bool      `json:"release_requested,omitempty"`
	UnknownReason    string    `json:"unknown_reason,omitempty"`
}

// Adapters must be idempotent by action ID and enforce Expires independently of
// controller availability. No adapter may accept arbitrary shell/network targets.
type Adapter interface {
	Apply(Lease) error
	// Status must query authoritative adapter state without applying/releasing.
	// Missing history must be unknown, unless absence is actually established.
	// Return the complete original binding, including the fixed expiry.
	Status(Lease, time.Time) (Lease, error)
	Release(string) error
}
type Approve struct {
	Key    string `json:"idempotency_key"`
	CaseID string `json:"case_id"`
	TTL    int    `json:"ttl_seconds"`
}
type record struct {
	Sequence      int              `json:"sequence"`
	Case          *hostguard.Alert `json:"case,omitempty"`
	Action        *Lease           `json:"action,omitempty"`
	Time          time.Time        `json:"recorded_at,omitempty"`
	Authorization *HostSigned      `json:"authorization,omitempty"`
	Previous      string           `json:"previous_sha256,omitempty"`
	SHA           string           `json:"record_sha256,omitempty"`
}
type Manager struct {
	evidence    *evidence.Store
	mu          sync.Mutex
	dir         string
	sequence    int
	engine      *hostguard.Engine
	cases       map[string]hostguard.Alert
	actions     map[string]Lease
	keys        map[string]string
	adapter     Adapter
	Budget      int64
	auditFailed bool
	lastTime    time.Time
	clock       func() time.Time
	signing     *hostSigning
}

func Open(dir string, a Adapter, canaries []string) (*Manager, error) {
	m, err := OpenAt(dir, a, canaries, time.Now().UTC())
	if err == nil {
		m.clock = func() time.Time { return time.Now().UTC() }
	}
	return m, err
}

// OpenAt is explicit offline replay. Reopening never reapplies a saved action;
// every unresolved lease is first persisted as unknown for status reconciliation.
func OpenAt(dir string, a Adapter, canaries []string, now time.Time) (*Manager, error) {
	return openAt(dir, a, canaries, now, nil)
}
func openAt(dir string, a Adapter, canaries []string, now time.Time, signing *hostSigning) (*Manager, error) {
	if a == nil {
		return nil, errors.New("adapter required")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	if now.IsZero() {
		return nil, errors.New("explicit host recovery time required")
	}
	m := &Manager{dir: dir, engine: hostguard.New(canaries), cases: map[string]hostguard.Alert{}, actions: map[string]Lease{}, keys: map[string]string{}, adapter: a, Budget: 8 << 20, clock: func() time.Time { return now }, signing: signing}
	if signing == nil {
		for _, name := range []string{"signed-context.json", "signed-owner"} {
			if _, err := os.Lstat(filepath.Join(dir, name)); !os.IsNotExist(err) {
				return nil, errors.New("signed host mode required for this ledger")
			}
		}
	}
	var err error
	m.evidence, err = evidence.NewRotating(filepath.Join(dir, "evidence"), 8<<20, 1<<20)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(filepath.Join(dir, "host-actions.jsonl"))
	if os.IsNotExist(err) {
		return m, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if st.Size() > m.Budget {
		return nil, errors.New("host audit budget exceeded")
	}
	if st.Size() > 0 {
		var tail [1]byte
		if _, err = f.ReadAt(tail[:], st.Size()-1); err != nil || tail[0] != '\n' {
			return nil, errors.New("incomplete host audit")
		}
	}
	scan := bufio.NewScanner(f)
	scan.Buffer(make([]byte, 4096), 16384)
	for scan.Scan() {
		var r record
		if decodeHostJSON(scan.Bytes(), &r, 16384) != nil || r.Sequence != m.sequence+1 || (r.Case == nil) == (r.Action == nil) || (!r.Time.IsZero() && r.Time.Before(m.lastTime)) {
			return nil, errors.New("invalid host audit chain")
		}
		if err := m.checkSignedRecord(r); err != nil {
			return nil, err
		}
		if r.Case != nil {
			c := r.Case
			if !hostguard.ID.MatchString(c.CaseID) || (c.RuleID != "RA-006" && c.RuleID != "RA-008") || c.Quality != "complete" || !hostguard.ID.MatchString(c.Workload) || c.Time.IsZero() || len(c.Evidence) == 0 || len(m.cases) >= 4096 {
				return nil, errors.New("invalid audited case")
			}
		}
		if r.Action != nil {
			p := r.Action
			c, ok := m.cases[p.CaseID]
			if !ok || !hostguard.ID.MatchString(p.ID) || !hostguard.ID.MatchString(p.Key) || p.Workload != c.Workload || p.Tenant != c.Tenant || p.Asset != c.Asset || !p.Expires.After(p.Issued) || p.Expires.Sub(p.Issued) > time.Minute || !validState(p.State) || !validReason(p.UnknownReason) || (p.State != "unknown" && p.UnknownReason != "") {
				return nil, errors.New("invalid audited lease")
			}
			ttl := p.Expires.Sub(p.Issued)
			if len(p.Hash) != 64 || p.Hash != digest(Approve{Key: p.Key, CaseID: p.CaseID, TTL: int(ttl / time.Second)}) || p.ID != "isolate-"+p.Hash[:32] || ttl%time.Second != 0 || p.Issued.Before(c.Time) || p.Issued.Sub(c.Time) > time.Minute {
				return nil, errors.New("invalid audited approval")
			}
			if _, exists := m.actions[p.ID]; !exists && p.State != "pending" {
				return nil, errors.New("missing audited action intent")
			}
			if old, exists := m.actions[p.ID]; exists && (!sameBinding(old, *p) || (old.ReleaseRequested && !p.ReleaseRequested) || (terminal(old.State) && p.State != old.State)) {
				return nil, errors.New("host lease resurrection or mutation")
			}
		}
		m.replay(r)
	}
	if scan.Err() != nil {
		return nil, scan.Err()
	}
	if now.Before(m.lastTime) {
		return nil, errors.New("host ledger clock moved backwards")
	}
	ids := make([]string, 0, len(m.actions))
	for id := range m.actions {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		p := m.actions[id]
		if terminal(p.State) || p.State == "unknown" {
			continue
		}
		p.ReleaseRequested = p.ReleaseRequested || p.State == "releasing"
		p.State, p.UnknownReason = "unknown", "recovered_unconfirmed"
		if err := m.commit(record{Action: &p, Time: now}); err != nil {
			return nil, err
		}
	}
	return m, nil
}
func (m *Manager) replay(r record) {
	m.sequence = r.Sequence
	if !r.Time.IsZero() {
		m.lastTime = r.Time
	}
	if r.Case != nil {
		m.cases[r.Case.CaseID] = *r.Case
	}
	if r.Action != nil {
		m.actions[r.Action.ID] = *r.Action
		m.keys[r.Action.Key] = r.Action.ID
	}
	if m.signing != nil {
		m.signing.head = r.SHA
		if r.Authorization != nil {
			m.signing.nonces[r.Authorization.Command.Nonce] = true
		}
	}
}
func (m *Manager) commit(r record) error {
	if m.auditFailed {
		return errors.New("host audit unavailable")
	}
	if r.Time.IsZero() || r.Time.Before(m.lastTime) {
		return errors.New("host ledger clock moved backwards")
	}
	r.Sequence = m.sequence + 1
	if m.signing != nil {
		r.Previous = m.signing.head
		r.SHA = signedRecordSHA(r)
	}
	if err := m.checkSignedRecord(r); err != nil {
		return err
	}
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	f, err := os.OpenFile(filepath.Join(m.dir, "host-actions.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if st.Size()+int64(len(b)) > m.Budget {
		return errors.New("host audit budget exceeded")
	}
	n, err := f.Write(b)
	if err != nil || n != len(b) {
		m.auditFailed = true
		return errors.New("host audit incomplete write")
	}
	if err = f.Sync(); err != nil {
		m.auditFailed = true
		return err
	}
	m.replay(r)
	return nil
}
func (m *Manager) Observe(e hostguard.Event, now time.Time) ([]hostguard.Alert, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.ready(now); err != nil {
		return nil, "unavailable", err
	}
	if e.Validate(now) != nil {
		return nil, "invalid", errors.New("invalid host observation")
	}
	e.IngestTime = now
	if err := m.evidence.Append("host-events", e); err != nil {
		return nil, "evidence_failed", err
	}
	alerts, status, _ := m.engine.Process(e, now)
	for i := range alerts {
		if len(m.cases) >= 4096 {
			return nil, "capacity_rejected", errors.New("case budget exceeded")
		}
		if err := m.commit(record{Case: &alerts[i], Time: now}); err != nil {
			return nil, "audit_failed", err
		}
	}
	return alerts, status, nil
}
func digest(v any) string {
	b, _ := json.Marshal(v)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func terminal(s string) bool { return s == "released" || s == "expired" || s == "not_applied" }
func validState(s string) bool {
	return s == "pending" || s == "active" || s == "releasing" || s == "unknown" || terminal(s)
}
func validReason(s string) bool {
	switch s {
	case "", "recovered_unconfirmed", "apply_unconfirmed", "release_unconfirmed", "status_unavailable", "status_unknown", "status_mismatch", "active_after_expiry", "clock_mismatch", "dispatch_expired", "case_expired", "authorization_expired":
		return true
	}
	return false
}
func sameBinding(a, b Lease) bool {
	return a.ID == b.ID && a.CaseID == b.CaseID && a.Workload == b.Workload && a.Tenant == b.Tenant && a.Asset == b.Asset && a.Key == b.Key && a.Hash == b.Hash && a.Issued.Equal(b.Issued) && a.Expires.Equal(b.Expires)
}
func (m *Manager) ready(now time.Time) error {
	if m.auditFailed {
		return errors.New("host audit unavailable")
	}
	if now.IsZero() || now.Before(m.lastTime) {
		return errors.New("host ledger clock moved backwards")
	}
	return nil
}
func (m *Manager) unknown(a Lease, reason string, now time.Time, cause error) (Lease, error) {
	a.State, a.UnknownReason = "unknown", reason
	if old := m.actions[a.ID]; old.State != a.State || old.UnknownReason != reason || old.ReleaseRequested != a.ReleaseRequested {
		if err := m.commit(record{Action: &a, Time: now}); err != nil {
			return m.actions[a.ID], errors.Join(cause, err)
		}
	}
	return a, cause
}

// readAdapter never mutates the adapter. A successful transport acknowledgment
// alone is not an observed state, and an adapter may not change the binding.
func (m *Manager) readAdapter(a Lease, now time.Time) (Lease, string, error) {
	observed, err := m.adapter.Status(a, now)
	if err != nil {
		return Lease{}, "status_unavailable", err
	}
	if !sameBinding(a, observed) || (observed.State != "active" && observed.State != "unknown" && !terminal(observed.State)) {
		return Lease{}, "status_mismatch", errors.New("adapter status binding/state mismatch")
	}
	if now.Before(a.Issued) {
		return Lease{}, "clock_mismatch", errors.New("adapter observation precedes issued lease")
	}
	if observed.State == "unknown" {
		return observed, "status_unknown", errors.New("adapter status unknown; no action retried")
	}
	if observed.State == "active" && !now.Before(a.Expires) {
		return observed, "active_after_expiry", errors.New("adapter reports active after fixed expiry")
	}
	if observed.State == "expired" && now.Before(a.Expires) {
		return observed, "status_mismatch", errors.New("adapter expiry precedes fixed deadline")
	}
	return observed, "", nil
}
func (m *Manager) saveObserved(a, observed Lease, now time.Time) (Lease, error) {
	a.State, a.UnknownReason = observed.State, ""
	if a.ReleaseRequested && a.State == "active" {
		a.State = "releasing"
	}
	old := m.actions[a.ID]
	if old.State != a.State || old.UnknownReason != a.UnknownReason || old.ReleaseRequested != a.ReleaseRequested {
		if err := m.commit(record{Action: &a, Time: now}); err != nil {
			return old, err
		}
	}
	return a, nil
}
func (m *Manager) query(a Lease, now time.Time) (Lease, error) {
	observed, reason, err := m.readAdapter(a, now)
	if err != nil {
		return m.unknown(a, reason, now, err)
	}
	return m.saveObserved(a, observed, now)
}
func (m *Manager) Approve(c Approve, now time.Time) (Lease, error) {
	return m.approve(c, now, nil)
}
func (m *Manager) approve(c Approve, now time.Time, authorization *HostSigned) (Lease, error) {
	started := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.ready(now); err != nil {
		return Lease{}, err
	}
	if (m.signing != nil) != (authorization != nil) {
		return Lease{}, ErrAuthorization
	}
	if authorization != nil {
		if err := m.verifyHost(*authorization, "approve", now, true); err != nil {
			return Lease{}, err
		}
		if _, ok := m.keys[c.Key]; ok {
			return Lease{}, ErrAuthorizationReplay
		}
	}
	h := digest(c)
	if id, ok := m.keys[c.Key]; ok {
		a := m.actions[id]
		if a.Hash != h {
			return Lease{}, errors.New("idempotency conflict")
		}
		if terminal(a.State) {
			return a, nil
		}
		// A duplicate approval can observe an existing action, never dispatch again.
		return m.query(a, now)
	}
	if !hostguard.ID.MatchString(c.Key) || c.TTL < 1 || c.TTL > 60 {
		return Lease{}, errors.New("invalid approval")
	}
	incident, ok := m.cases[c.CaseID]
	if !ok || incident.Time.After(now) || incident.Time.Before(now.Add(-time.Minute)) {
		return Lease{}, errors.New("recent observed case required")
	}
	if err := m.reconcile(now); err != nil {
		return Lease{}, err
	}
	if len(m.actions) >= 1024 {
		return Lease{}, errors.New("host action budget exceeded")
	}
	for _, a := range m.actions {
		if a.CaseID == c.CaseID {
			return Lease{}, errors.New("case already approved")
		}
		if a.Workload == incident.Workload && a.Tenant == incident.Tenant && a.Asset == incident.Asset && !terminal(a.State) {
			return Lease{}, errors.New("workload already leased")
		}
	}
	a := Lease{ID: "isolate-" + h[:32], CaseID: c.CaseID, Workload: incident.Workload, Tenant: incident.Tenant, Asset: incident.Asset, Issued: now, Expires: now.Add(time.Duration(c.TTL) * time.Second), State: "pending", Key: c.Key, Hash: h}
	if authorization != nil {
		a = authorization.Command.Lease
	}
	if err := m.commit(record{Action: &a, Time: now, Authorization: authorization}); err != nil {
		return Lease{}, err
	}
	// Recheck after durable intent and again after the status call. The caller's
	// explicit replay clock is a lower bound; a live Open uses the real clock.
	dispatchTime := func() time.Time {
		at := m.clock()
		elapsed := now.Add(time.Since(started))
		if at.Before(elapsed) {
			return elapsed
		}
		return at
	}
	observed, reason, err := m.readAdapter(a, dispatchTime())
	if err != nil {
		return m.unknown(a, reason, now, err)
	}
	if observed.State != "not_applied" {
		return m.saveObserved(a, observed, now)
	}
	if !dispatchTime().Before(a.Expires) {
		return m.unknown(a, "dispatch_expired", now, errors.New("fixed deadline elapsed before dispatch"))
	}
	if incident.Time.Before(dispatchTime().Add(-time.Minute)) {
		return m.unknown(a, "case_expired", now, errors.New("observed case expired before dispatch"))
	}
	if authorization != nil {
		// The nonce is already consumed. Verify freshness/current pinned trust
		// again after Sync and Status without allowing a second dispatch.
		if err := m.verifyHost(*authorization, "approve", dispatchTime(), false); err != nil {
			return m.unknown(a, "authorization_expired", now, err)
		}
		t, err := readHostTrust(m.signing.path)
		if err != nil || digest(t) != m.signing.context.TrustSHA {
			return m.unknown(a, "authorization_expired", now, ErrAuthorization)
		}
	}
	// Only this first, fresh, durable intent may call Apply. No recovery/status
	// path retries it, even if a later query establishes not_applied.
	if err := m.adapter.Apply(a); err != nil {
		return m.unknown(a, "apply_unconfirmed", now, err)
	}
	observed, reason, err = m.readAdapter(a, dispatchTime())
	if err != nil {
		return m.unknown(a, reason, now, err)
	}
	if observed.State != "active" {
		return m.unknown(a, "apply_unconfirmed", now, errors.New("apply acknowledgment was not confirmed active"))
	}
	return m.saveObserved(a, observed, now)
}

// Reconciliation queries only. Apply and Release are restricted to explicit
// operator methods; GET/status, startup and duplicate commands never invoke them.
func (m *Manager) reconcile(now time.Time) error {
	ids := make([]string, 0, len(m.actions))
	for id := range m.actions {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var failures []error
	for _, id := range ids {
		a := m.actions[id]
		if terminal(a.State) {
			continue
		}
		if _, err := m.query(a, now); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}
func (m *Manager) Release(id string, now time.Time) (Lease, error) {
	return m.release(id, now, nil)
}
func (m *Manager) release(id string, now time.Time, authorization *HostSigned) (Lease, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.ready(now); err != nil {
		return Lease{}, err
	}
	if (m.signing != nil) != (authorization != nil) {
		return Lease{}, ErrAuthorization
	}
	if authorization != nil {
		if err := m.verifyHost(*authorization, "release", now, true); err != nil {
			return Lease{}, err
		}
	}
	a, ok := m.actions[id]
	if !ok {
		return Lease{}, errors.New("unknown action")
	}
	if terminal(a.State) {
		if authorization != nil {
			return Lease{}, ErrAuthorizationReplay
		}
		return a, nil
	}
	if authorization != nil && a.ReleaseRequested {
		return Lease{}, ErrAuthorizationReplay
	}
	if !a.ReleaseRequested {
		a.ReleaseRequested, a.State, a.UnknownReason = true, "releasing", ""
		if err := m.commit(record{Action: &a, Time: now, Authorization: authorization}); err != nil {
			return m.actions[id], err
		}
	}
	a, err := m.query(a, now)
	if err != nil || terminal(a.State) {
		return a, err
	}
	if authorization != nil {
		at := m.clock()
		if at.Before(now) {
			at = now
		}
		if err := m.verifyHost(*authorization, "release", at, false); err != nil {
			return m.unknown(a, "authorization_expired", now, err)
		}
		t, e := readHostTrust(m.signing.path)
		if e != nil || digest(t) != m.signing.context.TrustSHA {
			return m.unknown(a, "authorization_expired", now, ErrAuthorization)
		}
	}
	// query confirmed active with the exact binding. A requested release may be
	// retried explicitly, but its effect still needs an independent status read.
	if err := m.adapter.Release(id); err != nil {
		return m.unknown(a, "release_unconfirmed", now, err)
	}
	observed, reason, err := m.readAdapter(a, now)
	if err != nil {
		return m.unknown(a, reason, now, err)
	}
	if !terminal(observed.State) {
		return m.unknown(a, "release_unconfirmed", now, errors.New("release acknowledgment did not confirm absence"))
	}
	return m.saveObserved(a, observed, now)
}
func (m *Manager) Status(now time.Time) ([]hostguard.Alert, []Lease, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	err := m.ready(now)
	if err == nil {
		err = m.reconcile(now)
	}
	cases, actions := []hostguard.Alert{}, []Lease{}
	for _, c := range m.cases {
		c.Evidence = append([]string(nil), c.Evidence...)
		cases = append(cases, c)
	}
	for _, a := range m.actions {
		actions = append(actions, a)
	}
	sort.Slice(cases, func(i, j int) bool { return cases[i].CaseID < cases[j].CaseID })
	sort.Slice(actions, func(i, j int) bool { return actions[i].ID < actions[j].ID })
	return cases, actions, err
}

// SimulationAdapter represents leases in memory only. It changes no process,
// container, firewall or network. A real adapter needs separate deployment review.
type SimulationAdapter struct {
	mu     sync.Mutex
	leases map[string]Lease
}

func NewSimulation() *SimulationAdapter { return &SimulationAdapter{leases: map[string]Lease{}} }
func (s *SimulationAdapter) Apply(a Lease) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if old, ok := s.leases[a.ID]; ok {
		if !sameBinding(old, a) {
			return errors.New("lease mutation")
		}
		if terminal(old.State) {
			return errors.New("retired simulated lease")
		}
		return nil
	}
	if len(s.leases) >= 1024 {
		return errors.New("simulation history budget exceeded")
	}
	a.State, a.ReleaseRequested, a.UnknownReason = "active", false, ""
	s.leases[a.ID] = a
	return nil
}
func (s *SimulationAdapter) Status(expected Lease, now time.Time) (Lease, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if now.IsZero() {
		return Lease{}, errors.New("explicit adapter observation time required")
	}
	if a, ok := s.leases[expected.ID]; ok {
		if a.State == "active" && !a.Expires.After(now) {
			a.State = "expired"
			s.leases[a.ID] = a
		}
		return a, nil
	}
	// This memory-only adapter's entire effect is this map. A fresh process has
	// no effect to recover. Real adapters with missing history must return unknown.
	expected.State, expected.ReleaseRequested, expected.UnknownReason = "not_applied", false, ""
	return expected, nil
}
func (s *SimulationAdapter) Release(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if a, ok := s.leases[id]; ok && !terminal(a.State) {
		a.State = "released"
		s.leases[id] = a
	}
	return nil
}
func (s *SimulationAdapter) Isolated(workload string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	isolated := false
	for id, a := range s.leases {
		if a.State == "active" && !a.Expires.After(now) {
			a.State = "expired"
			s.leases[id] = a
		}
		if a.State == "active" && a.Workload == workload && !now.Before(a.Issued) {
			isolated = true
		}
	}
	return isolated
}
