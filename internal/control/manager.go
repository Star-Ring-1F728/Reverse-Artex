// Package control is the only policy writer. Evidence producers have no admin
// authority. Every committed mutation is fsynced to a bounded append-only WAL.
package control

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reverse-artex/internal/event"
	"reverse-artex/internal/policy"
	"reverse-artex/internal/storagebudget"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

type Receipt struct {
	Version   uint64 `json:"version"`
	PolicyID  string `json:"policy_id,omitempty"`
	Operation string `json:"operation"`
	Hash      string `json:"-"`
}
type record struct {
	Version   uint64         `json:"version"`
	Epoch     string         `json:"epoch"`
	Time      time.Time      `json:"time"`
	Operation string         `json:"operation"`
	Actor     string         `json:"actor"`
	Key       string         `json:"command_key,omitempty"`
	Hash      string         `json:"command_hash,omitempty"`
	Policy    *policy.Policy `json:"policy,omitempty"`
	Removed   []string       `json:"removed,omitempty"`
	Auto      bool           `json:"auto_enabled"`
	Refs      []string       `json:"evidence_refs,omitempty"`
	Evidence  *event.Event   `json:"evidence,omitempty"`
}
type autoScope struct{ tenant, asset, principal, session, route string }

type Manager struct {
	autoScopes     map[autoScope]time.Time
	autoClock      time.Time
	shared         *storagebudget.Budget
	mu             mutationLock
	dir, epoch     string
	version        uint64
	active         map[string]policy.Policy
	keys           map[string]Receipt
	dead           map[string]bool
	events         map[string]event.Event
	evidenceScopes map[evidenceScope]map[string]struct{}
	evidenceExpiry evidenceDeadlines
	auto           bool
	Budget         int64
	auditFailed    bool
	audit          *os.File
	syncFile       func(*os.File) error
	closed         bool
	view           atomic.Pointer[committedPolicyView]
	ioMu           sync.Mutex
	ioTiming       map[string]ioDuration
	refreshMu      sync.Mutex
	refresh        *expiryFlight
	policyExpiry   policyDeadlines
}

// OpenPersistent retains the single writer's audit handle, preserving the
// existing per-record Sync and budget checks. Recovery validation is unchanged.
func OpenPersistent(dir string) (*Manager, error) {
	m, err := Open(dir)
	if err != nil {
		return nil, err
	}
	m.audit, err = os.OpenFile(filepath.Join(dir, "actions.jsonl"), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0600)
	if err != nil {
		return nil, err
	}
	return m, nil
}

func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	if m.audit != nil {
		err := m.audit.Close()
		m.audit = nil
		return err
	}
	return nil
}

const defaultAuditBudget = 128 << 20

// A full recent-evidence window can recover by aging out; unlike an ambiguous
// audit write it is safe for the sender to retain and retry the same event.
var ErrEvidenceCapacity = errors.New("evidence budget exceeded")

type Approve struct {
	Key        string `json:"idempotency_key"`
	CaseID     string `json:"case_id"`
	EvidenceID string `json:"subject_evidence_id"`
	Route      string `json:"route_template"`
	TTL        int    `json:"ttl_seconds"`
	Reason     string `json:"reason"`
}
type Revoke struct {
	Key    string `json:"idempotency_key"`
	ID     string `json:"policy_id"`
	Reason string `json:"reason"`
}
type Rollback struct {
	Key       string `json:"idempotency_key"`
	ToVersion uint64 `json:"to_version"`
	Reason    string `json:"reason"`
}

func Open(dir string) (*Manager, error) {
	shared, err := storagebudget.FromEnv(dir)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	m := &Manager{shared: shared, dir: dir, active: map[string]policy.Policy{}, keys: map[string]Receipt{}, dead: map[string]bool{}, events: map[string]event.Event{}, Budget: defaultAuditBudget}
	f, err := os.Open(filepath.Join(dir, "actions.jsonl"))
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if err == nil {
		defer f.Close()
		st, err := f.Stat()
		if err != nil || st.Size() > m.Budget {
			return nil, errors.New("audit budget exceeded")
		}
		// A missing JSONL delimiter would concatenate the next append with this
		// record. Preserve incomplete evidence and refuse recovery before replay.
		if st.Size() > 0 {
			var tail [1]byte
			if _, err := f.ReadAt(tail[:], st.Size()-1); err != nil || tail[0] != '\n' {
				return nil, errors.New("incomplete policy audit record")
			}
		}
		scan := bufio.NewScanner(f)
		scan.Buffer(make([]byte, 4096), 1<<20)
		for scan.Scan() {
			var r record
			if json.Unmarshal(scan.Bytes(), &r) != nil || r.Version != m.version+1 || !policy.ID.MatchString(r.Epoch) || (m.epoch != "" && r.Epoch != m.epoch) {
				return nil, errors.New("invalid policy audit chain")
			}
			if len(m.keys) >= 4096 && r.Key != "" {
				return nil, errors.New("audit command budget exceeded")
			}
			if r.Policy != nil && (r.Policy.Version != r.Version || policy.ValidateScoped(*r.Policy, r.Time) != nil || m.dead[r.Policy.ID]) {
				return nil, errors.New("invalid audited policy")
			}
			if r.Evidence != nil {
				m.pruneEvidence(r.Time)
				if r.Evidence.Validate(r.Time) != nil || (r.Operation != "evidence" && r.Operation != "auto-deny") || m.events[r.Evidence.EventID].EventID != "" {
					return nil, errors.New("invalid audited evidence")
				}
			}
			m.replay(r)
		}
		if scan.Err() != nil {
			return nil, scan.Err()
		}
	}
	if m.epoch == "" {
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		m.epoch = hex.EncodeToString(b)
		if _, err := m.commit(record{Operation: "initialize", Actor: "system", Time: time.Now().UTC()}); err != nil {
			return nil, err
		}
	}
	m.pruneEvidence(time.Now().UTC())
	m.publishPolicyView(true)
	return m, nil
}
func (m *Manager) replay(r record) {
	// Reconstruct suppression from synced auto policies, including revoked and
	// expired policies. No new journal format or replay of commands is needed.
	if r.Operation == "auto-deny" && r.Policy != nil {
		if m.autoScopes == nil {
			m.autoScopes = map[autoScope]time.Time{}
		}
		p := r.Policy
		key := autoScope{p.Tenant, p.Asset, p.Principal, p.Session, p.Route}
		if p.Issued.After(m.autoScopes[key]) {
			m.autoScopes[key] = p.Issued
		}
		if p.Issued.After(m.autoClock) {
			m.autoClock = p.Issued
		}
		for k, at := range m.autoScopes {
			if !at.Add(2 * time.Minute).After(m.autoClock) {
				delete(m.autoScopes, k)
			}
		}
	}
	m.epoch = r.Epoch
	m.version = r.Version
	m.auto = r.Auto
	for _, id := range r.Removed {
		delete(m.active, id)
		m.policyExpiry.remove(id)
		m.dead[id] = true
	}
	if r.Policy != nil {
		m.active[r.Policy.ID] = *r.Policy
		m.policyExpiry.retain(*r.Policy)
	}
	if r.Evidence != nil {
		m.retainEvidence(*r.Evidence)
	}
	if r.Key != "" {
		id := ""
		if r.Policy != nil {
			id = r.Policy.ID
		}
		m.keys[r.Key] = Receipt{r.Version, id, r.Operation, r.Hash}
	}
	m.publishPolicyView(r.Policy != nil || len(r.Removed) != 0)
}
func (m *Manager) commit(r record) (Receipt, error) {
	if m.auditFailed || m.closed {
		return Receipt{}, errors.New("audit is unavailable after incomplete write")
	}
	r.Version = m.version + 1
	r.Epoch = m.epoch
	b, err := json.Marshal(r)
	if err != nil {
		return Receipt{}, err
	}
	b = append(b, '\n')
	var result Receipt
	err = m.shared.With(func(l *storagebudget.Lease) error {
		if e := l.Allow(int64(len(b))); e != nil {
			return e
		}
		var e error
		result, e = m.writeRecord(r, b)
		return e
	})
	return result, err
}
func (m *Manager) writeRecord(r record, b []byte) (Receipt, error) {
	var err error
	f := m.audit
	if f == nil {
		f, err = os.OpenFile(filepath.Join(m.dir, "actions.jsonl"), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0600)
		if err != nil {
			return Receipt{}, err
		}
		defer f.Close()
	}
	statStarted := time.Now()
	st, err := f.Stat()
	m.recordIO("audit_stat", statStarted)
	if err != nil {
		return Receipt{}, err
	}
	if st.Size()+int64(len(b)) > m.Budget {
		return Receipt{}, errors.New("audit disk budget exceeded")
	}
	writeStarted := time.Now()
	n, err := f.Write(b)
	m.recordIO("audit_write", writeStarted)
	if err != nil || n != len(b) {
		m.auditFailed = true
		return Receipt{}, errors.New("audit write failed")
	}
	syncStarted := time.Now()
	syncFile := m.syncFile
	if syncFile == nil {
		syncFile = (*os.File).Sync
	}
	err = syncFile(f)
	m.recordIO("audit_sync", syncStarted)
	if err != nil {
		m.auditFailed = true
		return Receipt{}, err
	}
	m.replay(r)
	id := ""
	if r.Policy != nil {
		id = r.Policy.ID
	}
	return Receipt{r.Version, id, r.Operation, r.Hash}, nil
}
func hash(v any) string {
	b, _ := json.Marshal(v)
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
func (m *Manager) existing(key, h string) (Receipt, bool, error) {
	if !policy.ID.MatchString(key) {
		return Receipt{}, false, errors.New("invalid idempotency key")
	}
	if r, ok := m.keys[key]; ok {
		if r.Hash != h {
			return Receipt{}, true, errors.New("idempotency conflict")
		}
		return r, true, nil
	}
	if len(m.keys) >= 4096 {
		return Receipt{}, false, errors.New("command budget exceeded")
	}
	return Receipt{}, false, nil
}
func reason(s string) bool {
	return s == "operator_verified" || s == "false_positive" || s == "experiment" || s == "rollback"
}
func (m *Manager) expire(now time.Time) error {
	ids := m.policyExpiry.expiredIDs(now)
	if len(ids) == 0 {
		return nil
	}
	_, err := m.commit(record{Time: now, Operation: "expire", Actor: "system", Removed: ids, Auto: m.auto})
	return err
}
func (m *Manager) Approve(a Approve, now time.Time) (Receipt, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.approveLocked(a, now)
}
func (m *Manager) approveLocked(a Approve, now time.Time) (Receipt, error) {
	h := hash(a)
	if r, ok, err := m.existing(a.Key, h); ok || err != nil {
		return r, err
	}
	if !reason(a.Reason) || a.TTL < 1 || a.TTL > 60 || !policy.ID.MatchString(a.CaseID) || !policy.AllowedRoute(a.Route) {
		return Receipt{}, errors.New("invalid approved scope")
	}
	e, ok := m.events[a.EvidenceID]
	if !ok || e.Identity != "authenticated" || e.DataQuality != "complete" || e.EventTime.Before(now.Add(-time.Minute)) {
		return Receipt{}, errors.New("recent verified subject evidence required")
	}
	if err := m.expire(now); err != nil {
		return Receipt{}, err
	}
	if len(m.active) >= 1024 {
		return Receipt{}, errors.New("active policy budget exceeded")
	}
	p := policy.Policy{ID: "p-" + hash(a)[:32], CaseID: a.CaseID, Tenant: e.TenantID, Asset: e.AssetID, Principal: e.Principal, Session: e.SessionHMAC, Route: a.Route, RuleVersion: "manual-1.0", Issued: now, Expires: now.Add(time.Duration(a.TTL) * time.Second), Version: m.version + 1}
	if m.dead[p.ID] {
		return Receipt{}, errors.New("retired policy ID")
	}
	if err := policy.ValidateScoped(p, now); err != nil {
		return Receipt{}, err
	}
	return m.commit(record{Time: now, Operation: "approve", Actor: "operator:" + a.Reason, Key: a.Key, Hash: h, Policy: &p, Auto: m.auto, Refs: []string{e.EventID}})
}
func (m *Manager) Revoke(a Revoke, now time.Time) (Receipt, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.revokeLocked(a, now)
}
func (m *Manager) revokeLocked(a Revoke, now time.Time) (Receipt, error) {
	h := hash(a)
	if r, ok, err := m.existing(a.Key, h); ok || err != nil {
		return r, err
	}
	if !reason(a.Reason) || !policy.ID.MatchString(a.ID) {
		return Receipt{}, errors.New("invalid revoke")
	}
	return m.commit(record{Time: now, Operation: "revoke", Actor: "operator:" + a.Reason, Key: a.Key, Hash: h, Removed: []string{a.ID}, Auto: m.auto})
}

// Rollback is compensating release: removes policies created after a checkpoint
// and disables automatic actions. Revoked/expired policies are never restored.
func (m *Manager) Rollback(a Rollback, now time.Time) (Receipt, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.rollbackLocked(a, now)
}
func (m *Manager) rollbackLocked(a Rollback, now time.Time) (Receipt, error) {
	h := hash(a)
	if r, ok, err := m.existing(a.Key, h); ok || err != nil {
		return r, err
	}
	if !reason(a.Reason) || a.ToVersion > m.version {
		return Receipt{}, errors.New("invalid checkpoint")
	}
	ids := []string{}
	for id, p := range m.active {
		if p.Version > a.ToVersion {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return m.commit(record{Time: now, Operation: "rollback", Actor: "operator:" + a.Reason, Key: a.Key, Hash: h, Removed: ids, Auto: false})
}
func (m *Manager) SetAuto(key string, enabled bool, now time.Time) (Receipt, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.setAutoLocked(key, enabled, now)
}
func (m *Manager) setAutoLocked(key string, enabled bool, now time.Time) (Receipt, error) {
	h := hash(enabled)
	if r, ok, err := m.existing(key, h); ok || err != nil {
		return r, err
	}
	return m.commit(record{Time: now, Operation: "auto-mode", Actor: "operator", Key: key, Hash: h, Auto: enabled})
}
func (m *Manager) Snapshot(now time.Time, key []byte) (policy.Snapshot, error) {
	// A reader linearizes at this load, before or after a fully synced commit.
	// Evidence Sync cannot hold up a heartbeat for an unchanged policy view.
	if view := m.view.Load(); view != nil && (view.expires.IsZero() || view.expires.After(now)) {
		ps := append([]policy.Policy{}, view.policies...)
		return policy.Sign(policy.Snapshot{Epoch: view.epoch, Version: view.version, Generated: now, Policies: ps}, key), nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.expire(now); err != nil {
		return policy.Snapshot{}, err
	}
	ps := []policy.Policy{}
	for _, p := range m.active {
		ps = append(ps, p)
	}
	sort.Slice(ps, func(i, j int) bool { return ps[i].ID < ps[j].ID })
	return policy.Sign(policy.Snapshot{Epoch: m.epoch, Version: m.version, Generated: now, Policies: ps}, key), nil
}
func (m *Manager) Evidence(e event.Event, now time.Time) (*Receipt, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.evidenceLocked(e, now)
}
func (m *Manager) evidenceLocked(e event.Event, now time.Time) (*Receipt, error) {
	if err := e.Validate(now); err != nil {
		return nil, err
	}
	if e.SensorID != "lab-app" && e.SensorID != "lab-waf" {
		return nil, errors.New("unsupported evidence sensor")
	}
	if e.AssetID != "lab-api" || (e.TenantID != "alpha" && e.TenantID != "beta" && e.TenantID != "public") {
		return nil, errors.New("evidence outside configured lab scope")
	}
	m.pruneEvidence(now)
	if previous, ok := m.events[e.EventID]; ok {
		if hash(previous) != hash(e) {
			return nil, errors.New("evidence idempotency conflict")
		}
		return nil, nil
	}
	if len(m.events) >= 16384 {
		return nil, ErrEvidenceCapacity
	}
	// V1 safety fix: refs changing is not a new authorization to renew.
	// One automatic policy per subject/session/route, followed by a 60-second
	// cooldown after the fixed 60-second lease. Clock rollback cannot reset it.
	if m.auto && !m.autoClock.IsZero() && now.Before(m.autoClock) {
		return nil, m.persistEvidence(e, now)
	}
	autoKey := autoScope{e.TenantID, e.AssetID, e.Principal, e.SessionHMAC, "/api/objects/{id}"}
	if issued, ok := m.autoScopes[autoKey]; ok && now.Before(issued.Add(2*time.Minute)) {
		return nil, m.persistEvidence(e, now)
	}
	for _, p := range m.active {
		if p.RuleVersion == "RA-M3-001-1.0" && p.Tenant == e.TenantID && p.Asset == e.AssetID && p.Principal == e.Principal && p.Session == e.SessionHMAC && p.Route == autoKey.route && p.Expires.After(now) {
			return nil, m.persistEvidence(e, now)
		}
	}
	if !m.auto || e.Identity != "authenticated" || e.DataQuality != "complete" {
		return nil, m.persistEvidence(e, now)
	}
	// A normal request may be retained for investigation, but cannot
	// trigger/retrigger an automatic action using old denial references.
	actionable := (e.SensorID == "lab-waf" && e.Status == 403 && e.DetectorFamily == "waf-local-denial") ||
		(e.SensorID == "lab-app" && e.Status == 403 && e.Authorization == "deny" && e.Route == "/api/objects/{id}" && e.ResourceHMAC != "")
	if !actionable {
		return nil, m.persistEvidence(e, now)
	}
	waf := map[string]bool{}
	denials := map[string]bool{}
	resources := map[string]bool{}
	refs := []string{}
	consider := func(x event.Event) {
		if x.EventTime.Before(now.Add(-time.Minute)) || x.EventTime.After(now) || x.TenantID != e.TenantID || x.AssetID != e.AssetID || x.Principal != e.Principal || x.SessionHMAC != e.SessionHMAC || x.Identity != "authenticated" || x.DataQuality != "complete" {
			return
		}
		if x.SensorID == "lab-waf" && x.DetectorFamily == "waf-local-denial" && x.Status == 403 {
			waf[x.RequestID] = true
			refs = append(refs, x.EventID)
		}
		if x.SensorID == "lab-app" && x.Status == 403 && x.Authorization == "deny" && x.Route == "/api/objects/{id}" && x.ResourceHMAC != "" {
			denials[x.RequestID] = true
			resources[x.ResourceHMAC] = true
			refs = append(refs, x.EventID)
		}
	}
	for id := range m.evidenceScopes[scopeOf(e)] {
		consider(m.events[id])
	}
	consider(e)
	// Shared request IDs never count as independent evidence kinds.
	for id := range waf {
		if denials[id] {
			delete(waf, id)
		}
	}
	if len(waf) < 2 || len(denials) < 2 || len(resources) < 2 {
		return nil, m.persistEvidence(e, now)
	}
	sort.Strings(refs)
	if len(refs) > 32 {
		return nil, errors.New("automatic evidence budget exceeded")
	}
	// Retained suppression is bounded by the existing 4096-command WAL cap.
	// Expired entries are pruned only on a successfully synced auto issuance.
	count := 0
	for _, at := range m.autoScopes {
		if at.Add(2 * time.Minute).After(now) {
			count++
		}
	}
	if count >= 4096 {
		return nil, errors.New("automatic scope cooldown budget exceeded")
	}
	key := "auto-" + hash(refs)[:32]
	h := hash(refs)
	if r, ok, err := m.existing(key, h); ok || err != nil {
		if err != nil {
			return nil, err
		}
		return &r, m.persistEvidence(e, now)
	}
	if err := m.expire(now); err != nil {
		return nil, err
	}
	if len(m.active) >= 1024 {
		return nil, errors.New("active policy budget exceeded")
	}
	p := policy.Policy{ID: "p-" + hash(refs)[:32], CaseID: "case-" + hash(refs)[:32], Tenant: e.TenantID, Asset: e.AssetID, Principal: e.Principal, Session: e.SessionHMAC, Route: "/api/objects/{id}", RuleVersion: "RA-M3-001-1.0", Issued: now, Expires: now.Add(60 * time.Second), Version: m.version + 1}
	if err := policy.ValidateScoped(p, now); err != nil {
		return nil, err
	}
	r, err := m.commit(record{Time: now, Operation: "auto-deny", Actor: "validated-predicate", Key: key, Hash: h, Policy: &p, Auto: m.auto, Refs: refs, Evidence: &e})
	return &r, err
}

func (m *Manager) persistEvidence(e event.Event, now time.Time) error {
	_, err := m.commit(record{Time: now, Operation: "evidence", Actor: "sensor:" + e.SensorID, Auto: m.auto, Evidence: &e})
	return err
}
