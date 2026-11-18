package actionapproval

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"reverse-artex/internal/actionproposal"
	"reverse-artex/internal/decisions"
)

const MaxBytes = 8 << 20
const MaxRecord = 128 << 10
const MaxRecords = 512
const MaxEntries = 64

type Entry struct {
	ID              string                  `json:"entry_id"`
	Proposal        actionproposal.Proposal `json:"proposal"`
	ApprovalSHA     string                  `json:"authorization_sha256"`
	Consumed        time.Time               `json:"consumed_at"`
	ActionExpires   time.Time               `json:"action_expires_at"`
	Phase           string                  `json:"phase"`
	CancelRequested bool                    `json:"cancel_requested"`
	ObservationSHA  string                  `json:"observation_evidence_sha256,omitempty"`
	Simulation      *SimulationAttempt      `json:"simulation_attempt,omitempty"`
	Execution       *ExecutionAttempt       `json:"execution_attempt,omitempty"`
}

type use struct {
	SHA string    `json:"sha256"`
	At  time.Time `json:"at"`
}
type state struct {
	ID       string
	Head     string
	Sequence int
	At       time.Time
	Entries  map[string]Entry
	Nonces   map[string]use
	Stopped  map[string]bool
}

type View struct {
	Schema         string   `json:"schema"`
	Scope          string   `json:"scope"`
	Authority      string   `json:"authority"`
	Available      bool     `json:"available"`
	StorageState   string   `json:"storage_state"`
	LedgerID       string   `json:"ledger_id"`
	TrustSHA       string   `json:"trust_policy_sha256"`
	Head           string   `json:"head_sha256"`
	Sequence       int      `json:"sequence"`
	StoppedTenants []string `json:"stopped_tenants"`
	Entries        []Entry  `json:"entries"`
}

type record struct {
	Schema        string                  `json:"schema"`
	Sequence      int                     `json:"sequence"`
	Previous      string                  `json:"previous_sha256"`
	Time          time.Time               `json:"time"`
	LedgerID      string                  `json:"ledger_id"`
	TrustSHA      string                  `json:"trust_policy_sha256"`
	Kind          string                  `json:"kind"`
	Authorization *Signed                 `json:"authorization,omitempty"`
	Request       *actionproposal.Request `json:"request,omitempty"`
	Simulation    *SimulationAttempt      `json:"simulation_attempt,omitempty"`
	Execution     *ExecutionAttempt       `json:"execution_attempt,omitempty"`
	EntryID       string                  `json:"entry_id,omitempty"`
	SHA           string                  `json:"sha256"`
}

type Ledger struct {
	mu               sync.Mutex
	trust            Trust
	state            state
	file, owner      *os.File
	syncFile         func(*os.File) error
	write            func([]byte) (int, error)
	poisoned, closed bool
	approvals        map[string]Signed
	cancellations    map[string]Signed
}

func terminal(phase string) bool { return phase == "released" || phase == "not_applied" }
func recordHash(r record) string { r.SHA = ""; return decisions.Hash(r) }

// decode also rejects case aliases that encoding/json otherwise accepts.
func decode(raw []byte, out any, limit int) error {
	if err := decisions.DecodeStrict(raw, out, limit); err != nil {
		return err
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return err
	}
	var canonical func(any) bool
	canonical = func(v any) bool {
		switch x := v.(type) {
		case map[string]any:
			for k, child := range x {
				if k != strings.ToLower(k) || !canonical(child) {
					return false
				}
			}
		case []any:
			for _, child := range x {
				if !canonical(child) {
					return false
				}
			}
		}
		return true
	}
	if !canonical(v) {
		return errors.New("canonical lowercase JSON keys required")
	}
	return nil
}

func DecodeTrust(raw []byte) (Trust, error) {
	var t Trust
	if err := decode(raw, &t, 16<<10); err != nil {
		return t, err
	}
	return t, t.Validate()
}
func DecodeSigned(raw []byte) (Signed, error) {
	var s Signed
	err := decode(raw, &s, 8<<10)
	return s, err
}

func regular(path string) error {
	s, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !s.Mode().IsRegular() || s.Size() > MaxBytes {
		return errors.New("bounded regular ledger files required")
	}
	return nil
}

// Open holds a cross-process lock until Close. Every nonterminal intent is
// recovered as unknown before use. It never retries or infers an adapter effect.
func Open(path string, trust Trust, now time.Time) (*Ledger, error) {
	if path == "" || trust.Validate() != nil || now.IsZero() {
		return nil, errors.New("explicit ledger, trust and clock required")
	}
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	for _, p := range []string{path, path + ".lock"} {
		if err := regular(p); err != nil {
			return nil, err
		}
	}
	owner, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := lockOwner(owner); err != nil {
		owner.Close()
		return nil, errors.New("approval ledger already owned or unavailable")
	}
	fail := func(err error) (*Ledger, error) { unlockOwner(owner); owner.Close(); return nil, err }
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0600)
	if err != nil {
		return fail(err)
	}
	failFile := func(err error) (*Ledger, error) { file.Close(); return fail(err) }
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > MaxBytes {
		return failFile(errors.New("ledger byte limit or nonregular file"))
	}
	raw, err := io.ReadAll(io.LimitReader(file, MaxBytes+1))
	if err != nil || len(raw) > MaxBytes {
		return failFile(errors.New("ledger read failed or exceeded byte limit"))
	}
	if len(raw) > 0 && raw[len(raw)-1] != '\n' {
		return failFile(errors.New("incomplete ledger record retained"))
	}
	// Freeze caller-owned key slices; later mutations cannot change trust.
	trustRaw, _ := json.Marshal(trust)
	var frozen Trust
	if err := json.Unmarshal(trustRaw, &frozen); err != nil {
		return failFile(err)
	}
	l := &Ledger{trust: frozen, file: file, owner: owner, syncFile: func(f *os.File) error { return f.Sync() }, write: file.Write,
		approvals:     map[string]Signed{},
		cancellations: map[string]Signed{},
		state:         state{Entries: map[string]Entry{}, Nonces: map[string]use{}, Stopped: map[string]bool{}}}
	scan := bufio.NewScanner(bytes.NewReader(raw))
	scan.Buffer(make([]byte, 4096), MaxRecord)
	for scan.Scan() {
		var r record
		if err := decode(scan.Bytes(), &r, MaxRecord); err != nil {
			return failFile(err)
		}
		next, err := l.transition(r)
		if err != nil {
			return failFile(err)
		}
		l.state = next
		l.retainApproval(r)
	}
	if err := scan.Err(); err != nil {
		return failFile(err)
	}
	if now.Before(l.state.At) {
		return failFile(errors.New("ledger clock moved backwards"))
	}
	if l.state.Sequence == 0 {
		id := make([]byte, 32)
		if _, err := rand.Read(id); err != nil {
			return failFile(err)
		}
		if err := l.append(record{Kind: "initialize", LedgerID: hex.EncodeToString(id), Time: now}); err != nil {
			return failFile(err)
		}
	} else {
		for _, e := range l.state.Entries {
			if !terminal(e.Phase) && e.Phase != "unknown" {
				if err := l.append(record{Kind: "recover", Time: now}); err != nil {
					return failFile(err)
				}
				break
			}
		}
	}
	return l, nil
}

func (l *Ledger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	err := l.file.Close()
	unlockOwner(l.owner)
	ownerErr := l.owner.Close()
	if err == nil {
		err = ownerErr
	}
	return err
}

func (l *Ledger) Inspect() View {
	l.mu.Lock()
	defer l.mu.Unlock()
	v := View{Schema: "action-approval-view/1", Scope: "offline_signed_intent", Authority: "shadow", LedgerID: l.state.ID,
		Available: !l.closed && !l.poisoned, StorageState: "ready",
		TrustSHA: decisions.Hash(l.trust), Sequence: l.state.Sequence, Head: l.state.Head, StoppedTenants: []string{}, Entries: []Entry{}}
	if l.poisoned {
		v.StorageState = "ambiguous_write"
	} else if l.closed {
		v.StorageState = "closed"
	}
	for tenant, stopped := range l.state.Stopped {
		if stopped {
			v.StoppedTenants = append(v.StoppedTenants, tenant)
		}
	}
	for _, e := range l.state.Entries {
		if e.Execution != nil {
			v.Scope, v.Authority = "signed_intent_with_external_dispatch", "signed_intent_only"
		}
		raw, _ := json.Marshal(e)
		var copy Entry
		_ = json.Unmarshal(raw, &copy)
		v.Entries = append(v.Entries, copy)
	}
	sort.Strings(v.StoppedTenants)
	sort.Slice(v.Entries, func(a, b int) bool { return v.Entries[a].ID < v.Entries[b].ID })
	return v
}

func (l *Ledger) ready(now time.Time) error {
	if l.closed || l.poisoned {
		return errors.New("approval ledger unavailable after close or ambiguous write")
	}
	if now.IsZero() || now.Before(l.state.At) {
		return errors.New("ledger clock moved backwards")
	}
	return nil
}

// Consume records approval nonce and intent in one synced record. Returned
// entries are shadow status, never a capability to execute a policy.
func (l *Ledger) Consume(req actionproposal.Request, signed Signed, now time.Time) (Entry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.consumeLocked(req, signed, now)
}

func (l *Ledger) consumeLocked(req actionproposal.Request, signed Signed, now time.Time) (Entry, error) {
	if err := l.ready(now); err != nil {
		return Entry{}, err
	}
	if prior, exists := l.state.Nonces[signed.Command.Nonce]; exists {
		if prior.SHA != decisions.Hash(signed) || signed.Command.Kind != "approve" || verifySignature(l.trust, l.state.ID, signed, prior.At) != nil {
			return Entry{}, errors.New("authorization nonce replay conflict")
		}
		v, err := actionproposal.Build(req, prior.At)
		if err != nil || v.Proposal == nil || verifyApproval(signed.Command, *v.Proposal) != nil {
			return Entry{}, errors.New("duplicate approval context changed")
		}
		id := decisions.Hash([]string{l.state.ID, v.Proposal.Key})
		e, ok := l.state.Entries[id]
		if !ok || e.ApprovalSHA != prior.SHA {
			return Entry{}, errors.New("duplicate intent mismatch")
		}
		return cloneEntry(e), nil
	}
	if err := l.append(record{Kind: "command", Time: now, Authorization: &signed, Request: &req}); err != nil {
		return Entry{}, err
	}
	// transition has already validated/rebuilt the draft against this clock.
	v, _ := actionproposal.Build(req, now)
	id := decisions.Hash([]string{l.state.ID, v.Proposal.Key})
	return cloneEntry(l.state.Entries[id]), nil
}

func cloneEntry(e Entry) Entry {
	raw, _ := json.Marshal(e)
	var copy Entry
	_ = json.Unmarshal(raw, &copy)
	return copy
}

// Apply accepts signed cancel/stop/resume/observation declarations. Observed
// state is attested by a separate observer key; no sensor query occurs here.
func (l *Ledger) Apply(s Signed, now time.Time) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.ready(now); err != nil {
		return err
	}
	if s.Command.Kind == "approve" {
		return errors.New("approve requires original snapshot request")
	}
	if prior, exists := l.state.Nonces[s.Command.Nonce]; exists {
		if prior.SHA != decisions.Hash(s) || verifySignature(l.trust, l.state.ID, s, prior.At) != nil {
			return errors.New("authorization nonce replay conflict")
		}
		return nil
	}
	return l.append(record{Kind: "command", Time: now, Authorization: &s})
}

func (l *Ledger) append(r record) error {
	if err := l.ready(r.Time); err != nil {
		return err
	}
	if r.LedgerID == "" {
		r.LedgerID = l.state.ID
	}
	r.Schema, r.Sequence, r.Previous, r.TrustSHA = "action-approval-record/1", l.state.Sequence+1, l.state.Head, decisions.Hash(l.trust)
	r.SHA = recordHash(r)
	next, err := l.transition(r)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(r)
	if err != nil || len(raw)+1 >= MaxRecord {
		return errors.New("approval record byte limit")
	}
	raw = append(raw, '\n')
	info, err := l.file.Stat()
	if err != nil || info.Size()+int64(len(raw)) > MaxBytes {
		return errors.New("approval ledger byte budget")
	}
	n, err := l.write(raw)
	if err == nil && n != len(raw) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = l.syncFile(l.file)
	}
	if err != nil {
		l.poisoned = true
		return err
	}
	l.state = next
	l.retainApproval(r)
	return nil
}

func (l *Ledger) retainApproval(r record) {
	if r.Authorization != nil && (r.Authorization.Command.Kind == "approve" || r.Authorization.Command.Kind == "cancel") {
		raw, _ := json.Marshal(r.Authorization)
		var frozen Signed
		_ = json.Unmarshal(raw, &frozen)
		if frozen.Command.Kind == "approve" {
			l.approvals[decisions.Hash(frozen)] = frozen
		} else {
			l.cancellations[frozen.Command.EntryID] = frozen
		}
	}
}

func (l *Ledger) transition(r record) (state, error) {
	bad := func() (state, error) { return state{}, errors.New("invalid approval ledger transition") }
	if r.Schema != "action-approval-record/1" || r.Sequence != l.state.Sequence+1 || r.Sequence > MaxRecords ||
		r.Previous != l.state.Head || r.SHA != recordHash(r) || !decisions.ValidHash(r.LedgerID) || r.TrustSHA != decisions.Hash(l.trust) ||
		r.Time.IsZero() || r.Time.Before(l.state.At) || (l.state.ID != "" && r.LedgerID != l.state.ID) {
		return bad()
	}
	if r.Kind != "simulation_dispatch" && r.Kind != "simulation_unknown" && r.Kind != "simulation_release" && (r.Simulation != nil || r.EntryID != "") {
		if r.Kind != "execution_dispatch" && r.Kind != "execution_unknown" && r.Kind != "execution_release" {
			return bad()
		}
	}
	if r.Kind != "execution_dispatch" && r.Kind != "execution_unknown" && r.Kind != "execution_release" && r.Execution != nil {
		return bad()
	}
	raw, err := json.Marshal(l.state)
	if err != nil {
		return bad()
	}
	var next state
	if json.Unmarshal(raw, &next) != nil {
		return bad()
	}
	if r.Kind == "initialize" {
		if l.state.Sequence != 0 || r.Authorization != nil || r.Request != nil {
			return bad()
		}
		next.ID = r.LedgerID
	} else if r.Kind == "recover" {
		if l.state.Sequence == 0 || r.Authorization != nil || r.Request != nil {
			return bad()
		}
		changed := false
		for id, e := range next.Entries {
			if !terminal(e.Phase) && e.Phase != "unknown" {
				e.Phase = "unknown"
				next.Entries[id] = e
				changed = true
			}
		}
		if !changed {
			return bad()
		}
	} else if r.Kind == "simulation_dispatch" || r.Kind == "simulation_unknown" || r.Kind == "simulation_release" {
		if r.Execution != nil {
			return bad()
		}
		if err := l.simulationTransition(&next, r); err != nil {
			return state{}, err
		}
	} else if r.Kind == "execution_dispatch" || r.Kind == "execution_unknown" || r.Kind == "execution_release" {
		if err := l.executionTransition(&next, r); err != nil {
			return state{}, err
		}
	} else if r.Kind == "command" {
		if l.state.Sequence == 0 || r.Authorization == nil {
			return bad()
		}
		s := *r.Authorization
		c := s.Command
		if _, used := next.Nonces[c.Nonce]; used {
			return bad()
		}
		if err := verifySignature(l.trust, next.ID, s, r.Time); err != nil {
			return state{}, err
		}
		if c.Kind == "approve" {
			if r.Request == nil || len(next.Entries) >= MaxEntries || next.Stopped[c.Tenant] {
				return bad()
			}
			v, err := actionproposal.Build(*r.Request, r.Time)
			if err != nil || v.Proposal == nil || verifyApproval(c, *v.Proposal) != nil {
				return bad()
			}
			p := *v.Proposal
			id := decisions.Hash([]string{next.ID, p.Key})
			if _, exists := next.Entries[id]; exists {
				return state{}, errors.New("proposal key already consumed")
			}
			for _, entry := range next.Entries {
				if !terminal(entry.Phase) && decisions.Hash(entry.Proposal.Target) == c.TargetSHA {
					return state{}, errors.New("target conflict requires observed resolution")
				}
			}
			next.Entries[id] = Entry{ID: id, Proposal: p, ApprovalSHA: decisions.Hash(s), Consumed: r.Time,
				ActionExpires: r.Time.Add(time.Duration(p.TTL) * time.Second), Phase: "intent_recorded"}
		} else {
			if r.Request != nil || c.ProposalSHA != "" || c.TTL != 0 {
				return bad()
			}
			switch c.Kind {
			case "stop", "resume":
				if c.Role != "response-supervisor" || c.HeadSHA != l.state.Head || c.EntryID != "" || c.EntrySHA != "" || c.TargetSHA != "" || c.ObservedState != "" || c.EvidenceSHA != "" || !c.ActionExpires.IsZero() {
					return bad()
				}
				next.Stopped[c.Tenant] = c.Kind == "stop"
			case "cancel", "observe":
				e, exists := next.Entries[c.EntryID]
				if !exists || terminal(e.Phase) || e.Proposal.Target.Tenant != c.Tenant || c.Issued.Before(e.Consumed) || c.EntrySHA != decisions.Hash(e) || c.HeadSHA != "" {
					return bad()
				}
				if c.Kind == "cancel" {
					if c.Role != "response-operator" || c.TargetSHA != "" || c.ObservedState != "" || c.EvidenceSHA != "" || !c.ActionExpires.IsZero() {
						return bad()
					}
					e.CancelRequested, e.Phase = true, "cancel_requested"
				} else {
					if c.Role != "response-observer" || c.TargetSHA != decisions.Hash(e.Proposal.Target) ||
						!decisions.ValidHash(c.EvidenceSHA) || !c.ActionExpires.Equal(e.ActionExpires) {
						return bad()
					}
					switch c.ObservedState {
					case "not_applied", "released":
						e.Phase = c.ObservedState
					case "active":
						if !r.Time.Before(e.ActionExpires) {
							return state{}, errors.New("active observation exceeds fixed action expiry")
						}
						if e.CancelRequested {
							e.Phase = "cancel_requested"
						} else {
							e.Phase = "active"
						}
					default:
						return bad()
					}
					e.ObservationSHA = c.EvidenceSHA
				}
				next.Entries[c.EntryID] = e
			default:
				return bad()
			}
		}
		next.Nonces[c.Nonce] = use{decisions.Hash(s), r.Time}
	} else {
		return bad()
	}
	next.Sequence, next.Head, next.At = r.Sequence, r.SHA, r.Time
	return next, nil
}
