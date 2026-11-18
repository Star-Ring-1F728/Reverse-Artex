package assistance

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
)

type stateStore interface {
	load() (State, bool, error)
	save(State) error
	close() error
}
type fileStore struct {
	path  string
	owner *os.File
}

func regular(path string) error {
	st, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() || st.Size() > MaxState {
		return errors.New("bounded regular state file required")
	}
	return nil
}
func openStore(path string) (*fileStore, error) {
	if path == "" {
		return nil, errors.New("explicit local state path required")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if err = os.MkdirAll(filepath.Dir(abs), 0700); err != nil {
		return nil, err
	}
	if err = regular(abs); err != nil {
		return nil, err
	}
	if err = regular(abs + ".lock"); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(abs+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = lockOwner(f); err != nil {
		f.Close()
		return nil, errors.New("assistance state already owned or unavailable")
	}
	s := &fileStore{abs, f}
	if _, err = os.Lstat(abs + ".next"); !os.IsNotExist(err) {
		s.close()
		return nil, errors.New("interrupted state candidate retained; explicit operator recovery required")
	}
	return s, nil
}
func (s *fileStore) close() error { unlockOwner(s.owner); return s.owner.Close() }
func (s *fileStore) load() (State, bool, error) {
	var state State
	if err := regular(s.path); err != nil {
		return state, false, err
	}
	data, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return state, false, nil
	}
	if err != nil {
		return state, false, err
	}
	var envelope struct {
		Schema  string          `json:"schema"`
		Payload json.RawMessage `json:"payload"`
		Hash    string          `json:"sha256"`
	}
	if err = strict(data, &envelope); err != nil {
		return state, false, err
	}
	// hashRaw uses the same deterministic byte checksum as the snapshot encoder.
	if envelope.Schema != "assistance-envelope/1" || envelope.Hash != hashRaw(envelope.Payload) {
		return state, false, errors.New("assistance state checksum mismatch")
	}
	if err = strict(envelope.Payload, &state); err != nil {
		return state, false, err
	}
	err = validateState(state)
	return state, true, err
}
func (s *fileStore) save(state State) error {
	if err := validateState(state); err != nil {
		return err
	}
	payload, err := json.Marshal(state)
	if err != nil {
		return err
	}
	envelope := struct {
		Schema  string          `json:"schema"`
		Payload json.RawMessage `json:"payload"`
		Hash    string          `json:"sha256"`
	}{"assistance-envelope/1", payload, hashRaw(payload)}
	data, err := json.Marshal(envelope)
	if err != nil {
		return err
	}
	if len(data) > MaxState {
		return errors.New("assistance state capacity")
	}
	f, err := os.OpenFile(s.path+".next", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	complete := false
	defer func() {
		f.Close()
		if !complete {
			_ = os.Remove(s.path + ".next")
		}
	}()
	n, err := f.Write(data)
	if err == nil && n != len(data) {
		err = errors.New("short state write")
	}
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = regular(s.path); err != nil {
		return err
	}
	if err = replaceState(s.path+".next", s.path); err != nil {
		return err
	}
	complete = true
	return nil
}

func validateState(s State) error {
	bad := func() error { return errors.New("invalid or inconsistent assistance ledger") }
	if s.Schema != "assistance-state/1" || s.Epoch < 1 || s.Epoch > MaxEpochs || len(s.Activations) != s.Epoch || s.Config.Validate() != nil || len(s.Jobs) > MaxJobs || len(s.Parents) > MaxParents || s.Parents == nil || s.Window.Tenants == nil || len(s.Window.Tenants) > 16 || len(s.Breakers) != 2 {
		return bad()
	}
	for i, a := range s.Activations {
		if a.Epoch != i+1 || a.Config.Validate() != nil || !identifier.MatchString(a.Actor) {
			return bad()
		}
	}
	if s.Config != s.Activations[len(s.Activations)-1].Config {
		return bad()
	}
	for _, kind := range []string{Decision, Investigation} {
		b, ok := s.Breakers[kind]
		if !ok || b.Failures < 0 || b.Failures > 3 {
			return bad()
		}
	}
	parents := map[string]Parent{}
	window := Usage{}
	tenants := map[string]Usage{}
	seen := map[string]bool{}
	for _, j := range s.Jobs {
		if j.Snapshot.Validate() != nil || j.Epoch < 1 || j.Epoch > s.Epoch || j.ID != j.Snapshot.key(j.Epoch) || seen[j.ID] || j.Hash != hash(j.Snapshot) || j.Enqueued.IsZero() || len(j.Attempts) > 4 {
			return bad()
		}
		seen[j.ID] = true
		switch j.Phase {
		case "queued_decisions", "queued_investigator", "running_decisions", "running_investigator", "done", "cancelled", "interrupted":
		default:
			return bad()
		}
		if pending(j.Phase) && j.Epoch != s.Epoch {
			return bad()
		}
		parent := j.Snapshot.parent()
		if _, ok := parents[parent]; !ok {
			parents[parent] = Parent{Deadline: j.Enqueued.Add(60 * 1e9)}
		}
		if !j.Deadline.Equal(parents[parent].Deadline) || !j.Enqueued.Before(j.Deadline) {
			return bad()
		}
		for _, a := range j.Attempts {
			if (a.Kind != Decision && a.Kind != Investigation) || !s.Activations[j.Epoch-1].Config.module(a.Kind).Enabled || a.Started.IsZero() || a.Window.IsZero() || !a.Started.Before(j.Deadline) || a.Charge != chargeFor(a.Kind, j.Snapshot, s.Activations[j.Epoch-1].Config.module(a.Kind)) {
				return bad()
			}
			switch a.Outcome {
			case "running", "ok", "timeout", "refusal", "invalid", "panic", "cancelled", "stale", "error", "interrupted", "rate_limited":
			default:
				return bad()
			}
			if a.Result != nil {
				data, _ := json.Marshal(a.Result)
				if a.Outcome != "ok" {
					return bad()
				}
				if _, err := decodeResult(data, a.Kind, Call{Snapshot: j.Snapshot, Epoch: j.Epoch, Hash: j.Hash, Enqueued: j.Enqueued, Expires: decisionDeadline(j)}); err != nil {
					return bad()
				}
			}
			p := parents[parent]
			p.Usage = p.Usage.add(a.Charge)
			parents[parent] = p
			if a.Window.Equal(s.Window.Start) {
				window = window.add(a.Charge)
				tenants[j.Snapshot.Tenant] = tenants[j.Snapshot.Tenant].add(a.Charge)
			}
		}
	}
	if !reflect.DeepEqual(parents, s.Parents) || window != s.Window.Usage || !reflect.DeepEqual(tenants, s.Window.Tenants) || !windowAllows(window) {
		return bad()
	}
	for _, u := range parents {
		if !parentAllows(u.Usage) {
			return bad()
		}
	}
	for _, u := range tenants {
		if u.Calls > 30 {
			return bad()
		}
	}
	return nil
}
