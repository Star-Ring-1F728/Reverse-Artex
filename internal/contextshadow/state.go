package contextshadow

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

const observerStateBytes = 4096

// One preallocated block is synced before readonly observation starts. If the
// attempt file cannot even be created, this pending intent still blocks restart.
// It is not a guarantee against device errors, power loss or privileged edits.
type observerState struct {
	Schema            string    `json:"schema"`
	Tenant            string    `json:"tenant_id"`
	CandidateSHA      string    `json:"candidate_sha256"`
	Pending           bool      `json:"pending"`
	NextSequence      int       `json:"next_sequence"`
	CommittedSequence int       `json:"committed_sequence"`
	UpdatedAt         time.Time `json:"updated_at"`
	SHA               string    `json:"sha256"`
}

func stateSHA(v observerState) string { v.SHA = ""; b, _ := json.Marshal(v); return fileSHA(b) }
func (s *Live) stateValue(pending bool) observerState {
	n := s.baseSequence + len(s.attempts)
	v := observerState{Schema: "context-shadow-observer-state/1", Tenant: s.c.Tenant, CandidateSHA: s.c.SHA, Pending: pending, NextSequence: n + 1, CommittedSequence: n, UpdatedAt: time.Now().UTC()}
	v.SHA = stateSHA(v)
	return v
}
func (s *Live) openObserverState() error {
	path := filepath.Join(s.dir, "observer.state.json")
	info, err := os.Lstat(path)
	if err == nil {
		if !info.Mode().IsRegular() || info.Size() != observerStateBytes {
			return errors.New("invalid observer state allocation")
		}
		var state observerState
		if err = ReadPublic(path, &state); err != nil {
			return err
		}
		n := s.baseSequence + len(s.attempts)
		if state.Schema != "context-shadow-observer-state/1" || state.Tenant != s.c.Tenant || state.CandidateSHA != s.c.SHA || state.SHA != stateSHA(state) || state.CommittedSequence != n || state.NextSequence != n+1 || state.Pending {
			return errors.New("unfinished or inconsistent shadow observation intent; preserve history and require operator review")
		}
		s.stateFile, err = os.OpenFile(path, os.O_RDWR, 0600)
		return err
	}
	if !os.IsNotExist(err) {
		return err
	}
	if s.totalBytes+observerStateBytes+4096 > s.limits.TotalBytes {
		return ErrLimit
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	s.stateFile = f
	if err = s.writeObserverState(false); err != nil {
		f.Close()
		s.stateFile = nil
		return err
	}
	s.totalBytes += observerStateBytes
	return nil
}
func (s *Live) writeObserverState(pending bool) error {
	// Storage-only unit tests may exercise the file layer without a live worker.
	if s.stateFile == nil {
		return nil
	}
	v := s.stateValue(pending)
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(b) > observerStateBytes-1 {
		return errors.New("observer state exceeds reserved block")
	}
	raw := bytes.Repeat([]byte(" "), observerStateBytes)
	copy(raw, b)
	raw[len(raw)-1] = '\n'
	if _, err = s.stateFile.Seek(0, io.SeekStart); err != nil {
		return err
	}
	n, writeErr := s.stateFile.Write(raw)
	if writeErr == nil && n != len(raw) {
		writeErr = io.ErrShortWrite
	}
	return errors.Join(writeErr, s.stateFile.Sync())
}
func (s *Live) finishObserverState() {
	if s.storageFailed {
		return
	} // Leave the durable pending intent unresolved.
	if err := s.writeObserverState(false); err != nil {
		s.storageFailed = true
		s.status.Enabled = false
		s.status.Error = fmt.Sprintf("shadow completion state unverified: %v", err)
	}
}
