package contextshadow

import (
	"embed"
	"errors"
	"os"
	"path/filepath"
	"reverse-artex/internal/actioncontext"
	"reverse-artex/internal/casememory"
	"reverse-artex/internal/contextlearning"
	"time"
)

//go:embed reader.go live.go history.go state.go lock_linux.go lock_windows.go lock_other.go
var readerSources embed.FS

func HistoryReaderSHA() string {
	values := []string{SourceSHA()}
	for _, n := range []string{"reader.go", "live.go", "history.go", "state.go", "lock_linux.go", "lock_windows.go", "lock_other.go"} {
		raw, _ := readerSources.ReadFile(n)
		values = append(values, n, contextlearning.Digest(string(raw)))
	}
	return contextlearning.Digest(values)
}

type HistorySnapshot struct {
	Schema          string    `json:"schema"`
	CandidateSHA    string    `json:"candidate_sha256"`
	Attempts        []Attempt `json:"attempts"`
	StateSHA        string    `json:"observer_state_sha256"`
	CommittedBefore time.Time `json:"committed_before"`
	CapacityPaused  bool      `json:"capacity_paused"`
	UnsavedChecks   int       `json:"unsaved_checks"`
	SHA             string    `json:"history_sha256"`
}

func HistorySnapshotSHA(h HistorySnapshot) string { h.SHA = ""; return contextlearning.Digest(h) }

// ReadHistory restores all archives and active attempts under the existing
// owner lock without creating files, starting workers, or repairing intents.
func ReadHistory(dir string, c contextlearning.Candidate, a casememory.LearningTrust, trust actioncontext.Trust, limits StorageLimits) (HistorySnapshot, error) {
	h := HistorySnapshot{Schema: "context-shadow-history/2", CandidateSHA: c.SHA, Attempts: []Attempt{}}
	if !limits.valid() || ValidateCandidate(c, c.SHA, a, trust) != nil {
		return h, contextlearning.ErrInvalid
	}
	st, e := os.Lstat(dir)
	if os.IsNotExist(e) {
		h.SHA = HistorySnapshotSHA(h)
		return h, nil
	}
	if e != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return h, contextlearning.ErrInvalid
	}
	path := filepath.Join(dir, "owner.lock")
	st, e = os.Lstat(path)
	if e != nil || !st.Mode().IsRegular() {
		return h, errors.New("existing shadow owner required; preserve history")
	}
	owner, e := os.OpenFile(path, os.O_RDWR, 0600)
	if e != nil {
		return h, e
	}
	defer owner.Close()
	if e = lockOwner(owner); e != nil {
		return h, e
	}
	defer unlockOwner(owner)
	live := &Live{dir: dir, c: c, a: a, trust: trust, limits: limits}
	if e = live.restoreHistory(); e != nil {
		return h, e
	}
	path = filepath.Join(dir, "observer.state.json")
	st, e = os.Lstat(path)
	if e != nil || !st.Mode().IsRegular() || st.Size() != observerStateBytes {
		return h, errors.New("committed observer state required")
	}
	var state observerState
	if e = ReadPublic(path, &state); e != nil {
		return h, e
	}
	n := live.baseSequence + len(live.attempts)
	if state.Schema != "context-shadow-observer-state/1" || state.Tenant != c.Tenant || state.CandidateSHA != c.SHA || state.SHA != stateSHA(state) || state.Pending || state.CommittedSequence != n || state.NextSequence != n+1 || state.UpdatedAt.IsZero() || live.latest != nil && state.UpdatedAt.Before(live.latest.FinishedAt) {
		return h, errors.New("unfinished observer intent; preserve original history")
	}
	for sequence := 1; sequence <= n; sequence++ {
		v, e := live.History(sequence)
		if e != nil {
			return h, e
		}
		h.Attempts = append(h.Attempts, v)
	}
	h.StateSHA = state.SHA
	h.CommittedBefore = state.UpdatedAt
	h.CapacityPaused = live.storageFull
	h.UnsavedChecks = live.unsavedChecks
	h.SHA = HistorySnapshotSHA(h)
	return h, nil
}
