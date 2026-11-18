package casememory

import (
	"embed"
	"reflect"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

const MaxAutoControls = 64
const stopReserveBytes = 8192

func (s *Store) stopReservationsAfter(r record) int {
	count := 0
	for tenant, h := range s.production {
		enabled := len(h) > 0 && h[len(h)-1].Request.Action != "stop"
		if r.ProductionChange != nil && r.ProductionChange.Tenant == tenant {
			enabled = r.ProductionChange.Request.Action != "stop"
		}
		if enabled {
			count++
		}
	}
	if r.ProductionChange != nil && len(s.production[r.ProductionChange.Tenant]) == 0 && r.ProductionChange.Request.Action != "stop" {
		count++
	}
	for run, history := range s.automatic {
		enabled := len(history) > 0 && history[len(history)-1].Request.Enabled
		if r.AutoControl != nil && r.AutoControl.RunID == run {
			enabled = r.AutoControl.Request.Enabled
		}
		if enabled {
			count++
		}
	}
	if r.AutoControl != nil && len(s.automatic[r.AutoControl.RunID]) == 0 && r.AutoControl.Request.Enabled {
		count++
	}
	for tenant, history := range s.advisory {
		enabled := len(history) > 0 && history[len(history)-1].Request.Action != "stop"
		if r.AdvisoryChange != nil && r.AdvisoryChange.Tenant == tenant {
			enabled = r.AdvisoryChange.Request.Action != "stop"
		}
		if enabled {
			count++
		}
	}
	if r.AdvisoryChange != nil && len(s.advisory[r.AdvisoryChange.Tenant]) == 0 && r.AdvisoryChange.Request.Action != "stop" {
		count++
	}
	return count
}

//go:embed automatic.go observer.go
var automaticSources embed.FS

func automaticSourceSHA() string {
	values := []string{}
	for _, name := range []string{"automatic.go", "observer.go"} {
		raw, _ := automaticSources.ReadFile(name)
		values = append(values, name, hash(raw))
	}
	return hash(values)
}

type AutoRequest struct {
	Expected int    `json:"expected_revision"`
	Enabled  bool   `json:"enabled"`
	Reason   string `json:"reason"`
}

type AutoControl struct {
	Schema    string      `json:"schema"`
	Tenant    string      `json:"tenant_id"`
	RunID     string      `json:"run_id"`
	Revision  int         `json:"revision"`
	Previous  string      `json:"previous_sha256"`
	SourceSHA string      `json:"automation_source_sha256,omitempty"`
	Request   AutoRequest `json:"request"`
	At        time.Time   `json:"changed_at"`
	SHA       string      `json:"control_sha256"`
}

type AutoView struct {
	RunID             string        `json:"run_id"`
	Revision          int           `json:"revision"`
	Enabled           bool          `json:"enabled"`
	State             string        `json:"state"`
	Blockers          []string      `json:"blockers"`
	History           []AutoControl `json:"history"`
	SnapshotRevision  int           `json:"snapshot_revision"`
	Coverage          string        `json:"coverage"`
	DeploymentAllowed bool          `json:"deployment_allowed"`
}

func validReason(reason string) bool {
	return reason != "" && utf8.ValidString(reason) && utf8.RuneCountInString(reason) <= 1000
}

func (s *Store) makeAuto(tenant, run string, q AutoRequest, at time.Time, source string) AutoControl {
	history := s.automatic[run]
	c := AutoControl{Schema: "case-shadow-auto/2", Tenant: tenant, RunID: run, Revision: len(history) + 1, Request: q, At: at, SourceSHA: source}
	if len(history) > 0 {
		c.Previous = history[len(history)-1].SHA
	}
	c.SHA = hash(c)
	return c
}

func (s *Store) validateAuto(c AutoControl) error {
	state, ok := s.shadows[c.RunID]
	if !ok || state.Plan.Tenant != c.Tenant {
		return ErrNotFound
	}
	history := s.automatic[c.RunID]
	if len(history) >= MaxAutoControls || (c.Request.Enabled && len(history) >= MaxAutoControls-1) {
		return ErrLimit
	}
	if c.Request.Expected != len(history) {
		return ErrConflict
	}
	// The early local v1 format had no automation source pin. Preserve its
	// original JSON/hash shape, replay it, and keep it blocked at runtime.
	if (c.Schema != "case-shadow-auto/1" && c.Schema != "case-shadow-auto/2") ||
		(c.Schema == "case-shadow-auto/2" && !digest.MatchString(c.SourceSHA)) ||
		(c.SourceSHA != "" && !digest.MatchString(c.SourceSHA)) || c.At.IsZero() || c.At.Before(state.Plan.StartedAt) || (len(history) > 0 && c.At.Before(history[len(history)-1].At)) ||
		strings.TrimSpace(c.Request.Reason) != c.Request.Reason || !validReason(c.Request.Reason) {
		return ErrInvalid
	}
	if c.Request.Enabled {
		if _, ok := s.reviews[c.RunID]; !ok {
			return ErrConflict
		}
		if len(s.trainingChanges(s.candidates[state.Plan.CandidateID])) > 0 || len(state.Snapshots) >= MaxShadowSnapshots {
			return ErrConflict
		}
	}
	want := s.makeAuto(c.Tenant, c.RunID, c.Request, c.At, c.SourceSHA)
	want.Schema = c.Schema
	want.SHA = ""
	want.SHA = hash(want)
	if !reflect.DeepEqual(c, want) {
		return ErrInvalid
	}
	return nil
}

func (s *Store) autoView(run string) AutoView {
	state := s.shadows[run]
	history := s.automatic[run]
	v := AutoView{RunID: run, Revision: len(history), State: "disabled", Blockers: []string{}, History: append([]AutoControl{}, history...), SnapshotRevision: len(state.Snapshots), Coverage: "verified case-memory updates only; not full traffic coverage"}
	if len(history) == 0 || !history[len(history)-1].Request.Enabled {
		return v
	}
	v.Enabled = true
	if history[len(history)-1].SourceSHA != automaticSourceSHA() {
		v.Blockers = append(v.Blockers, "automation_implementation_changed")
	}
	view := s.shadowView(state, 0)
	if view.ReevaluationRequired {
		v.Blockers = append(v.Blockers, "training_or_observer_changed")
	}
	if len(state.Snapshots) >= MaxShadowSnapshots {
		v.Blockers = append(v.Blockers, "snapshot_capacity_reached")
	}
	stops := s.stopReservationsAfter(record{})
	if s.sequence+stops+1 > 8192 || s.size+int64(stops*stopReserveBytes)+MaxRecord > MaxJournal {
		v.Blockers = append(v.Blockers, "journal_capacity_near_limit")
	}
	v.State = "observing"
	if len(v.Blockers) > 0 {
		v.State = "blocked"
	}
	return v
}

func (s *Store) Automatic(tenant, run string) (AutoView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return AutoView{}, err
	}
	state, ok := s.shadows[run]
	if !ok || state.Plan.Tenant != tenant {
		return AutoView{}, ErrNotFound
	}
	return clone(s.autoView(run)), nil
}

func (s *Store) SetAutomatic(tenant, run string, q AutoRequest) (AutoView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return AutoView{}, err
	}
	state, ok := s.shadows[run]
	if !ok || state.Plan.Tenant != tenant {
		return AutoView{}, ErrNotFound
	}
	q.Reason = strings.TrimSpace(q.Reason)
	for _, old := range s.automatic[run] {
		if old.Request == q {
			return clone(s.autoView(run)), nil
		}
	}
	if q.Enabled && s.shadowView(state, 0).ReevaluationRequired {
		return AutoView{}, ErrConflict
	}
	c := s.makeAuto(tenant, run, q, time.Now().UTC(), automaticSourceSHA())
	if err := s.append(record{AutoControl: &c}); err != nil {
		return AutoView{}, err
	}
	if err := s.captureAutomaticLocked(); err != nil {
		return AutoView{}, err
	}
	return clone(s.autoView(run)), nil
}

// The caller holds the store lock across import/prediction/label ordering.
// Known stale/capacity conditions remain visible as blocked, without preventing
// unrelated label work. An actual journal failure is returned and latches closed.
func (s *Store) captureAutomaticLocked() error {
	runs := make([]string, 0, len(s.automatic))
	for run := range s.automatic {
		runs = append(runs, run)
	}
	sort.Strings(runs)
	for _, run := range runs {
		if s.autoView(run).State != "observing" {
			continue
		}
		state := s.shadows[run]
		view := s.shadowView(state, 0)
		if !view.RefreshRequired && len(state.Snapshots) > 0 {
			continue
		}
		snapshot, err := s.shadowSnapshot(state, s.candidates[state.Plan.CandidateID], time.Now().UTC())
		if err != nil {
			return err
		}
		if err = s.append(record{ShadowSnapshot: &snapshot}); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) NeedsAutomaticSync() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.available() != nil {
		return false
	}
	for tenant, h := range s.production {
		if len(h) > 0 && h[len(h)-1].Request.Action != "stop" && len(s.productionBlockers(tenant, time.Now().UTC())) == 0 {
			return true
		}
	}
	for run := range s.automatic {
		if s.autoView(run).State == "observing" {
			return true
		}
	}
	return false
}
