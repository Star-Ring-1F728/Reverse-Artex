package responsev2

import (
	"errors"
	"reverse-artex/internal/protection"
	"time"
)

const (
	legacyCaseLimit   = 512
	retainedCaseLimit = 1024
)

type caseRetirement struct {
	ID  string `json:"case_id"`
	SHA string `json:"case_sha256"`
}

func (s *Store) caseLimit() int {
	if s.retained != nil {
		return retainedCaseLimit
	}
	return legacyCaseLimit
}

// cleanCaseToRetire selects a case only when all its observations are still
// available and establish a normal read. Decisions, policies and unresolved
// response attempts keep their case. Retirement only removes the working
// view; the existing retained journal handles the signed event and write.
func (s *Store) cleanCaseToRetire(now time.Time) *caseRetirement {
	if s.retained == nil || len(s.cases) < retainedCaseLimit {
		return nil
	}
	pinned := make(map[string]bool)
	for _, history := range s.histories {
		pinned[caseID(history.Binding.Scope)] = true
	}
	for _, lease := range s.leases {
		pinned[caseID(lease.Scope)] = true
	}
	for _, job := range s.jobs {
		pinned[job.CaseID] = true
	}
	for _, run := range s.l3Runs {
		pinned[run.Request.CaseID] = true
	}
	var oldest Case
	for _, c := range s.cases {
		if oldest.ID != "" && (c.Updated.After(oldest.Updated) || (c.Updated.Equal(oldest.Updated) && c.ID > oldest.ID)) {
			continue
		}
		if s.pendingCases[c.ID] != 0 || pinned[c.ID] || c.Revision != len(c.Refs) || len(c.Refs) == 0 || now.Sub(c.Updated) < protection.ProofLifetime {
			continue
		}
		clean := true
		for _, ref := range c.Refs {
			e, present := s.events[ref]
			if !present || e.Kind != "authorized_representation" || e.Status != 200 || now.Sub(e.Binding.Started) < protection.ProofLifetime {
				clean = false
				break
			}
		}
		if clean {
			oldest = c
		}
	}
	if oldest.ID == "" {
		return nil
	}
	return &caseRetirement{ID: oldest.ID, SHA: oldest.SHA}
}

func (s *Store) validateCaseRetirement(r record) error {
	if r.Case == nil {
		if r.RetiredCase != nil {
			return errors.New("case retirement requires signed replacement")
		}
		return nil
	}
	if _, exists := s.cases[r.Case.ID]; exists || len(s.cases) < s.caseLimit() {
		if r.RetiredCase != nil {
			return errors.New("unexpected case retirement")
		}
		return nil
	}
	expected := s.cleanCaseToRetire(r.At)
	if expected == nil || r.RetiredCase == nil || *expected != *r.RetiredCase {
		return errors.New("case replacement exceeds retained working capacity or retirement differs")
	}
	return nil
}
