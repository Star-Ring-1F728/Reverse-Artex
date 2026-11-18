package responsev2

import (
	"encoding/json"
	"sort"
	"time"
)

// Candidate links let the model identify the signed fact and exact scope
// behind an opaque server candidate without exposing identity or raw proof.
// Selection still requires the current case/epoch checks in l3Apply.
func l3CandidateLinks(view CaseView) []map[string]string {
	links := make([]map[string]string, 0, len(view.Candidates))
	for _, candidate := range view.Candidates {
		links = append(links, map[string]string{"candidate_id": candidate.ID, "evidence_id": candidate.EvidenceID, "scope_id": scopeID(candidate.Scope)})
	}
	return links
}

// l3Context publishes only the same redacted information as the three
// individual read tools, under one current-case/epoch/time check and lock.
func (s *Store) l3Context(id string, bound CaseView) (map[string]any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if err := s.check(now); err != nil {
		return nil, err
	}
	run, ok := s.l3Runs[id]
	if !ok || run.Status != "running" || run.Cancelled || s.paused || run.Epoch != s.epoch || !now.Before(run.Deadline) || run.Request.CaseSHA != bound.Case.SHA || s.cases[run.Request.CaseID].SHA != bound.Case.SHA || bound.Case.Tenant != run.Request.Tenant {
		return nil, ErrStale
	}
	facts := []map[string]any{}
	scopes := map[string]bool{}
	for _, f := range bound.Evidence {
		scopes[scopeID(f.Scope)] = true
		fact := map[string]any{"evidence_id": f.ID, "kind": f.Kind, "scope_id": scopeID(f.Scope), "resource_pseudonym": f.Scope.Resource, "method": f.Scope.Method, "sdk_status": f.Status, "observed_at": f.At}
		if run.GroundingScheme == l3GroundingScheme {
			age, state := l3EvidenceAge(f.At, now)
			fact["age_ms"], fact["freshness"] = age, state
		}
		facts = append(facts, fact)
	}
	leases := []Lease{}
	for _, lease := range s.leases {
		if lease.Scope.Tenant == run.Request.Tenant && scopes[scopeID(lease.Scope)] && now.Before(lease.Expires) && now.Before(s.deadlines[lease.ID]) && len(lease.Claims) > 0 {
			leases = append(leases, lease)
		}
	}
	sort.Slice(leases, func(i, j int) bool { return leases[i].ID < leases[j].ID })
	policies := []map[string]any{}
	for _, p := range leases {
		policies = append(policies, map[string]any{"policy_id": p.ID, "episode_id": p.Episode, "generation": p.Generation, "scope_id": scopeID(p.Scope), "expires_at": p.Expires, "owners": len(p.Claims)})
	}
	result := map[string]any{
		"case":  map[string]any{"case_id": bound.Case.ID, "case_sha256": bound.Case.SHA, "revision": bound.Case.Revision, "evidence_count": len(bound.Evidence), "coverage": bound.Coverage, "mandatory_review": bound.PendingReview},
		"facts": facts, "truncated": bound.Case.Revision > 32,
		"candidates": l3CandidateLinks(bound),
		"responses":  map[string]any{"policies": policies, "installation_is_effect": false},
	}
	if run.GroundingScheme == l3GroundingScheme {
		result["grounding"] = l3EvidenceGrounding(bound, now)
	}
	if run.Strategy != nil {
		result["strategy"] = clone(*run.Strategy)
	}
	raw, err := json.Marshal(result)
	if err != nil || len(raw) > 16<<10 {
		return nil, ErrLimit
	}
	return result, nil
}
