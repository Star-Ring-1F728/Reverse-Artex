package responsev2

import (
	"reverse-artex/internal/decisions"
	"sort"
	"time"
)

// Strategy is a bounded projection of verified journal facts, never model
// prose or an attacker-supplied instruction. Revisions use journal sequence
// numbers so receiving a response outcome can change a plan without new SDK
// evidence. The projection is advisory outside an explicitly requested L3 run.
type DefenseStrategy struct {
	Schema              string             `json:"schema"`
	Tenant              string             `json:"tenant"`
	CaseID              string             `json:"case_id"`
	CaseSHA             string             `json:"case_sha256"`
	Epoch               int                `json:"cancel_epoch"`
	Sequence            int                `json:"as_of_sequence"`
	SHA                 string             `json:"strategy_sha256"`
	Pattern             string             `json:"observed_pattern"`
	Next                string             `json:"next_step"`
	Denied              int                `json:"current_denials"`
	Allowed             int                `json:"current_allowed"`
	Other               int                `json:"current_other"`
	Historical          int                `json:"historical_observations"`
	Resources           int                `json:"denied_resources"`
	RepeatedScopes      int                `json:"repeated_denied_scopes"`
	Candidates          []string           `json:"priority_candidate_ids"`
	ActiveScopes        int                `json:"already_contained_scopes"`
	MaskedScopes        int                `json:"sdk_masked_scopes"`
	Feedback            []StrategyFeedback `json:"response_feedback"`
	FeedbackTruncated   bool               `json:"feedback_truncated"`
	OmittedObservations int                `json:"omitted_observations,omitempty"`
	CompleteHistory     bool               `json:"complete_case_history,omitempty"`
	CooldownScopes      int                `json:"cooldown_scopes,omitempty"`
}

type StrategyFeedback struct {
	PolicyID   string `json:"policy_id"`
	Episode    string `json:"episode_id"`
	ScopeID    string `json:"scope_id"`
	OutcomeSHA string `json:"outcome_sha256"`
	Effect     string `json:"policy_effect"`
	Target     string `json:"target"`
	Benign     string `json:"benign_impact"`
	Recovery   string `json:"recovery"`
	Unknown    int    `json:"unknown_responses"`
}

func strategySHA(p DefenseStrategy) string { p.SHA = ""; return decisions.Hash(p) }

// Strategy does not enqueue inference or change policies. It remains readable
// while paused, so an operator can inspect collateral and recover safely.
func (s *Store) Strategy(tenant, id string) (DefenseStrategy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if err := s.check(now); err != nil {
		return DefenseStrategy{}, err
	}
	v, err := s.viewLocked(tenant, id, now)
	if err != nil {
		return DefenseStrategy{}, err
	}
	return s.strategyLocked(v, now), nil
}

func strategyCompatible(a, b Scope) bool {
	a.Resource, b.Resource = "", ""
	return a == b
}

func (s *Store) strategyLocked(v CaseView, now time.Time) DefenseStrategy {
	p := DefenseStrategy{Schema: "defense-strategy/1", Tenant: v.Case.Tenant, CaseID: v.Case.ID, CaseSHA: v.Case.SHA, Epoch: s.epoch, Sequence: s.sequence, Pattern: "no_current_denials", Next: "observe", Candidates: []string{}, Feedback: []StrategyFeedback{}}
	counts, resources, allowedScopes := map[string]int{}, map[string]bool{}, map[string]bool{}
	latest := map[string]time.Time{}
	for _, e := range v.Evidence {
		if e.At.After(now) || e.At.Before(now.Add(-time.Minute)) {
			p.Historical++
			continue
		}
		switch e.Kind {
		case "prevented_unauthorized_access":
			p.Denied++
			resources[e.Scope.Resource] = true
			id := scopeID(e.Scope)
			counts[id]++
			if e.At.After(latest[id]) {
				latest[id] = e.At
			}
		case "authorized_representation":
			p.Allowed++
			allowedScopes[scopeID(e.Scope)] = true
		default:
			p.Other++
		}
	}
	p.OmittedObservations = v.Case.Revision - len(v.Evidence)
	p.CompleteHistory = p.OmittedObservations == 0
	if p.OmittedObservations > 0 {
		// The model context is a sample, not the whole journal. A lifetime
		// revision above 32 must not permanently disable scoped defense when
		// all signed-source events are still retained. Count exact case events
		// before trusting this completeness claim; retained/evicted gaps hold.
		retained := 0
		for _, e := range s.events {
			if caseID(e.Scope) != v.Case.ID {
				continue
			}
			retained++
			if e.At.After(now) || e.At.Before(now.Add(-time.Minute)) {
				continue
			}
			// An earlier allow or other conflicting result on the exact target
			// must survive rotation out of the model's last-32 context window.
			if e.Kind != "prevented_unauthorized_access" {
				allowedScopes[scopeID(e.Scope)] = true
			}
		}
		p.CompleteHistory = retained == v.Case.Revision
	}
	p.Resources = len(resources)
	for _, n := range counts {
		if n > 1 {
			p.RepeatedScopes++
		}
	}
	if p.Denied > 0 {
		p.Pattern = "denied_access"
	}
	if p.Resources >= 2 {
		p.Pattern = "multi_resource_denials"
	}
	if p.Denied > 0 && p.Allowed > 0 {
		p.Pattern = "mixed_allowed_and_denied"
	}
	if p.Other > 0 {
		p.Pattern = "unknown_observations"
	}

	// Read only compatible actor/session, authorization, route, registry and
	// enforcer history. Never transfer an old decision across trust revisions.
	histories := []PolicyHistory{}
	for _, h := range s.histories {
		for _, e := range v.Evidence {
			if strategyCompatible(h.Binding.Scope, e.Scope) {
				histories = append(histories, h)
				break
			}
		}
	}
	sort.Slice(histories, func(i, j int) bool { return histories[i].InstalledSequence > histories[j].InstalledSequence })
	if len(histories) > 4 {
		p.FeedbackTruncated = true
		histories = histories[:4]
	}
	masked := map[string]bool{}
	collateral, recoveryPending, uncertain := false, false, false
	for _, h := range histories {
		o, err := s.outcomeLocked(v.Case.Tenant, h.Binding.PolicyID, h.Binding.Episode, now)
		if err != nil {
			uncertain = true
			continue
		}
		p.Feedback = append(p.Feedback, StrategyFeedback{PolicyID: o.PolicyID, Episode: o.Episode, ScopeID: o.ScopeID, OutcomeSHA: decisions.Hash(o), Effect: o.PolicyEffect, Target: o.Target.State, Benign: o.Benign.State, Recovery: o.Recovery.State, Unknown: o.UnknownResponses})
		if o.PolicyEffect == "masked_by_sdk" {
			masked[o.ScopeID] = true
		}
		collateral = collateral || o.Benign.State == "observed_collateral"
		recoveryPending = recoveryPending || (o.RecoveryReason != "" && o.Recovery.State != "observed_guard_baseline_restored")
		uncertain = uncertain || o.UnknownResponses > 0
	}
	active := map[string]bool{}
	cooldown := map[string]bool{}
	for _, c := range v.Candidates {
		id := scopeID(c.Scope)
		if counts[id] == 0 {
			continue
		}
		if s.gate(v.Case, c.Scope, now).Deny {
			active[id] = true
			continue
		}
		if masked[id] || allowedScopes[id] {
			continue
		}
		if lease, ok := s.leases[id]; ok && now.Before(lease.Cooldown) && (!now.Before(lease.Expires) || len(lease.Claims) == 0) {
			cooldown[id] = true
			continue
		}
		p.Candidates = append(p.Candidates, c.ID)
	}
	p.ActiveScopes, p.MaskedScopes = len(active), len(masked)
	p.CooldownScopes = len(cooldown)
	byID := map[string]Candidate{}
	for _, c := range v.Candidates {
		byID[c.ID] = c
	}
	sort.Slice(p.Candidates, func(i, j int) bool {
		a, b := scopeID(byID[p.Candidates[i]].Scope), scopeID(byID[p.Candidates[j]].Scope)
		if counts[a] != counts[b] {
			return counts[a] > counts[b]
		}
		if !latest[a].Equal(latest[b]) {
			return latest[a].After(latest[b])
		}
		return p.Candidates[i] < p.Candidates[j]
	})
	switch {
	case collateral || s.paused:
		p.Next = "review_collateral"
	case p.FeedbackTruncated:
		p.Next = "review_history"
	case uncertain:
		p.Next = "verify_response"
	case recoveryPending:
		p.Next = "verify_recovery"
	case p.Other > 0 || !p.CompleteHistory:
		p.Next = "review_evidence"
	case len(p.Candidates) > 0:
		p.Next = "contain_exact"
	case len(active) > 0:
		p.Next = "verify_existing_response"
	case len(masked) > 0:
		p.Next = "observe_guard_baseline"
	case len(cooldown) > 0:
		p.Next = "wait_cooldown"
	case p.Denied > 0:
		p.Next = "review_evidence"
	}
	if p.Next != "contain_exact" {
		p.Candidates = []string{}
	}
	p.SHA = strategySHA(p)
	return p
}

func strategyAllows(p DefenseStrategy, candidate string) bool {
	if p.Next != "contain_exact" {
		return false
	}
	for _, id := range p.Candidates {
		if id == candidate {
			return true
		}
	}
	return false
}

func validStrategy(p DefenseStrategy, q L3Request, initial bool) bool {
	if p.Schema != "defense-strategy/1" || p.Tenant != q.Tenant || p.CaseID != q.CaseID || !decisions.ValidHash(p.CaseSHA) || (initial && p.CaseSHA != q.CaseSHA) || p.Epoch < 1 || p.Sequence < 0 || p.SHA != strategySHA(p) || len(p.Candidates) > 32 || len(p.Feedback) > 4 {
		return false
	}
	switch p.Next {
	case "observe", "contain_exact", "review_collateral", "review_history", "verify_response", "verify_recovery", "review_evidence", "verify_existing_response", "observe_guard_baseline", "wait_cooldown":
	default:
		return false
	}
	switch p.Pattern {
	case "no_current_denials", "denied_access", "multi_resource_denials", "mixed_allowed_and_denied", "unknown_observations":
	default:
		return false
	}
	if p.Denied < 0 || p.Allowed < 0 || p.Other < 0 || p.Historical < 0 || p.Denied+p.Allowed+p.Other+p.Historical > 32 || p.Resources < 0 || p.Resources > p.Denied || p.RepeatedScopes < 0 || p.RepeatedScopes > p.Denied/2 || p.ActiveScopes < 0 || p.ActiveScopes > 32 || p.MaskedScopes < 0 || p.MaskedScopes > 4 {
		return false
	}
	if p.OmittedObservations < 0 || p.CooldownScopes < 0 || p.CooldownScopes > 32 || (p.OmittedObservations > 0 && !p.CompleteHistory && len(p.Candidates) > 0) {
		return false
	}
	if p.Next != "contain_exact" && len(p.Candidates) != 0 {
		return false
	}
	seen := map[string]bool{}
	for _, id := range p.Candidates {
		if !decisions.ValidHash(id) || seen[id] {
			return false
		}
		seen[id] = true
	}
	for _, f := range p.Feedback {
		if !decisions.ValidHash(f.PolicyID) || !decisions.ValidHash(f.ScopeID) || !decisions.ValidHash(f.OutcomeSHA) || f.Episode == "" || f.Unknown < 0 {
			return false
		}
	}
	return true
}
