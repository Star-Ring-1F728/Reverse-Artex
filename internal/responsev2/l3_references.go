package responsev2

import (
	"fmt"
	"reverse-artex/internal/decisions"
)

const l3ReferenceScheme = "l3-run-references/1"

// These labels are local to one pinned run, not policy capabilities. Every
// selection still resolves to the original complete ID and is revalidated by
// l3Apply/l3Complete. The prefix also rejects another run's remembered labels.
func l3ReferenceTag(q L3Request) string {
	return decisions.Hash([]string{l3ReferenceScheme, q.ID, q.Tenant, q.CaseID, q.CaseSHA})[:8]
}

type l3References struct {
	tag                       string
	evidence, candidates      map[string]string // original ID -> displayed label
	evidenceIDs, candidateIDs map[string]string // displayed label -> original ID
}

func newL3References(run L3Run, view CaseView) (*l3References, error) {
	if run.ReferenceScheme == "" {
		return nil, nil
	}
	if run.ReferenceScheme != l3ReferenceScheme || run.Request.CaseID != view.Case.ID || run.Request.CaseSHA != view.Case.SHA || run.Request.Tenant != view.Case.Tenant || len(view.Evidence) == 0 || len(view.Evidence) > 32 || len(view.Candidates) > 32 {
		return nil, ErrStale
	}
	r := &l3References{tag: l3ReferenceTag(run.Request), evidence: map[string]string{}, candidates: map[string]string{}, evidenceIDs: map[string]string{}, candidateIDs: map[string]string{}}
	for index, evidence := range view.Evidence {
		if !decisions.ValidHash(evidence.ID) || r.evidence[evidence.ID] != "" {
			return nil, ErrStale
		}
		label := fmt.Sprintf("e%d-%s", index+1, r.tag)
		r.evidence[evidence.ID], r.evidenceIDs[label] = label, evidence.ID
	}
	for index, candidate := range view.Candidates {
		if !decisions.ValidHash(candidate.ID) || r.candidates[candidate.ID] != "" || r.evidence[candidate.EvidenceID] == "" {
			return nil, ErrStale
		}
		label := fmt.Sprintf("c%d-%s", index+1, r.tag)
		r.candidates[candidate.ID], r.candidateIDs[label] = label, candidate.ID
	}
	return r, nil
}

// The context is freshly detached by l3Context. Only the displayed selection
// references change; signed evidence, scopes, case digest and stored IDs do not.
func (r *l3References) context(value map[string]any) (map[string]any, error) {
	facts, ok := value["facts"].([]map[string]any)
	if !ok {
		return nil, ErrStale
	}
	for _, fact := range facts {
		id, ok := fact["evidence_id"].(string)
		if !ok || r.evidence[id] == "" {
			return nil, ErrStale
		}
		fact["evidence_id"] = r.evidence[id]
	}
	candidates, ok := value["candidates"].([]map[string]string)
	if !ok {
		return nil, ErrStale
	}
	for _, candidate := range candidates {
		id, evidence := r.candidates[candidate["candidate_id"]], r.evidence[candidate["evidence_id"]]
		if id == "" || evidence == "" {
			return nil, ErrStale
		}
		candidate["candidate_id"], candidate["evidence_id"] = id, evidence
	}
	if strategy, ok := value["strategy"].(DefenseStrategy); ok {
		labels := make([]string, 0, len(strategy.Candidates))
		for _, id := range strategy.Candidates {
			if r.candidates[id] == "" {
				return nil, ErrStale
			}
			labels = append(labels, r.candidates[id])
		}
		// The canonical strategy hash describes stored source IDs. Displayed
		// references are explicitly the same per-run aliases as the tool offer.
		display := strategyWithoutCandidates(strategy)
		display["priority_candidate_ids"], display["candidate_reference_scheme"] = labels, l3ReferenceScheme
		value["strategy"] = display
	}
	return value, nil
}

func strategyWithoutCandidates(p DefenseStrategy) map[string]any {
	return map[string]any{"schema": p.Schema, "case_id": p.CaseID, "case_sha256": p.CaseSHA, "cancel_epoch": p.Epoch, "as_of_sequence": p.Sequence, "strategy_sha256": p.SHA, "observed_pattern": p.Pattern, "next_step": p.Next, "current_denials": p.Denied, "current_allowed": p.Allowed, "current_other": p.Other, "historical_observations": p.Historical, "denied_resources": p.Resources, "repeated_denied_scopes": p.RepeatedScopes, "already_contained_scopes": p.ActiveScopes, "sdk_masked_scopes": p.MaskedScopes, "response_feedback": p.Feedback, "feedback_truncated": p.FeedbackTruncated, "omitted_observations": p.OmittedObservations, "complete_case_history": p.CompleteHistory, "cooldown_scopes": p.CooldownScopes}
}

func (r *l3References) assessment(value L3Assessment) (L3Assessment, error) {
	resolved := make([]string, len(value.Evidence))
	for index, label := range value.Evidence {
		id, ok := r.evidenceIDs[label]
		if !ok {
			return L3Assessment{}, ErrStale
		}
		resolved[index] = id
	}
	value.Evidence = resolved
	return value, nil
}
