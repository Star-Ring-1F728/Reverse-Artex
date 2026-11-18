// Package actionproposal builds offline review drafts. It has no approval,
// transport, credential, policy writer or execution capability.
package actionproposal

import (
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"strings"
	"time"

	"reverse-artex/internal/assistance"
	"reverse-artex/internal/decisions"
	"reverse-artex/internal/detect"
	"reverse-artex/internal/event"
	"reverse-artex/internal/policy"
)

const MaxRequest = 64 << 10

// Request is an explicit offline declaration, not an authenticated case read.
// A live integration must obtain this context and events from trusted stores.
// No target, template, TTL, approval or command is accepted from the model.
type Request struct {
	Schema         string              `json:"schema"`
	Snapshot       assistance.Snapshot `json:"snapshot"`
	Epoch          int                 `json:"current_config_epoch"`
	Enqueued       time.Time           `json:"enqueued_at"`
	DecisionExpiry time.Time           `json:"classification_deadline"`
	ParentDeadline time.Time           `json:"parent_deadline"`
	Decision       decisions.Result    `json:"decision"`
	SubjectRef     string              `json:"subject_evidence_id"`
	Events         []event.Event       `json:"events"`
}

type Target struct {
	Tenant    string `json:"tenant_id"`
	Asset     string `json:"asset_id"`
	Principal string `json:"principal_id"`
	Session   string `json:"session_hmac"`
	Route     string `json:"route_template"`
}

type Proposal struct {
	Schema          string    `json:"schema"`
	ID              string    `json:"proposal_id"`
	Key             string    `json:"idempotency_key"`
	CaseID          string    `json:"case_id"`
	Revision        int       `json:"case_revision"`
	Epoch           int       `json:"config_epoch"`
	SnapshotSHA     string    `json:"snapshot_sha256"`
	SourceCommit    string    `json:"source_commit"`
	DecisionSHA     string    `json:"decision_result_sha256"`
	EvidenceSHA     string    `json:"evidence_sha256"`
	EvidenceRefs    []string  `json:"evidence_refs"`
	Rule            string    `json:"independent_rule"`
	Template        string    `json:"template_id"`
	TemplateVersion int       `json:"template_version"`
	Target          Target    `json:"target"`
	TTL             int       `json:"requested_ttl_seconds"`
	Impact          string    `json:"impact"`
	Recovery        string    `json:"recovery_type"`
	Created         time.Time `json:"created_at"`
	Expires         time.Time `json:"expires_at"`
}

// ApprovalRequirement is a review binding, never a grant or approval token.
type ApprovalRequirement struct {
	ProposalSHA string    `json:"proposal_sha256"`
	TargetSHA   string    `json:"target_sha256"`
	TTL         int       `json:"ttl_seconds"`
	Expires     time.Time `json:"expires_at"`
	Role        string    `json:"required_role"`
}

type Review struct {
	Schema    string               `json:"schema"`
	Scope     string               `json:"scope"`
	Authority string               `json:"authority"`
	Status    string               `json:"status"`
	Reason    string               `json:"reason"`
	Proposal  *Proposal            `json:"proposal,omitempty"`
	Approval  *ApprovalRequirement `json:"approval_required,omitempty"`
}

func DecodeRequest(raw []byte) (Request, error) {
	var r Request
	if err := decisions.DecodeStrict(raw, &r, MaxRequest); err != nil {
		return r, err
	}
	// encoding/json otherwise accepts case aliases such as Schema/SCHEMA.
	var document any
	if err := json.Unmarshal(raw, &document); err != nil {
		return r, err
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
	if !canonical(document) {
		return r, errors.New("canonical lowercase JSON keys required")
	}
	return r, nil
}

// Input reconstructs the existing classifier binding from the current declared
// snapshot. A model cannot supply a different tenant, revision or observation.
func (r Request) Input() (decisions.Input, error) {
	if r.Schema != "action-proposal-request/1" || r.Snapshot.Validate() != nil ||
		r.Snapshot.QuestionSet != decisions.QuestionVersion || r.Epoch < 1 || r.Epoch > assistance.MaxEpochs ||
		r.Enqueued.IsZero() || !r.ParentDeadline.After(r.Enqueued) || r.ParentDeadline.Sub(r.Enqueued) > 60*time.Second ||
		r.DecisionExpiry.After(r.ParentDeadline) || r.Snapshot.Observation.To.After(r.Enqueued) {
		return decisions.Input{}, errors.New("current typed snapshot and bounded parent context required")
	}
	i := decisions.Input{Schema: "decision-input/1", Epoch: r.Epoch, SnapshotSHA: decisions.Hash(r.Snapshot),
		CaseID: r.Snapshot.CaseID, Revision: r.Snapshot.Revision, Tenant: r.Snapshot.Tenant, Asset: r.Snapshot.Asset,
		Commit: r.Snapshot.SourceCommit, QuestionSHA: decisions.QuestionHash(), Enqueued: r.Enqueued,
		Expires: r.DecisionExpiry, Observation: *r.Snapshot.Observation}
	return i, i.Validate()
}

func Build(r Request, now time.Time) (Review, error) {
	v := Review{Schema: "action-proposal-review/1", Scope: "offline_declared_context", Authority: "shadow",
		Status: "pending_review"}
	if len(r.Events) > 16 {
		return v, errors.New("at most sixteen events required")
	}
	if raw, err := json.Marshal(r); err != nil || len(raw) > MaxRequest {
		return v, errors.New("bounded finite proposal request required")
	}
	i, err := r.Input()
	if err != nil {
		return v, err
	}
	if err = r.Decision.Validate(i); err != nil {
		return v, err
	}
	if now.IsZero() || now.Before(r.Decision.Completed) {
		return v, errors.New("explicit as-of time cannot precede classification")
	}
	if !now.Before(r.ParentDeadline) {
		v.Reason = "parent_expired"
		return v, nil
	}
	if r.Decision.Status != "ok" {
		v.Reason = "classification_" + r.Decision.Status
		return v, nil
	}
	if r.Decision.Choice("candidate_action") != "temporary_limit_candidate" {
		v.Reason = "no_temporary_limit_candidate"
		return v, nil
	}
	o := i.Observation
	if r.Decision.Choice("disposition") != "suspicious" || o.Coverage != "complete" || o.Quality != "complete" ||
		o.Truncated || o.AttackSignals == 0 || o.BenignSignals != 0 {
		v.Reason = "incomplete_or_conflicting_observation"
		return v, nil
	}
	if len(r.Events) == 0 || len(r.Events) > 16 || len(r.Events) != len(r.Snapshot.Evidence) {
		return v, errors.New("exact bounded snapshot event set required")
	}
	refs := map[string]bool{}
	for _, ref := range r.Snapshot.Evidence {
		refs[ref] = true
	}
	events := append([]event.Event(nil), r.Events...)
	sort.Slice(events, func(a, b int) bool {
		if events[a].EventTime.Equal(events[b].EventTime) {
			return events[a].EventID < events[b].EventID
		}
		return events[a].EventTime.Before(events[b].EventTime)
	})
	var subject event.Event
	seenRequests := map[string]bool{}
	expires := r.Decision.Completed.Add(30 * time.Second)
	if r.ParentDeadline.Before(expires) {
		expires = r.ParentDeadline
	}
	for _, e := range events {
		if !refs[e.EventID] || seenRequests[e.RequestID] || e.Validate(now) != nil ||
			e.TenantID != i.Tenant || e.AssetID != i.Asset || e.Identity != "authenticated" || e.DataQuality != "complete" ||
			e.EventTime.Before(o.From) || e.EventTime.After(o.To) || e.IngestTime.Before(e.EventTime) ||
			e.IngestTime.After(r.Enqueued) || e.EventTime.After(now) || !policy.AllowedRoute(e.Route) || !e.KnownRoute {
			return v, errors.New("fresh complete scoped snapshot evidence required")
		}
		delete(refs, e.EventID)
		seenRequests[e.RequestID] = true
		if e.EventID == r.SubjectRef {
			subject = e
		}
		if deadline := e.EventTime.Add(time.Minute); deadline.Before(expires) {
			expires = deadline
		}
	}
	if len(refs) != 0 || subject.EventID == "" {
		return v, errors.New("subject must be an exact snapshot evidence reference")
	}
	if !now.Before(expires) {
		v.Reason = "proposal_or_evidence_expired"
		return v, nil
	}
	// Restrict this first template to one exact session and route. Correlating
	// other sessions or widening the route needs a separate reviewed template.
	for _, e := range events {
		if e.Principal != subject.Principal || e.SessionHMAC != subject.SessionHMAC || e.Route != subject.Route {
			return v, errors.New("one exact principal/session/route required")
		}
	}
	engine := detect.New()
	var witnesses []string
	for _, e := range events {
		alerts, outcome := engine.Process(e, now)
		if outcome != "accepted" {
			return v, errors.New("independent detector replay refused evidence")
		}
		for _, alert := range alerts {
			if alert.RuleID == "RA-004" && alert.DataQuality == "complete" {
				for _, ref := range alert.Evidence {
					if ref == subject.EventID {
						witnesses = append([]string(nil), alert.Evidence...)
					}
				}
			}
		}
	}
	if len(witnesses) == 0 {
		v.Reason = "independent_rule_not_reproduced"
		return v, nil
	}
	sort.Strings(witnesses)
	p := Proposal{Schema: "action-proposal/1", CaseID: i.CaseID, Revision: i.Revision, Epoch: i.Epoch,
		SnapshotSHA: i.SnapshotSHA, SourceCommit: i.Commit, DecisionSHA: decisions.Hash(r.Decision),
		EvidenceSHA: decisions.Hash(events), EvidenceRefs: witnesses, Rule: "RA-004/1.1",
		Template: "session-route-deny", TemplateVersion: 1,
		Target: Target{i.Tenant, i.Asset, subject.Principal, subject.SessionHMAC, subject.Route},
		TTL:    10, Impact: "deny_exact_session_route", Recovery: "ttl_or_operator_release",
		Created: r.Decision.Completed, Expires: expires}
	// Reuse the existing scoped policy validator without creating a policy.
	if err := policy.ValidateScoped(policy.Policy{ID: "draft", CaseID: p.CaseID, Tenant: p.Target.Tenant,
		Asset: p.Target.Asset, Principal: p.Target.Principal, Session: p.Target.Session, Route: p.Target.Route,
		RuleVersion: "proposal-1", Issued: now, Expires: now.Add(10 * time.Second)}, now); err != nil {
		return v, err
	}
	p.Key = decisions.Hash([]any{p.Template, p.TemplateVersion, p.CaseID, p.Revision, p.Epoch, p.Target})
	p.ID = decisions.Hash(p) // ID is empty while hashing; all draft content is bound.
	v.Status, v.Reason, v.Proposal = "approval_required", "independent_rule_reproduced", &p
	v.Approval = &ApprovalRequirement{decisions.Hash(p), decisions.Hash(p.Target), p.TTL, p.Expires, "response-operator"}
	return v, nil
}

// Verify rebuilds the entire draft against current context and freshness. Hash
// checks alone would allow changed TTL/target fields to be rehashed by a caller.
func Verify(p Proposal, r Request, now time.Time) error {
	v, err := Build(r, now)
	if err != nil {
		return err
	}
	if v.Proposal == nil || !reflect.DeepEqual(p, *v.Proposal) {
		return errors.New("proposal differs from current deterministic draft")
	}
	return nil
}

// Compare detects duplicate/conflicting independently verified drafts. This is not a durable dispatch
// lock, approval nonce consumption or an exactly-once execution guarantee.
func Compare(existing, candidate Proposal) error {
	if existing.Key != candidate.Key || !reflect.DeepEqual(existing, candidate) {
		return errors.New("proposal idempotency conflict")
	}
	return nil
}
