// Package responsev2 is a co-located, single-writer incident/policy runtime.
// V1 journals and remote policy contracts are never reinterpreted as V2.
package responsev2

import (
	"errors"
	"reverse-artex/internal/decisions"
	"reverse-artex/internal/protection"
	"time"
)

var ErrStale = errors.New("v2 case, epoch, candidate or evidence changed")
var ErrUnavailable = errors.New("v2 journal unavailable")
var ErrLimit = errors.New("v2 capacity or budget reached")

type Scope struct {
	Tenant    string `json:"tenant"`
	Asset     string `json:"asset"`
	Principal string `json:"principal"`
	Session   string `json:"session"`
	Route     string `json:"route_id"`
	Method    string `json:"method"`
	Resource  string `json:"resource_hmac"`
	Authz     string `json:"authz_revision"`
	Registry  string `json:"registry_digest"`
	Enforcer  string `json:"enforcer_id"`
}

func scope(p protection.Proof, r *protection.Registry) Scope {
	return Scope{p.Tenant, p.Asset, p.Principal, p.Session, p.Route, p.Method, p.Resource, p.AuthzRevision, p.Registry, r.Enforcer()}
}
func scopeID(s Scope) string { return decisions.Hash(s) }

type Evidence struct {
	Schema     string                    `json:"schema"`
	ID         string                    `json:"event_id"`
	Request    string                    `json:"request_id"`
	Scope      Scope                     `json:"scope"`
	Kind       string                    `json:"kind"`
	At         time.Time                 `json:"observed_at"`
	Proof      string                    `json:"signed_sdk_proof"`
	Binding    protection.RequestBinding `json:"request_binding"`
	Status     int                       `json:"sdk_status"`
	BodyLength int                       `json:"body_length"`
	BodySHA    string                    `json:"body_sha256"`
}
type Case struct {
	Schema   string    `json:"schema"`
	ID       string    `json:"case_id"`
	Tenant   string    `json:"tenant"`
	Asset    string    `json:"asset"`
	Revision int       `json:"revision"`
	SHA      string    `json:"case_sha256"`
	Refs     []string  `json:"evidence_ids"`
	Updated  time.Time `json:"updated_at"`
}

func caseSHA(c Case) string { c.SHA = ""; return decisions.Hash(c) }
func caseID(s Scope) string {
	return "c2-" + decisions.Hash([]string{s.Tenant, s.Asset, s.Principal, s.Session})[:32]
}

type Candidate struct {
	ID         string `json:"candidate_id"`
	EvidenceID string `json:"evidence_id"`
	Scope      Scope  `json:"scope"`
}
type CaseView struct {
	Case          Case        `json:"case"`
	Evidence      []Evidence  `json:"evidence"`
	Candidates    []Candidate `json:"candidates"`
	PendingReview bool        `json:"pending_review"`
	Coverage      string      `json:"coverage"`
}
type Claim struct {
	Owner   string    `json:"owner"`
	Run     string    `json:"run_id"`
	Intent  string    `json:"intent_id"`
	Expires time.Time `json:"expires_at"`
}
type Lease struct {
	Schema        string    `json:"schema"`
	ID            string    `json:"policy_id"`
	Scope         Scope     `json:"scope"`
	Episode       string    `json:"episode_id"`
	Issued        time.Time `json:"issued_at"`
	Expires       time.Time `json:"expires_at"`
	HardEnd       time.Time `json:"hard_end"`
	Cooldown      time.Time `json:"cooldown_until"`
	LastViolation time.Time `json:"last_violation_at"`
	Generation    int       `json:"generation"`
	Claims        []Claim   `json:"claims"`
	Consumed      []string  `json:"consumed_requests"`
}
type Intent struct {
	ID          string `json:"intent_id"`
	CaseID      string `json:"case_id"`
	CaseSHA     string `json:"case_sha256"`
	CandidateID string `json:"candidate_id"`
	Owner       string `json:"owner"`
	Run         string `json:"run_id"`
	Epoch       int    `json:"cancel_epoch"`
}
type Receipt struct {
	Intent     string    `json:"intent_id"`
	PolicyID   string    `json:"policy_id"`
	Generation int       `json:"generation"`
	State      string    `json:"state"`
	Expires    time.Time `json:"expires_at"`
	Effect     string    `json:"effect"`
}
type GateResult struct {
	CaseID   string `json:"case_id"`
	CaseSHA  string `json:"case_sha256"`
	PolicyID string `json:"policy_id,omitempty"`
	Deny     bool   `json:"deny"`
}
type record struct {
	WriterBoot  string               `json:"writer_boot_id,omitempty"`
	CommandID   string               `json:"command_id,omitempty"`
	CommandSHA  string               `json:"command_sha256,omitempty"`
	Schema      string               `json:"schema"`
	Sequence    int                  `json:"sequence"`
	Previous    string               `json:"previous_sha256"`
	Registry    string               `json:"registry_digest"`
	At          time.Time            `json:"at"`
	Operation   string               `json:"operation"`
	Event       *Evidence            `json:"event,omitempty"`
	Case        *Case                `json:"case,omitempty"`
	RetiredCase *caseRetirement      `json:"retired_case,omitempty"`
	Lease       *Lease               `json:"lease,omitempty"`
	Intent      *Intent              `json:"intent,omitempty"`
	Receipt     *Receipt             `json:"receipt,omitempty"`
	Epoch       *int                 `json:"epoch,omitempty"`
	Paused      *bool                `json:"paused,omitempty"`
	Job         *Job                 `json:"job,omitempty"`
	Attempt     *ResponseAttempt     `json:"response_attempt,omitempty"`
	Observation *ResponseObservation `json:"response_observation,omitempty"`
	L3          *L3Run               `json:"l3_run,omitempty"`
	SHA         string               `json:"sha256"`
}

func recordSHA(r record) string { r.SHA = ""; return decisions.Hash(r) }
