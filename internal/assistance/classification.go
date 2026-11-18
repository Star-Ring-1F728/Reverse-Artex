package assistance

import (
	"encoding/hex"
	"reverse-artex/internal/decisions"
	"time"
)

func classificationInput(c Call) decisions.Input {
	var observation decisions.Observation
	if c.Snapshot.Observation != nil {
		observation = *c.Snapshot.Observation
	}
	return decisions.Input{Schema: "decision-input/1", Epoch: c.Epoch, SnapshotSHA: c.Hash,
		CaseID: c.Snapshot.CaseID, Revision: c.Snapshot.Revision, Tenant: c.Snapshot.Tenant,
		Asset: c.Snapshot.Asset, Commit: c.Snapshot.SourceCommit, QuestionSHA: decisions.QuestionHash(), Enqueued: c.Enqueued, Expires: c.Expires, Observation: observation}
}

func decisionDeadline(j Job) time.Time {
	deadline := j.Enqueued.Add(5 * time.Second)
	if j.Deadline.Before(deadline) {
		deadline = j.Deadline
	}
	return deadline
}
func classificationConclusion(r decisions.Result) string {
	switch r.Choice("disposition") {
	case "benign":
		if r.Choice("candidate_action") != "observe" {
			return "review"
		}
		return "benign"
	case "suspicious", "needs_review":
		return "review"
	default:
		return "unknown"
	}
}

// Stable roughly 10% public-lab audit sample (26/256 hash buckets). This is not a probabilistic guarantee;
// attackers choosing identifiers can influence selection. Mandatory review is
// independent of this sample, the classifier score and the benign choice.
func sampleAudit(s Snapshot) bool {
	h, _ := hex.DecodeString(hash([]any{s.Tenant, s.Asset, s.CaseID, s.Revision, decisions.QuestionVersion}))
	return len(h) > 0 && int(h[0]) < 26
}

type RoutingReceipt struct {
	Schema              string    `json:"schema"`
	Router              string    `json:"router_version"`
	JobID               string    `json:"job_id"`
	Epoch               int       `json:"config_epoch"`
	SnapshotSHA         string    `json:"snapshot_sha256"`
	DecisionSHA         string    `json:"decision_result_sha256,omitempty"`
	QuestionSHA         string    `json:"question_set_sha256"`
	RulePriority        int       `json:"rule_priority"`
	SuggestedPriority   *float64  `json:"suggested_priority,omitempty"`
	Route               string    `json:"route"`
	Reason              string    `json:"reason"`
	DecisionStatus      string    `json:"decision_status"`
	InvestigationStatus string    `json:"investigation_status"`
	JobPhase            string    `json:"job_phase"`
	JobOutcome          string    `json:"job_outcome"`
	PendingReview       bool      `json:"pending_review"`
	Deadline            time.Time `json:"parent_deadline"`
	DecisionDeadline    time.Time `json:"classification_enqueue_deadline"`
	AuditSelected       bool      `json:"audit_selected"`
	Authority           string    `json:"authority"`
}

// Routing is a reproducible view of the durable job ledger, including off,
// failed, missing, cancelled and queued work. It grants no policy authority and
// never schedules by the model's suggested priority.
func routingFor(s State) []RoutingReceipt {
	rows := []RoutingReceipt{}
	for _, j := range s.Jobs {
		if j.Snapshot.QuestionSet != decisions.QuestionVersion {
			continue
		}
		r := RoutingReceipt{Schema: "decision-routing/1", Router: "shadow-router-v1", JobID: j.ID, Epoch: j.Epoch,
			SnapshotSHA: j.Hash, QuestionSHA: decisions.QuestionHash(), Route: "shadow_only", Reason: "classification_only",
			DecisionStatus: "not_called", InvestigationStatus: "not_called", JobPhase: j.Phase, JobOutcome: j.Outcome, PendingReview: j.PendingReview,
			Deadline: j.Deadline, DecisionDeadline: j.Enqueued.Add(5 * time.Second), AuditSelected: sampleAudit(j.Snapshot), Authority: "shadow"}
		if j.Snapshot.RequiresInvestigation {
			r.RulePriority = 2
			r.Route = "pending_review"
			r.Reason = "mandatory_review"
		}
		if j.Snapshot.HighRisk {
			r.RulePriority = 3
			r.Reason = "independent_high_risk"
		}
		for _, a := range j.Attempts {
			if a.Kind == Investigation {
				r.InvestigationStatus = a.Outcome
				r.Route = "investigator"
				if a.Outcome != "ok" && a.Outcome != "running" {
					r.Route = "pending_review"
				}
				continue
			}
			r.DecisionStatus = a.Outcome
			if a.Result != nil && a.Result.Classification != nil && !a.Late && j.Epoch == s.Epoch {
				r.DecisionSHA = hash(a.Result.Classification)
				priority := a.Result.Classification.Priority()
				r.SuggestedPriority = &priority
				if a.Result.Conclusion != "benign" && r.Route != "investigator" {
					r.Route = "pending_review"
					if r.RulePriority == 0 {
						r.Reason = "classifier_review"
					}
				}
			}
		}
		if r.Route != "investigator" && j.PendingReview {
			r.Route = "pending_review"
		}
		if j.Phase == "queued_investigator" || j.Phase == "running_investigator" {
			r.Route = "investigator"
		}
		if r.AuditSelected && r.RulePriority == 0 {
			r.Reason = "sample_audit"
		}
		if j.Outcome != "ok" && j.Outcome != "base_only" && j.Outcome != "queued" && j.Outcome != "running" {
			r.Reason = j.Outcome
		}
		if j.Epoch != s.Epoch || j.Phase == "cancelled" || j.Phase == "interrupted" {
			r.Route = "pending_review"
			r.Reason = "inactive_epoch_or_interrupted"
			r.DecisionSHA = ""
			r.SuggestedPriority = nil
		}
		rows = append(rows, r)
	}
	return rows
}
