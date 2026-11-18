package contextevaluation

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"reverse-artex/internal/casememory"
	"reverse-artex/internal/contextadmission"
	"reverse-artex/internal/contextlearning"
	"reverse-artex/internal/contextshadow"
	"reverse-artex/internal/evidence"
	"reverse-artex/internal/incident"
	"sort"
	"time"
)

type observation struct {
	row             contextshadow.Row
	attempt         contextshadow.Attempt
	committedBefore time.Time
}
type labelInput struct {
	Trust casememory.LearningTrust `json:"trust"`
	Views []casememory.View        `json:"views"`
}
type eventRows struct{ rows [][]byte }

func (r eventRows) VisitRecords(stream string, visit func([]byte) error) error {
	if stream != "events" {
		return ErrInvalid
	}
	for _, b := range r.rows {
		if e := visit(b); e != nil {
			return e
		}
	}
	return nil
}
func bucket(candidate, tenant, caseID string, percent int) string {
	d := sha256.Sum256([]byte(contextlearning.Digest([]string{"context-canary-bucket/2", candidate, tenant, caseID})))
	if int(binary.BigEndian.Uint64(d[:8])%100) < percent {
		return "candidate"
	}
	return "reference"
}
func contains(values []string, v string) bool {
	i := sort.SearchStrings(values, v)
	return i < len(values) && values[i] == v
}
func add(c *casememory.QualityCounts, label, prediction string) {
	if label == "confirmed_attack" {
		c.Attack++
		if prediction == "suspicious" {
			c.TrueAttack++
		} else {
			c.FalseBenign++
		}
	} else if label == "confirmed_benign" {
		c.Benign++
		if prediction == "benign" {
			c.TrueBenign++
		} else {
			c.FalseAttack++
		}
	}
}
func bounds(a *Arm) {
	a.FalseBenignUpperBPS = casememory.ErrorUpperBPS(a.Counts.FalseBenign, a.Counts.Attack)
	a.FalseAttackUpperBPS = casememory.ErrorUpperBPS(a.Counts.FalseAttack, a.Counts.Benign)
}
func evidenceKeys(c incident.Case) []string {
	keys := []string{}
	for _, ref := range c.Evidence {
		keys = append(keys, contextlearning.Digest([]string{ref.Stream, ref.Tenant, ref.Asset, ref.EventID, ref.LineSHA}))
	}
	sort.Strings(keys)
	return keys
}

func (s *Session) validateHistory(h contextshadow.HistorySnapshot, at time.Time) error {
	candidate := s.version.Bundle.Capsule.Candidate
	if h.Schema != "context-shadow-history/2" || h.CandidateSHA != candidate.SHA || h.SHA != contextshadow.HistorySnapshotSHA(h) || len(h.Attempts) > 192 || h.CommittedBefore.After(at) || len(h.Attempts) > 0 && (h.CommittedBefore.IsZero() || h.CommittedBefore.Before(h.Attempts[len(h.Attempts)-1].FinishedAt)) {
		return ErrInvalid
	}
	var previous time.Time
	observedVersions := map[string]string{}
	for i, a := range h.Attempts {
		copy := a
		copy.SHA = ""
		if a.Schema != "case-context-live-attempt/2" || a.Sequence != i+1 || a.SHA != contextlearning.Digest(copy) || a.Tenant != candidate.Tenant || a.CandidateSHA != candidate.SHA || a.StartedAt.IsZero() || a.StartedAt.Before(previous) || a.FinishedAt.Before(a.StartedAt) || a.FinishedAt.After(at) || (a.Receipt == nil) == (a.Error == "") {
			return ErrInvalid
		}
		previous = a.FinishedAt
		if a.Receipt == nil {
			continue
		}
		r := *a.Receipt
		if r.Schema != "case-context-shadow-receipt/2" || r.Mode != "shadow" || r.ObserverSourceSHA != contextshadow.SourceSHA() || r.Tenant != candidate.Tenant || r.CandidateSHA != candidate.SHA || r.RuntimeSHA != candidate.RuntimeSHA || r.FeatureSHA != candidate.FeatureSHA || r.ContextTrustSHA != candidate.ContextTrustSHA || r.DeploymentAllowed || r.SHA != contextshadow.ReceiptSHA(r) || !pin.MatchString(r.SourceSHA) || !pin.MatchString(r.ManifestSHA) || r.StartedAt.Before(a.StartedAt) || r.FinishedAt.Before(r.StartedAt) || r.FinishedAt.After(a.FinishedAt) || r.Planned < 0 || r.Planned > 512 || r.Planned != len(r.Rows) || r.OtherTenantCases < 0 {
			return ErrInvalid
		}
		observed, unavailable := 0, 0
		last := ""
		for _, row := range r.Rows {
			if !identifier.MatchString(row.CaseID) || row.CaseID <= last || !pin.MatchString(row.CaseSHA) || row.EvidenceKeys == nil || len(row.EvidenceKeys) > 128 || !sort.StringsAreSorted(row.EvidenceKeys) {
				return ErrInvalid
			}
			last = row.CaseID
			for n, key := range row.EvidenceKeys {
				if !pin.MatchString(key) || n > 0 && key == row.EvidenceKeys[n-1] {
					return ErrInvalid
				}
			}
			switch row.Status {
			case "observed":
				observed++
				if row.Features == nil || row.Reason != "" || len(row.EvidenceKeys) == 0 {
					return ErrInvalid
				}
				prediction, e := contextlearning.Predict(candidate.Model, *row.Features)
				if e != nil || prediction != row.Prediction {
					return ErrInvalid
				}
				// The extractor is stateless for an exact case SHA and trust.
				// Later duplicate snapshots cannot hide a conflicting vector.
				key := contextlearning.Digest([]string{row.CaseID, row.CaseSHA})
				digest := contextlearning.Digest(row)
				if old, exists := observedVersions[key]; exists && old != digest {
					return ErrInvalid
				}
				observedVersions[key] = digest
			case "unavailable":
				unavailable++
				if row.Prediction != "unknown" || row.Reason == "" {
					return ErrInvalid
				}
			default:
				return ErrInvalid
			}
		}
		coverage := 0
		if r.Planned > 0 {
			coverage = observed * 10000 / r.Planned
		}
		if r.Observed != observed || r.Unavailable != unavailable || r.CoverageBPS != coverage {
			return ErrInvalid
		}
	}
	return nil
}

func verifyLabel(v casememory.View, c incident.Case, trust casememory.LearningTrust, predicted, at time.Time) (casememory.Label, string) {
	if v.Current.SHA != contextlearning.Digest(c) || v.Current.Case.ID != c.ID || v.Current.Case.Tenant != c.Tenant {
		return casememory.Label{}, "case_memory_stale"
	}
	if len(v.Labels) == 0 {
		return casememory.Label{}, "label_missing"
	}
	l := v.Labels[len(v.Labels)-1]
	for _, old := range v.Labels {
		if !old.At.After(predicted) || old.Verification != nil && !old.Verification.Statement.IssuedAt.After(predicted) {
			return l, "label_known_before_prediction"
		}
	}
	if l.CaseSHA != contextlearning.Digest(c) {
		return l, "label_stale_for_case"
	}
	if l.Verification == nil {
		return l, "label_not_verified"
	}
	q := l.Verification.Statement
	digest := casememory.LearningTrustDigest(trust)
	copy := l
	copy.SHA = ""
	if l.SHA != contextlearning.Digest(copy) || q.Schema != "case-verified-label/1" || q.TrustSHA != digest || l.Verification.TrustSHA != digest || q.Tenant != c.Tenant || q.CaseID != c.ID || q.Expected+1 != l.Revision || q.Previous != l.Previous || q.CaseSHA != l.CaseSHA || q.SourceSHA != v.Current.Source || q.EvidenceSHA != contextlearning.Digest(c.Evidence) || q.Value != l.Value || q.Reason != l.Reason || q.Basis != "evidence_review" || q.IssuedAt.IsZero() || q.IssuedAt.After(l.At) || !l.At.Before(q.ExpiresAt) || q.ExpiresAt.Sub(q.IssuedAt) > 24*time.Hour || l.At.After(at) {
		return l, "label_authority_or_binding_invalid"
	}
	valid := false
	for _, key := range trust.Keys {
		if key.ID == q.KeyID && key.Role == "label_reviewer" && !key.Revoked && key.Actor == l.Actor {
			pub, e1 := base64.StdEncoding.Strict().DecodeString(key.PublicKey)
			sig, e2 := base64.StdEncoding.Strict().DecodeString(q.Signature)
			valid = e1 == nil && e2 == nil && len(pub) == 32 && len(sig) == 64 && ed25519.Verify(pub, casememory.LabelSigningBytes(q), sig)
		}
	}
	if !valid {
		return l, "label_signature_or_key_invalid"
	}
	if l.Value != "confirmed_attack" && l.Value != "confirmed_benign" {
		return l, "label_unresolved"
	}
	return l, ""
}

// Assess consumes complete replay-verified history and the current case-label
// journal. It does not import labels, rerun inference, or select an output cohort.
func (s *Session) Assess(snapshot *evidence.Snapshot, memory *casememory.Store, expectedPlan string, at time.Time) (Report, error) {
	if at.IsZero() || memory == nil || s.fresh() != nil {
		return Report{}, ErrConflict
	}
	if e := s.verifySnapshot(snapshot); e != nil {
		return Report{}, e
	}
	p, e := s.loadPlan(expectedPlan)
	if e != nil {
		return Report{}, e
	}
	if at.Before(p.CreatedAt) {
		return Report{}, ErrInvalid
	}
	h, e := s.history()
	if e != nil {
		return Report{}, e
	}
	if verifyPrefix(p, h) != nil || s.validateHistory(h, at) != nil {
		return Report{}, ErrInvalid
	}
	trust, e := memory.LearningTrust(p.Tenant)
	if e != nil || casememory.LearningTrustDigest(trust) != p.LabelTrustSHA {
		return Report{}, ErrConflict
	}
	views, e := memory.List(p.Tenant)
	if e != nil {
		return Report{}, e
	}
	for i := range views {
		views[i].Production = nil
	}
	return s.score(snapshot, p, h, labelInput{trust, views}, at)
}

func (s *Session) score(snapshot *evidence.Snapshot, p Plan, h contextshadow.HistorySnapshot, labels labelInput, at time.Time) (Report, error) {
	candidate := s.version.Bundle.Capsule.Candidate
	end := s.version.End
	closed := !at.Before(end)
	if end.After(at) {
		end = at
	}
	if !end.After(p.CreatedAt) {
		return Report{}, ErrInvalid
	}
	r := Report{Schema: "case-context-canary-evaluation/2", Tenant: p.Tenant, PlanSHA: p.SHA, ReleaseSHA: p.ReleaseSHA, CandidateSHA: candidate.SHA, SourceSHA: snapshot.SHA256(), LabelSnapshotSHA: contextlearning.Digest(labels), HistorySHA: h.SHA, JournalHead: s.version.JournalHead, EvaluationSHA: SourceSHA(), WindowStart: p.CreatedAt, WindowEnd: end, WindowClosed: closed, EvaluatedAt: at, Reasons: []string{}, Rows: []ResultRow{}, MandatoryReviewPreserved: true}
	manifest, e := incident.Build(snapshot)
	if e != nil {
		return r, e
	}
	cases := map[string]incident.Case{}
	universe := map[string]bool{}
	versions := map[string]map[string]observation{}
	for _, c := range manifest.Cases {
		if c.Tenant != p.Tenant {
			continue
		}
		r.TenantCases++
		cases[c.ID] = c
		if !contains(p.Baseline.Cases, c.ID) && !contains(s.version.Release.Baseline.Cases, c.ID) && !c.First.Before(p.CreatedAt) && c.First.Before(end) {
			universe[c.ID] = true
		}
	}
	for index, a := range h.Attempts {
		if a.StartedAt.Before(p.CreatedAt) || !a.StartedAt.Before(end) {
			continue
		}
		if a.Error != "" {
			r.FailedChecks++
			continue
		}
		if a.FinishedAt.After(end) {
			r.FailedChecks++
			continue
		}
		duration := a.Receipt.FinishedAt.Sub(a.Receipt.StartedAt).Milliseconds()
		if duration > r.MaximumBatchMilliseconds {
			r.MaximumBatchMilliseconds = duration
		}
		for _, row := range a.Receipt.Rows {
			if contains(p.Baseline.Cases, row.CaseID) || contains(s.version.Release.Baseline.Cases, row.CaseID) {
				continue
			}
			if c, ok := cases[row.CaseID]; ok && c.First.Before(p.CreatedAt) {
				continue
			}
			universe[row.CaseID] = true
			if versions[row.CaseID] == nil {
				versions[row.CaseID] = map[string]observation{}
			}
			if _, exists := versions[row.CaseID][row.CaseSHA]; !exists {
				boundary := h.CommittedBefore
				if index+1 < len(h.Attempts) {
					boundary = h.Attempts[index+1].StartedAt
				}
				versions[row.CaseID][row.CaseSHA] = observation{row, a, boundary}
			}
		}
	}
	if len(universe) > 512 {
		return r, ErrInvalid
	}
	// Index actual raw events once; each Extract sees only that case's exact refs.
	events := map[string][]byte{}
	if e = snapshot.VisitRecords("events", func(raw []byte) error {
		var event struct {
			Tenant string `json:"tenant_id"`
			Asset  string `json:"asset_id"`
			ID     string `json:"event_id"`
		}
		if json.Unmarshal(raw, &event) != nil {
			return ErrInvalid
		}
		key := contextlearning.Digest([]string{event.Tenant, event.Asset, event.ID})
		if old, ok := events[key]; ok && !bytes.Equal(old, raw) {
			return ErrInvalid
		}
		events[key] = raw
		return nil
	}); e != nil {
		return r, e
	}
	byLabel := map[string]casememory.View{}
	for _, v := range labels.Views {
		byLabel[v.Current.Case.ID] = v
	}
	ids := []string{}
	for id := range universe {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	shared := map[string]int{}
	for _, id := range ids {
		if c, ok := cases[id]; ok {
			for _, key := range evidenceKeys(c) {
				shared[key]++
			}
		}
	}
	var first, last time.Time
	for _, id := range ids {
		c, exists := cases[id]
		sha := ""
		if exists {
			sha = contextlearning.Digest(c)
		}
		out := ResultRow{CaseID: id, CaseSHA: sha, Branch: bucket(candidate.SHA, p.Tenant, id, s.version.Release.Approval.Request.Percent), Prediction: "unknown", Status: "unresolved"}
		r.Planned++
		arm := &r.ReferenceArm
		if out.Branch == "candidate" {
			arm = &r.CandidateArm
		}
		arm.Planned++
		fail := func(reason string) { out.Reason = reason; r.Unresolved++; r.Rows = append(r.Rows, out) }
		if !exists {
			fail("source_case_missing")
			continue
		}
		got, ok := versions[id][sha]
		if !ok {
			fail("exact_case_prediction_missing")
			continue
		}
		out.AttemptSHA = got.attempt.SHA
		out.PredictedAt = got.attempt.FinishedAt
		out.CommitBoundary = got.committedBefore
		out.Prediction = got.row.Prediction
		if got.row.Status != "observed" {
			fail(got.row.Reason)
			continue
		}
		invalid := ""
		keys := evidenceKeys(c)
		for _, key := range keys {
			if contains(p.Baseline.Evidence, key) || contains(s.version.Release.Baseline.Evidence, key) {
				invalid = "pre_plan_evidence_overlap"
			}
			if contains(candidate.TrainingEvidence, key) {
				invalid = "training_evidence_overlap"
			}
			if shared[key] > 1 {
				invalid = "shared_evidence_between_cases"
			}
		}
		raw := eventRows{rows: [][]byte{}}
		for _, ref := range c.Evidence {
			if !ref.Time.After(p.CreatedAt) {
				invalid = "evidence_predates_plan"
			}
			if !ref.Time.Before(end) {
				invalid = "evidence_after_window"
			}
			if ref.Time.After(got.attempt.FinishedAt) {
				invalid = "evidence_after_prediction"
			}
			key := contextlearning.Digest([]string{ref.Tenant, ref.Asset, ref.EventID})
			if b, ok := events[key]; ok {
				raw.rows = append(raw.rows, b)
			}
		}
		if invalid != "" {
			fail(invalid)
			continue
		}
		actual, e := contextlearning.Extract(raw, []incident.Case{c}, s.cfg.Context)
		if e != nil || len(actual) != 1 {
			return r, ErrInvalid
		}
		if got.row.Features == nil || *got.row.Features != actual[0].Features || contextlearning.Digest(keys) != contextlearning.Digest(got.row.EvidenceKeys) || contextlearning.Digest(keys) != contextlearning.Digest(actual[0].EvidenceKeys) {
			return r, ErrInvalid
		}
		if first.IsZero() || out.PredictedAt.Before(first) {
			first = out.PredictedAt
		}
		if out.PredictedAt.After(last) {
			last = out.PredictedAt
		}
		v, ok := byLabel[id]
		if !ok {
			fail("case_memory_missing")
			continue
		}
		l, reason := verifyLabel(v, c, labels.Trust, out.CommitBoundary, at)
		out.LabelSHA = l.SHA
		out.LabelRevision = l.Revision
		out.Label = l.Value
		if l.Revision > 1 {
			r.Corrected++
		}
		if reason != "" {
			if reason == "label_unresolved" {
				r.Unknown++
			}
			fail(reason)
			continue
		}
		out.Status = "scored"
		r.Scored++
		arm.Scored++
		assigned := "suspicious"
		if out.Branch == "candidate" {
			assigned = out.Prediction
		}
		add(&arm.Counts, l.Value, assigned)
		add(&r.PairedCandidate, l.Value, out.Prediction)
		add(&r.PairedReference, l.Value, "suspicious")
		r.Rows = append(r.Rows, out)
	}
	r.Excluded = r.TenantCases
	for _, id := range ids {
		if _, ok := cases[id]; ok {
			r.Excluded--
		}
	}
	if r.Planned > 0 {
		r.CoverageBPS = r.Scored * 10000 / r.Planned
	}
	if !first.IsZero() {
		r.ObservedSpanSeconds = int64(last.Sub(first) / time.Second)
	}
	bounds(&r.CandidateArm)
	bounds(&r.ReferenceArm)
	criteria := p.Criteria
	why := func(condition bool, reason string) {
		if condition {
			r.Reasons = append(r.Reasons, reason)
		}
	}
	why(!closed, "canary_window_still_open")
	why(r.CandidateArm.Planned < criteria.MinimumCases || r.CandidateArm.Counts.Attack < criteria.MinimumAttack || r.CandidateArm.Counts.Benign < criteria.MinimumBenign, "insufficient_candidate_arm_samples")
	why(r.ReferenceArm.Planned < criteria.MinimumCases || r.ReferenceArm.Counts.Attack < criteria.MinimumAttack || r.ReferenceArm.Counts.Benign < criteria.MinimumBenign, "insufficient_reference_arm_samples")
	why(r.ObservedSpanSeconds < int64(criteria.MinimumSeconds), "observed_duration_below_minimum")
	why(r.CoverageBPS < criteria.MinimumCoverageBPS || r.Planned == 0, "label_or_prediction_coverage_below_minimum")
	why(r.Unresolved > 0, "unresolved_cases")
	why(r.FailedChecks > 0, "failed_observation_checks")
	why(h.UnsavedChecks > 0 || h.CapacityPaused, "observation_capacity_or_unsaved_checks")
	why(r.MaximumBatchMilliseconds > 30000, "observation_latency_above_maximum")
	why(r.CandidateArm.FalseBenignUpperBPS > criteria.MaximumFalseBenignUpperBPS || casememory.ErrorUpperBPS(r.PairedCandidate.FalseBenign, r.PairedCandidate.Attack) > criteria.MaximumFalseBenignUpperBPS, "candidate_false_benign_confidence_bound")
	why(r.CandidateArm.FalseAttackUpperBPS > criteria.MaximumFalseAttackUpperBPS || casememory.ErrorUpperBPS(r.PairedCandidate.FalseAttack, r.PairedCandidate.Benign) > criteria.MaximumFalseAttackUpperBPS, "candidate_false_attack_confidence_bound")
	why(r.PairedCandidate.FalseBenign > r.PairedReference.FalseBenign || r.PairedCandidate.FalseAttack > r.PairedReference.FalseAttack, "paired_reference_regression")
	why(r.PairedCandidate.FalseBenign+r.PairedCandidate.FalseAttack >= r.PairedReference.FalseBenign+r.PairedReference.FalseAttack, "no_paired_measured_improvement")
	r.CriteriaPassed = len(r.Reasons) == 0
	quality, e := contextadmission.Assess(s.cfg.Admission, s.version.Bundle.Capsule, s.version.Bundle.Endorsement, s.cfg.Authorities, s.cfg.Context, at)
	r.QualityValidNow = e == nil && quality.Accepted
	why(!r.QualityValidNow, "current_independent_quality_unavailable")
	r.ReleaseReviewReady = r.CriteriaPassed && r.QualityValidNow
	r.State = "BLOCKED"
	if r.ReleaseReviewReady {
		r.State = "CANARY_CRITERIA_MET_SEPARATE_RELEASE_REVIEW_REQUIRED"
	}
	r.SHA = ReportSHA(r)
	return r, nil
}
