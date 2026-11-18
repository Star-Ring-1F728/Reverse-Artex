package casememory

import (
	"crypto/sha256"
	"embed"
	"encoding/binary"
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"
)

const MaxProductionChanges = 32
const MaxRuntimeReceipts = 4096

//go:embed production.go production_types.go quality.go quality_types.go quality_score.go candidate.go dataset.go store.go verified.go
var productionSources embed.FS

var productionFingerprintOnce sync.Once
var productionFingerprint string

func ProductionRuntimeSourceSHA() string {
	productionFingerprintOnce.Do(func() {
		values := []string{}
		for _, name := range []string{"production.go", "production_types.go", "quality.go", "quality_types.go", "quality_score.go", "candidate.go", "dataset.go", "store.go", "verified.go"} {
			raw, _ := productionSources.ReadFile(name)
			values = append(values, name, hash(raw))
		}
		productionFingerprint = hash(values)
	})
	return productionFingerprint
}

func ProductionSigningBytes(q SignedProductionChange) []byte {
	q.Signature = ""
	b, _ := json.Marshal(q)
	return append([]byte("reverse-artex/production-change/1\n"), b...)
}
func productionBucket(plan, tenant, id string) int {
	sum := sha256.Sum256([]byte(hash([]string{"production-bucket/1", plan, tenant, id})))
	return int(binary.BigEndian.Uint64(sum[:8]) % 100)
}
func (s *Store) productionBlockers(tenant string, at time.Time) []string {
	h := s.production[tenant]
	blockers := []string{}
	if len(h) == 0 || h[len(h)-1].Request.Action == "stop" {
		return blockers
	}
	current := h[len(h)-1]
	plan := s.qualityPlans[current.Request.PlanID]
	blockers = s.qualityPlanBlockers(plan)
	proof, ok := s.qualityProofs[plan.ID]
	if !ok || !proof.Statement.Report.Passed || proof.SHA != current.Request.QualitySHA {
		blockers = append(blockers, "independent_quality_not_accepted")
	} else if at.Before(proof.Statement.Report.FinishedAt) || at.Sub(proof.Statement.Report.FinishedAt) > time.Duration(s.productionPolicies[tenant].MaximumReportAgeSeconds)*time.Second {
		blockers = append(blockers, "quality_evidence_expired")
	}
	if current.Request.RuntimeSHA != ProductionRuntimeSourceSHA() {
		blockers = append(blockers, "runtime_implementation_changed")
	}
	if state, ok := s.reviews[current.Request.ReviewRunID]; ok && len(state.Decisions) > 0 && state.Decisions[len(state.Decisions)-1].Request.Decision != "approve_for_evaluation" {
		blockers = append(blockers, "review_withdrawn")
	}
	return blockers
}
func (s *Store) makeProductionChange(tenant string, q ProductionRequest, authorization *SignedProductionChange, at time.Time) ProductionChange {
	history := s.production[tenant]
	r := ProductionChange{Schema: "case-production-change/1", Tenant: tenant, Revision: len(history) + 1, Request: q, Authorization: authorization, Baseline: []string{}, BaselineEvidence: []string{}, At: at}
	if len(history) > 0 {
		r.Previous = history[len(history)-1].SHA
	}
	if q.Action != "stop" {
		refs := map[string]bool{}
		for _, binding := range s.selectCases(tenant).Items {
			r.Baseline = append(r.Baseline, binding.CaseID)
			entry := s.cases[caseKey(tenant, binding.CaseID)]
			for _, ref := range entry.Revisions[len(entry.Revisions)-1].Case.Evidence {
				refs[evidenceKey(ref)] = true
			}
		}
		for value := range refs {
			r.BaselineEvidence = append(r.BaselineEvidence, value)
		}
		sort.Strings(r.BaselineEvidence)
	}
	r.SHA = hash(r)
	return r
}
func (s *Store) validateProductionChange(r ProductionChange) error {
	q := r.Request
	history := s.production[r.Tenant]
	if r.Schema != "case-production-change/1" || !identity.MatchString(r.Tenant) || r.At.IsZero() || !validReason(q.Reason) || q.Reason != strings.TrimSpace(q.Reason) || q.Expected != len(history) {
		return ErrConflict
	}
	if len(r.BaselineEvidence) > 16384 {
		return ErrLimit
	}
	if len(history) >= MaxProductionChanges || (q.Action != "stop" && len(history) >= MaxProductionChanges-1) {
		return ErrLimit
	}
	if len(history) > 0 && r.At.Before(history[len(history)-1].At) {
		return ErrInvalid
	}
	if q.Action == "stop" {
		if r.Authorization != nil || q.PlanID != "" || q.QualitySHA != "" || q.PolicySHA != "" || q.RuntimeSHA != "" || q.ReviewRunID != "" || q.ReviewSHA != "" || q.CanarySHA != "" || q.Percent != 0 {
			return ErrInvalid
		}
	} else {
		if q.Action != "canary" && q.Action != "activate" && q.Action != "rollback" {
			return ErrInvalid
		}
		if r.Authorization == nil {
			return ErrInvalid
		}
		signed := r.Authorization
		key, ok := authorizedKey(s.trust[r.Tenant], signed.KeyID, "production_approver")
		if !ok || signed.Schema != "case-production-authorization/1" || signed.Tenant != r.Tenant || signed.TrustSHA != hash(s.trust[r.Tenant]) || signed.Request != q || !admissionTime(signed.IssuedAt, signed.ExpiresAt, r.At) || !validSignature(key, signed.Signature, ProductionSigningBytes(*signed)) {
			return ErrInvalid
		}
		policy := s.productionPolicies[r.Tenant]
		plan, ok := s.qualityPlans[q.PlanID]
		proof, proofOK := s.qualityProofs[q.PlanID]
		if !ok || plan.Tenant != r.Tenant || !policy.Enabled || !productionRoles(s.trust[r.Tenant]) || q.PolicySHA != hash(policy) || plan.PolicySHA != q.PolicySHA || plan.TrustSHA != hash(s.trust[r.Tenant]) || q.RuntimeSHA != plan.RuntimeSHA || !proofOK || !proof.Statement.Report.Passed || proof.SHA != q.QualitySHA || r.At.Before(proof.Statement.Report.FinishedAt) || r.At.Sub(proof.Statement.Report.FinishedAt) > time.Duration(policy.MaximumReportAgeSeconds)*time.Second || len(s.trainingChanges(s.candidates[plan.CandidateID])) > 0 {
			return ErrConflict
		}
		review, ok := s.reviews[q.ReviewRunID]
		shadow := s.shadows[q.ReviewRunID]
		if !ok || shadow.Plan.CandidateID != plan.CandidateID || len(review.Decisions) == 0 || review.Decisions[len(review.Decisions)-1].Request.Decision != "approve_for_evaluation" {
			return ErrConflict
		}
		switch q.Action {
		case "canary":
			last := review.Decisions[len(review.Decisions)-1]
			snapshot := reviewSnapshot(shadow)
			if q.Percent < 1 || q.Percent > 50 || q.CanarySHA != "" || snapshot == nil || last.SHA != q.ReviewSHA || !last.Assessment.CriteriaMet || last.SnapshotSHA != snapshot.SHA || snapshot.InputSHA != s.selectCases(r.Tenant).SHA || plan.IncumbentSHA != hash(s.incumbentModel(r.Tenant)) {
				return ErrConflict
			}
			if len(history) > 0 && history[len(history)-1].Request.Action == "canary" {
				return ErrConflict
			}
		case "activate":
			if q.Percent != 100 || len(history) == 0 {
				return ErrConflict
			}
			prior := history[len(history)-1]
			if prior.Request.Action != "canary" || prior.Request.PlanID != q.PlanID || q.ReviewRunID != prior.Request.ReviewRunID || q.ReviewSHA != prior.Request.ReviewSHA {
				return ErrConflict
			}
			canary := s.productionCanary(prior)
			if !canary.Ready || q.CanarySHA != canary.SHA {
				return ErrConflict
			}
		case "rollback":
			if q.Percent != 100 || q.CanarySHA != "" {
				return ErrInvalid
			}
			found := false
			for _, old := range history {
				if old.Request.Action == "activate" && old.Request.PlanID == q.PlanID && old.Request.QualitySHA == q.QualitySHA && old.Request.ReviewRunID == q.ReviewRunID && old.Request.ReviewSHA == q.ReviewSHA {
					found = true
				}
			}
			if !found {
				return ErrConflict
			}
		}
	}
	want := s.makeProductionChange(r.Tenant, q, r.Authorization, r.At)
	if !reflect.DeepEqual(r, want) {
		return ErrInvalid
	}
	return nil
}
func (s *Store) ChangeProduction(tenant string, q SignedProductionChange) (ProductionView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return ProductionView{}, err
	}
	if tenant != q.Tenant || q.Request.Action == "stop" {
		return ProductionView{}, ErrInvalid
	}
	for _, old := range s.production[tenant] {
		if old.Authorization != nil && reflect.DeepEqual(*old.Authorization, q) {
			return clone(s.productionView(tenant, time.Now().UTC())), nil
		}
	}
	plan, ok := s.qualityPlans[q.Request.PlanID]
	if !ok || plan.Tenant != tenant {
		return ProductionView{}, ErrNotFound
	}
	if len(s.qualityPlanBlockers(plan)) > 0 || q.Request.RuntimeSHA != ProductionRuntimeSourceSHA() {
		return ProductionView{}, ErrConflict
	}
	if q.Request.Action == "canary" {
		shadow, ok := s.shadows[q.Request.ReviewRunID]
		if !ok || s.reviewView(shadow).State != "APPROVED_FOR_EVALUATION" {
			return ProductionView{}, ErrConflict
		}
	}
	r := s.makeProductionChange(tenant, q.Request, &q, time.Now().UTC())
	if err := s.append(record{ProductionChange: &r}); err != nil {
		return ProductionView{}, err
	}
	return clone(s.productionView(tenant, r.At)), nil
}
func (s *Store) StopProduction(tenant string, expected int, reason string) (ProductionView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return ProductionView{}, err
	}
	q := ProductionRequest{Expected: expected, Action: "stop", Reason: strings.TrimSpace(reason)}
	for _, old := range s.production[tenant] {
		if old.Request == q {
			return clone(s.productionView(tenant, time.Now().UTC())), nil
		}
	}
	r := s.makeProductionChange(tenant, q, nil, time.Now().UTC())
	if err := s.append(record{ProductionChange: &r}); err != nil {
		return ProductionView{}, err
	}
	return clone(s.productionView(tenant, r.At)), nil
}
func runtimeKey(release, caseSHA string) string { return hash([]string{release, caseSHA}) }
func (s *Store) makeRuntimeBatch(tenant string, at time.Time) RuntimeBatch {
	result := RuntimeBatch{Tenant: tenant, At: at, Rows: []RuntimeReceipt{}}
	history := s.production[tenant]
	if len(history) == 0 || history[len(history)-1].Request.Action == "stop" {
		return result
	}
	current := history[len(history)-1]
	plan := s.qualityPlans[current.Request.PlanID]
	candidate := s.candidates[plan.CandidateID]
	baseline := map[string]bool{}
	for _, id := range current.Baseline {
		baseline[id] = true
	}
	existing := map[string]bool{}
	for _, key := range current.BaselineEvidence {
		existing[key] = true
	}
	training := map[string]bool{}
	for _, key := range s.qualityCapsule(plan.ID).ForbiddenEvidence {
		training[key] = true
	}
	for _, binding := range s.selectCases(tenant).Items {
		if _, ok := s.runtimeReceipts[runtimeKey(current.SHA, binding.CaseSHA)]; ok {
			continue
		}
		entry := s.cases[caseKey(tenant, binding.CaseID)]
		revision := entry.Revisions[len(entry.Revisions)-1]
		r := RuntimeReceipt{Schema: "case-production-inference/1", Tenant: tenant, CaseID: binding.CaseID, CaseSHA: revision.SHA, SourceSHA: revision.Source, ReleaseSHA: current.SHA, FeatureSHA: plan.FeatureSHA, RuntimeSHA: plan.RuntimeSHA, Features: caseFeatures(revision.Case), At: at, MandatoryReviewPreserved: true, Route: "candidate", CohortEligible: true}
		if baseline[r.CaseID] || revision.Case.First.Before(current.At) {
			r.CohortEligible = false
			r.Exclusion = "preexisting_case"
		}
		if len(entry.Labels) > 0 {
			r.CohortEligible = false
			r.Exclusion = "label_known_before_runtime_prediction"
		}
		for _, ref := range revision.Case.Evidence {
			if existing[evidenceKey(ref)] {
				r.CohortEligible = false
				r.Exclusion = "preexisting_evidence_overlap"
			}
		}
		for _, ref := range revision.Case.Evidence {
			if training[evidenceKey(ref)] {
				r.CohortEligible = false
				r.Exclusion = "training_evidence_overlap"
			}
		}
		model := candidate.Model
		if current.Request.Action == "canary" && productionBucket(plan.ID, tenant, r.CaseID) >= current.Request.Percent {
			model = plan.Incumbent
			r.Route = "incumbent"
		}
		r.ModelSHA = hash(model)
		r.Prediction, _ = PredictLearningVector(model, r.Features)
		r.SHA = hash(r)
		result.Rows = append(result.Rows, r)
	}
	return result
}
func (s *Store) validateRuntimeBatch(b RuntimeBatch) error {
	history := s.production[b.Tenant]
	if b.At.IsZero() || len(history) == 0 || len(b.Rows) == 0 || len(b.Rows) > 512 || len(s.runtimeReceipts)+len(b.Rows) > MaxRuntimeReceipts {
		return ErrLimit
	}
	current := history[len(history)-1]
	for _, old := range s.runtimeLatest[b.Tenant] {
		if b.At.Before(old.At) {
			return ErrConflict
		}
	}
	if current.Request.Action == "stop" || b.At.Before(current.At) {
		return ErrConflict
	}
	plan := s.qualityPlans[current.Request.PlanID]
	policy := s.productionPolicies[b.Tenant]
	proof := s.qualityProofs[plan.ID]
	// Replay uses the persisted v1 semantics and admission time, not today's
	// source fingerprint. Current execution additionally checks productionBlockers.
	if plan.PolicySHA != hash(policy) || plan.TrustSHA != hash(s.trust[b.Tenant]) || !policy.Enabled || len(s.trainingChanges(s.candidates[plan.CandidateID])) > 0 || b.At.Before(proof.Statement.Report.FinishedAt) || b.At.Sub(proof.Statement.Report.FinishedAt) > time.Duration(policy.MaximumReportAgeSeconds)*time.Second {
		return ErrConflict
	}
	want := s.makeRuntimeBatch(b.Tenant, b.At)
	if !reflect.DeepEqual(b, want) {
		return ErrInvalid
	}
	return nil
}
func (s *Store) captureProductionLocked() error {
	tenants := []string{}
	for tenant := range s.production {
		tenants = append(tenants, tenant)
	}
	sort.Strings(tenants)
	for _, tenant := range tenants {
		at := time.Now().UTC()
		if len(s.productionBlockers(tenant, at)) > 0 {
			continue
		}
		b := s.makeRuntimeBatch(tenant, at)
		if len(b.Rows) == 0 {
			continue
		}
		if err := s.append(record{RuntimeBatch: &b}); err != nil {
			return err
		}
	}
	return nil
}
func (s *Store) captureLearningLocked() error {
	if err := s.captureAutomaticLocked(); err != nil {
		return err
	}
	return s.captureProductionLocked()
}
func (s *Store) productionCanary(change ProductionChange) ProductionCanary {
	result := ProductionCanary{ReleaseSHA: change.SHA, Reasons: []string{}, LabelBindings: []string{}}
	criteria := s.productionPolicies[change.Tenant].Canary
	latest := change.At
	receipts := []RuntimeReceipt{}
	for _, r := range s.runtimeReceipts {
		if r.ReleaseSHA == change.SHA {
			receipts = append(receipts, r)
		}
	}
	sort.Slice(receipts, func(i, j int) bool { return receipts[i].SHA < receipts[j].SHA })
	// Each case contributes at most one immutable first prediction; changed case
	// revisions stay in the denominator as exclusions rather than new samples.
	baseline := map[string]bool{}
	for _, id := range change.Baseline {
		baseline[id] = true
	}
	first := map[string]RuntimeReceipt{}
	for _, r := range receipts {
		if old, ok := first[r.CaseID]; !ok || r.At.Before(old.At) {
			first[r.CaseID] = r
		}
	}
	shared := map[string]int{}
	for _, r := range first {
		if baseline[r.CaseID] {
			continue
		}
		entry := s.cases[caseKey(change.Tenant, r.CaseID)]
		if entry.Revisions[len(entry.Revisions)-1].SHA != r.CaseSHA {
			continue
		}
		for _, ref := range entry.Revisions[len(entry.Revisions)-1].Case.Evidence {
			shared[evidenceKey(ref)]++
		}
	}
	for _, r := range receipts {
		if first[r.CaseID].SHA != r.SHA {
			continue
		}
		if baseline[r.CaseID] || r.Exclusion == "preexisting_case" {
			result.BaselineExcluded++
			continue
		}
		result.Total++
		if r.At.After(latest) {
			latest = r.At
		}
		if r.Route == "incumbent" {
			result.ReferenceTotal++
			continue
		}
		result.CandidateTotal++
		entry := s.cases[caseKey(change.Tenant, r.CaseID)]
		labelSHA := ""
		if len(entry.Labels) > 0 {
			labelSHA = entry.Labels[len(entry.Labels)-1].SHA
		}
		result.LabelBindings = append(result.LabelBindings, hash([]string{r.SHA, labelSHA}))
		overlap := false
		for _, ref := range entry.Revisions[len(entry.Revisions)-1].Case.Evidence {
			if shared[evidenceKey(ref)] > 1 {
				overlap = true
			}
		}
		if overlap || !r.CohortEligible || entry.Revisions[len(entry.Revisions)-1].SHA != r.CaseSHA {
			result.Excluded++
			continue
		}
		if len(entry.Labels) == 0 {
			result.Awaiting++
			continue
		}
		label := entry.Labels[len(entry.Labels)-1]
		if !s.verifiedBinding(change.Tenant, r.CaseID, label.SHA, s.trust[change.Tenant]) || label.Verification == nil || !label.Verification.Statement.IssuedAt.After(r.At) || label.Value == "uncertain" || label.Value == "disputed" {
			result.Excluded++
			continue
		}
		if label.At.After(latest) {
			latest = label.At
		}
		result.Scored++
		addCount(&result.Counts, label.Value, r.Prediction)
	}
	result.Seconds = int(latest.Sub(change.At).Seconds())
	if result.CandidateTotal < criteria.MinimumCases || result.Counts.Attack < criteria.MinimumAttack || result.Counts.Benign < criteria.MinimumBenign {
		result.Reasons = append(result.Reasons, "insufficient_canary_samples")
	}
	if result.ReferenceTotal == 0 {
		result.Reasons = append(result.Reasons, "reference_branch_missing")
	}
	if result.Seconds < criteria.MinimumSeconds {
		result.Reasons = append(result.Reasons, "canary_window_too_short")
	}
	if result.CandidateTotal == 0 || result.Scored*10000 < criteria.MinimumCoverageBPS*result.CandidateTotal {
		result.Reasons = append(result.Reasons, "canary_coverage_below_minimum")
	}
	if ErrorUpperBPS(result.Counts.FalseBenign, result.Counts.Attack) > criteria.MaximumFalseBenignUpperBPS || ErrorUpperBPS(result.Counts.FalseAttack, result.Counts.Benign) > criteria.MaximumFalseAttackUpperBPS {
		result.Reasons = append(result.Reasons, "canary_error_confidence_bound")
	}
	result.Ready = len(result.Reasons) == 0
	result.SHA = hash(result)
	return result
}
func (s *Store) productionView(tenant string, at time.Time) ProductionView {
	h := s.production[tenant]
	v := ProductionView{Revision: len(h), State: "off", History: append([]ProductionChange{}, h...), Blockers: []string{}, Scope: "incident_triage/1", RuntimeSourceSHA: ProductionRuntimeSourceSHA(), Latest: []RuntimeReceipt{}}
	if p, ok := s.productionPolicies[tenant]; ok {
		v.Policy = &p
	}
	if len(h) == 0 {
		return v
	}
	current := h[len(h)-1]
	v.Current = &current
	if current.Request.Action == "stop" {
		v.State = "stopped"
		return v
	}
	v.State = current.Request.Action
	v.Blockers = s.productionBlockers(tenant, at)
	if current.Request.Action == "canary" {
		a := s.productionCanary(current)
		v.Canary = &a
	}
	if len(v.Blockers) > 0 {
		v.State = "blocked"
		return v
	}
	v.RuntimeEnabled = true
	for _, r := range s.runtimeLatest[tenant] {
		if r.ReleaseSHA == current.SHA {
			entry := s.cases[caseKey(tenant, r.CaseID)]
			if entry.Revisions[len(entry.Revisions)-1].SHA == r.CaseSHA {
				v.Latest = append(v.Latest, r)
			}
		}
	}
	sort.Slice(v.Latest, func(i, j int) bool { return v.Latest[i].CaseID < v.Latest[j].CaseID })
	return v
}
func (s *Store) Production(tenant string) (ProductionView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return ProductionView{}, err
	}
	if !identity.MatchString(tenant) {
		return ProductionView{}, ErrInvalid
	}
	return clone(s.productionView(tenant, time.Now().UTC())), nil
}

// Serving is performed by source synchronization, not by this read. A model
// result is returned only with a durable matching input/version receipt.
func (s *Store) attachRuntime(view View) View {
	tenant := view.Current.Case.Tenant
	history := s.production[tenant]
	if len(history) == 0 || len(s.productionBlockers(tenant, time.Now().UTC())) > 0 {
		return view
	}
	current := history[len(history)-1]
	if current.Request.Action == "stop" {
		return view
	}
	receipt, ok := s.runtimeLatest[tenant][view.Current.Case.ID]
	if ok && receipt.ReleaseSHA == current.SHA && receipt.CaseSHA == view.Current.SHA {
		view.Production = &receipt
	}
	return view
}
