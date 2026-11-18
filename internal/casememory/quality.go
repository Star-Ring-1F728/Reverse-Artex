package casememory

import (
	"encoding/json"
	"reflect"
	"sort"
	"time"
)

const MaxQualityPlans = 16

func validLearningRole(role string) bool {
	switch role {
	case "label_reviewer", "release_approver", "evaluation_custodian", "independent_evaluator", "production_approver":
		return true
	}
	return false
}
func productionRoles(p LearningTrust) bool {
	required := map[string]bool{"evaluation_custodian": false, "independent_evaluator": false, "production_approver": false}
	actors, keys := map[string]bool{}, map[string]bool{}
	for _, k := range p.Keys {
		if k.Revoked {
			continue
		}
		if actors[k.Actor] || keys[k.PublicKey] {
			return false
		}
		actors[k.Actor] = true
		keys[k.PublicKey] = true
		if _, ok := required[k.Role]; ok {
			required[k.Role] = true
		}
	}
	for _, ok := range required {
		if !ok {
			return false
		}
	}
	return true
}
func (s *Store) validateProductionPolicy(p ProductionPolicy) error {
	if p.Schema != "case-production-policy/1" || !identity.MatchString(p.Tenant) || p.Scope != "incident_triage/1" || !validTrust(s.trust[p.Tenant]) || hash(s.trust[p.Tenant]) != p.TrustSHA || p.Revision < 1 || p.Revision > 128 || !validQualityCriteria(p.Quality) || !validCanaryCriteria(p.Canary) || p.MaximumReportAgeSeconds < 60 || p.MaximumReportAgeSeconds > 604800 {
		return ErrInvalid
	}
	old, exists := s.productionPolicies[p.Tenant]
	if (!exists && p.Revision != 1) || (exists && p.Revision != old.Revision+1) {
		return ErrConflict
	}
	if p.Enabled && !productionRoles(s.trust[p.Tenant]) {
		return ErrInvalid
	}
	return nil
}
func (s *Store) SetProductionPolicy(p ProductionPolicy) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return "", err
	}
	if old, ok := s.productionPolicies[p.Tenant]; ok && reflect.DeepEqual(old, p) {
		return hash(old), nil
	}
	if err := s.append(record{ProductionPolicy: &p}); err != nil {
		return "", err
	}
	return hash(p), nil
}
func (s *Store) incumbentModel(tenant string) CandidateModel {
	h := s.production[tenant]
	if len(h) > 0 && h[len(h)-1].Request.Action != "stop" {
		plan := s.qualityPlans[h[len(h)-1].Request.PlanID]
		return s.candidates[plan.CandidateID].Model
	}
	return CandidateModel{Kind: "all_alerts_suspicious", Feature: -1}
}
func (s *Store) makeQualityPlan(candidate LearningCandidate, at time.Time, runtimeSHA string) QualityPlan {
	policy := s.productionPolicies[candidate.Tenant]
	incumbent := s.incumbentModel(candidate.Tenant)
	q := QualityPlan{TrainingEvidenceSHA: hash(s.trainingEvidence(candidate)), Schema: "case-quality-plan/1", Tenant: candidate.Tenant, CandidateID: candidate.ID, CandidateSHA: candidate.SHA, ModelSHA: candidate.ModelSHA, FeatureSHA: candidate.FeatureSHA, TrainerSHA: candidate.TrainerSHA, RuntimeSHA: runtimeSHA, PolicySHA: hash(policy), TrustSHA: hash(s.trust[candidate.Tenant]), Incumbent: incumbent, IncumbentSHA: hash(incumbent), Criteria: policy.Quality, CreatedAt: at}
	q.ID = hash(q)
	return q
}
func (s *Store) validateQualityPlan(q QualityPlan) error {
	candidate, ok := s.candidates[q.CandidateID]
	if !ok || candidate.Tenant != q.Tenant {
		return ErrNotFound
	}
	if len(s.trainingEvidence(candidate)) > 4096 {
		return ErrLimit
	}
	if len(s.qualityPlans) >= MaxQualityPlans {
		return ErrLimit
	}
	if _, ok := s.qualityPlans[q.ID]; ok {
		return ErrConflict
	}
	if candidate.Selection.TrustSHA == "" || candidate.TrainingStatus != "fit_complete" || len(s.trainingChanges(candidate)) > 0 || !validQualityCriteria(s.productionPolicies[q.Tenant].Quality) || !digest.MatchString(q.RuntimeSHA) || q.CreatedAt.IsZero() {
		return ErrInvalid
	}
	want := s.makeQualityPlan(candidate, q.CreatedAt, q.RuntimeSHA)
	if !reflect.DeepEqual(q, want) {
		return ErrInvalid
	}
	return nil
}
func (s *Store) qualityPlanBlockers(p QualityPlan) []string {
	blockers := []string{}
	c := s.candidates[p.CandidateID]
	policy := s.productionPolicies[p.Tenant]
	if p.TrustSHA != hash(s.trust[p.Tenant]) || p.PolicySHA != hash(policy) {
		blockers = append(blockers, "trust_or_production_policy_changed")
	}
	if !policy.Enabled {
		blockers = append(blockers, "production_policy_disabled")
	}
	if !productionRoles(s.trust[p.Tenant]) {
		blockers = append(blockers, "independent_roles_unavailable")
	}
	if c.TrainerSHA != trainerSHA() || p.RuntimeSHA != ProductionRuntimeSourceSHA() || len(s.trainingChanges(c)) > 0 {
		blockers = append(blockers, "training_or_runtime_changed")
	}
	return blockers
}
func (s *Store) qualityCapsule(id string) QualityCapsule {
	plan := s.qualityPlans[id]
	candidate := s.candidates[plan.CandidateID]
	evidence := s.trainingEvidence(candidate)
	result := QualityCapsule{Schema: "case-quality-capsule/1", Plan: plan, Model: candidate.Model, ForbiddenEvidence: evidence, Cohort: s.cohorts[id]}
	result.SHA = QualityCapsuleDigest(result)
	return result
}
func (s *Store) qualityView(id string) QualityView {
	plan := s.qualityPlans[id]
	v := QualityView{Capsule: s.qualityCapsule(id), State: "PREPARED_NOT_READY", Blockers: s.qualityPlanBlockers(plan)}
	if _, ok := s.cohorts[id]; !ok {
		v.Blockers = append(v.Blockers, "independent_cohort_not_admitted")
	} else {
		v.State = "SEALED_READY_FOR_EVALUATION"
	}
	if proof, ok := s.qualityProofs[id]; ok {
		v.Proof = &proof
		v.State = "QUALITY_REJECTED"
		if proof.Statement.Report.Passed {
			v.State = "QUALITY_ACCEPTED"
		}
		if time.Since(proof.Statement.Report.FinishedAt) > time.Duration(s.productionPolicies[plan.Tenant].MaximumReportAgeSeconds)*time.Second {
			v.Blockers = append(v.Blockers, "quality_evidence_expired")
		}
	}
	if len(v.Blockers) > 0 && v.State != "PREPARED_NOT_READY" {
		v.State = "BLOCKED"
	}
	return v
}
func (s *Store) PrepareQuality(tenant, candidateID string) (QualityView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return QualityView{}, err
	}
	c, ok := s.candidates[candidateID]
	if !ok || c.Tenant != tenant {
		return QualityView{}, ErrNotFound
	}
	if c.TrainerSHA != trainerSHA() || len(s.trainingChanges(c)) > 0 {
		return QualityView{}, ErrConflict
	}
	if len(s.production[c.Tenant]) > 0 && s.production[c.Tenant][len(s.production[c.Tenant])-1].Request.Action != "stop" && len(s.productionBlockers(c.Tenant, time.Now().UTC())) > 0 {
		return QualityView{}, ErrConflict
	}
	q := s.makeQualityPlan(c, time.Now().UTC(), ProductionRuntimeSourceSHA())
	if err := s.append(record{QualityPlan: &q}); err != nil {
		return QualityView{}, err
	}
	return clone(s.qualityView(q.ID)), nil
}
func (s *Store) Quality(tenant, id string) (QualityView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return QualityView{}, err
	}
	if p, ok := s.qualityPlans[id]; !ok || p.Tenant != tenant {
		return QualityView{}, ErrNotFound
	}
	return clone(s.qualityView(id)), nil
}
func CohortSigningBytes(q CohortSeal) []byte {
	q.Signature = ""
	b, _ := json.Marshal(q)
	return append([]byte("reverse-artex/quality-cohort/1\n"), b...)
}
func QualitySigningBytes(q SignedQualityReport) []byte {
	q.Signature = ""
	b, _ := json.Marshal(q)
	return append([]byte("reverse-artex/quality-report/1\n"), b...)
}
func (s *Store) validateCohort(r CohortRecord) error {
	q := r.Statement
	plan, ok := s.qualityPlans[q.PlanID]
	if !ok || plan.Tenant != q.Tenant {
		return ErrNotFound
	}
	key, ok := authorizedKey(s.trust[q.Tenant], q.KeyID, "evaluation_custodian")
	copy := r
	copy.SHA = ""
	if !ok || q.Schema != "case-quality-cohort/1" || q.TrustSHA != plan.TrustSHA || q.TrustSHA != hash(s.trust[q.Tenant]) || !identity.MatchString(q.DatasetID) || !digest.MatchString(q.InputsSHA) || !digest.MatchString(q.GoldSHA) || !digest.MatchString(q.MembershipSHA) || !digest.MatchString(q.ProvenanceSHA) || q.Planned < plan.Criteria.MinimumCases || q.Planned > 512 || q.Families < plan.Criteria.MinimumFamilies || q.Families > 32 || q.SourceGroups < plan.Criteria.MinimumSourceGroups || q.SourceGroups > 512 || !q.IndependentCustody || !q.RuntimeGoldDenied || q.TrainingOverlap != 0 || q.IssuedAt.Before(plan.CreatedAt) || !admissionTime(q.IssuedAt, q.ExpiresAt, r.At) || r.SHA != hash(copy) || !validSignature(key, q.Signature, CohortSigningBytes(q)) {
		return ErrInvalid
	}
	if _, ok := s.cohorts[q.PlanID]; ok {
		return ErrConflict
	}
	// A sealed dataset is single-use across candidates/plans, including rejects.
	for _, old := range s.cohorts {
		a := old.Statement
		if a.MembershipSHA == q.MembershipSHA || a.DatasetID == q.DatasetID || a.InputsSHA == q.InputsSHA || a.GoldSHA == q.GoldSHA || a.ProvenanceSHA == q.ProvenanceSHA {
			return ErrConflict
		}
	}
	return nil
}
func (s *Store) AdmitQualityCohort(tenant string, q CohortSeal) (CohortRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return CohortRecord{}, err
	}
	plan, ok := s.qualityPlans[q.PlanID]
	if !ok || q.Tenant != tenant || plan.Tenant != tenant {
		return CohortRecord{}, ErrNotFound
	}
	if old, ok := s.cohorts[q.PlanID]; ok && reflect.DeepEqual(old.Statement, q) {
		return clone(old), nil
	}
	if len(s.qualityPlanBlockers(plan)) > 0 {
		return CohortRecord{}, ErrConflict
	}
	r := CohortRecord{Statement: q, At: time.Now().UTC()}
	r.SHA = hash(r)
	if err := s.append(record{QualityCohort: &r}); err != nil {
		return CohortRecord{}, err
	}
	return clone(r), nil
}
func (s *Store) validateQualityProof(r QualityRecord) error {
	q := r.Statement
	plan, ok := s.qualityPlans[q.Report.PlanID]
	if !ok || plan.Tenant != q.Tenant {
		return ErrNotFound
	}
	if _, sealed := s.cohorts[plan.ID]; !sealed {
		return ErrConflict
	}
	key, ok := authorizedKey(s.trust[q.Tenant], q.KeyID, "independent_evaluator")
	copy := r
	copy.SHA = ""
	if !ok || q.Schema != "case-quality-attestation/1" || q.TrustSHA != plan.TrustSHA || q.TrustSHA != hash(s.trust[q.Tenant]) || !q.IndependenceAttested || !q.IsolationAttested || !admissionTime(q.IssuedAt, q.ExpiresAt, r.At) || q.IssuedAt.Before(q.Report.FinishedAt) || r.At.Before(q.Report.FinishedAt) || r.SHA != hash(copy) || !validSignature(key, q.Signature, QualitySigningBytes(q)) {
		return ErrInvalid
	}
	if _, ok := s.qualityProofs[plan.ID]; ok {
		return ErrConflict
	}
	if err := validateQualityReport(q.Report, s.qualityCapsule(plan.ID)); err != nil {
		return err
	}
	return nil
}
func (s *Store) ImportQuality(tenant string, q SignedQualityReport) (QualityRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return QualityRecord{}, err
	}
	plan, ok := s.qualityPlans[q.Report.PlanID]
	if !ok || plan.Tenant != tenant || q.Tenant != tenant {
		return QualityRecord{}, ErrNotFound
	}
	if old, ok := s.qualityProofs[plan.ID]; ok && reflect.DeepEqual(old.Statement, q) {
		return clone(old), nil
	}
	if len(s.qualityPlanBlockers(plan)) > 0 {
		return QualityRecord{}, ErrConflict
	}
	r := QualityRecord{Statement: q, At: time.Now().UTC()}
	r.SHA = hash(r)
	if err := s.append(record{QualityProof: &r}); err != nil {
		return QualityRecord{}, err
	}
	return clone(r), nil
}

func (s *Store) trainingEvidence(candidate LearningCandidate) []string {
	evidence := []string{}
	seen := map[string]bool{}
	for _, binding := range candidate.Selection.Items {
		seen[binding.EvidenceSHA] = true
		entry := s.cases[caseKey(candidate.Tenant, binding.CaseID)]
		// The plan is made with current training bindings; later reads retain the
		// exact revision by SHA, never substitute a changed case's evidence.
		for _, revision := range entry.Revisions {
			if revision.SHA == binding.CaseSHA {
				for _, ref := range revision.Case.Evidence {
					seen[evidenceKey(ref)] = true
				}
				break
			}
		}
	}
	for value := range seen {
		evidence = append(evidence, value)
	}
	sort.Strings(evidence)
	return evidence
}
