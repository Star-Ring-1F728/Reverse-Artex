package casememory

import "time"

// This is the persisted case-shadow-plan/1 replay contract. New observer
// behavior must use a new schema/dispatcher branch and keep this implementation
// available for old journals; a source fingerprint alone cannot select semantics.
func (s *Store) shadowSnapshotV1(state shadowState, candidate LearningCandidate, at time.Time) ShadowSnapshot {
	snapshot := ShadowSnapshot{Schema: "case-shadow-snapshot/1", RunID: state.Plan.ID, Revision: len(state.Snapshots) + 1,
		JournalSequence: s.sequence + 1, At: at, InputSHA: s.selectCases(state.Plan.Tenant).SHA, Rows: []ShadowRow{}}
	previous := map[string]ShadowRow{}
	if len(state.Snapshots) > 0 {
		old := state.Snapshots[len(state.Snapshots)-1]
		snapshot.Previous = old.SHA
		for _, row := range old.Rows {
			previous[row.CaseID] = row
		}
	}
	baseline := map[string]bool{}
	for _, b := range state.Plan.Baseline.Items {
		baseline[b.CaseID] = true
	}
	entries := s.shadowCases(state.Plan.Tenant)
	baselineRefs, counts := map[string]bool{}, map[string]int{}
	for _, entry := range entries {
		current := entry.Revisions[len(entry.Revisions)-1]
		for _, ref := range current.Case.Evidence {
			key := evidenceKey(ref)
			if baseline[current.Case.ID] {
				baselineRefs[key] = true
			} else {
				counts[key]++
			}
		}
	}
	scored := []CandidateRow{}
	for _, entry := range entries {
		current := entry.Revisions[len(entry.Revisions)-1]
		if baseline[current.Case.ID] {
			continue
		}
		row, seen := previous[current.Case.ID]
		if !seen {
			row = ShadowRow{CaseID: current.Case.ID, CaseSHA: current.SHA, SourceSHA: current.Source, PredictedAt: at, PredictionSequence: s.sequence + 1, Features: caseFeatures(current.Case)}
			if len(entry.Labels) > 0 {
				row.CaptureExclusion = "prelabeled_before_prediction"
			}
			if current.Case.First.Before(state.Plan.StartedAt) {
				row.CaptureExclusion = "preexisting_observation"
			}
			for _, ref := range current.Case.Evidence {
				if ref.Time.Before(state.Plan.StartedAt) {
					row.CaptureExclusion = "preexisting_observation"
				}
			}
			if row.CaptureExclusion == "" {
				row.Prediction = "benign"
				if candidate.Model.suspicious(row.Features) {
					row.Prediction = "suspicious"
				}
			}
		}
		row.LabelSHA, row.Label, row.LabelRevision = "", "", 0
		if len(entry.Labels) > 0 {
			label := entry.Labels[len(entry.Labels)-1]
			row.LabelSHA, row.Label, row.LabelRevision = label.SHA, label.Value, label.Revision
		}
		overlap := false
		for _, ref := range current.Case.Evidence {
			key := evidenceKey(ref)
			if baselineRefs[key] || counts[key] > 1 {
				overlap = true
			}
		}
		switch {
		case row.CaptureExclusion != "":
			row.Status = row.CaptureExclusion
		case current.SHA != row.CaseSHA:
			row.Status = "evidence_changed"
		case overlap:
			row.Status = "overlapping_evidence"
		case row.LabelSHA == "":
			row.Status = "awaiting_label"
		case entry.Labels[len(entry.Labels)-1].CaseSHA != row.CaseSHA:
			row.Status = "stale_label"
		case row.Label == "uncertain" || row.Label == "disputed":
			row.Status = row.Label
		default:
			row.Status = "scored"
			scored = append(scored, CandidateRow{Label: row.Label, Features: row.Features})
		}
		snapshot.Rows = append(snapshot.Rows, row)
		if row.Prediction != "" {
			snapshot.Predicted++
		}
		switch row.Status {
		case "scored":
			snapshot.Scored++
		case "awaiting_label":
			snapshot.Awaiting++
		default:
			snapshot.Excluded++
		}
	}
	snapshot.Total = len(snapshot.Rows)
	snapshot.Comparison = CandidateComparison{measure(CandidateModel{Kind: "all_alerts_suspicious", Feature: -1}, scored, false), measure(candidate.Model, scored, false)}
	snapshot.SHA = hash(snapshot)
	return snapshot
}
