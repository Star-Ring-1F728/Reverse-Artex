package casememory

import "reverse-artex/internal/incident"

// TrainingSample separates audit identity/labels from the future feature vector.
// Free-text review reasons are deliberately absent from training input.
type TrainingSample struct {
	Case      incident.Case `json:"case"`
	CaseSHA   string        `json:"case_sha256"`
	SourceSHA string        `json:"source_snapshot_sha256"`
	LabelSHA  string        `json:"label_sha256"`
	Label     string        `json:"label"`
}

type TrainingDataset struct {
	Schema    string           `json:"schema"`
	Tenant    string           `json:"tenant_id"`
	Selection Selection        `json:"selection"`
	Samples   []TrainingSample `json:"samples"`
	SHA       string           `json:"dataset_sha256"`
}

// Dataset freezes an exact saved selection and its corresponding current case
// versions in a single critical section. A corrected/stale selection is refused.
// This neither creates labels nor silently selects a different training cohort.
func (s *Store) Dataset(tenant, selectionSHA string) (TrainingDataset, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	result, err := s.dataset(tenant, selectionSHA)
	return clone(result), err
}

// Caller owns s.mu; candidate generation uses the same frozen selection.
func (s *Store) dataset(tenant, selectionSHA string) (TrainingDataset, error) {
	if err := s.available(); err != nil {
		return TrainingDataset{}, err
	}
	selected, ok := s.selections[selectionSHA]
	if !ok || selected.Tenant != tenant {
		return TrainingDataset{}, ErrNotFound
	}
	if s.selectionFor(selected).SHA != selected.SHA {
		return TrainingDataset{}, ErrConflict
	}
	result := TrainingDataset{Schema: "case-training-dataset/1", Tenant: tenant, Selection: selected, Samples: []TrainingSample{}}
	for _, binding := range selected.Items {
		if binding.Exclusion != "" {
			continue
		}
		entry := s.cases[caseKey(tenant, binding.CaseID)]
		revision := entry.Revisions[len(entry.Revisions)-1]
		label := entry.Labels[len(entry.Labels)-1]
		if revision.SHA != binding.CaseSHA || label.SHA != binding.LabelSHA || label.CaseSHA != revision.SHA {
			return TrainingDataset{}, ErrConflict
		}
		result.Samples = append(result.Samples, TrainingSample{revision.Case, revision.SHA, revision.Source, label.SHA, label.Value})
	}
	result.SHA = hash(result)
	return result, nil
}

// DatasetDigest allows an isolated trainer to verify the exported capsule.
func DatasetDigest(dataset TrainingDataset) string { dataset.SHA = ""; return hash(dataset) }
