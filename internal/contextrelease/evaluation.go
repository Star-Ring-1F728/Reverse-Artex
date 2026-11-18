package contextrelease

import (
	"embed"
	"path/filepath"
	"reverse-artex/internal/contextlearning"
	"time"
)

// This read-only adapter is independently pinned by the follow-up evaluator.
// It does not change the already frozen canary serving/approval source pin.
//
//go:embed evaluation.go
var evaluationSource embed.FS

func EvaluationReaderSHA() string {
	raw, _ := evaluationSource.ReadFile("evaluation.go")
	return contextlearning.Digest(string(raw))
}

type EvaluationRelease struct {
	Release          Change    `json:"release"`
	Bundle           Bundle    `json:"bundle"`
	JournalHead      string    `json:"journal_head_sha256"`
	JournalRevisions int       `json:"journal_revisions"`
	End              time.Time `json:"window_end"`
	HistoryPath      string    `json:"history_path"`
	PlanPath         string    `json:"plan_path"`
}

// ReadEvaluationRelease returns a detached, replay-verified historical version.
// The caller must keep Store open to exclude collector and offline writers.
func (s *Store) ReadEvaluationRelease(sha string) (EvaluationRelease, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.available() != nil {
		return EvaluationRelease{}, ErrUnavailable
	}
	for i, r := range s.changes {
		if r.SHA != sha {
			continue
		}
		if r.Approval == nil || r.Config == nil || r.Baseline == nil {
			return EvaluationRelease{}, ErrInvalid
		}
		b, ok := s.packages[r.Approval.Request.BundleSHA]
		if !ok {
			return EvaluationRelease{}, ErrInvalid
		}
		end := r.Approval.Request.Until
		if i+1 < len(s.changes) && s.changes[i+1].At.Before(end) {
			end = s.changes[i+1].At
		}
		return clone(EvaluationRelease{Release: r, Bundle: b, JournalHead: s.head(), JournalRevisions: len(s.changes), End: end, HistoryPath: filepath.Join(s.path+".observations", r.Approval.Request.BundleSHA), PlanPath: filepath.Join(s.path+".evaluations", r.SHA, "plan.json")}), nil
	}
	return EvaluationRelease{}, ErrInvalid
}
