package caseledger

import (
	"errors"
	"reverse-artex/internal/casefile"
)

// ResponseContext is a current authenticated DB read, not a response grant.
// Raw events and credentials never enter this projection. The caller must
// independently verify its proposal and exact source event hashes.
type ResponseContext struct {
	Schema   string                   `json:"schema"`
	Head     Receipt                  `json:"head"`
	Window   casefile.Window          `json:"observed_window"`
	Quality  string                   `json:"data_quality"`
	Bindings []casefile.SourceBinding `json:"bindings"`
}

func ProjectResponse(s Stored) (ResponseContext, error) {
	if len(s.Revisions) == 0 || len(s.Revisions) > 64 {
		return ResponseContext{}, errors.New("verified case head required")
	}
	r := s.Revisions[len(s.Revisions)-1]
	if validate(r.Plan) != nil || r.SHA256 != hash(encoded(r.Plan)) || s.Head != receipt(r.Plan, r.SHA256) {
		return ResponseContext{}, errors.New("response case head mismatch")
	}
	e := r.Plan.Context.Document.Envelope.HTTP
	if len(r.Plan.Source.Bindings) > 128 {
		return ResponseContext{}, errors.New("response source limit")
	}
	return ResponseContext{Schema: "case-response-context/1", Head: s.Head, Window: e.Window, Quality: r.Plan.Context.Document.Envelope.Quality,
		Bindings: append([]casefile.SourceBinding{}, r.Plan.Source.Bindings...)}, nil
}
