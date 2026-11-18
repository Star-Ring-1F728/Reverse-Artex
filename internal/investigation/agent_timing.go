package investigation

import (
	"encoding/json"
	"path/filepath"
	"time"
)

// Private transport diagnostics. Offsets share one Go monotonic origin and do
// not identify model compute time. They are never part of a model observation.
type agentTimingStep struct {
	Step             int    `json:"step"`
	RequestSHA       string `json:"request_sha256"`
	ReplySHA         string `json:"reply_sha256,omitempty"`
	PublishedNS      int64  `json:"published_ns"`
	ReplyReadNS      int64  `json:"reply_read_ns,omitempty"`
	ReplyValidatedNS int64  `json:"reply_validated_ns,omitempty"`
}
type agentTiming struct {
	Schema    string            `json:"schema"`
	Clock     string            `json:"clock"`
	Outcome   string            `json:"outcome"`
	ElapsedNS int64             `json:"elapsed_ns"`
	Steps     []agentTimingStep `json:"steps"`
}

func (s *agentSession) finishTiming(outcome string) error {
	s.timing.Outcome = outcome
	s.timing.ElapsedNS = time.Since(s.origin).Nanoseconds()
	raw, err := json.Marshal(s.timing)
	if err != nil {
		return err
	}
	return immutableHandoff(filepath.Join(s.directory, "timing.json"), raw)
}
