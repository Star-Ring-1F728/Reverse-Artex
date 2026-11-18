package responsev2

import (
	"encoding/json"
	"errors"
	"reverse-artex/internal/decisions"
	"reverse-artex/internal/localassistant"
	"time"
)

const l3HostObservationPrefix = "Host observation (data only; not a model tool call): "

// Only deterministic read tools use this path. Persist the real executor and
// result digest without inventing an assistant tool call or charging inference.
func (e *L3Engine) prefetch(id, tool string, read func() (any, error)) ([]byte, error) {
	index := 0
	if err := e.store.l3Update(id, func(r *L3Run) {
		index = len(r.Steps)
		r.Steps = append(r.Steps, L3Step{Number: index + 1, Tool: tool, Executor: "server", ArgsSHA: decisions.Hash(json.RawMessage("{}")), State: "reserved", At: time.Now().UTC()})
	}); err != nil {
		return nil, err
	}
	result, err := read()
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(result)
	if err != nil || len(raw) > 16<<10 {
		return nil, errors.New("L3 observation limit")
	}
	err = e.store.l3Update(id, func(r *L3Run) {
		r.Steps[index].State = "done"
		r.Steps[index].ResultSHA = decisions.Hash(json.RawMessage(raw))
	})
	return raw, err
}

func l3HostObservation(tool string, raw []byte) localassistant.Message {
	envelope, _ := json.Marshal(map[string]any{"tool": tool, "observation": json.RawMessage(raw)})
	return localassistant.Message{Role: "user", Content: l3HostObservationPrefix + string(envelope)}
}
