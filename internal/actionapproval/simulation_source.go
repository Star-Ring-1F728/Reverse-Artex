package actionapproval

import (
	"encoding/json"
	"errors"
	"sync"

	"reverse-artex/internal/actionproposal"
	"reverse-artex/internal/assistance"
	"reverse-artex/internal/decisions"
)

// CurrentCase is a locally supplied case/configuration binding. This lab source
// does not authenticate a real case service, sensor or human operator.
type CurrentCase struct {
	Epoch    int                 `json:"config_epoch"`
	Snapshot assistance.Snapshot `json:"snapshot"`
}

type LocalCaseSource struct {
	mu    sync.Mutex
	cases map[string]CurrentCase
}

func NewLocalCaseSource() *LocalCaseSource    { return &LocalCaseSource{cases: map[string]CurrentCase{}} }
func caseKey(tenant, asset, id string) string { return decisions.Hash([]string{tenant, asset, id}) }

func DecodeCurrentCase(raw []byte) (CurrentCase, error) {
	var c CurrentCase
	if err := decode(raw, &c, 8<<10); err != nil {
		return c, err
	}
	return c, c.validate()
}
func (c CurrentCase) validate() error {
	if c.Epoch < 1 || c.Epoch > assistance.MaxEpochs || c.Snapshot.Validate() != nil || c.Snapshot.QuestionSet != decisions.QuestionVersion {
		return errors.New("current typed case/configuration required")
	}
	return nil
}
func (s *LocalCaseSource) Put(c CurrentCase) error {
	if s == nil || c.validate() != nil {
		return errors.New("valid local current case required")
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return err
	}
	var frozen CurrentCase
	if err := json.Unmarshal(raw, &frozen); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k := caseKey(c.Snapshot.Tenant, c.Snapshot.Asset, c.Snapshot.CaseID)
	if old, exists := s.cases[k]; exists {
		if c.Epoch < old.Epoch || c.Snapshot.Revision < old.Snapshot.Revision ||
			(c.Snapshot.Revision == old.Snapshot.Revision && decisions.Hash(c.Snapshot) != decisions.Hash(old.Snapshot)) {
			return errors.New("case update requires monotonic epoch/revision and immutable revision content")
		}
	} else if len(s.cases) >= MaxEntries {
		return errors.New("local case source capacity")
	}
	s.cases[k] = frozen
	return nil
}

// The source lock stays held through preflight and the local effect boundary.
// Updates never call back into Ledger; lock order is ledger then case source.
func (s *LocalCaseSource) withCurrent(p actionproposal.Proposal, operation func() error) error {
	if s == nil {
		return errors.New("explicit local current-case source required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	c, exists := s.cases[caseKey(p.Target.Tenant, p.Target.Asset, p.CaseID)]
	if !exists || c.Epoch != p.Epoch || c.Snapshot.Revision != p.Revision || decisions.Hash(c.Snapshot) != p.SnapshotSHA {
		return errors.New("approved case/configuration is stale or unavailable")
	}
	return operation()
}
