package responsev2

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"os"
	"reverse-artex/internal/decisions"
	"reverse-artex/internal/protection"
	"time"
)

type VerifiedResponse struct {
	RequestID     string              `json:"request_id"`
	EvidenceID    string              `json:"evidence_id"`
	ProofSHA      string              `json:"sdk_proof_sha256"`
	Registry      string              `json:"registry_digest"`
	Scope         Scope               `json:"scope"`
	SDKStatus     int                 `json:"sdk_status"`
	SDKBodySHA    string              `json:"sdk_body_sha256"`
	SDKBodyLength int                 `json:"sdk_body_length"`
	Attempt       ResponseAttempt     `json:"response_attempt"`
	Observation   ResponseObservation `json:"response_observation"`
}
type JournalVerification struct {
	Schema            string            `json:"schema"`
	Passed            bool              `json:"passed"`
	ReadOnly          bool              `json:"read_only"`
	Sequence          int               `json:"sequence"`
	Head              string            `json:"journal_head_sha256"`
	TotalEvents       int               `json:"total_events"`
	TotalAttempts     int               `json:"total_attempts"`
	TotalObservations int               `json:"total_observations"`
	Pending           int               `json:"pending_unknown"`
	AuditAvailable    bool              `json:"audit_available"`
	Retention         map[string]any    `json:"retention"`
	OutcomeDigests    map[string]string `json:"outcome_sha256"`
}

// VerifyJournal takes the writer's shared ownership lock and replays every raw
// signed record. It never publishes recovery files or a new writer boot. Output
// callbacks are derived records, not remote-client delivery attestations.
func VerifyJournal(path string, registry *protection.Registry, emit func(VerifiedResponse) error) (JournalVerification, error) {
	result := JournalVerification{Schema: "response-journal-verification/1", ReadOnly: true}
	if !retentionSupported() || registry == nil {
		return result, ErrUnavailable
	}
	if err := validateRetentionPath(path); err != nil {
		return result, err
	}
	owner, err := openJournalReadLock(path)
	if err != nil {
		return result, err
	}
	defer owner.Close()
	defer unlockRetentionRead(owner)
	return verifyStoppedJournal(path, registry, emit)
}

func openJournalReadLock(path string) (*os.File, error) {
	name := path + ".owner"
	info, err := os.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, ErrUnavailable
	}
	owner, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	opened, err := owner.Stat()
	if err != nil || !os.SameFile(info, opened) {
		owner.Close()
		return nil, ErrUnavailable
	}
	if err = lockRetentionRead(owner); err != nil {
		owner.Close()
		return nil, err
	}
	return owner, nil
}

// The caller holds the shared lock throughout replay.
func verifyStoppedJournal(path string, registry *protection.Registry, emit func(VerifiedResponse) error) (JournalVerification, error) {
	result := JournalVerification{Schema: "response-journal-verification/1", ReadOnly: true}
	s, err := newStore(nil, nil, registry)
	if err != nil {
		return result, err
	}
	defer func() {
		if s.file != nil {
			s.file.Close()
		}
	}()
	s.replayObserver = func(record record) error {
		if record.Observation == nil || emit == nil {
			return nil
		}
		obs := *record.Observation
		a := s.attempts[obs.Write.AttemptID]
		e := s.events[a.EvidenceID]
		return emit(VerifiedResponse{e.Request, e.ID, protection.BodyHash([]byte(e.Proof)), registry.Digest(), e.Scope, e.Status, e.BodySHA, e.BodyLength, a, obs})
	}
	if retainedRootPresent(path) {
		raw, e := readRetainedFile(path, 16<<10)
		if e != nil {
			return result, e
		}
		var root retentionRoot
		if e = decisions.DecodeStrict(raw, &root, 16<<10); e != nil {
			return result, e
		}
		if root.Schema != "response-retention-root/1" || root.Registry != registry.Digest() || root.Config.Validate() != nil {
			return result, ErrUnavailable
		}
		s.retained = &retainedJournal{path: path, dir: path + ".retained", id: root.ID, config: root.Config}
		if err = s.replayRetained(root, false); err != nil {
			return result, err
		}
	} else {
		if _, err := os.Lstat(path + ".retained"); err == nil {
			return result, errors.New("retained directory without a valid marker; writer recovery required")
		} else if !os.IsNotExist(err) {
			return result, err
		}
		raw, err := readRetainedFile(path, 64<<20)
		if err != nil {
			return result, err
		}
		reader := bufio.NewReaderSize(bytes.NewReader(raw), 64<<10)
		for {
			line, e := reader.ReadSlice('\n')
			if e == io.EOF && len(line) == 0 {
				break
			}
			if e != nil {
				return result, errors.New("incomplete legacy journal")
			}
			if err = s.replayRecord(line); err != nil {
				return result, err
			}
		}
	}
	if time.Now().Before(s.high) {
		return result, errors.New("journal clock rollback")
	}
	pending := 0
	for id := range s.attempts {
		if _, ok := s.observations[id]; !ok {
			pending++
		}
	}
	outcomes := map[string]string{}
	for key, history := range s.histories {
		outcome, err := s.outcomeLocked(history.Binding.Scope.Tenant, history.Binding.PolicyID, history.Binding.Episode, time.Now())
		if err != nil {
			return result, err
		}
		outcomes[key] = decisions.Hash(outcome)
	}
	result.Passed = true
	result.Sequence = s.sequence
	result.Head = s.head
	result.TotalEvents = s.totalEvents
	result.TotalAttempts = s.totalAttempts
	result.TotalObservations = s.totalObservations
	result.Pending = pending
	result.AuditAvailable = !s.outcomeFailed && pending == 0
	result.Retention = s.retainedStatusLocked()
	result.OutcomeDigests = outcomes
	return result, nil
}
