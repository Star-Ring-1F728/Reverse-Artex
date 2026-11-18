//go:build linux || windows

package responsev2

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func TestRetainedSignedResponsesRemainVerifiableAcrossSevenDays(t *testing.T) {
	const perDay = 128
	base := time.Now().UTC().Add(-8 * 24 * time.Hour)
	s, registry, key, path := openRetirementFixture(t, base)
	for day := 0; day <= 7; day++ {
		for index := 0; index < perDay; index++ {
			at := base.Add(time.Duration(day)*24*time.Hour + time.Duration(index)*time.Millisecond)
			id := fmt.Sprintf("week-%d-%03d", day, index)
			q := retirementProof(t, registry, key, id, id, at)
			gate, err := s.observeAndPrepareAtLocked(q.raw, q.binding, q.status, q.body, at)
			if err != nil {
				t.Fatal(id, err)
			}
			write := responseBatchWrite(q, gate)
			write.CompletedAt = at
			if err := retainedCompleteAtFixture(s, write, at); err != nil {
				t.Fatal(id, err)
			}
		}
		if err := s.Checkpoint(); err != nil {
			t.Fatal(day, err)
		}
	}
	head := s.head
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	count := 0
	verified, err := VerifyJournal(path, registry, func(row VerifiedResponse) error {
		expected := fmt.Sprintf("week-%d-%03d", count/perDay, count%perDay)
		if row.RequestID != expected || !row.Observation.Write.Complete || row.SDKBodySHA != row.Observation.Write.BodySHA {
			return fmt.Errorf("unexpected signed observation at position %d", count)
		}
		count++
		return nil
	})
	if err != nil || !verified.Passed || !verified.AuditAvailable || verified.Head != head || count != 8*perDay {
		t.Fatal("weekly journal replay lost an observation", count, err)
	}
}

func TestRetainedCompletionClockRollbackCannotAppendUnreplayableRecord(t *testing.T) {
	s, reg, key, path := retainedFixture(t, DefaultRetentionConfig())
	pending := combinedResponseFixture(t, s, reg, key, "pending-clock-fence", "own", "allow")
	// A previously durable high-water mark can be ahead after a wall-clock step.
	// Simulate that step without changing the process or host clock.
	s.high = time.Now().Add(time.Hour).UTC()
	before, err := os.ReadFile(path + ".retained/" + segmentName(s.retained.generation))
	if err != nil {
		t.Fatal(err)
	}
	seq, head := s.sequence, s.head
	if err = s.CompleteResponse(pending); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("completion accepted rollback: %v", err)
	}
	after, err := os.ReadFile(path + ".retained/" + segmentName(s.retained.generation))
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) || s.sequence != seq || s.head != head || len(s.observations) != 0 {
		t.Fatal("rollback completion changed durable journal or observed success")
	}
	if !s.outcomeFailed {
		t.Fatal("unknown completion did not fence later response admission")
	}
}

func TestRetainedCommitClockRollbackRejectedBeforeDurableWrite(t *testing.T) {
	s, _, _, path := retainedFixture(t, DefaultRetentionConfig())
	before, err := os.ReadFile(path + ".retained/" + segmentName(s.retained.generation))
	if err != nil {
		t.Fatal(err)
	}
	seq, head, high := s.sequence, s.head, s.high
	if err = s.commit(record{Operation: "writer-started", WriterBoot: s.bootID, At: high.Add(-time.Nanosecond)}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("commit accepted rollback: %v", err)
	}
	after, err := os.ReadFile(path + ".retained/" + segmentName(s.retained.generation))
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) || s.sequence != seq || s.head != head || !s.high.Equal(high) {
		t.Fatal("rejected rollback changed journal state")
	}
}

func TestRetainedReplayRejectsRehashedTimestampRollback(t *testing.T) {
	s, reg, _, path := retainedFixture(t, DefaultRetentionConfig())
	rec := record{Schema: "response-journal/2", Sequence: s.sequence + 1, Previous: s.head, Registry: reg.Digest(), At: s.high.Add(-time.Nanosecond), Operation: "writer-started", WriterBoot: s.bootID}
	rec.SHA = recordSHA(rec)
	raw, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	// Model already persisted damage without routing it through the guarded
	// writer. A valid hash chain must not neutralize the original clock fence.
	if _, err = s.file.Write(append(raw, '\n')); err != nil {
		t.Fatal(err)
	}
	if err = s.file.Sync(); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	if reopened, err := OpenRetained(path, reg, DefaultRetentionConfig()); err == nil {
		reopened.Close()
		t.Fatal("rehashed timestamp rollback accepted on replay")
	} else if !strings.Contains(err.Error(), "timestamp rollback") {
		t.Fatalf("unexpected rejection: %v", err)
	}
}

func TestRetainedCommitEqualHighwaterRemainsAllowed(t *testing.T) {
	s, _, _, _ := retainedFixture(t, DefaultRetentionConfig())
	seq, high := s.sequence, s.high
	if err := s.commit(record{Operation: "writer-started", WriterBoot: s.bootID, At: high}); err != nil {
		t.Fatal(err)
	}
	if s.sequence != seq+1 || !s.high.Equal(high) {
		t.Fatal("equal authority time did not commit exactly once")
	}
}

func TestRetainedMigrationRejectsLegacyTimestampRollbackBeforePublication(t *testing.T) {
	s, reg, key, path := storeFixture(t)
	combinedResponseFixture(t, s, reg, key, "legacy-clock-source", "own", "allow")
	rec := record{Schema: "response-journal/2", Sequence: s.sequence + 1, Previous: s.head, Registry: reg.Digest(), At: s.high.Add(-time.Nanosecond), Operation: "writer-started", WriterBoot: s.bootID}
	rec.SHA = recordSHA(rec)
	raw, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.file.Write(append(raw, '\n')); err != nil {
		t.Fatal(err)
	}
	if err = s.file.Sync(); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// The legacy format historically tolerates nonmonotone records. Opting
	// into strict retention must reject these bytes before publishing a root.
	if migrated, err := OpenRetained(path, reg, DefaultRetentionConfig()); err == nil {
		migrated.Close()
		t.Fatal("legacy rollback published an unreplayable retained root")
	} else if !strings.Contains(err.Error(), "timestamp rollback") {
		t.Fatalf("unexpected rejection: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) || retainedRootPresent(path) {
		t.Fatal("rejected migration rewrote legacy bytes or published a retained root")
	}
	if _, err = os.Stat(path + ".retained"); !os.IsNotExist(err) {
		t.Fatalf("rejected migration created retained state: %v", err)
	}
}
