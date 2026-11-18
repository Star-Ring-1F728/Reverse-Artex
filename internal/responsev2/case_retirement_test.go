//go:build linux || windows

package responsev2

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reverse-artex/internal/decisions"
	"reverse-artex/internal/protection"
	"testing"
	"time"
)

func retirementProof(t *testing.T, reg *protection.Registry, key ed25519.PrivateKey, id, session string, at time.Time) *responseBatchRequest {
	t.Helper()
	raw, binding, status, body := proofFixture(reg, key, id, "own", "alpha", "allow", at)
	p, err := reg.Verify(raw, binding, status, body, at)
	if err != nil {
		t.Fatal(err)
	}
	p.Session, binding.Session = session, session
	payload, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(protection.Envelope{KeyID: p.KeyID, Payload: base64.RawURLEncoding.EncodeToString(payload), Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, payload))})
	if err != nil {
		t.Fatal(err)
	}
	return &responseBatchRequest{raw: string(wire), binding: binding, status: status, body: body}
}

func fillRetirementCases(t *testing.T, s *Store, reg *protection.Registry, key ed25519.PrivateKey, now time.Time, pending int) (string, protection.ResponseWrite) {
	t.Helper()
	var pendingCase string
	var write protection.ResponseWrite
	for i := range retainedCaseLimit {
		id := fmt.Sprintf("retirement-%04d", i)
		q := retirementProof(t, reg, key, id, id, now)
		gate, err := s.observeAndPrepareAtLocked(q.raw, q.binding, q.status, q.body, now)
		if err != nil {
			t.Fatal(i, err)
		}
		w := responseBatchWrite(q, gate)
		w.CompletedAt = now
		if i == pending {
			pendingCase, write = gate.CaseID, w
		} else if err = retainedCompleteAtFixture(s, w, now); err != nil {
			t.Fatal(i, err)
		}
	}
	return pendingCase, write
}

func openRetirementFixture(t *testing.T, at time.Time) (*Store, *protection.Registry, ed25519.PrivateKey, string) {
	t.Helper()
	legacy, reg, key, path := storeFixture(t)
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := openRetainedUsingClock(path, reg, DefaultRetentionConfig(), nil, func() time.Time { return at })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, reg, key, path
}

func TestRetainedCaseRetirementPreservesAuditAcrossCheckpointAndRestart(t *testing.T) {
	base := time.Now().UTC().Add(-time.Minute)
	s, reg, key, path := openRetirementFixture(t, base)
	pending, write := fillRetirementCases(t, s, reg, key, base, 0)
	if len(s.pendingCases) != 1 || s.pendingCases[pending] != 1 {
		t.Fatal("unresolved response index differs from the journal")
	}
	q := retirementProof(t, reg, key, "too-young", "new-session", base.Add(time.Second))
	if _, err := s.observeAndPrepareAtLocked(q.raw, q.binding, q.status, q.body, base.Add(time.Second)); !errors.Is(err, ErrLimit) {
		t.Fatal("retired a case that still had live proof", err)
	}
	now := base.Add(6 * time.Second)
	q = retirementProof(t, reg, key, "new-after-expiry", "new-session", now)
	_, r, err := s.observationRecordLocked(q.raw, q.binding, q.status, q.body, now)
	if err != nil || r.RetiredCase == nil || r.RetiredCase.ID == pending {
		t.Fatal("no eligible case or pending case selected", err)
	}
	retired := *r.RetiredCase
	r.RetiredCase = &caseRetirement{ID: pending, SHA: s.cases[pending].SHA}
	if err = s.validateExtension(*r); err == nil {
		t.Fatal("replay validation accepted retirement of a pending case")
	}
	g, err := s.Observe(q.raw, q.binding, q.status, q.body, now)
	if err != nil || len(s.cases) != retainedCaseLimit || s.cases[retired.ID].ID != "" || s.cases[g.CaseID].ID == "" || s.cases[pending].ID == "" {
		t.Fatal("split observation did not replace just the eligible case", err)
	}
	a, err := s.PrepareResponse(q.binding.Tenant, decisions.Hash(q.raw), now)
	if err != nil {
		t.Fatal(err)
	}
	newWrite := responseBatchWrite(q, a)
	newWrite.CompletedAt = now
	for _, w := range []protection.ResponseWrite{write, newWrite} {
		if err = retainedCompleteAtFixture(s, w, now); err != nil {
			t.Fatal(err)
		}
	}
	if len(s.pendingCases) != 0 {
		t.Fatal("completed responses still pin retirement")
	}
	// Follow the split replacement with a full cohort of new sessions on
	// the combined path. Each original signed response remains exportable.
	now = now.Add(6 * time.Second)
	for i := range retainedCaseLimit {
		id := fmt.Sprintf("replacement-%04d", i)
		q = retirementProof(t, reg, key, id, id, now)
		a, err = s.observeAndPrepareAtLocked(q.raw, q.binding, q.status, q.body, now)
		if err != nil || len(s.cases) != retainedCaseLimit {
			t.Fatal(i, "unbounded or blocked session replacement", err)
		}
		w := responseBatchWrite(q, a)
		w.CompletedAt = now
		if err = retainedCompleteAtFixture(s, w, now); err != nil {
			t.Fatal(err)
		}
	}
	if err = s.Checkpoint(); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	last := s.cases[a.CaseID]
	reopened, err := OpenRetained(path, reg, DefaultRetentionConfig())
	if err != nil {
		t.Fatal(err)
	}
	if len(reopened.cases) != retainedCaseLimit || reopened.cases[last.ID].SHA != last.SHA || reopened.cases[retired.ID].ID != "" {
		t.Fatal("restart changed active view or revived a retired case")
	}
	if err = reopened.Close(); err != nil {
		t.Fatal(err)
	}
	exported := 0
	verified, err := VerifyJournal(path, reg, func(row VerifiedResponse) error {
		exported++
		return nil
	})
	if err != nil || !verified.Passed || !verified.AuditAvailable || exported != 2*retainedCaseLimit+1 || verified.TotalObservations != exported {
		t.Fatal("retirement lost signed response history", exported, verified, err)
	}
}

func TestRetainedCaseRetirementRollsBackOnBatchSyncFailure(t *testing.T) {
	base := time.Now().UTC().Add(-30 * time.Second)
	s, reg, key, _ := openRetirementFixture(t, base)
	fillRetirementCases(t, s, reg, key, base, -1)
	batcher := responseBatchFixture(t, s)
	before := decisions.Hash(s.retainedState())
	s.syncFile = func(*os.File) error { return errors.New("fixture Sync failure") }
	now := time.Now()
	q := retirementProof(t, reg, key, "failed-new", "new-session", now)
	result := batcher.process([]*responseBatchRequest{q})[0]
	if !errors.Is(result.err, ErrUnavailable) || result.gate.AttemptID != "" || !s.failed || decisions.Hash(s.retainedState()) != before || len(s.pendingCases) != 0 {
		t.Fatal("failed batch acknowledged or changed a case", result.err)
	}
}
