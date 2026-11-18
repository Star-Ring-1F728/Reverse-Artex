//go:build linux

package responsev2

import (
	"fmt"
	"reverse-artex/internal/decisions"
	"testing"
	"time"
)

func TestAdaptiveStrategySnapshotsSurviveRetainedCheckpoint(t *testing.T) {
	s, reg, key, path := storeFixture(t)
	v := eligibleFixture(t, s, reg, key)
	m := newMockL3(t)
	cfg := referenceConfig(m)
	cfg.AdaptiveStrategy = true
	engine, err := NewL3(s, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Enqueue(L3Request{ID: "retained-strategy", Tenant: "alpha", CaseID: v.Case.ID, CaseSHA: v.Case.SHA, Mode: "contain"}); err != nil {
		engine.Close()
		t.Fatal(err)
	}
	run := awaitL3(t, s, "retained-strategy")
	engine.Close()
	if run.Status != "completed" || run.Strategy == nil || run.RevisedStrategy == nil {
		t.Fatal(run)
	}
	reopened := checkpointRestartForRetentionTest(t, s, reg, path)
	again, err := reopened.L3Run("alpha", run.Request.ID)
	if err != nil || decisions.Hash(again.Strategy) != decisions.Hash(run.Strategy) || decisions.Hash(again.RevisedStrategy) != decisions.Hash(run.RevisedStrategy) {
		t.Fatal("checkpoint lost strategy provenance", again, err)
	}
	p := strategyFixture(t, reopened, v.Case.ID)
	if p.ActiveScopes != 1 || len(p.Feedback) != 1 {
		t.Fatal("checkpoint lost policy feedback", p)
	}
}

func TestStrategyCheckpointDoesNotClaimEvictedHistoryComplete(t *testing.T) {
	s, reg, key, path := storeFixture(t)
	base := time.Now().Add(-10 * time.Second)
	var id string
	for i := 0; i < 40; i++ {
		object := "one"
		if i%2 != 0 {
			object = "two"
		}
		g := observeFixture(t, s, reg, key, fmt.Sprintf("aged-burst-%d", i), object, "alpha", "deny", base.Add(time.Duration(i)*time.Millisecond))
		id = g.CaseID
	}
	observeFixture(t, s, reg, key, "current-burst", "one", "alpha", "deny", time.Now())
	before := strategyFixture(t, s, id)
	if before.Next != "contain_exact" || !before.CompleteHistory || before.OmittedObservations != 9 {
		t.Fatal(before)
	}
	s.Close()
	var err error
	s, err = OpenRetained(path, reg, DefaultRetentionConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Checkpoint(); err != nil {
		t.Fatal(err)
	}
	after := strategyFixture(t, s, id)
	if after.CompleteHistory || after.Next != "review_evidence" || len(after.Candidates) != 0 {
		t.Fatal("evicted history silently authorized containment", after)
	}
	s.Close()
	reopened, err := OpenRetained(path, reg, DefaultRetentionConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	again := strategyFixture(t, reopened, id)
	if again.CompleteHistory || again.Next != "review_evidence" {
		t.Fatal("restart forgot evidence gap", again)
	}
}
