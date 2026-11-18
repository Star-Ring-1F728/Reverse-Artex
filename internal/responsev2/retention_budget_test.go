//go:build linux

package responsev2

import (
	"context"
	"errors"
	"reverse-artex/internal/decisions"
	api "reverse-artex/internal/decisions/openai"
	"reverse-artex/internal/protection"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func checkpointRestartForRetentionTest(t *testing.T, s *Store, reg *protection.Registry, path string) *Store {
	t.Helper()
	if s.retained == nil {
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		var err error
		s, err = OpenRetained(path, reg, DefaultRetentionConfig())
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Checkpoint(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenRetained(path, reg, DefaultRetentionConfig())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	return reopened
}

func TestRetainedDecisionsDailyCallBudgetAndDuplicateJobID(t *testing.T) {
	s, reg, key, path := storeFixture(t)
	v := eligibleFixture(t, s, reg, key)
	provider := &stubDecider{}
	cfg := configFixture("advisory")
	cfg.DailyCalls = 1
	runner, err := NewRunner(s, cfg, []byte(strings.Repeat("p", 32)), provider)
	if err != nil {
		t.Fatal(err)
	}
	job, err := runner.Enqueue("alpha", v.Case.ID, v.Case.SHA, "retained-call")
	if err != nil {
		t.Fatal(err)
	}
	if done := waitJob(t, runner, job.ID); done.Status != "ok" {
		t.Fatal(done)
	}
	if _, err = runner.Enqueue("alpha", v.Case.ID, v.Case.SHA, job.ID); err != nil || provider.calls.Load() != 1 {
		t.Fatal("same job ID was dispatched twice", err, provider.calls.Load())
	}
	runner.Close()
	reopened := checkpointRestartForRetentionTest(t, s, reg, path)
	next, err := NewRunner(reopened, cfg, []byte(strings.Repeat("p", 32)), provider)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	dup, err := next.Enqueue("alpha", v.Case.ID, v.Case.SHA, job.ID)
	if err != nil || dup.Status != "ok" || dup.Result == nil || provider.calls.Load() != 1 {
		t.Fatal("completed duplicate did not remain idempotent", dup, err, provider.calls.Load())
	}
	if _, err = next.Enqueue("alpha", v.Case.ID, v.Case.SHA, "retained-call-two"); !errors.Is(err, ErrLimit) {
		t.Fatal("checkpoint reset the daily call budget", err)
	}
	if provider.calls.Load() != 1 {
		t.Fatal("budget rejection dispatched provider", provider.calls.Load())
	}
}

func TestRetainedDecisionsReservedTokenBudgetSurvivesCheckpoint(t *testing.T) {
	s, reg, key, path := storeFixture(t)
	v := eligibleFixture(t, s, reg, key)
	provider := &stubDecider{}
	cfg := configFixture("advisory")
	cfg.DailyCalls = 100
	cfg.DailyTokens = cfg.ReserveTokens
	runner, err := NewRunner(s, cfg, []byte(strings.Repeat("p", 32)), provider)
	if err != nil {
		t.Fatal(err)
	}
	job, err := runner.Enqueue("alpha", v.Case.ID, v.Case.SHA, "retained-token-call")
	if err != nil {
		t.Fatal(err)
	}
	if done := waitJob(t, runner, job.ID); done.Status != "ok" || done.ReservedTokens != cfg.ReserveTokens {
		t.Fatal(done)
	}
	runner.Close()
	reopened := checkpointRestartForRetentionTest(t, s, reg, path)
	next, err := NewRunner(reopened, cfg, []byte(strings.Repeat("p", 32)), provider)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	if _, err = next.Enqueue("alpha", v.Case.ID, v.Case.SHA, "retained-token-call-two"); !errors.Is(err, ErrLimit) {
		t.Fatal("checkpoint reset reserved-token accounting", err)
	}
	if provider.calls.Load() != 1 {
		t.Fatal("token budget rejection dispatched provider", provider.calls.Load())
	}
}

type retentionOverReservationDecider struct{ calls atomic.Int32 }

func (d *retentionOverReservationDecider) Decide(_ context.Context, input api.Input) api.Result {
	d.calls.Add(1)
	return api.Result{Schema: "decision-result/2", Status: "ok", InputSHA: decisions.Hash(input), Model: api.Model, Origin: api.Endpoint, Started: time.Now().UTC(), Completed: time.Now().UTC(), Usage: &api.Usage{Input: 1, Total: 8193}}
}

func TestRetainedDecisionsUsageOverReservationBlockSurvivesCheckpoint(t *testing.T) {
	s, reg, key, path := storeFixture(t)
	v := eligibleFixture(t, s, reg, key)
	provider := &retentionOverReservationDecider{}
	cfg := configFixture("advisory")
	runner, err := NewRunner(s, cfg, []byte(strings.Repeat("p", 32)), provider)
	if err != nil {
		t.Fatal(err)
	}
	job, err := runner.Enqueue("alpha", v.Case.ID, v.Case.SHA, "over-reserved")
	if err != nil {
		t.Fatal(err)
	}
	if done := waitJob(t, runner, job.ID); done.Status != "usage_over_reservation" {
		t.Fatal(done)
	}
	if runner.Status()["credential_or_usage_blocked"] != true {
		t.Fatal("over-reservation did not block further calls")
	}
	runner.Close()
	reopened := checkpointRestartForRetentionTest(t, s, reg, path)
	next, err := NewRunner(reopened, cfg, []byte(strings.Repeat("p", 32)), provider)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	if next.Status()["credential_or_usage_blocked"] != true {
		t.Fatal("retained result did not restore credential/usage block")
	}
	if _, err = next.Enqueue("alpha", v.Case.ID, v.Case.SHA, "after-over-reservation"); err == nil {
		t.Fatal("retained usage block admitted another dispatch")
	}
	if provider.calls.Load() != 1 {
		t.Fatal("retained usage block redispatched provider", provider.calls.Load())
	}
}

func TestRetainedDecisionsCircuitSurvivesCheckpoint(t *testing.T) {
	s, reg, key, path := storeFixture(t)
	v := eligibleFixture(t, s, reg, key)
	provider := &errorDecider{}
	cfg := configFixture("shadow")
	runner, err := NewRunner(s, cfg, []byte(strings.Repeat("p", 32)), provider)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"retained-failure-a", "retained-failure-b", "retained-failure-c"} {
		job, enqueueErr := runner.Enqueue("alpha", v.Case.ID, v.Case.SHA, id)
		if enqueueErr != nil {
			t.Fatal(enqueueErr)
		}
		if done := waitJob(t, runner, job.ID); done.Status != "provider_error" {
			t.Fatal(done)
		}
	}
	if _, err = runner.Enqueue("alpha", v.Case.ID, v.Case.SHA, "circuit-before-checkpoint"); err == nil {
		t.Fatal("three failures did not open the circuit")
	}
	runner.Close()
	reopened := checkpointRestartForRetentionTest(t, s, reg, path)
	next, err := NewRunner(reopened, cfg, []byte(strings.Repeat("p", 32)), provider)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	if _, err = next.Enqueue("alpha", v.Case.ID, v.Case.SHA, "circuit-after-checkpoint"); err == nil {
		t.Fatal("retained provider failures cleared the circuit")
	}
	if provider.calls.Load() != 3 {
		t.Fatal("open circuit dispatched provider", provider.calls.Load())
	}
}

func TestRetainedL3SourceReleaseCoOwnerAndInterruptedRun(t *testing.T) {
	s, reg, key, path := storeFixture(t)
	v := eligibleFixture(t, s, reg, key)
	firstModel := newMockL3(t)
	firstCfg := l3Cfg(firstModel)
	engine, err := NewL3(s, firstCfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	engineClosed := false
	defer func() {
		if !engineClosed {
			engine.Close()
		}
	}()
	containReq := L3Request{ID: "retained-contain", Tenant: "alpha", CaseID: v.Case.ID, CaseSHA: v.Case.SHA, Mode: "contain"}
	if _, err = engine.Enqueue(containReq); err != nil {
		t.Fatal(err)
	}
	contained := awaitL3(t, s, containReq.ID)
	if contained.Status != "completed" || contained.Binding == nil || contained.Receipt == nil || contained.ActionCandidate == "" {
		t.Fatal("containment did not persist its owned binding", contained)
	}
	joined, err := s.Apply(context.Background(), "alpha", Intent{ID: "retained-operator-coowner", CaseID: v.Case.ID, CaseSHA: v.Case.SHA, CandidateID: contained.ActionCandidate, Owner: "operator", Run: "human-review", Epoch: s.Epoch()})
	if err != nil || joined.PolicyID != contained.Binding.PolicyID {
		t.Fatal("operator co-owner did not join the same policy", joined, err)
	}
	engine.Close()
	engineClosed = true
	reopened := checkpointRestartForRetentionTest(t, s, reg, path)
	restoredContain, err := reopened.L3Run("alpha", containReq.ID)
	if err != nil || restoredContain.Status != "completed" || restoredContain.Binding == nil || restoredContain.Receipt == nil || restoredContain.ActionIntent != contained.ActionIntent {
		t.Fatal("retained source run lost its action binding/receipt", restoredContain, err)
	}
	secondModel := newMockL3(t)
	releaseCfg := l3Cfg(secondModel)
	releaseEngine, err := NewL3(reopened, releaseCfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	releaseEngineClosed := false
	defer func() {
		if !releaseEngineClosed {
			releaseEngine.Close()
		}
	}()
	releaseReq := L3Request{ID: "retained-release", Tenant: "alpha", CaseID: v.Case.ID, CaseSHA: v.Case.SHA, Mode: "release", SourceRun: containReq.ID}
	if _, err = releaseEngine.Enqueue(releaseReq); err != nil {
		t.Fatal("retained source run could not authorize owned release", err)
	}
	released := awaitL3(t, reopened, releaseReq.ID)
	if released.Status != "completed" || released.Receipt == nil || released.Receipt.State != "retained_by_other_owner" {
		t.Fatal("release did not preserve the co-owner", released)
	}
	policies := reopened.Policies("alpha")
	if len(policies) != 1 || len(policies[0].Claims) != 1 || policies[0].Claims[0].Owner != "operator" {
		t.Fatal("release removed the other owner's claim", policies)
	}
	callCount := secondModel.calls.Load()
	again, err := releaseEngine.Enqueue(releaseReq)
	if err != nil || again.Status != "completed" || secondModel.calls.Load() != callCount {
		t.Fatal("duplicate release run was redispatched", again, err, secondModel.calls.Load())
	}
	releaseEngine.Close()
	releaseEngineClosed = true

	// A run persisted as running is fenced as unknown on the next writer boot.
	crashReq := L3Request{ID: "retained-crash-run", Tenant: "alpha", CaseID: v.Case.ID, CaseSHA: v.Case.SHA, Mode: "analyze"}
	if _, err = reopened.l3Start(crashReq, releaseCfg); err != nil {
		t.Fatal(err)
	}
	if err = reopened.l3Update(crashReq.ID, func(run *L3Run) { run.Status = "running" }); err != nil {
		t.Fatal(err)
	}
	if err = reopened.Checkpoint(); err != nil {
		t.Fatal(err)
	}
	if err = reopened.Close(); err != nil {
		t.Fatal(err)
	}
	afterBoot, err := OpenRetained(path, reg, DefaultRetentionConfig())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = afterBoot.Close() })
	interrupted, err := afterBoot.L3Run("alpha", crashReq.ID)
	if err != nil || interrupted.Status != "interrupted_unknown" || !strings.Contains(interrupted.Error, "not replayed") {
		t.Fatal("writer restart did not fence the in-flight L3 run", interrupted, err)
	}
	afterBootEngine, err := NewL3(afterBoot, releaseCfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer afterBootEngine.Close()
	got, err := afterBootEngine.Enqueue(crashReq)
	if err != nil || got.Status != "interrupted_unknown" || secondModel.calls.Load() != callCount {
		t.Fatal("interrupted run was redispatched", got, err, secondModel.calls.Load())
	}
}

func TestRetainedIntentDigestAndCancelEpochSurviveCheckpoint(t *testing.T) {
	s, reg, key, path := storeFixture(t)
	v := eligibleFixture(t, s, reg, key)
	intent := intentFixture(s, v, "retained-intent", "operator", "manual-run")
	original, err := s.Apply(context.Background(), "alpha", intent)
	if err != nil {
		t.Fatal(err)
	}
	changed := intent
	changed.Run = "different-payload"
	if _, err = s.Apply(context.Background(), "alpha", changed); !errors.Is(err, ErrStale) {
		t.Fatal("same intent ID accepted a different payload", err)
	}
	reopened := checkpointRestartForRetentionTest(t, s, reg, path)
	replayed, err := reopened.Apply(context.Background(), "alpha", intent)
	if err != nil || replayed.Intent != original.Intent || replayed.PolicyID != original.PolicyID || replayed.Generation != original.Generation {
		t.Fatal("exact action replay lost its durable receipt", replayed, err)
	}
	if _, err = reopened.Apply(context.Background(), "alpha", changed); !errors.Is(err, ErrStale) {
		t.Fatal("retained action ID was rebound to a different payload", err)
	}
	epoch := reopened.Epoch()
	if err = reopened.Pause(true); err != nil {
		t.Fatal(err)
	}
	afterPause := reopened.Epoch()
	if afterPause != epoch+1 {
		t.Fatal("pause did not advance the cancellation epoch", epoch, afterPause)
	}
	reopened = checkpointRestartForRetentionTest(t, reopened, reg, path)
	if reopened.Epoch() != afterPause {
		t.Fatal("retained restart lost cancellation epoch", afterPause, reopened.Epoch())
	}
	newIntent := intent
	newIntent.ID = "retained-after-pause"
	newIntent.Epoch = afterPause
	if _, err = reopened.Apply(context.Background(), "alpha", newIntent); !errors.Is(err, ErrStale) {
		t.Fatal("paused retained store admitted a new action", err)
	}
}
