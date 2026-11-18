package responsev2

import (
	"context"
	"encoding/json"
	"reverse-artex/internal/decisions"
	api "reverse-artex/internal/decisions/openai"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type stubDecider struct {
	calls atomic.Int32
	wait  chan struct{}
}

func (d *stubDecider) Decide(ctx context.Context, i api.Input) api.Result {
	d.calls.Add(1)
	if d.wait != nil {
		select {
		case <-d.wait:
		case <-ctx.Done():
		}
	}
	probability := 0.99
	choice := "temporary_limit_candidate"
	score := 3.0
	return api.Result{Schema: "decision-result/2", Status: "ok", InputSHA: decisions.Hash(i), Model: api.Model, Origin: api.Endpoint, Started: time.Now().UTC(), Completed: time.Now().UTC(), Answers: []api.Answer{{Name: "ongoing_abuse", Type: "predicate", Probability: &probability}, {Name: "candidate_action", Type: "choice", Choice: &choice}, {Name: "priority", Type: "score", Score: &score}}, Usage: &api.Usage{Input: 10, Total: 10}}
}
func configFixture(mode string) api.Config {
	return api.Config{Revision: "test-v1", Mode: mode, KeyEnv: "RA_SYNTHETIC_TEST_KEY", DailyCalls: 100, DailyTokens: 1000000, ReserveTokens: 8192, Threshold: 0.95, GateSHA: strings.Repeat("a", 64)}
}
func waitJob(t *testing.T, r *Runner, id string) Job {
	t.Helper()
	until := time.Now().Add(3 * time.Second)
	for time.Now().Before(until) {
		j, err := r.Job("alpha", id)
		if err != nil {
			t.Fatal(err)
		}
		if j.Status != "reserved" && j.Status != "dispatched" {
			return j
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("job did not complete")
	return Job{}
}
func TestOffNeverInitializesOrCallsProviderAndShadowHasNoPolicyAuthority(t *testing.T) {
	s, reg, key, _ := storeFixture(t)
	v := eligibleFixture(t, s, reg, key)
	provider := &stubDecider{}
	off, err := NewRunner(s, api.Config{Mode: "off"}, []byte(strings.Repeat("p", 32)), provider)
	if err != nil {
		t.Fatal(err)
	}
	j, err := off.Enqueue("alpha", v.Case.ID, v.Case.SHA, "off")
	if err != nil || j.Status != "off" || provider.calls.Load() != 0 || len(s.jobs) != 0 {
		t.Fatal("off called provider", j, err)
	}
	off.Close()
	shadow, err := NewRunner(s, configFixture("shadow"), []byte(strings.Repeat("p", 32)), provider)
	if err != nil {
		t.Fatal(err)
	}
	defer shadow.Close()
	j, err = shadow.Enqueue("alpha", v.Case.ID, v.Case.SHA, "shadow")
	if err != nil {
		t.Fatal(err)
	}
	j = waitJob(t, shadow, j.ID)
	if j.Status != "ok" || j.Receipt != nil || !j.ReviewPreserved || len(s.Policies("alpha")) != 0 {
		t.Fatal(j)
	}
	raw, _ := json.Marshal(j.Input)
	if strings.Contains(string(raw), "principal") || strings.Contains(string(raw), "signed_sdk_proof") {
		t.Fatal("raw scope sent to provider")
	}
}
func TestFreshDecisionsCandidateInstallsOnlyServerScopeAndStaleCannot(t *testing.T) {
	for _, kind := range []string{"fresh", "case-change", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			s, reg, key, _ := storeFixture(t)
			v := eligibleFixture(t, s, reg, key)
			provider := &stubDecider{wait: make(chan struct{})}
			runner, err := NewRunner(s, configFixture("enforce-gated"), []byte(strings.Repeat("p", 32)), provider)
			if err != nil {
				t.Fatal(err)
			}
			defer runner.Close()
			j, err := runner.Enqueue("alpha", v.Case.ID, v.Case.SHA, "candidate")
			if err != nil {
				t.Fatal(err)
			}
			until := time.Now().Add(time.Second)
			for provider.calls.Load() == 0 && time.Now().Before(until) {
				time.Sleep(time.Millisecond)
			}
			if provider.calls.Load() != 1 {
				t.Fatal("not dispatched")
			}
			if kind == "case-change" {
				observeFixture(t, s, reg, key, "r3", "own", "alpha", "allow", time.Now())
			}
			if kind == "cancel" {
				s.Pause(true)
			}
			close(provider.wait)
			done := waitJob(t, runner, j.ID)
			if kind == "fresh" {
				ps := s.Policies("alpha")
				if done.Receipt == nil || len(ps) != 1 || ps[0].Scope.Tenant != "alpha" || ps[0].Claims[0].Owner != "decisions" {
					t.Fatal(done, ps)
				}
			} else if done.Receipt != nil || len(s.Policies("alpha")) != 0 || done.Status != "stale_result" {
				t.Fatal("stale result mutated", done)
			}
		})
	}
}
func TestDurableDailyReservationSurvivesRestartAndDuplicateEnqueue(t *testing.T) {
	s, reg, key, path := storeFixture(t)
	v := eligibleFixture(t, s, reg, key)
	provider := &stubDecider{}
	cfg := configFixture("advisory")
	cfg.DailyCalls = 1
	r, err := NewRunner(s, cfg, []byte(strings.Repeat("p", 32)), provider)
	if err != nil {
		t.Fatal(err)
	}
	j, err := r.Enqueue("alpha", v.Case.ID, v.Case.SHA, "one-call")
	if err != nil {
		t.Fatal(err)
	}
	waitJob(t, r, j.ID)
	again, err := r.Enqueue("alpha", v.Case.ID, v.Case.SHA, "one-call")
	if err != nil || again.ID != j.ID || provider.calls.Load() != 1 {
		t.Fatal("duplicate billed twice", again, err)
	}
	r.Close()
	s.Close()
	restored, err := Open(path, reg)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	second, err := NewRunner(restored, cfg, []byte(strings.Repeat("p", 32)), provider)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if _, err = second.Enqueue("alpha", v.Case.ID, v.Case.SHA, "over-budget"); err == nil {
		t.Fatal("restart reset budget")
	}
	if provider.calls.Load() != 1 {
		t.Fatal("paid calls replayed")
	}
}

type errorDecider struct{ calls atomic.Int32 }

func (d *errorDecider) Decide(ctx context.Context, i api.Input) api.Result {
	d.calls.Add(1)
	return api.Result{Schema: "decision-result/2", Status: "provider_error", InputSHA: decisions.Hash(i), Started: time.Now().UTC(), Completed: time.Now().UTC(), Model: api.Model, Origin: api.Endpoint}
}
func TestCircuitAndUnknownReservationAreNotResetByRestart(t *testing.T) {
	s, reg, key, path := storeFixture(t)
	v := eligibleFixture(t, s, reg, key)
	provider := &errorDecider{}
	cfg := configFixture("shadow")
	r, err := NewRunner(s, cfg, []byte(strings.Repeat("p", 32)), provider)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"failure-a", "failure-b", "failure-c"} {
		j, err := r.Enqueue("alpha", v.Case.ID, v.Case.SHA, id)
		if err != nil {
			t.Fatal(err)
		}
		waitJob(t, r, j.ID)
	}
	if _, err = r.Enqueue("alpha", v.Case.ID, v.Case.SHA, "circuit-open"); err == nil {
		t.Fatal("open circuit admitted API call")
	}
	r.Close()
	s.Close()
	restored, err := Open(path, reg)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	next, err := NewRunner(restored, cfg, []byte(strings.Repeat("p", 32)), provider)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	if _, err = next.Enqueue("alpha", v.Case.ID, v.Case.SHA, "after-restart"); err == nil {
		t.Fatal("restart cleared circuit")
	}
	if provider.calls.Load() != 3 {
		t.Fatal("failed calls replayed")
	}
}
