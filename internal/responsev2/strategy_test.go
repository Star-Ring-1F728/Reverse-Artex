package responsev2

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"reverse-artex/internal/decisions"
	api "reverse-artex/internal/decisions/openai"
	"strings"
	"testing"
	"time"
)

func strategyFixture(t *testing.T, s *Store, id string) DefenseStrategy {
	t.Helper()
	p, err := s.Strategy("alpha", id)
	if err != nil || p.SHA != strategySHA(p) {
		t.Fatal(p, err)
	}
	return p
}

func TestStrategyReprioritizesRepeatedAndNewResources(t *testing.T) {
	s, reg, key, _ := storeFixture(t)
	v := eligibleFixture(t, s, reg, key)
	for _, id := range []string{"repeat-1", "repeat-2"} {
		observeFixture(t, s, reg, key, id, "one", "alpha", "deny", time.Now())
	}
	v, _ = s.Case("alpha", v.Case.ID)
	p := strategyFixture(t, s, v.Case.ID)
	if p.Pattern != "multi_resource_denials" || p.Denied != 4 || p.Resources != 2 || p.RepeatedScopes != 1 || p.Next != "contain_exact" {
		t.Fatal(p)
	}
	var first Candidate
	for _, c := range v.Candidates {
		if c.ID == p.Candidates[0] {
			first = c
		}
	}
	if first.Scope.Resource != decisions.Hash("one") {
		t.Fatal("repetition did not change priority", p)
	}
	_, err := s.Apply(context.Background(), "alpha", Intent{ID: "first", CaseID: v.Case.ID, CaseSHA: v.Case.SHA, CandidateID: first.ID, Owner: "operator", Run: "first", Epoch: s.Epoch()})
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"new-1", "new-2", "new-3"} {
		observeFixture(t, s, reg, key, id, "three", "alpha", "deny", time.Now())
	}
	v, _ = s.Case("alpha", v.Case.ID)
	p2 := strategyFixture(t, s, v.Case.ID)
	if p2.SHA == p.SHA || p2.CaseSHA == p.CaseSHA || p2.ActiveScopes != 1 || len(p2.Feedback) != 1 || len(p2.Candidates) != 2 {
		t.Fatal(p2)
	}
	for _, c := range v.Candidates {
		if c.ID == p2.Candidates[0] && c.Scope.Resource != decisions.Hash("three") {
			t.Fatal("new repeated resource not prioritized", p2)
		}
		if c.Scope == first.Scope && strategyAllows(p2, c.ID) {
			t.Fatal("duplicate active containment offered")
		}
	}
}

func TestStrategyLearnsFromActualResponseAndRecovery(t *testing.T) {
	s, reg, key, path := storeFixture(t)
	v := eligibleFixture(t, s, reg, key)
	r, err := s.Apply(context.Background(), "alpha", intentFixture(s, v, "install", "operator", "run"))
	if err != nil {
		t.Fatal(err)
	}
	pending := responseFixture(t, s, reg, key, "pending", targetObject(v), "deny", false)
	p := strategyFixture(t, s, v.Case.ID)
	if p.Next != "verify_response" || len(p.Candidates) != 0 || p.Feedback[0].Target != "unknown" || p.Feedback[0].Unknown != 1 {
		t.Fatal(p)
	}
	if err = s.CompleteResponse(pending); err != nil {
		t.Fatal(err)
	}
	p2 := strategyFixture(t, s, v.Case.ID)
	if p2.Sequence <= p.Sequence || p2.CaseSHA != p.CaseSHA || p2.SHA == p.SHA || p2.Feedback[0].Effect != "masked_by_sdk" || p2.MaskedScopes != 1 {
		t.Fatal("response outcome did not revise strategy", p2)
	}
	policy := s.Policies("alpha")[0]
	if _, err = s.Release(context.Background(), "alpha", r.PolicyID, "operator", "run", "release", policy.Generation); err != nil {
		t.Fatal(err)
	}
	p = strategyFixture(t, s, v.Case.ID)
	if p.Next != "verify_recovery" || len(p.Candidates) != 0 {
		t.Fatal(p)
	}
	responseFixture(t, s, reg, key, "restored-target", targetObject(v), "deny", true)
	responseFixture(t, s, reg, key, "restored-normal", "own", "allow", true)
	p = strategyFixture(t, s, v.Case.ID)
	if p.Next != "contain_exact" || len(p.Candidates) != 1 || p.Feedback[0].Recovery != "observed_guard_baseline_restored" {
		t.Fatal(p)
	}
	current, _ := s.Case("alpha", v.Case.ID)
	for _, c := range current.Candidates {
		if c.Scope == policy.Scope && strategyAllows(p, c.ID) {
			t.Fatal("previously masked repetition caused redundant containment")
		}
	}
	// The unchanged signed history, including feedback, survives process restart.
	s.Close()
	reopened, err := Open(path, reg)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	again := strategyFixture(t, reopened, v.Case.ID)
	if decisions.Hash(p) != decisions.Hash(again) {
		t.Fatal("strategy lost on replay", p, again)
	}
	if _, err := reopened.Strategy("beta", v.Case.ID); err == nil {
		t.Fatal("cross tenant strategy leaked")
	}
	// Trust changes cannot carry the prior outcome into another authorization.
	current.Evidence = clone(current.Evidence)
	for i := range current.Evidence {
		current.Evidence[i].Scope.Authz = "new-authorization"
	}
	reopened.mu.Lock()
	newTrust := reopened.strategyLocked(current, time.Now())
	reopened.mu.Unlock()
	if len(newTrust.Feedback) != 0 || newTrust.MaskedScopes != 0 {
		t.Fatal("feedback crossed authorization revision", newTrust)
	}
}

func TestStrategyCollateralAndAmbiguousEvidenceStopEscalation(t *testing.T) {
	s, reg, key, _ := storeFixture(t)
	v := eligibleFixture(t, s, reg, key)
	// Signed allow and deny on one exact scope cannot justify containing it.
	observeFixture(t, s, reg, key, "allowed", targetObject(v), "alpha", "allow", time.Now())
	p := strategyFixture(t, s, v.Case.ID)
	current, _ := s.Case("alpha", v.Case.ID)
	if p.Pattern != "mixed_allowed_and_denied" || len(p.Candidates) != 1 {
		t.Fatal(p)
	}
	for _, c := range current.Candidates {
		if c.Scope == v.Candidates[0].Scope && strategyAllows(p, c.ID) {
			t.Fatal("ambiguous allow/deny scope eligible")
		}
	}
	// The operator may still use the existing explicit management contract.
	if _, err := s.Apply(context.Background(), "alpha", intentFixture(s, current, "install", "operator", "run")); err != nil {
		t.Fatal(err)
	}
	object := "one"
	if current.Candidates[0].Scope.Resource != decisions.Hash(object) {
		object = "two"
	}
	responseFixture(t, s, reg, key, "collateral", object, "allow", true)
	p = strategyFixture(t, s, v.Case.ID)
	if p.Next != "review_collateral" || len(p.Candidates) != 0 || !s.paused || p.Feedback[0].Benign != "observed_collateral" {
		t.Fatal(p)
	}
}

func TestStrategyWindowAndBoundedHistory(t *testing.T) {
	s, reg, key, _ := storeFixture(t)
	v := eligibleFixture(t, s, reg, key)
	s.mu.Lock()
	p := s.strategyLocked(v, time.Now().Add(61*time.Second))
	s.mu.Unlock()
	// Candidates in a supplied view must also pass the planner's own clock.
	if p.Denied != 0 || p.Historical != 2 || len(p.Candidates) != 0 {
		t.Fatal(p)
	}
	for _, object := range []string{"three", "four", "five"} {
		observeFixture(t, s, reg, key, object, object, "alpha", "deny", time.Now())
	}
	v, _ = s.Case("alpha", v.Case.ID)
	for i, c := range v.Candidates {
		run := strings.Repeat("x", i+1)
		_, err := s.Apply(context.Background(), "alpha", Intent{ID: run, CaseID: v.Case.ID, CaseSHA: v.Case.SHA, CandidateID: c.ID, Owner: "operator", Run: run, Epoch: s.Epoch()})
		if err != nil {
			t.Fatal(err)
		}
	}
	p = strategyFixture(t, s, v.Case.ID)
	if !p.FeedbackTruncated || len(p.Feedback) != 4 || p.Next != "review_history" || len(p.Candidates) != 0 {
		t.Fatal(p)
	}
}

func TestL3AdaptiveStrategyChangesActualOffersAndReplays(t *testing.T) {
	s, reg, key, path := storeFixture(t)
	v := eligibleFixture(t, s, reg, key)
	m := newMockL3(t)
	cfg := referenceConfig(m)
	cfg.AdaptiveStrategy = true
	engine, err := NewL3(s, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	check := func(id string, calls int, next string) L3Run {
		t.Helper()
		if _, err := engine.Enqueue(L3Request{ID: id, Tenant: "alpha", CaseID: v.Case.ID, CaseSHA: v.Case.SHA, Mode: "contain"}); err != nil {
			t.Fatal(err)
		}
		r := awaitL3(t, s, id)
		if r.Status != "completed" || r.Calls != calls || r.Strategy == nil || r.Strategy.Next != next {
			t.Fatal(r)
		}
		return r
	}
	one := check("adaptive-one", 2, "contain_exact")
	two := check("adaptive-two", 2, "contain_exact")
	three := check("adaptive-three", 1, "verify_existing_response")
	if one.Binding == nil || two.Binding == nil || one.Binding.Scope == two.Binding.Scope || three.Binding != nil || one.RevisedStrategy == nil || two.RevisedStrategy == nil || two.RevisedStrategy.Next != "verify_existing_response" {
		t.Fatal(one, two, three)
	}
	if len(s.Policies("alpha")) != 2 {
		t.Fatal("strategy added duplicate policies")
	}
	for _, l := range s.Policies("alpha") {
		if len(l.Claims) != 1 {
			t.Fatal("duplicate model claim", l)
		}
	}
	m.mu.Lock()
	messages := clone(m.modelMessages)
	m.mu.Unlock()
	for _, history := range messages {
		for _, message := range history {
			tool, raw, ok := mockL3Observation(message)
			if ok && tool == "get_defense_outcome" {
				var observation struct {
					Next map[string]any `json:"next_strategy"`
				}
				if err := json.Unmarshal([]byte(raw), &observation); err != nil {
					t.Fatal(err)
				}
				if observation.Next["priority_candidate_ids"] != nil || observation.Next["candidate_selection"] != "requires_new_bound_investigation" || observation.Next["priority_candidate_count"] == nil {
					t.Fatal("post-action advice introduced unbound selection references", raw)
				}
			}
			if !ok || tool != "get_investigation_context" {
				continue
			}
			var context struct {
				Strategy struct {
					Candidates []string `json:"priority_candidate_ids"`
				} `json:"strategy"`
			}
			if err := json.Unmarshal([]byte(raw), &context); err != nil {
				t.Fatal(err)
			}
			for _, id := range context.Strategy.Candidates {
				if !strings.HasPrefix(id, "c") || len(id) == 64 {
					t.Fatal("canonical ID leaked into short selection refs", id)
				}
			}
		}
	}
	engine.Close()
	s.Close()
	reopened, err := Open(path, reg)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	restored, err := reopened.L3Run("alpha", two.Request.ID)
	if err != nil || decisions.Hash(restored.Strategy) != decisions.Hash(two.Strategy) || decisions.Hash(restored.RevisedStrategy) != decisions.Hash(two.RevisedStrategy) {
		t.Fatal("strategy audit lost on replay", restored, err)
	}
}

func TestL3AdaptiveStrategyRechecksNewPolicyBeforeActing(t *testing.T) {
	s, reg, key, _ := storeFixture(t)
	v := eligibleFixture(t, s, reg, key)
	m := newMockL3(t)
	cfg := referenceConfig(m)
	cfg.AdaptiveStrategy = true
	m.before = func(n int) {
		if n != 1 {
			return
		}
		p := strategyFixture(t, s, v.Case.ID)
		_, err := s.Apply(context.Background(), "alpha", Intent{ID: "concurrent", CaseID: v.Case.ID, CaseSHA: v.Case.SHA, CandidateID: p.Candidates[0], Owner: "operator", Run: "human", Epoch: s.Epoch()})
		if err != nil {
			t.Error(err)
		}
	}
	engine, err := NewL3(s, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	if _, err = engine.Enqueue(L3Request{ID: "race", Tenant: "alpha", CaseID: v.Case.ID, CaseSHA: v.Case.SHA, Mode: "contain"}); err != nil {
		t.Fatal(err)
	}
	r := awaitL3(t, s, "race")
	if r.Status == "completed" || r.Binding != nil {
		t.Fatal("stale strategy acted", r)
	}
	policies := s.Policies("alpha")
	if len(policies) != 1 || len(policies[0].Claims) != 1 || policies[0].Claims[0].Owner != "operator" {
		t.Fatal(policies)
	}
}

func TestStrategyHTTPAndConfiguration(t *testing.T) {
	s, reg, key, _ := storeFixture(t)
	v := eligibleFixture(t, s, reg, key)
	m := newMockL3(t)
	cfg := l3Cfg(m)
	cfg.AdaptiveStrategy = true
	if cfg.Validate() == nil {
		t.Fatal("adaptive strategy without prefetch accepted")
	}
	cfg.BundleContext = true
	if cfg.Validate() == nil {
		t.Fatal("adaptive strategy without prefetch accepted")
	}
	cfg.Prefetch = true
	if cfg.Validate() != nil {
		t.Fatal("valid adaptive configuration rejected")
	}
	runner, _ := NewRunner(s, api.Config{Mode: "off"}, []byte(strings.Repeat("s", 32)), nil)
	defer runner.Close()
	reader := strings.Repeat("r", 32)
	h := Handler(s, runner, reader, strings.Repeat("o", 32))
	for _, tc := range []struct {
		tenant, token, origin string
		status                int
	}{{"alpha", reader, "", 200}, {"beta", reader, "", 404}, {"alpha", "bad", "", 401}, {"alpha", reader, "http://foreign.example", 403}} {
		q := httptest.NewRequest("GET", "http://127.0.0.1:9999/v2/strategy?tenant="+tc.tenant+"&id="+v.Case.ID, nil)
		q.Header.Set("Authorization", "Bearer "+tc.token)
		q.Header.Set("Origin", tc.origin)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, q)
		if w.Code != tc.status {
			t.Fatal(w.Code, tc.status, w.Body.String())
		}
		if tc.status == 200 && (strings.Contains(w.Body.String(), v.Evidence[0].Proof) || strings.Contains(w.Body.String(), "principal\"")) {
			t.Fatal("raw proof/identity leaked")
		}
	}
	if len(s.Policies("alpha")) != 0 || m.calls.Load() != 0 {
		t.Fatal("read-only strategy triggered model or action")
	}
}

func TestStrategySnapshotRejectsTampering(t *testing.T) {
	s, reg, key, _ := storeFixture(t)
	v := eligibleFixture(t, s, reg, key)
	m := newMockL3(t)
	cfg := referenceConfig(m)
	cfg.AdaptiveStrategy = true
	q := L3Request{ID: "immutable", Tenant: "alpha", CaseID: v.Case.ID, CaseSHA: v.Case.SHA, Mode: "analyze"}
	if _, err := s.l3Start(q, cfg); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	baseline := clone(s.l3Runs[q.ID])
	baselineErr := s.validateExtension(record{Sequence: s.sequence + 1, L3: &baseline})
	s.mu.Unlock()
	if baselineErr != nil {
		t.Fatal("valid strategy rejected", baselineErr)
	}
	for _, mutate := range []func(*L3Run){
		func(r *L3Run) { r.Strategy.Next = "arbitrary_action" },
		func(r *L3Run) { r.Strategy = nil },
		func(r *L3Run) { r.Strategy.Sequence++; r.Strategy.SHA = strategySHA(*r.Strategy) },
		func(r *L3Run) { p := *r.Strategy; p.Tenant = "beta"; p.SHA = strategySHA(p); r.RevisedStrategy = &p },
		func(r *L3Run) { p := *r.Strategy; p.Epoch++; p.SHA = strategySHA(p); r.RevisedStrategy = &p },
		func(r *L3Run) {
			p := *r.Strategy
			p.Sequence = s.sequence + 1
			p.SHA = strategySHA(p)
			r.RevisedStrategy = &p
		},
	} {
		// Validate a detached record directly; a rejected durable write correctly
		// poisons the writer and is tested elsewhere in the journal suite.
		s.mu.Lock()
		run := clone(s.l3Runs[q.ID])
		mutate(&run)
		err := s.validateExtension(record{Sequence: s.sequence + 1, L3: &run})
		s.mu.Unlock()
		if err == nil {
			t.Fatal("tampered strategy accepted", run)
		}
	}
}
