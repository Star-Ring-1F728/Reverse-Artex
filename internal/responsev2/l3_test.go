package responsev2

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reverse-artex/internal/decisions"
	"reverse-artex/internal/localassistant"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type mockCandidateLink struct {
	CandidateID string `json:"candidate_id"`
	EvidenceID  string `json:"evidence_id"`
	ScopeID     string `json:"scope_id"`
}

type mockCandidateContext struct {
	Tool        string
	Raw         string
	Links       []mockCandidateLink
	ExactFields bool
}

type mockCandidateOffer struct {
	Context mockCandidateContext
	IDs     []string
}

type mockL3 struct {
	server            *httptest.Server
	calls             atomic.Int32
	before            func(int)
	invalid           string
	rewriteArgs       func(string, json.RawMessage) json.RawMessage
	remote            bool
	mu                sync.Mutex
	candidateContexts []mockCandidateContext
	candidateOffers   []mockCandidateOffer
	modelMessages     [][]localassistant.Message
}

func mockL3Observation(message localassistant.Message) (string, string, bool) {
	if message.Role == "tool" {
		return message.ToolName, message.Content, true
	}
	if message.Role == "user" && strings.HasPrefix(message.Content, l3HostObservationPrefix) {
		var envelope struct {
			Tool        string          `json:"tool"`
			Observation json.RawMessage `json:"observation"`
		}
		if json.Unmarshal([]byte(strings.TrimPrefix(message.Content, l3HostObservationPrefix)), &envelope) == nil {
			return envelope.Tool, string(envelope.Observation), true
		}
	}
	return "", "", false
}

func (m *mockL3) captureCandidateContext(messages []localassistant.Message, tools []localassistant.ToolDefinition) {
	contexts := []mockCandidateContext{}
	for _, message := range messages {
		tool, raw, ok := mockL3Observation(message)
		if !ok || (tool != "get_case" && tool != "get_investigation_context") {
			continue
		}
		var envelope map[string]json.RawMessage
		if json.Unmarshal([]byte(raw), &envelope) != nil || envelope["candidates"] == nil {
			continue
		}
		var rawRows []map[string]json.RawMessage
		if json.Unmarshal(envelope["candidates"], &rawRows) != nil {
			contexts = append(contexts, mockCandidateContext{Tool: tool, Raw: raw})
			continue
		}
		context := mockCandidateContext{Tool: tool, Raw: raw, ExactFields: true}
		for _, row := range rawRows {
			if len(row) != 3 || row["candidate_id"] == nil || row["evidence_id"] == nil || row["scope_id"] == nil {
				context.ExactFields = false
			}
			var link mockCandidateLink
			if json.Unmarshal(mustJSON(row), &link) != nil {
				context.ExactFields = false
			}
			context.Links = append(context.Links, link)
		}
		contexts = append(contexts, context)
	}

	offers := []mockCandidateOffer{}
	for _, tool := range tools {
		if tool.Function.Name != "apply_containment" {
			continue
		}
		properties, _ := tool.Function.Parameters["properties"].(map[string]any)
		candidate, _ := properties["candidate_id"].(map[string]any)
		enum, _ := candidate["enum"].([]any)
		ids := make([]string, 0, len(enum))
		for _, item := range enum {
			if id, ok := item.(string); ok {
				ids = append(ids, id)
			}
		}
		if len(contexts) > 0 {
			offers = append(offers, mockCandidateOffer{Context: contexts[len(contexts)-1], IDs: ids})
		}
	}
	m.mu.Lock()
	m.modelMessages = append(m.modelMessages, append([]localassistant.Message(nil), messages...))
	m.candidateContexts = append(m.candidateContexts, contexts...)
	m.candidateOffers = append(m.candidateOffers, offers...)
	m.mu.Unlock()
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

func (m *mockL3) candidateSnapshot() ([]mockCandidateContext, []mockCandidateOffer) {
	m.mu.Lock()
	defer m.mu.Unlock()
	contexts := append([]mockCandidateContext(nil), m.candidateContexts...)
	offers := append([]mockCandidateOffer(nil), m.candidateOffers...)
	return contexts, offers
}

func newMockL3(t *testing.T) *mockL3 {
	t.Helper()
	m := &mockL3{}
	m.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Error("credential sent to model")
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/tags":
			json.NewEncoder(w).Encode(map[string]any{"models": []localassistant.Model{{Name: "qwen-local:fixture", Digest: decisions.Hash("pinned")}}})
		case "/api/show":
			if m.remote {
				json.NewEncoder(w).Encode(map[string]any{"capabilities": []string{"tools"}, "remote_host": "cloud"})
			} else {
				json.NewEncoder(w).Encode(map[string]any{"capabilities": []string{"tools"}})
			}
		case "/api/chat":
			var q struct {
				Tools    []localassistant.ToolDefinition `json:"tools"`
				Messages []localassistant.Message        `json:"messages"`
				Model    string                          `json:"model"`
				Stream   bool                            `json:"stream"`
				Think    bool                            `json:"think"`
				Keep     string                          `json:"keep_alive"`
				Options  map[string]any                  `json:"options"`
			}
			if json.NewDecoder(r.Body).Decode(&q) != nil || len(q.Tools) == 0 {
				t.Error("bad request")
				w.WriteHeader(400)
				return
			}
			m.captureCandidateContext(q.Messages, q.Tools)
			n := int(m.calls.Add(1))
			if m.before != nil {
				m.before(n)
			}
			name := q.Tools[0].Function.Name
			args := map[string]any{}
			for _, tool := range q.Tools {
				if tool.Function.Name == "apply_containment" {
					name = tool.Function.Name
					props := tool.Function.Parameters["properties"].(map[string]any)
					ids := props["candidate_id"].(map[string]any)["enum"].([]any)
					args["candidate_id"] = ids[0]
				}
			}
			if name == "finish_assessment" {
				ids := []string{}
				for _, message := range q.Messages {
					tool, raw, ok := mockL3Observation(message)
					if ok && (tool == "get_evidence" || tool == "get_investigation_context") {
						var out struct {
							Facts []struct {
								ID string `json:"evidence_id"`
							} `json:"facts"`
						}
						json.Unmarshal([]byte(raw), &out)
						for _, f := range out.Facts {
							ids = append(ids, f.ID)
						}
					}
				}
				args = map[string]any{"classification": "needs_review", "summary": "Mock assessment; actual effect remains the recorded outcome.", "evidence_ids": ids}
			}
			if m.invalid == "tool" {
				name = "execute_shell"
			}
			if m.invalid == "candidate" && name == "apply_containment" {
				args["candidate_id"] = "forged-scope"
			}
			if m.invalid == "refs" && name == "finish_assessment" {
				args["evidence_ids"] = []string{"forged"}
			}
			if m.invalid == "context-args" && name == "get_investigation_context" {
				args = map[string]any{"tenant": "beta"}
			}
			raw, _ := json.Marshal(args)
			if m.rewriteArgs != nil {
				raw = m.rewriteArgs(name, raw)
			}
			call := localassistant.ToolCall{}
			call.Function.Name = name
			call.Function.Arguments = raw
			json.NewEncoder(w).Encode(map[string]any{"done": true, "message": map[string]any{"tool_calls": []localassistant.ToolCall{call}}})
		default:
			t.Error("unexpected model path", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(m.server.Close)
	return m
}
func l3Cfg(m *mockL3) L3Config {
	return L3Config{Enabled: true, Origin: m.server.URL, Model: "qwen-local:fixture", Digest: decisions.Hash("pinned"), AllowContain: true, DailyRuns: 32}
}
func awaitL3(t *testing.T, s *Store, id string) L3Run {
	t.Helper()
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		run, err := s.L3Run("alpha", id)
		if err == nil && run.Status != "reserved" && run.Status != "running" {
			return run
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("mock L3 deadline")
	return L3Run{}
}

func assertCandidateContext(t *testing.T, got mockCandidateContext, view CaseView) {
	t.Helper()
	if !got.ExactFields {
		t.Fatalf("candidate link must contain exactly candidate_id, evidence_id and scope_id: %+v", got)
	}
	facts := map[string]bool{}
	for _, fact := range view.Evidence {
		facts[fact.ID] = true
		for _, forbidden := range []string{fact.Proof, fact.Binding.Principal, fact.Binding.Session, `{"error":"forbidden"}`} {
			if forbidden != "" && strings.Contains(got.Raw, forbidden) {
				t.Fatalf("candidate context exposed raw proof, identity, session or body")
			}
		}
	}
	want := make(map[string]mockCandidateLink, len(view.Candidates))
	for _, candidate := range view.Candidates {
		if !facts[candidate.EvidenceID] {
			t.Fatalf("fixture candidate has no signed fact: %+v", candidate)
		}
		want[candidate.ID] = mockCandidateLink{CandidateID: candidate.ID, EvidenceID: candidate.EvidenceID, ScopeID: scopeID(candidate.Scope)}
	}
	if len(got.Links) != len(want) {
		t.Fatalf("candidate links=%d want=%d", len(got.Links), len(want))
	}
	for _, link := range got.Links {
		expected, ok := want[link.CandidateID]
		if !ok || link != expected {
			t.Fatalf("candidate link is not bound to its signed fact and exact scope: got=%+v want=%+v", link, expected)
		}
		delete(want, link.CandidateID)
	}
	if len(want) != 0 {
		t.Fatalf("candidate links omitted %d offered candidates", len(want))
	}
}

func assertCandidateLinks(t *testing.T, m *mockL3, sourceTool string, view CaseView, requireOffered bool) {
	t.Helper()
	contexts, offers := m.candidateSnapshot()
	found := false
	for _, got := range contexts {
		if got.Tool == sourceTool {
			assertCandidateContext(t, got, view)
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("mock model request did not receive %s candidate links", sourceTool)
	}
	if !requireOffered {
		return
	}
	want := make(map[string]bool, len(view.Candidates))
	for _, candidate := range view.Candidates {
		want[candidate.ID] = true
	}
	for _, offer := range offers {
		if offer.Context.Tool != sourceTool {
			continue
		}
		assertCandidateContext(t, offer.Context, view)
		if len(offer.IDs) != len(want) {
			t.Fatalf("offered candidate IDs=%d mapped candidates=%d", len(offer.IDs), len(want))
		}
		seen := make(map[string]bool, len(offer.IDs))
		for _, id := range offer.IDs {
			if !want[id] || seen[id] {
				t.Fatalf("unmapped or repeated candidate was offered: %q", id)
			}
			seen[id] = true
		}
		return
	}
	t.Fatalf("mock model was not offered apply_containment after %s", sourceTool)
}

func TestL3PinnedLocalContainAndOwnedReleaseWorkflow(t *testing.T) {
	s, reg, key, _ := storeFixture(t)
	v := eligibleFixture(t, s, reg, key)
	m := newMockL3(t)
	engine, err := NewL3(s, l3Cfg(m), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	request := L3Request{ID: "run1", Tenant: "alpha", CaseID: v.Case.ID, CaseSHA: v.Case.SHA, Mode: "contain"}
	if _, err = engine.Enqueue(request); err != nil {
		t.Fatal(err)
	}
	run := awaitL3(t, s, "run1")
	if run.Status != "completed" || run.Calls != 6 || len(run.Steps) != 6 || run.Binding == nil || run.Assessment == nil || run.Steps[4].Tool != "get_defense_outcome" {
		t.Fatal(run)
	}
	assertCandidateLinks(t, m, "get_case", v, true)
	policies := s.Policies("alpha")
	if len(policies) != 1 || policies[0].Claims[0].Owner != "l3" || policies[0].Claims[0].Run != "run1" {
		t.Fatal(policies)
	}
	for i := 0; i < 10; i++ {
		if _, err = engine.Enqueue(request); err != nil {
			t.Fatal(err)
		}
	}
	if m.calls.Load() != 6 {
		t.Fatal("stable run redispatched")
	}
	// A different owner joins. L3 release must retain it.
	joined, err := s.Apply(context.Background(), "alpha", Intent{ID: "operator", CaseID: v.Case.ID, CaseSHA: v.Case.SHA, CandidateID: run.ActionCandidate, Owner: "operator", Run: "human", Epoch: s.Epoch()})
	if err != nil {
		t.Fatal(err)
	}
	_ = joined
	_, err = engine.Enqueue(L3Request{ID: "release1", Tenant: "alpha", CaseID: v.Case.ID, CaseSHA: v.Case.SHA, Mode: "release", SourceRun: "run1"})
	if err != nil {
		t.Fatal(err)
	}
	release := awaitL3(t, s, "release1")
	if release.Status != "completed" || release.Calls != 6 {
		t.Fatal(release)
	}
	policies = s.Policies("alpha")
	if len(policies) != 1 || len(policies[0].Claims) != 1 || policies[0].Claims[0].Owner != "operator" {
		t.Fatal("other owner removed", policies)
	}
	o, _ := s.Outcome("alpha", run.Binding.PolicyID, run.Binding.Episode)
	if o.Release.State != "retained_by_other_owner" || o.Recovery.State != "retained_by_other_owner" {
		t.Fatal(o)
	}
}

func TestL3BundledContextAnalyzeContainReleaseAndCoOwner(t *testing.T) {
	s, reg, key, _ := storeFixture(t)
	v := eligibleFixture(t, s, reg, key)
	m := newMockL3(t)
	cfg := l3Cfg(m)
	cfg.BundleContext = true
	engine, err := NewL3(s, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()

	assertFacts := func(run L3Run) {
		t.Helper()
		if run.Assessment == nil || len(run.Assessment.Evidence) != len(v.Evidence) {
			t.Fatalf("assessment did not retain bundled fact refs: %+v", run.Assessment)
		}
		want := map[string]bool{}
		for _, fact := range v.Evidence {
			want[fact.ID] = true
		}
		for _, id := range run.Assessment.Evidence {
			if !want[id] {
				t.Fatalf("assessment used a non-root fact ref %q", id)
			}
		}
	}
	checkRun := func(id, mode, source string, calls int) L3Run {
		t.Helper()
		request := L3Request{ID: id, Tenant: "alpha", CaseID: v.Case.ID, CaseSHA: v.Case.SHA, Mode: mode, SourceRun: source}
		if _, err := engine.Enqueue(request); err != nil {
			t.Fatal(err)
		}
		run := awaitL3(t, s, id)
		if run.Status != "completed" || run.Calls != calls || len(run.Steps) != calls || run.Steps[0].Tool != "get_investigation_context" || run.Steps[len(run.Steps)-1].Tool != "finish_assessment" {
			t.Fatalf("unexpected bundled %s run: %+v", mode, run)
		}
		assertFacts(run)
		return run
	}

	analyze := checkRun("analyze", "analyze", "", 2)
	if analyze.Steps[0].Tool != "get_investigation_context" {
		t.Fatal(analyze.Steps)
	}
	contained := checkRun("contain", "contain", "", 4)
	if contained.Steps[1].Tool != "apply_containment" || contained.Steps[2].Tool != "get_defense_outcome" || contained.Binding == nil {
		t.Fatal(contained.Steps, contained.Binding)
	}
	assertCandidateLinks(t, m, "get_investigation_context", v, true)
	joined, err := s.Apply(context.Background(), "alpha", Intent{ID: "operator", CaseID: v.Case.ID, CaseSHA: v.Case.SHA, CandidateID: contained.ActionCandidate, Owner: "operator", Run: "human", Epoch: s.Epoch()})
	if err != nil || joined.PolicyID != contained.Binding.PolicyID {
		t.Fatal("co-owner did not join the L3 claim", joined, err)
	}
	released := checkRun("release", "release", "contain", 4)
	if released.Steps[1].Tool != "release_owned_claim" || released.Steps[2].Tool != "get_defense_outcome" {
		t.Fatal(released.Steps)
	}
	policies := s.Policies("alpha")
	if len(policies) != 1 || len(policies[0].Claims) != 1 || policies[0].Claims[0].Owner != "operator" {
		t.Fatal("bundled release removed the co-owner", policies)
	}
	outcome, err := s.Outcome("alpha", contained.Binding.PolicyID, contained.Binding.Episode)
	if err != nil || outcome.Release.State != "retained_by_other_owner" || outcome.Recovery.State != "retained_by_other_owner" {
		t.Fatal("bundled co-owner release was not retained", outcome, err)
	}
	if m.calls.Load() != 10 {
		t.Fatal("unexpected model call count", m.calls.Load())
	}
}

func TestL3DisabledAnalyzeAndUntrustedToolsCannotContain(t *testing.T) {
	for _, kind := range []string{"disabled", "analyze", "tool", "candidate", "refs", "remote", "digest", "bundled-context-args", "bundled-candidate", "bundled-refs"} {
		t.Run(kind, func(t *testing.T) {
			s, reg, key, _ := storeFixture(t)
			v := eligibleFixture(t, s, reg, key)
			m := newMockL3(t)
			cfg := l3Cfg(m)
			mode := "contain"
			if kind == "disabled" {
				cfg.Enabled = false
			}
			if kind == "analyze" {
				mode = "analyze"
			}
			if kind == "remote" {
				m.remote = true
			}
			if kind == "digest" {
				cfg.Digest = decisions.Hash("changed")
			}
			m.invalid = kind
			if strings.HasPrefix(kind, "bundled-") {
				cfg.BundleContext = true
				m.invalid = strings.TrimPrefix(kind, "bundled-")
			}
			engine, err := NewL3(s, cfg, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer engine.Close()
			result, err := engine.Enqueue(L3Request{ID: "test", Tenant: "alpha", CaseID: v.Case.ID, CaseSHA: v.Case.SHA, Mode: mode})
			if err != nil {
				t.Fatal(err)
			}
			if kind == "disabled" {
				if result.Status != "off" || m.calls.Load() != 0 {
					t.Fatal(result)
				}
				return
			}
			run := awaitL3(t, s, "test")
			if kind == "analyze" {
				if run.Status != "completed" || run.Calls != 4 {
					t.Fatal(run)
				}
			} else if run.Status == "completed" {
				t.Fatal("unsafe run completed", run)
			}
			if kind != "refs" && kind != "bundled-refs" && len(s.Policies("alpha")) != 0 {
				t.Fatal("unexpected containment")
			}
			if (kind == "digest" || kind == "remote") && m.calls.Load() != 0 {
				t.Fatal("inference after model rejection")
			}
		})
	}
}
func TestL3CurrentCaseCancelEpochAndDirectRecovery(t *testing.T) {
	for _, kind := range []string{"case", "epoch", "cancel", "fallback", "bundled-case", "bundled-epoch", "bundled-cancel"} {
		t.Run(kind, func(t *testing.T) {
			s, reg, key, _ := storeFixture(t)
			v := eligibleFixture(t, s, reg, key)
			m := newMockL3(t)
			var engine *L3Engine
			baseKind := strings.TrimPrefix(kind, "bundled-")
			bundled := baseKind != kind
			if baseKind != "fallback" {
				actionCall := 4
				if bundled {
					actionCall = 2
				}
				m.before = func(n int) {
					if n == actionCall {
						switch baseKind {
						case "case":
							observeFixture(t, s, reg, key, "later", "three", "alpha", "allow", time.Now())
						case "epoch":
							s.Pause(true)
						case "cancel":
							engine.Cancel("alpha", "run")
						}
					}
				}
			}
			cfg := l3Cfg(m)
			cfg.BundleContext = bundled
			engine, _ = NewL3(s, cfg, nil)
			defer engine.Close()
			engine.Enqueue(L3Request{ID: "run", Tenant: "alpha", CaseID: v.Case.ID, CaseSHA: v.Case.SHA, Mode: "contain"})
			run := awaitL3(t, s, "run")
			if baseKind != "fallback" {
				if len(s.Policies("alpha")) != 0 || run.Status == "completed" {
					t.Fatal(run)
				}
				return
			}
			engine.Close() // Direct recovery remains available with no inference engine.
			if run.Binding == nil {
				t.Fatal(run)
			}
			p := s.Policies("alpha")[0]
			if _, err := s.ReleaseL3(context.Background(), "alpha", "run", "wrong", "bad", s.Epoch(), p.Generation); err == nil {
				t.Fatal("stale case released")
			}
			receipt, err := s.ReleaseL3(context.Background(), "alpha", "run", v.Case.SHA, "manual", s.Epoch(), p.Generation)
			if err != nil || receipt.State != "no_effective_policy" {
				t.Fatal(receipt, err)
			}
			if m.calls.Load() != 6 {
				t.Fatal("recovery invoked model")
			}
		})
	}
}

func TestL3BundledContextFallsBackAboveBudgetWithoutDroppingPolicies(t *testing.T) {
	t.Run("bundled", func(t *testing.T) { testL3LargeContext(t, false) })
	t.Run("prefetched", func(t *testing.T) { testL3LargeContext(t, true) })
}

func testL3LargeContext(t *testing.T, prefetch bool) {
	s, reg, key, _ := storeFixture(t)
	at := time.Now().Add(-100 * time.Millisecond)
	caseRef := ""
	for n := 0; n < 32; n++ {
		id := fmt.Sprintf("dense-%02d", n)
		object := fmt.Sprintf("object-%02d", n)
		raw, binding, status, body := proofFixture(reg, key, id, object, "alpha", "deny", at)
		observed, err := s.Observe(raw, binding, status, body, at)
		if err != nil {
			t.Fatal("observe dense signed fact", n, err)
		}
		if n == 0 {
			caseRef = observed.CaseID
		}
	}
	view, err := s.Case("alpha", caseRef)
	if err != nil || len(view.Evidence) != 32 || len(view.Candidates) != 32 {
		t.Fatalf("expected 32 signed facts and exact candidates: evidence=%d candidates=%d err=%v", len(view.Evidence), len(view.Candidates), err)
	}
	for n, candidate := range view.Candidates {
		intent := Intent{ID: fmt.Sprintf("dense-policy-%02d", n), CaseID: view.Case.ID, CaseSHA: view.Case.SHA,
			CandidateID: candidate.ID, Owner: "operator", Run: fmt.Sprintf("dense-owner-%02d", n), Epoch: s.Epoch()}
		if _, err := s.Apply(context.Background(), "alpha", intent); err != nil {
			t.Fatal("install exact policy", n, err)
		}
	}
	policiesBefore := s.Policies("alpha")
	if len(policiesBefore) != 32 {
		t.Fatalf("active policy count=%d want=32", len(policiesBefore))
	}
	factScopes := make(map[string]bool, len(view.Evidence))
	for _, fact := range view.Evidence {
		factScopes[scopeID(fact.Scope)] = true
	}
	claimCount := 0
	for _, policy := range policiesBefore {
		claimCount += len(policy.Claims)
		if !factScopes[scopeID(policy.Scope)] || len(policy.Claims) != 1 || !time.Now().Before(policy.Expires) {
			t.Fatalf("fixture policy is not an active exact-scope claim: %+v", policy)
		}
	}
	if claimCount != 32 {
		t.Fatalf("active policy claim count=%d want=32", claimCount)
	}

	// Probe the same production size check with a valid in-flight run. The
	// unjournaled probe is removed before the real engine starts.
	s.mu.Lock()
	s.l3Runs["size-probe"] = L3Run{Request: L3Request{ID: "size-probe", Tenant: "alpha", CaseID: view.Case.ID, CaseSHA: view.Case.SHA}, Epoch: s.epoch, Status: "running", Deadline: time.Now().Add(time.Minute)}
	s.mu.Unlock()
	_, contextErr := s.l3Context("size-probe", view)
	s.mu.Lock()
	delete(s.l3Runs, "size-probe")
	s.mu.Unlock()
	if !errors.Is(contextErr, ErrLimit) {
		t.Fatalf("32 facts and 32 active exact policies should exceed bundled-context budget: %v", contextErr)
	}

	m := newMockL3(t)
	cfg := l3Cfg(m)
	cfg.BundleContext = true
	cfg.Prefetch = prefetch
	engine, err := NewL3(s, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	if _, err := engine.Enqueue(L3Request{ID: "dense-analyze", Tenant: "alpha", CaseID: view.Case.ID, CaseSHA: view.Case.SHA, Mode: "analyze"}); err != nil {
		t.Fatal(err)
	}
	run := awaitL3(t, s, "dense-analyze")
	wantTools := []string{"get_case", "get_evidence", "get_response", "finish_assessment"}
	if run.Status != "completed" || run.Calls != len(wantTools) || len(run.Steps) != len(wantTools) {
		t.Fatalf("oversized bundle did not fall back to individual reads: %+v", run)
	}
	for n, want := range wantTools {
		if run.Steps[n].Tool != want {
			t.Fatalf("fallback step %d tool=%q want=%q", n, run.Steps[n].Tool, want)
		}
	}
	if run.Assessment == nil || len(run.Assessment.Evidence) != 32 {
		t.Fatalf("fallback assessment lost signed evidence refs: %+v", run.Assessment)
	}
	assertCandidateLinks(t, m, "get_case", view, false)
	claims := func(policies []Lease) map[string][]Claim {
		out := make(map[string][]Claim, len(policies))
		for _, policy := range policies {
			out[policy.ID] = append([]Claim(nil), policy.Claims...)
		}
		return out
	}
	policiesAfter := s.Policies("alpha")
	if len(policiesAfter) != 32 || decisions.Hash(claims(policiesBefore)) != decisions.Hash(claims(policiesAfter)) {
		t.Fatal("fallback analysis changed or dropped policy claims")
	}
}
func TestL3RestartReconcilesDurableActionWithoutReplayingModel(t *testing.T) {
	s, reg, key, path := storeFixture(t)
	v := eligibleFixture(t, s, reg, key)
	m := newMockL3(t)
	cfg := l3Cfg(m)
	// Simulate process loss immediately after action commit, before the tool result.
	run, err := s.l3Start(L3Request{ID: "crashed", Tenant: "alpha", CaseID: v.Case.ID, CaseSHA: v.Case.SHA, Mode: "contain"}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	err = s.l3Update(run.Request.ID, func(r *L3Run) {
		r.Status = "running"
		r.ActionIntent = "durable"
		r.ActionCandidate = v.Candidates[0].ID
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.l3Apply(context.Background(), "crashed", v.Candidates[0].ID); err != nil {
		t.Fatal(err)
	}
	s.Close()
	reopened, err := Open(path, reg)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	engine, err := NewL3(reopened, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	got, err := engine.Enqueue(run.Request)
	if err != nil || got.Status != "interrupted_unknown" || got.Binding == nil || got.Receipt == nil || m.calls.Load() != 0 {
		t.Fatal(got, err)
	}
	if !strings.Contains(got.Error, "not replayed") {
		t.Fatal(got)
	}
}
func TestL3RejectsUnsafeConfiguration(t *testing.T) {
	for _, origin := range []string{"https://127.0.0.1:1", "http://localhost:1", "http://192.0.2.1:1", "http://127.0.0.1:1/path", "http://user@127.0.0.1:1"} {
		c := L3Config{Enabled: true, Origin: origin, Model: "qwen", Digest: decisions.Hash("pin"), DailyRuns: 1}
		if c.Validate() == nil {
			t.Fatal(origin)
		}
	}
}
