package responsev2

import (
	"context"
	"encoding/json"
	"fmt"
	"reverse-artex/internal/decisions"
	"strings"
	"testing"
	"time"
)

func referenceConfig(m *mockL3) L3Config {
	cfg := l3Cfg(m)
	cfg.BundleContext, cfg.Prefetch, cfg.ShortReferences = true, true, true
	return cfg
}

func TestL3ShortReferencesResolveCanonicalSourcesAndReplayOwnedRelease(t *testing.T) {
	s, reg, key, path := storeFixture(t)
	v := eligibleFixture(t, s, reg, key)
	m := newMockL3(t)
	cfg := referenceConfig(m)
	engine, err := NewL3(s, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	check := func(id, mode, source string) L3Run {
		t.Helper()
		_, err := engine.Enqueue(L3Request{ID: id, Tenant: "alpha", CaseID: v.Case.ID, CaseSHA: v.Case.SHA, Mode: mode, SourceRun: source})
		if err != nil {
			t.Fatal(err)
		}
		run := awaitL3(t, s, id)
		if run.Status != "completed" || run.ReferenceScheme != l3ReferenceScheme || run.Assessment == nil || run.Deadline.Sub(run.Started) != 30*time.Second {
			t.Fatal("reference workflow changed native completion/deadline", run)
		}
		want := map[string]bool{}
		for _, evidence := range v.Evidence {
			want[evidence.ID] = true
		}
		for _, id := range run.Assessment.Evidence {
			if !want[id] || !decisions.ValidHash(id) {
				t.Fatal("assessment stored a display label or fabricated source", run.Assessment)
			}
		}
		if len(run.Assessment.Evidence) != len(want) {
			t.Fatal("canonical evidence was lost")
		}
		return run
	}
	check("short-analysis", "analyze", "")
	contained := check("short-contain", "contain", "")
	if contained.Binding == nil || !decisions.ValidHash(contained.ActionCandidate) {
		t.Fatal("policy did not use canonical exact candidate", contained)
	}
	joined, err := s.Apply(context.Background(), "alpha", Intent{ID: "short-coowner", CaseID: v.Case.ID, CaseSHA: v.Case.SHA, CandidateID: contained.ActionCandidate, Owner: "operator", Run: "human", Epoch: s.Epoch()})
	if err != nil || joined.PolicyID != contained.Binding.PolicyID {
		t.Fatal(joined, err)
	}
	released := check("short-release", "release", "short-contain")
	if released.Receipt == nil || released.Receipt.State != "retained_by_other_owner" {
		t.Fatal("short labels changed claim ownership", released)
	}
	policies := s.Policies("alpha")
	if len(policies) != 1 || len(policies[0].Claims) != 1 || policies[0].Claims[0].Owner != "operator" || m.calls.Load() != 5 {
		t.Fatal("unexpected ownership/model accounting", policies, m.calls.Load())
	}
	// The actual model-selected bytes remain short and their original hash is
	// recorded. Only the trusted assessment/policy projection uses full IDs.
	m.mu.Lock()
	histories := m.modelMessages
	m.mu.Unlock()
	matched := false
	var host struct {
		Observation json.RawMessage `json:"observation"`
	}
	if len(histories) < 3 || json.Unmarshal([]byte(strings.TrimPrefix(histories[1][2].Content, l3HostObservationPrefix)), &host) != nil || decisions.Hash(host.Observation) != contained.Steps[0].ResultSHA {
		t.Fatal("prefetched result digest does not describe the actual alias context")
	}
	for _, history := range histories {
		for _, message := range history {
			for _, call := range message.Calls {
				if call.Function.Name != "apply_containment" {
					continue
				}
				var args struct {
					Candidate string `json:"candidate_id"`
				}
				if json.Unmarshal(call.Function.Arguments, &args) != nil || !strings.HasPrefix(args.Candidate, "c") || len(args.Candidate) > 12 || args.Candidate == contained.ActionCandidate {
					t.Fatal("model still copied a full hash or lost original args", string(call.Function.Arguments))
				}
				if contained.Steps[1].ArgsSHA != decisions.Hash(json.RawMessage(call.Function.Arguments)) {
					t.Fatal("original model argument hash was replaced by resolved IDs")
				}
				matched = true
			}
		}
	}
	if !matched {
		t.Fatal("actual selected short candidate was not observed")
	}
	engine.Close()
	s.Close()
	reopened, err := Open(path, reg)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	restored, err := reopened.L3Run("alpha", released.Request.ID)
	if err != nil || decisions.Hash(restored) != decisions.Hash(released) {
		t.Fatal("journal replay lost canonical refs/receipts", restored, err)
	}
}

func TestL3ShortReferencesRejectUnmappedAndForeignLabelsBeforeActions(t *testing.T) {
	for _, kind := range []string{"candidate-full-id", "candidate-truncated", "candidate-other-run", "evidence-full-id", "evidence-truncated", "evidence-other-run", "evidence-duplicate"} {
		t.Run(kind, func(t *testing.T) {
			s, reg, key, _ := storeFixture(t)
			v := eligibleFixture(t, s, reg, key)
			foreignRequest := L3Request{ID: "foreign-reference", Tenant: "alpha", CaseID: v.Case.ID, CaseSHA: v.Case.SHA}
			currentRequest := L3Request{ID: "reject-short", Tenant: "alpha", CaseID: v.Case.ID, CaseSHA: v.Case.SHA}
			for l3ReferenceTag(foreignRequest) == l3ReferenceTag(currentRequest) {
				foreignRequest.ID += "x"
			}
			foreign, err := newL3References(L3Run{Request: foreignRequest, ReferenceScheme: l3ReferenceScheme}, v)
			if err != nil {
				t.Fatal(err)
			}
			m := newMockL3(t)
			m.rewriteArgs = func(tool string, raw json.RawMessage) json.RawMessage {
				var args map[string]any
				json.Unmarshal(raw, &args)
				if tool == "apply_containment" {
					label := args["candidate_id"].(string)
					switch kind {
					case "candidate-full-id":
						args["candidate_id"] = v.Candidates[0].ID
					case "candidate-truncated":
						args["candidate_id"] = label[:len(label)-1]
					case "candidate-other-run":
						args["candidate_id"] = foreign.candidates[v.Candidates[0].ID]
					}
				}
				if tool == "finish_assessment" {
					labels := args["evidence_ids"].([]any)
					switch kind {
					case "evidence-full-id":
						args["evidence_ids"] = []string{v.Evidence[0].ID}
					case "evidence-truncated":
						label := labels[0].(string)
						args["evidence_ids"] = []string{label[:len(label)-1]}
					case "evidence-other-run":
						args["evidence_ids"] = []string{foreign.evidence[v.Evidence[0].ID]}
					case "evidence-duplicate":
						args["evidence_ids"] = []any{labels[0], labels[0]}
					}
				}
				changed, _ := json.Marshal(args)
				return changed
			}
			engine, err := NewL3(s, referenceConfig(m), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer engine.Close()
			mode := "analyze"
			if strings.HasPrefix(kind, "candidate-") {
				mode = "contain"
			}
			if _, err := engine.Enqueue(L3Request{ID: "reject-short", Tenant: "alpha", CaseID: v.Case.ID, CaseSHA: v.Case.SHA, Mode: mode}); err != nil {
				t.Fatal(err)
			}
			run := awaitL3(t, s, "reject-short")
			if run.Status != "failed" || run.Assessment != nil || run.ActionIntent != "" || run.Binding != nil || len(s.Policies("alpha")) != 0 {
				t.Fatal("unoffered reference authorized a result/action", run)
			}
		})
	}
}

func TestL3ShortReferencesStillRecheckCaseCancellationEpochAndDeadline(t *testing.T) {
	for _, change := range []string{"case", "cancel", "epoch", "deadline"} {
		t.Run(change, func(t *testing.T) {
			s, reg, key, _ := storeFixture(t)
			v := eligibleFixture(t, s, reg, key)
			m := newMockL3(t)
			engine, err := NewL3(s, referenceConfig(m), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer engine.Close()
			m.before = func(call int) {
				if call != 1 {
					return
				}
				switch change {
				case "case":
					observeFixture(t, s, reg, key, "changed", "own", "alpha", "allow", time.Now())
				case "cancel":
					if err := engine.Cancel("alpha", "short-fence"); err != nil {
						t.Error(err)
					}
				case "epoch":
					if err := s.Pause(true); err != nil {
						t.Error(err)
					}
				case "deadline":
					if err := s.l3Update("short-fence", func(r *L3Run) { r.Deadline = time.Now().Add(-time.Second) }); err != nil {
						t.Error(err)
					}
				}
			}
			if _, err := engine.Enqueue(L3Request{ID: "short-fence", Tenant: "alpha", CaseID: v.Case.ID, CaseSHA: v.Case.SHA, Mode: "contain"}); err != nil {
				t.Fatal(err)
			}
			run := awaitL3(t, s, "short-fence")
			if run.Status == "completed" || run.Assessment != nil || run.ActionIntent != "" || run.Binding != nil || len(s.Policies("alpha")) != 0 {
				t.Fatal("short reference bypassed native authority fence", run)
			}
		})
	}
}

func TestL3ShortReferenceConfigurationAndLargeContextFailClosed(t *testing.T) {
	for _, missing := range []string{"bundle", "prefetch"} {
		cfg := L3Config{Enabled: true, Origin: "http://127.0.0.1:1", Model: "local", Digest: decisions.Hash("pin"), DailyRuns: 1, BundleContext: true, Prefetch: true, ShortReferences: true}
		if missing == "bundle" {
			cfg.BundleContext = false
		} else {
			cfg.Prefetch = false
		}
		if cfg.Validate() == nil {
			t.Fatal("short references accepted without bundled prefetch", missing)
		}
	}
	s, reg, key, _ := storeFixture(t)
	at := time.Now().Add(-100 * time.Millisecond)
	var caseID string
	for n := 0; n < 32; n++ {
		g := observeFixture(t, s, reg, key, fmt.Sprintf("large-%02d", n), fmt.Sprintf("resource-%02d", n), "alpha", "deny", at.Add(time.Duration(n)*time.Microsecond))
		caseID = g.CaseID
	}
	v, err := s.Case("alpha", caseID)
	if err != nil {
		t.Fatal(err)
	}
	m := newMockL3(t)
	engine, err := NewL3(s, referenceConfig(m), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	if _, err := engine.Enqueue(L3Request{ID: "large-short", Tenant: "alpha", CaseID: v.Case.ID, CaseSHA: v.Case.SHA, Mode: "contain"}); err != nil {
		t.Fatal(err)
	}
	run := awaitL3(t, s, "large-short")
	if run.Status != "failed" || run.Calls != 0 || m.calls.Load() != 0 || run.Binding != nil || len(s.Policies("alpha")) != 0 {
		t.Fatal("oversize short-reference context weakened budget or fell back ambiguously", run)
	}
}
