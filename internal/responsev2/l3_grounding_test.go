package responsev2

import (
	"context"
	"encoding/json"
	"reflect"
	"reverse-artex/internal/decisions"
	"reverse-artex/internal/localassistant"
	"strings"
	"testing"
	"time"
)

type groundingInspectProvider struct {
	L3Provider
	t      *testing.T
	offers int
}

func (p *groundingInspectProvider) Next(ctx context.Context, model localassistant.Model, messages []localassistant.Message, tools []localassistant.ToolDefinition) (localassistant.ToolCall, int, error) {
	p.offers++
	if len(tools) != 1 || tools[0].Function.Name != "finish_assessment" {
		p.t.Error("grounded analysis offered mutation/read alternatives", tools)
	}
	props := tools[0].Function.Parameters["properties"].(map[string]any)
	classes := props["classification"].(map[string]any)["enum"]
	if !reflect.DeepEqual(classes, []string{"needs_review", "insufficient_evidence", "suspicious"}) {
		p.t.Error("offer ignores actual grounded denial eligibility", classes)
	}
	var host struct {
		Observation struct {
			Grounding l3Grounding `json:"grounding"`
		} `json:"observation"`
	}
	if len(messages) != 3 || json.Unmarshal([]byte(strings.TrimPrefix(messages[2].Content, l3HostObservationPrefix)), &host) != nil || host.Observation.Grounding.Counts.DistinctDeniedResources != 2 {
		p.t.Error("genuine native grounding omitted from model context")
	}
	return p.L3Provider.Next(ctx, model, messages, tools)
}

func groundingFact(seed, resource, kind string, status int, at time.Time) Evidence {
	return Evidence{ID: decisions.Hash(seed), Kind: kind, Status: status, At: at,
		Scope: Scope{Tenant: "alpha", Asset: "lab-api", Principal: "alice", Session: decisions.Hash("session"),
			Route: "legacy", Method: "GET", Resource: decisions.Hash(resource)}}
}

func TestGroundingDispositionEligibilityUsesActualCurrentKindsAndDistinctResources(t *testing.T) {
	now := time.Date(2026, 11, 15, 1, 2, 3, 0, time.UTC)
	allow := groundingFact("allow", "one", "authorized_representation", 200, now.Add(-time.Second))
	deny := groundingFact("deny", "two", "prevented_unauthorized_access", 403, now.Add(-time.Second))
	other := groundingFact("other", "three", "prevented_unauthorized_access", 403, now.Add(-2*time.Second))
	unknown := groundingFact("unknown", "one", "unknown", 503, now.Add(-time.Second))
	cases := []struct {
		name  string
		facts []Evidence
		extra string
	}{
		{"sampled-all-allow", []Evidence{allow}, "benign"},
		{"distinct-denied-pattern", []Evidence{deny, other}, "suspicious"},
		{"single-denied", []Evidence{deny}, ""},
		{"same-resource-repeat", []Evidence{deny, groundingFact("again", "two", "prevented_unauthorized_access", 403, now)}, ""},
		{"mixed-same-resource", []Evidence{allow, groundingFact("changed", "one", "prevented_unauthorized_access", 403, now)}, ""},
		{"unknown-authority", []Evidence{unknown}, ""},
		{"empty", nil, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := l3EvidenceGrounding(CaseView{Evidence: tc.facts}, now)
			want := []string{"needs_review", "insufficient_evidence"}
			if tc.extra != "" {
				want = append(want, tc.extra)
			}
			if !reflect.DeepEqual(g.Admissible, want) || g.Schema != l3GroundingScheme || g.FreshnessSeconds != 60 {
				t.Fatal(g, want)
			}
		})
	}
	bad := allow
	bad.Status = 403
	if got := l3EvidenceGrounding(CaseView{Evidence: []Evidence{bad}}, now); len(got.Admissible) != 2 {
		t.Fatal("kind/status mismatch authorized", got)
	}
}

func TestGroundingExactFreshnessBoundaryFutureAndMixedHistoricalAbstain(t *testing.T) {
	now := time.Date(2026, 11, 15, 1, 2, 3, 0, time.UTC)
	for _, tc := range []struct {
		age    time.Duration
		state  string
		benign bool
	}{
		{60 * time.Second, "current", true}, {60*time.Second + time.Nanosecond, "historical", false},
		{-time.Nanosecond, "future", false}, {59 * time.Second, "current", true},
	} {
		e := groundingFact("boundary", "one", "authorized_representation", 200, now.Add(-tc.age))
		_, state := l3EvidenceAge(e.At, now)
		g := l3EvidenceGrounding(CaseView{Evidence: []Evidence{e}}, now)
		if state != tc.state || (len(g.Admissible) == 3) != tc.benign {
			t.Fatal(tc, state, g)
		}
	}
	old := groundingFact("old", "two", "prevented_unauthorized_access", 403, now.Add(-61*time.Second))
	fresh := groundingFact("new", "one", "authorized_representation", 200, now)
	if got := l3EvidenceGrounding(CaseView{Evidence: []Evidence{old, fresh}}, now); len(got.Admissible) != 2 {
		t.Fatal("historical fact ignored", got)
	}
}

func TestGroundingAssessmentRejectsUnsupportedOrUncitedPatternWithoutRepair(t *testing.T) {
	now := time.Now().UTC()
	a := groundingFact("a", "one", "prevented_unauthorized_access", 403, now)
	b := groundingFact("b", "two", "prevented_unauthorized_access", 403, now)
	v := CaseView{Evidence: []Evidence{a, b}}
	for _, assessment := range []L3Assessment{
		{Classification: "benign", Summary: "Denied is benign", Evidence: []string{a.ID}},
		{Classification: "suspicious", Summary: "Repeated", Evidence: []string{a.ID}},
		{Classification: "suspicious", Summary: "Repeated", Evidence: []string{a.ID, a.ID}},
		{Classification: "needs_review", Summary: "Unknown source", Evidence: []string{decisions.Hash("foreign")}},
	} {
		before := decisions.Hash(assessment)
		if l3ValidateGroundedAssessment(v, assessment, now) == nil {
			t.Fatal("unsupported assessment accepted", assessment)
		}
		if decisions.Hash(assessment) != before {
			t.Fatal("assessment repaired")
		}
	}
	valid := L3Assessment{Classification: "suspicious", Summary: "Two sampled resources were denied; intent remains unknown.", Evidence: []string{a.ID, b.ID}}
	if err := l3ValidateGroundedAssessment(v, valid, now); err != nil {
		t.Fatal(err)
	}
	valid.Classification = "insufficient_evidence"
	valid.Evidence = []string{a.ID}
	if err := l3ValidateGroundedAssessment(v, valid, now); err != nil {
		t.Fatal("abstention removed", err)
	}
}

func TestGroundingRechecksCrossingFreshnessBetweenOfferAndFinalCommit(t *testing.T) {
	now := time.Date(2026, 11, 15, 1, 2, 3, 0, time.UTC)
	fact := groundingFact("crossing", "one", "authorized_representation", 200, now.Add(-59*time.Second))
	view := CaseView{Evidence: []Evidence{fact}}
	assessment := L3Assessment{Classification: "benign", Summary: "This sampled observation was authorized.", Evidence: []string{fact.ID}}
	before := decisions.Hash(assessment)
	if err := l3ValidateGroundedAssessment(view, assessment, now); err != nil {
		t.Fatal("fresh offer unexpectedly rejected", err)
	}
	if err := l3ValidateGroundedAssessment(view, assessment, now.Add(2*time.Second)); err == nil {
		t.Fatal("stale final commit used earlier offer authority")
	}
	if decisions.Hash(assessment) != before {
		t.Fatal("stale classification was rewritten")
	}
	assessment.Classification = "needs_review"
	if err := l3ValidateGroundedAssessment(view, assessment, now.Add(2*time.Second)); err != nil {
		t.Fatal("historical abstention rejected", err)
	}
}

func TestGroundingNativeProviderOfferAndUnchangedRawArgumentReceipts(t *testing.T) {
	for _, blocked := range []bool{false, true} {
		t.Run(map[bool]string{false: "valid-abstention", true: "forged-benign"}[blocked], func(t *testing.T) {
			s, reg, key, _ := storeFixture(t)
			v := eligibleFixture(t, s, reg, key)
			m := newMockL3(t)
			var argumentSHA string
			m.rewriteArgs = func(name string, raw json.RawMessage) json.RawMessage {
				if name != "finish_assessment" {
					t.Error("unoffered model action", name)
				}
				var assessment L3Assessment
				json.Unmarshal(raw, &assessment)
				assessment.Summary = "原样<&> model prose is not authority."
				if blocked {
					assessment.Classification = "benign"
				}
				wire, _ := json.Marshal(assessment)
				argumentSHA = decisions.Hash(json.RawMessage(wire))
				return wire
			}
			cfg := referenceConfig(m)
			cfg.AllowContain = false
			cfg.GroundedAssessment = true
			client, err := localassistant.NewLocalClient(m.server.URL)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			provider := &groundingInspectProvider{L3Provider: client, t: t}
			engine, err := NewL3(s, cfg, provider)
			if err != nil {
				t.Fatal(err)
			}
			defer engine.Close()
			id := "grounded-provider"
			_, err = engine.Enqueue(L3Request{ID: id, Tenant: "alpha", CaseID: v.Case.ID, CaseSHA: v.Case.SHA, Mode: "analyze"})
			if err != nil {
				t.Fatal(err)
			}
			r := awaitL3(t, s, id)
			if provider.offers != 1 || r.Calls != 1 || r.Deadline.Sub(r.Started) != 30*time.Second {
				t.Fatal("native/model deadline or call accounting changed", r)
			}
			steps := []L3Step{}
			for _, step := range r.Steps {
				if step.Executor != "server" {
					steps = append(steps, step)
				}
			}
			if len(steps) != 1 || steps[0].ArgsSHA != argumentSHA {
				t.Fatal("original native argument bytes lost/repaired", r)
			}
			if blocked {
				if r.Status == "completed" || r.Assessment != nil {
					t.Fatal("unsupported model classification committed", r)
				}
			} else {
				if r.Status != "completed" || r.Assessment == nil || r.Assessment.Classification != "needs_review" || r.Assessment.Summary != "原样<&> model prose is not authority." {
					t.Fatal("valid choice rewritten/rejected", r)
				}
				for _, identifier := range r.Assessment.Evidence {
					if !decisions.ValidHash(identifier) {
						t.Fatal("display reference stored as canonical", identifier)
					}
				}
			}
		})
	}
}

func TestGroundingOptInContextAndSameLockCompletionGatePersist(t *testing.T) {
	s, reg, key, path := storeFixture(t)
	v := eligibleFixture(t, s, reg, key)
	m := newMockL3(t)
	cfg := referenceConfig(m)
	cfg.AllowContain = false
	cfg.GroundedAssessment = true
	q := L3Request{ID: "grounded-analysis", Tenant: "alpha", CaseID: v.Case.ID, CaseSHA: v.Case.SHA, Mode: "analyze"}
	if _, err := s.l3Start(q, cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.l3Update(q.ID, func(r *L3Run) { r.Status = "running" }); err != nil {
		t.Fatal(err)
	}
	context, err := s.l3Context(q.ID, v)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := context["grounding"]; !ok {
		t.Fatal("native grounding missing")
	}
	facts := context["facts"].([]map[string]any)
	if _, ok := facts[0]["age_ms"]; !ok {
		t.Fatal("actual age missing")
	}
	a := L3Assessment{Classification: "benign", Summary: "This unsupported model classification must remain unchanged.", Evidence: []string{v.Evidence[0].ID}}
	if err := s.l3Complete(q.ID, a, false); err == nil {
		t.Fatal("same-lock completion accepted unsupported benign")
	}
	r, _ := s.L3Run("alpha", q.ID)
	if r.Status != "running" || r.Assessment != nil || r.GroundingScheme != l3GroundingScheme {
		t.Fatal("rejected assessment persisted/repaired", r)
	}
	a.Classification = "needs_review"
	if err := s.l3Complete(q.ID, a, false); err != nil {
		t.Fatal(err)
	}
	r, _ = s.L3Run("alpha", q.ID)
	if r.Assessment == nil || !reflect.DeepEqual(*r.Assessment, a) || r.Deadline.Sub(r.Started) != 30*time.Second {
		t.Fatal(r)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	replay, err := Open(path, reg)
	if err != nil {
		t.Fatal(err)
	}
	defer replay.Close()
	r, _ = replay.L3Run("alpha", q.ID)
	if r.GroundingScheme != l3GroundingScheme || r.Assessment == nil || !reflect.DeepEqual(*r.Assessment, a) {
		t.Fatal("grounding source receipt lost on replay", r)
	}
}

func TestGroundingDisabledPreservesOldContextAndRejectsMutationModes(t *testing.T) {
	s, reg, key, _ := storeFixture(t)
	v := eligibleFixture(t, s, reg, key)
	m := newMockL3(t)
	cfg := referenceConfig(m)
	q := L3Request{ID: "old-analysis", Tenant: "alpha", CaseID: v.Case.ID, CaseSHA: v.Case.SHA, Mode: "analyze"}
	if _, err := s.l3Start(q, cfg); err != nil {
		t.Fatal(err)
	}
	s.l3Update(q.ID, func(r *L3Run) { r.Status = "running" })
	context, err := s.l3Context(q.ID, v)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := context["grounding"]; ok {
		t.Fatal("default context changed")
	}
	for _, fact := range context["facts"].([]map[string]any) {
		if len(fact) != 7 {
			t.Fatal("default fact changed", fact)
		}
	}
	old, _ := json.Marshal(cfg)
	if strings.Contains(string(old), "grounded_assessment") {
		t.Fatal("off-by-default config wire changed", string(old))
	}
	// Red control: the legacy ungated contract accepts this structurally valid
	// but unsupported class. Opt-in same-lock test above must reject it.
	if err := s.l3Complete(q.ID, L3Assessment{Classification: "benign", Summary: "Legacy raw model choice.", Evidence: []string{v.Evidence[0].ID}}, false); err != nil {
		t.Fatal("legacy contract was silently tightened", err)
	}
	cfg.AllowContain = false
	cfg.GroundedAssessment = true
	for _, mode := range []string{"contain", "release"} {
		q.ID = "grounded-" + mode
		q.Mode = mode
		if _, err := s.l3Start(q, cfg); err == nil {
			t.Fatal("grounding admitted mutation mode", mode)
		}
	}
	for _, broken := range []string{"bundle", "prefetch", "references", "contain"} {
		bad := cfg
		switch broken {
		case "bundle":
			bad.BundleContext = false
		case "prefetch":
			bad.Prefetch = false
		case "references":
			bad.ShortReferences = false
		case "contain":
			bad.AllowContain = true
		}
		if bad.Validate() == nil {
			t.Fatal("unsafe grounding config accepted", broken)
		}
	}
}
