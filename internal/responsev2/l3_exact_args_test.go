package responsev2

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestL3RejectsArgumentsOutsideOfferedSchema(t *testing.T) {
	for _, kind := range []string{"candidate-case", "candidate-shadow", "assessment-case", "assessment-shadow", "summary-ascii-over", "summary-unicode-over", "valid", "summary-ascii-limit", "summary-unicode-limit"} {
		t.Run(kind, func(t *testing.T) {
			s, reg, key, _ := storeFixture(t)
			v := eligibleFixture(t, s, reg, key)
			m := newMockL3(t)
			m.rewriteArgs = func(name string, raw json.RawMessage) json.RawMessage {
				if name == "apply_containment" {
					switch kind {
					case "candidate-case":
						return []byte(strings.Replace(string(raw), `"candidate_id"`, `"Candidate_ID"`, 1))
					case "candidate-shadow":
						return []byte(`{"candidate_id":"unoffered",` + strings.TrimPrefix(strings.Replace(string(raw), `"candidate_id"`, `"CANDIDATE_ID"`, 1), "{"))
					}
				}
				if name == "finish_assessment" {
					switch kind {
					case "assessment-case":
						return []byte(strings.Replace(string(raw), `"classification"`, `"Classification"`, 1))
					case "assessment-shadow":
						return []byte(`{"classification":"unoffered",` + strings.TrimPrefix(strings.Replace(string(raw), `"classification"`, `"CLASSIFICATION"`, 1), "{"))
					case "summary-ascii-over", "summary-unicode-over", "summary-ascii-limit", "summary-unicode-limit":
						var args map[string]any
						if err := json.Unmarshal(raw, &args); err != nil {
							t.Error(err)
							return raw
						}
						count, char := 1400, "a"
						if strings.HasSuffix(kind, "-over") {
							count++
						}
						if strings.Contains(kind, "unicode") {
							char = "é"
						}
						args["summary"] = strings.Repeat(char, count)
						changed, _ := json.Marshal(args)
						return changed
					}
				}
				return raw
			}
			cfg := l3Cfg(m)
			cfg.BundleContext, cfg.Prefetch = true, true
			engine, err := NewL3(s, cfg, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer engine.Close()
			mode := "analyze"
			if strings.HasPrefix(kind, "candidate-") {
				mode = "contain"
			}
			if _, err = engine.Enqueue(L3Request{ID: "exact-args", Tenant: "alpha", CaseID: v.Case.ID, CaseSHA: v.Case.SHA, Mode: mode}); err != nil {
				t.Fatal(err)
			}
			run := awaitL3(t, s, "exact-args")
			valid := kind == "valid" || strings.HasSuffix(kind, "-limit")
			if valid {
				if run.Status != "completed" || run.Assessment == nil {
					t.Fatalf("schema-valid assessment rejected: %+v", run)
				}
			} else if run.Status != "failed" || run.Assessment != nil || run.Binding != nil || run.ActionIntent != "" || len(s.Policies("alpha")) != 0 {
				t.Fatalf("out-of-schema arguments accepted or mutated policy: status=%s assessment=%t binding=%t intent=%q policies=%d", run.Status, run.Assessment != nil, run.Binding != nil, run.ActionIntent, len(s.Policies("alpha")))
			}
		})
	}
}
