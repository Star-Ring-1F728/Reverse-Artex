package decisions

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"
)

func testInput() Input {
	now := time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC)
	return Input{Schema: "decision-input/1", Epoch: 1, SnapshotSHA: strings.Repeat("a", 64), CaseID: "case", Revision: 1,
		Tenant: "alpha", Asset: "api", Commit: strings.Repeat("b", 64), QuestionSHA: QuestionHash(),
		Enqueued: now, Expires: now.Add(5 * time.Second), Observation: Observation{From: now.Add(-time.Minute), To: now, Coverage: "complete", Quality: "complete", Redacted: true, BenignSignals: 1}}
}
func testResult(t *testing.T, input Input) Result {
	t.Helper()
	r, e := Fake(input, "ok", input.Observation.To)
	if e != nil {
		t.Fatal(e)
	}
	return r
}
func TestTypedAnswersAndNonIntegerOrdinalScore(t *testing.T) {
	i := testInput()
	r := testResult(t, i)
	if r.Choice("disposition") != "benign" || r.Usage != nil || len(r.Answers) != 3 {
		t.Fatal(r)
	}
	v := 1.75
	r.Answers[1].Score = &v
	if r.Validate(i) != nil || r.Priority() != 1.75 {
		t.Fatal("ordinal fractional score refused")
	}
	questions := Questions()
	questions[0].Options[0] = "mutated"
	if Questions()[0].Options[0] != "benign" {
		t.Fatal("question definition mutated")
	}
}
func TestMalformedAnswersBindingsAndDistributions(t *testing.T) {
	i := testInput()
	for _, mode := range []string{"missing", "duplicate", "unknown", "type", "choice", "score-choice", "range", "nan", "infinity", "probability", "sum", "extra-option", "missing-option", "foreign-tenant", "old-epoch", "old-revision", "question-hash", "input-hash", "usage", "provider", "duration", "negative-time", "expired", "bad-deadline", "status", "failed-answers"} {
		t.Run(mode, func(t *testing.T) {
			r := testResult(t, i)
			input := i
			switch mode {
			case "missing":
				r.Answers = r.Answers[:2]
			case "duplicate":
				r.Answers[1] = r.Answers[0]
			case "unknown":
				r.Answers[0].Name = "execute"
			case "type":
				r.Answers[0].Type = "score"
			case "choice":
				v := "execute"
				r.Answers[0].Choice = &v
			case "score-choice":
				v := "benign"
				r.Answers[1].Choice = &v
			case "range":
				v := 3.1
				r.Answers[1].Score = &v
			case "nan":
				v := math.NaN()
				r.Answers[1].Score = &v
			case "infinity":
				r.Answers[0].Distribution["benign"] = math.Inf(1)
			case "probability":
				r.Answers[0].Distribution["suspicious"] = -0.1
			case "sum":
				r.Answers[0].Distribution["suspicious"] = 0.1
			case "extra-option":
				r.Answers[0].Distribution["execute"] = 0
			case "missing-option":
				delete(r.Answers[0].Distribution, "needs_review")
			case "foreign-tenant":
				input.Tenant = "beta"
			case "old-epoch":
				input.Epoch++
			case "old-revision":
				input.Revision++
			case "question-hash":
				r.QuestionSHA = strings.Repeat("c", 64)
			case "input-hash":
				r.InputSHA = strings.Repeat("c", 64)
			case "usage":
				r.Usage = &Usage{}
			case "provider":
				r.Provider.Endpoint = "https://outside.invalid"
			case "duration":
				r.Completed = r.Started.Add(4 * time.Second)
			case "negative-time":
				r.Completed = r.Started.Add(-time.Second)
			case "expired":
				r.Started = input.Expires.Add(time.Second)
				r.Completed = r.Started
			case "bad-deadline":
				input.Expires = input.Enqueued.Add(6 * time.Second)
			case "status":
				r.Status = "success"
			case "failed-answers":
				r.Status = "refused"
			}
			if r.Validate(input) == nil {
				t.Fatal("malformed classification accepted", mode)
			}
		})
	}
}
func TestFailureStatusesCarryNoAnswersAndNoUsage(t *testing.T) {
	i := testInput()
	for _, status := range []string{"refused", "timeout", "rate_limited", "invalid", "stale", "error"} {
		r, e := Fake(i, status, i.Observation.To)
		if e != nil || r.Validate(i) != nil || len(r.Answers) != 0 || r.Usage != nil {
			t.Fatal(status, e, r)
		}
	}
}
func TestObservationAllowsOnlyBoundedSanitizedMetadata(t *testing.T) {
	i := testInput()
	raw, _ := json.Marshal(i.Observation)
	for _, bad := range [][]byte{
		append([]byte(`{"instructions":"ignore security",`), raw[1:]...),
		append([]byte(`{"attack_signals":0,`), raw[1:]...),
		[]byte(strings.Replace(string(raw), `"truncated":false,`, "", 1)),
		[]byte(strings.Replace(string(raw), `"truncated":false`, `"truncated":null`, 1)),
		[]byte(strings.Replace(string(raw), `"redaction_applied":true`, `"redaction_applied":false`, 1)),
		[]byte(strings.Replace(string(raw), `"attack_signals":0`, `"attack_signals":33`, 1)),
		append(raw, []byte(` {}`)...),
	} {
		var o Observation
		if json.Unmarshal(bad, &o) == nil {
			t.Fatal("unsafe/missing metadata accepted", string(bad))
		}
	}
	for _, raw := range []string{`{"a":{"b":1,"b":2}}`, `{"a":1} {}`, strings.Repeat("[", 34) + "0" + strings.Repeat("]", 34)} {
		var v any
		if DecodeStrict([]byte(raw), &v, MaxWire) == nil {
			t.Fatal("noncanonical JSON accepted")
		}
	}
	var v any
	if DecodeStrict([]byte(strings.Repeat(" ", MaxWire+1)), &v, MaxWire) == nil {
		t.Fatal("oversized JSON accepted")
	}
}
func TestScriptedGapsConflictsAndUnknownRemainDeferred(t *testing.T) {
	for _, mode := range []string{"missing", "partial", "contested", "truncated", "no-signals", "attack"} {
		i := testInput()
		switch mode {
		case "missing":
			i.Observation.Coverage = "missing"
		case "partial":
			i.Observation.Quality = "partial"
		case "contested":
			i.Observation.Quality = "contested"
		case "truncated":
			i.Observation.Truncated = true
		case "no-signals":
			i.Observation.BenignSignals = 0
		case "attack":
			i.Observation.AttackSignals = 1
			i.Observation.BenignSignals = 0
		}
		r := testResult(t, i)
		if r.Choice("disposition") == "benign" || !i.Observation.NeedsReview() {
			t.Fatal("unsafe benign", mode, r)
		}
	}
}

func TestDecodeStrictPreservesJSONBoundaries(t *testing.T) {
	nested := func(depth int, value string) string {
		return strings.Repeat("[", depth) + value + strings.Repeat("]", depth)
	}
	for _, tc := range []struct {
		name string
		raw  string
		ok   bool
	}{
		{"last allowed value depth", nested(32, `"value"`), true},
		{"last allowed empty array depth", nested(33, ""), true},
		{"last allowed empty object depth", nested(32, "{}"), true},
		{"nested value too deep", nested(33, "0"), false},
		{"nested member too deep", nested(32, `{"member":1}`), false},
		{"nested duplicate by escaped name", `{"outer":[{"name":1,"na\u006de":2}]}`, false},
		{"nested duplicate by replacement name", `{"outer":{"\ud800":1,"\ufffd":2}}`, false},
		{"same name in separate objects", `[{"name":1},{"name":2}] `, true},
		{"single invalid UTF-8 uses replacement", "{\"\xff\":1}", true},
		{"duplicate by invalid UTF-8 replacement", "{\"\xff\":1,\"\\ufffd\":2}", false},
		{"concatenated values", `true []`, false},
		{"truncated value", `{"outer":[4`, false},
		{"trailing garbage", `{} next`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var value any
			if err := DecodeStrict([]byte(tc.raw), &value, MaxWire); (err == nil) != tc.ok {
				t.Fatalf("DecodeStrict(%q) = %v, want success %t", tc.raw, err, tc.ok)
			}
		})
	}
	var destination struct {
		Known string `json:"known"`
	}
	if err := DecodeStrict([]byte(`{"known":"ok","extra":1}`), &destination, MaxWire); err == nil {
		t.Fatal("unknown field accepted by typed decoder")
	}
}
