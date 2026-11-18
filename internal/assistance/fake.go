package assistance

import (
	"context"
	"encoding/json"
	"errors"
	"reverse-artex/internal/decisions"
	"sync/atomic"
	"time"
)

type DecisionProvider interface {
	Decide(context.Context, Call) ([]byte, error)
}
type InvestigationProvider interface {
	Investigate(context.Context, Call) ([]byte, error)
}

var errRefusal = errors.New("mock refusal")
var errRateLimited = errors.New("mock rate limited")

type fake struct {
	kind  string
	spec  FakeSpec
	calls *atomic.Int64
}

func (f *fake) Decide(ctx context.Context, c Call) ([]byte, error)      { return f.run(ctx, c) }
func (f *fake) Investigate(ctx context.Context, c Call) ([]byte, error) { return f.run(ctx, c) }
func (f *fake) run(ctx context.Context, c Call) ([]byte, error) {
	f.calls.Add(1)
	if f.spec.Scenario == "timeout" {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if f.spec.DelayMS > 0 {
		t := time.NewTimer(time.Duration(f.spec.DelayMS) * time.Millisecond)
		defer t.Stop()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-t.C:
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	switch f.spec.Scenario {
	case "refusal":
		return nil, errRefusal
	case "rate_limited":
		return nil, errRateLimited
	case "stale":
		return nil, decisions.ErrStale
	case "invalid":
		return []byte(`{"execute":"policy"}`), nil
	case "panic":
		panic("mock failure")
	}
	r := Result{Schema: "mock-assistance-result/1", Kind: f.kind, Epoch: c.Epoch, Hash: c.Hash, Complete: true, Evidence: append([]string(nil), c.Snapshot.Evidence...)}
	if f.kind == Decision {
		r.Conclusion = "review"
		if f.spec.Scenario == "benign" {
			r.Conclusion = "benign"
		}
	} else {
		r.Conclusion = "supported"
	}
	if f.spec.Scenario == "continue" {
		r.Conclusion, r.Complete = "unknown", false
	}
	if f.kind == Decision && c.Snapshot.QuestionSet == decisions.QuestionVersion {
		detail, err := decisions.Fake(classificationInput(c), f.spec.Scenario, time.Now().UTC())
		if err != nil {
			return nil, err
		}
		r.Classification = &detail
		r.Conclusion, r.Complete = classificationConclusion(detail), true
	}
	return json.Marshal(r)
}

// Factories are private: the public runtime exposes no arbitrary endpoint,
// SDK, credential, network transport, or dynamic provider registration.
type factories struct {
	decision      func(FakeSpec) (DecisionProvider, error)
	investigation func(FakeSpec) (InvestigationProvider, error)
}
type metrics struct{ decisionInit, investigationInit, decisionCalls, investigationCalls atomic.Int64 }

func fakeFactories(m *metrics) factories {
	return factories{
		decision: func(s FakeSpec) (DecisionProvider, error) {
			if s.Kind != "fake" {
				return nil, errors.New("explicit case API open required")
			}
			m.decisionInit.Add(1)
			if s.Scenario == "unavailable" {
				return nil, errors.New("mock provider unavailable")
			}
			return &fake{Decision, s, &m.decisionCalls}, nil
		},
		investigation: func(s FakeSpec) (InvestigationProvider, error) {
			if s.Kind != "fake" {
				return nil, errors.New("explicit case API open required")
			}
			m.investigationInit.Add(1)
			if s.Scenario == "unavailable" {
				return nil, errors.New("mock provider unavailable")
			}
			return &fake{Investigation, s, &m.investigationCalls}, nil
		},
	}
}
