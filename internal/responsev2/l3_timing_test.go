package responsev2

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"reverse-artex/internal/localassistant"
	"testing"
	"time"
)

func TestL3DiagnosticTimingsAreOptIn(t *testing.T) {
	s, reg, key, _ := storeFixture(t)
	view := eligibleFixture(t, s, reg, key)
	mock := newMockL3(t)
	cfg := referenceConfig(mock)
	engine, err := NewL3(s, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	if _, err = engine.Enqueue(L3Request{ID: "default-timings-off", Tenant: "alpha", CaseID: view.Case.ID, CaseSHA: view.Case.SHA, Mode: "analyze"}); err != nil {
		t.Fatal(err)
	}
	run := awaitL3(t, s, "default-timings-off")
	raw, _ := json.Marshal(run)
	config, _ := json.Marshal(cfg)
	if run.Status != "completed" || run.Calls != 1 || len(run.ModelTimings) != 0 || bytes.Contains(raw, []byte(`"model_timings"`)) || bytes.Contains(config, []byte(`"diagnostic_timings"`)) {
		t.Fatal("default diagnostics changed normal run/config journal fields", string(raw), string(config))
	}
}

type timedL3Provider struct {
	L3Provider
	stage string
}

func (p timedL3Provider) Check(ctx context.Context, name string) (localassistant.Model, error) {
	time.Sleep(3 * time.Millisecond)
	if p.stage == "check" {
		return localassistant.Model{}, errors.New("fixture catalog unavailable")
	}
	return p.L3Provider.Check(ctx, name)
}

func (p timedL3Provider) Next(ctx context.Context, model localassistant.Model, messages []localassistant.Message, tools []localassistant.ToolDefinition) (localassistant.ToolCall, int, error) {
	time.Sleep(6 * time.Millisecond)
	if p.stage == "next" {
		return localassistant.ToolCall{}, 0, errors.New("fixture inference unavailable")
	}
	return p.L3Provider.Next(ctx, model, messages, tools)
}

func TestL3ProviderTimingsSeparateCatalogFromInferenceAndReplay(t *testing.T) {
	for _, stage := range []string{"", "check", "next"} {
		t.Run(map[string]string{"": "success", "check": "catalog-failure", "next": "inference-failure"}[stage], func(t *testing.T) {
			s, reg, key, path := storeFixture(t)
			view := eligibleFixture(t, s, reg, key)
			mock := newMockL3(t)
			client, err := localassistant.NewLocalClient(mock.server.URL)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			cfg := referenceConfig(mock)
			cfg.DiagnosticTimings = true
			engine, err := NewL3(s, cfg, timedL3Provider{client, stage})
			if err != nil {
				t.Fatal(err)
			}
			defer engine.Close()
			if _, err = engine.Enqueue(L3Request{ID: "timed", Tenant: "alpha", CaseID: view.Case.ID, CaseSHA: view.Case.SHA, Mode: "analyze"}); err != nil {
				t.Fatal(err)
			}
			run := awaitL3(t, s, "timed")
			if len(run.ModelTimings) != 1 || run.Deadline.Sub(run.Started) != 30*time.Second {
				t.Fatal("lost timing receipt or changed native deadline", run)
			}
			timing := run.ModelTimings[0]
			if timing.Number != 1 || timing.Started.IsZero() || timing.CheckUS < 3000 {
				t.Fatal("catalog duration not measured at provider boundary", timing)
			}
			if stage == "check" {
				if run.Calls != 0 || timing.NextUS != 0 || timing.State != "failed" || timing.ErrorStage != "provider_check" {
					t.Fatal("catalog failure charged inference or lost stage", run)
				}
			} else {
				if run.Calls != 1 || timing.NextUS < 6000 {
					t.Fatal("inference duration/accounting lost", run)
				}
				if stage == "next" && (run.Status != "failed" || timing.State != "failed" || timing.ErrorStage != "provider_next") {
					t.Fatal("inference failure stage lost", run)
				}
				if stage == "" && (run.Status != "completed" || timing.State != "returned" || timing.ErrorStage != "" || run.Assessment == nil) {
					t.Fatal("instrumentation changed successful assessment", run)
				}
			}
			engine.Close()
			s.Close()
			reopened, err := Open(path, reg)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			restored, err := reopened.L3Run("alpha", "timed")
			if err != nil || !reflect.DeepEqual(restored.ModelTimings, run.ModelTimings) || restored.Calls != run.Calls {
				t.Fatal("provider timings were not durably replayed", restored, err)
			}
		})
	}
}

func TestL3TimingReceiptsRejectCorruptJournalOnReplay(t *testing.T) {
	for i, mutate := range []func(*L3Run){
		func(r *L3Run) { r.ModelTimings = make([]L3ModelTiming, 7) },
		func(r *L3Run) { r.ModelTimings = []L3ModelTiming{{Number: 2, Started: time.Now(), State: "failed"}} },
		func(r *L3Run) {
			r.ModelTimings = []L3ModelTiming{{Number: 1, Started: time.Now(), State: "failed", CheckUS: -1}}
		},
		func(r *L3Run) {
			r.ModelTimings = []L3ModelTiming{{Number: 1, Started: time.Now(), State: "returned", ErrorStage: "provider_next"}}
		},
	} {
		t.Run([]string{"excess-attempts", "wrong-sequence", "negative-duration", "contradictory-stage"}[i], func(t *testing.T) {
			s, reg, key, path := storeFixture(t)
			view := eligibleFixture(t, s, reg, key)
			cfg := referenceConfig(newMockL3(t))
			if _, err := s.l3Start(L3Request{ID: "bounded-timing", Tenant: "alpha", CaseID: view.Case.ID, CaseSHA: view.Case.SHA, Mode: "analyze"}, cfg); err != nil {
				t.Fatal(err)
			}
			// Deliberately use the internal journal writer to model a corrupt
			// record. Public callers cannot provide provider timing receipts.
			if err := s.l3Update("bounded-timing", mutate); err != nil {
				t.Fatal(err)
			}
			s.Close()
			if reopened, err := Open(path, reg); err == nil {
				reopened.Close()
				t.Fatal("invalid timing receipt replayed as authoritative evidence")
			}
		})
	}
}

type failedServiceL3Provider struct {
	L3Provider
	stage string
}

func (p failedServiceL3Provider) Check(ctx context.Context, name string) (localassistant.Model, error) {
	if p.stage == "check" {
		return localassistant.Model{}, &localassistant.ServiceError{Kind: "http_status", HTTPStatus: 503}
	}
	return p.L3Provider.Check(ctx, name)
}
func (p failedServiceL3Provider) Next(context.Context, localassistant.Model, []localassistant.Message, []localassistant.ToolDefinition) (localassistant.ToolCall, int, error) {
	return localassistant.ToolCall{}, 0, &localassistant.ServiceError{Kind: "http_status", HTTPStatus: 502}
}

func TestL3ProviderFailureDiagnosticsSurviveRestart(t *testing.T) {
	for _, stage := range []string{"check", "next"} {
		t.Run(stage, func(t *testing.T) {
			s, reg, key, path := storeFixture(t)
			view := eligibleFixture(t, s, reg, key)
			mock := newMockL3(t)
			client, err := localassistant.NewLocalClient(mock.server.URL)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			cfg := referenceConfig(mock)
			cfg.DiagnosticTimings = true
			engine, err := NewL3(s, cfg, failedServiceL3Provider{client, stage})
			if err != nil {
				t.Fatal(err)
			}
			_, err = engine.Enqueue(L3Request{ID: "service-failure", Tenant: "alpha", CaseID: view.Case.ID, CaseSHA: view.Case.SHA, Mode: "analyze"})
			if err != nil {
				t.Fatal(err)
			}
			run := awaitL3(t, s, "service-failure")
			engine.Close()
			if run.Status != "failed" || run.ActionIntent != "" || run.Assessment != nil || len(run.ModelTimings) != 1 {
				t.Fatal("failed provider gained authority", run)
			}
			failure := run.ModelTimings[0].ProviderFailure
			want := 502
			if stage == "check" {
				want = 503
			}
			if failure == nil || failure.Kind != "http_status" || failure.HTTPStatus != want {
				t.Fatal("failure diagnosis lost", failure)
			}
			s.Close()
			reopened, err := Open(path, reg)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			restored, err := reopened.L3Run("alpha", "service-failure")
			if err != nil || !reflect.DeepEqual(run.ModelTimings, restored.ModelTimings) {
				t.Fatal("failure diagnosis changed on replay", err)
			}
		})
	}
}

func TestL3RejectsInvalidProviderFailureDiagnostics(t *testing.T) {
	for _, failure := range []*localassistant.ServiceError{
		{Kind: "PRIVATE_ERROR"}, {Kind: "http_status", HTTPStatus: 200}, {Kind: "http_status", HTTPStatus: 999}, {Kind: "timeout", HTTPStatus: 503},
	} {
		s, reg, key, path := storeFixture(t)
		view := eligibleFixture(t, s, reg, key)
		cfg := referenceConfig(newMockL3(t))
		_, err := s.l3Start(L3Request{ID: "invalid-service-failure", Tenant: "alpha", CaseID: view.Case.ID, CaseSHA: view.Case.SHA, Mode: "analyze"}, cfg)
		if err != nil {
			t.Fatal(err)
		}
		err = s.l3Update("invalid-service-failure", func(r *L3Run) {
			r.ModelTimings = []L3ModelTiming{{Number: 1, Started: time.Now(), State: "failed", ErrorStage: "provider_check", ProviderFailure: failure}}
		})
		if err != nil {
			t.Fatal(err)
		}
		s.Close()
		reopened, err := Open(path, reg)
		if err == nil {
			reopened.Close()
			t.Fatal("invalid diagnosis replayed")
		}
	}
}
