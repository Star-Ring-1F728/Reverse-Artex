// Package recovery replays persisted detector evaluations without delivering policies.
package recovery

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"reflect"
	"reverse-artex/internal/actioncontext"
	"reverse-artex/internal/detect"
	"reverse-artex/internal/event"
	"reverse-artex/internal/hostguard"
	"time"
)

// Reader supplies complete records in their original commit order.
type Reader interface {
	VisitRecords(string, func([]byte) error) error
}

const Version = 1

// Bump when either detector's state transition or alert encoding changes.
const Ruleset = "http-1.2-host-1.0"
const MaxRecords = 1_000_000

type Metadata struct {
	ContextTrust    *actioncontext.Trust          `json:"action_context_trust,omitempty"`
	Version         int                           `json:"version"`
	Ruleset         string                        `json:"ruleset"`
	Correlation     string                        `json:"correlation"`
	Canaries        []string                      `json:"canaries"`
	PolicyControl   string                        `json:"policy_control,omitempty"`
	CriticalReserve string                        `json:"critical_reserve,omitempty"`
	TenantFairness  *detect.TenantFairnessProfile `json:"tenant_fairness,omitempty"`
}

type Evaluation struct {
	EventID        string            `json:"event_id"`
	Result         string            `json:"result"`
	Rules          map[string]string `json:"rules"`
	ProcessTime    time.Time         `json:"process_time"`
	PolicyDelivery bool              `json:"policy_delivery,omitempty"`
}

func ReadEvaluations(store Reader, stream string) ([]Evaluation, error) {
	var out []Evaluation
	err := store.VisitRecords(stream, func(line []byte) error {
		if len(out) >= MaxRecords {
			return errors.New("recovery evaluation count exceeds limit")
		}
		var x Evaluation
		if err := json.Unmarshal(line, &x); err != nil {
			return err
		}
		if x.EventID == "" || x.Result == "" || x.ProcessTime.IsZero() || x.Rules == nil {
			return errors.New("incomplete evaluation record")
		}
		out = append(out, x)
		return nil
	})
	return out, err
}

func readAlertHashes(store Reader, stream string) (map[[32]byte]int, error) {
	counts := map[[32]byte]int{}
	total := 0
	err := store.VisitRecords(stream, func(line []byte) error {
		if total >= MaxRecords {
			return errors.New("recovery alert count exceeds limit")
		}
		if !json.Valid(line) {
			return errors.New("invalid alert JSON")
		}
		counts[sha256.Sum256(line)]++
		total++
		return nil
	})
	return counts, err
}

func consumeAlert(counts map[[32]byte]int, alert any) error {
	b, err := json.Marshal(alert)
	if err != nil {
		return err
	}
	h := sha256.Sum256(b)
	if counts[h] == 0 {
		return errors.New("missing or changed alert evidence")
	}
	counts[h]--
	return nil
}

func allAlertsConsumed(counts map[[32]byte]int) bool {
	for _, n := range counts {
		if n != 0 {
			return false
		}
	}
	return true
}

func HTTP(store Reader, engine *detect.Engine) error { return HTTPWithContext(store, engine, nil) }
func HTTPWithContext(store Reader, engine *detect.Engine, trust *actioncontext.Trust) error {
	if trust != nil {
		if err := trust.Validate(); err != nil {
			return err
		}
	}
	evals, err := ReadEvaluations(store, "evaluations")
	if err != nil {
		return err
	}
	alerts, err := readAlertHashes(store, "alerts")
	if err != nil {
		return err
	}
	index := 0
	err = store.VisitRecords("events", func(line []byte) error {
		if index >= len(evals) {
			return errors.New("event without committed evaluation")
		}
		var e event.Event
		if err := json.Unmarshal(line, &e); err != nil {
			return err
		}
		ev := evals[index]
		index++
		if err := e.Validate(e.IngestTime); err != nil || ev.EventID != e.EventID || ev.ProcessTime.Before(e.IngestTime) {
			return errors.New("invalid event/evaluation pair")
		}
		if err := trust.Verify(e.Context, e.ContextBinding()); err != nil {
			return err
		}
		produced, status := engine.Process(e, ev.ProcessTime)
		rules := engine.EvaluabilityForResult(e, status)
		if status != ev.Result || !reflect.DeepEqual(rules, ev.Rules) {
			return errors.New("HTTP replay differs from committed evaluation")
		}
		for _, alert := range produced {
			if err := consumeAlert(alerts, alert); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	if index != len(evals) || !allAlertsConsumed(alerts) {
		return errors.New("orphan HTTP evaluation or alert")
	}
	return nil
}

func Host(store Reader, engine *hostguard.Engine) error {
	evals, err := ReadEvaluations(store, "host-evaluations")
	if err != nil {
		return err
	}
	alerts, err := readAlertHashes(store, "host-alerts")
	if err != nil {
		return err
	}
	index := 0
	err = store.VisitRecords("host-events", func(line []byte) error {
		if index >= len(evals) {
			return errors.New("host event without committed evaluation")
		}
		var e hostguard.Event
		if err := json.Unmarshal(line, &e); err != nil {
			return err
		}
		ev := evals[index]
		index++
		if err := e.Validate(e.IngestTime); err != nil || ev.EventID != e.EventID || ev.ProcessTime.Before(e.IngestTime) {
			return errors.New("invalid host event/evaluation pair")
		}
		produced, status, rules := engine.Process(e, ev.ProcessTime)
		if status == "capacity_rejected" {
			for rule := range rules {
				rules[rule] = "not_evaluable_capacity_rejected"
			}
		}
		if status != ev.Result || !reflect.DeepEqual(rules, ev.Rules) {
			return errors.New("host replay differs from committed evaluation")
		}
		for _, alert := range produced {
			if err := consumeAlert(alerts, alert); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	if index != len(evals) || !allAlertsConsumed(alerts) {
		return errors.New("orphan host evaluation or alert")
	}
	return nil
}
