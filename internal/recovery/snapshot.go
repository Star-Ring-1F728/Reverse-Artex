package recovery

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"reverse-artex/internal/detect"
	"reverse-artex/internal/evidence"
	"reverse-artex/internal/hostguard"
	"strings"
)

// VerifySnapshot uses the recorded configuration to verify detector replay.
// This proves internal consistency, not trusted configuration, source identity,
// policy delivery, database durability, or the source's global newest cursor.
func VerifySnapshot(s *evidence.Snapshot) error {
	if s == nil {
		return errors.New("snapshot required")
	}
	raw := s.Metadata()
	if err := unambiguousJSON(raw); err != nil {
		return err
	}
	var m Metadata
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&m); err != nil {
		return err
	}
	if m.Version != Version || m.Ruleset != Ruleset || (m.Correlation != "session" && m.Correlation != "principal") || (m.CriticalReserve != "" && m.CriticalReserve != detect.CriticalReserveVersion) {
		return errors.New("unsupported recovery configuration")
	}
	engine := detect.New()
	if m.Correlation == "principal" {
		engine = detect.NewPrincipal()
	}
	if m.CriticalReserve != "" {
		engine = detect.NewWithCriticalReserve(m.Correlation == "principal")
	}
	if m.TenantFairness != nil {
		var err error
		engine, err = detect.NewWithTenantFairness(m.Correlation == "principal", m.CriticalReserve != "", m.TenantFairness.Tenants)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(m.TenantFairness, engine.FairnessProfile()) {
			return errors.New("recovery fairness profile mismatch")
		}
	}
	engine.Canaries = map[string]bool{}
	for _, id := range m.Canaries {
		engine.Canaries[id] = true
	}
	// Reject JSON ambiguity before the legacy replay parser sees these bytes.
	for _, c := range s.Commitments() {
		if err := s.VisitRecords(c.Stream, unambiguousJSON); err != nil {
			return fmt.Errorf("%s: %w", c.Stream, err)
		}
	}
	if err := HTTPWithContext(s, engine, m.ContextTrust); err != nil {
		return fmt.Errorf("HTTP replay refused: %w", err)
	}
	if err := Host(s, hostguard.New(m.Canaries)); err != nil {
		return fmt.Errorf("host replay refused: %w", err)
	}
	return nil
}

// Reject duplicate and case-aliased keys (including nested rule maps), excessive
// depth and trailing JSON. Null handling remains with the typed replay contract.
func unambiguousJSON(data []byte) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var value func(int) error
	value = func(depth int) error {
		if depth > 32 {
			return errors.New("recovery JSON nesting limit")
		}
		t, err := d.Token()
		if err != nil {
			return err
		}
		v, ok := t.(json.Delim)
		if !ok {
			return nil
		}
		switch v {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				t, err := d.Token()
				if err != nil {
					return err
				}
				key, ok := t.(string)
				if !ok {
					return errors.New("invalid JSON key")
				}
				key = strings.ToLower(key)
				if seen[key] {
					return errors.New("duplicate recovery JSON field")
				}
				seen[key] = true
				if err := value(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for d.More() {
				if err := value(depth + 1); err != nil {
					return err
				}
			}
		default:
			return errors.New("invalid recovery JSON delimiter")
		}
		_, err = d.Token()
		return err
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("single recovery JSON value required")
	}
	return nil
}
