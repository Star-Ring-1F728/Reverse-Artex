package casefile

import (
	"encoding/json"
	"errors"
	"fmt"
	"reverse-artex/internal/event"
	"sort"
	"strings"
	"time"
)

// Build treats the local registry as fixture configuration, not proof of live
// sensor authentication. It has no side effects and returns no partial result
// on an invalid, conflicting or out-of-scope source record.
func Build(b Bundle, at time.Time) (Document, error) {
	if err := b.validate(at); err != nil {
		return Document{}, err
	}
	e := Envelope{
		Schema: "case-envelope/1", Scope: "offline_fixture_registry", CaseID: b.CaseID, Revision: b.Revision,
		Tenant: b.Tenant, Assets: append([]string{}, b.Assets...),
		Window: Window{b.Window.Start.UTC(), b.Window.End.UTC()}, ObservedAt: b.ObservedAt.UTC(), ExpiresAt: b.ExpiresAt.UTC(),
		Quality: "complete", Evidence: []Evidence{}, Coverage: []Coverage{}, Groups: []Group{}, Assertions: []Assertion{},
	}
	sort.Strings(e.Assets)
	registry := map[string]Sensor{}
	counts, incomplete := map[string]int{}, map[string]bool{}
	for _, s := range b.Sensors {
		registry[tuple(s.Tenant, s.Asset, s.ID)] = s
	}
	assertion := func(kind, code, subject string, refs []string) {
		refs = append([]string{}, refs...)
		sort.Strings(refs)
		a := Assertion{Kind: kind, Code: code, Subject: subject, Refs: refs}
		a.ID = hash([]any{b.Tenant, b.CaseID, b.Revision, a})
		e.Assertions = append(e.Assertions, a)
		if kind == "unknown" || kind == "contradicted" {
			e.Quality = "degraded"
		}
	}
	seen := map[string]string{}
	total := 0
	for index, record := range b.Records {
		total += len(record.Line)
		if len(record.Line) == 0 || len(record.Line) > MaxLine || total > MaxBundle || strings.ContainsAny(record.Line, "\r\n") || !sha.MatchString(record.LineSHA) || hashBytes([]byte(record.Line)) != record.LineSHA {
			return Document{}, fmt.Errorf("record %d: invalid bounded source line/hash", index)
		}
		if err := wire([]byte(record.Line)); err != nil {
			return Document{}, fmt.Errorf("record %d: invalid source JSON", index)
		}
		v, err := event.DecodeAt(strings.NewReader(record.Line), b.ObservedAt)
		if err != nil {
			return Document{}, fmt.Errorf("record %d: event contract rejected", index)
		}
		key := tuple(v.TenantID, v.AssetID, v.SensorID)
		s, ok := registry[key]
		if !ok || v.TenantID != b.Tenant || s.Status == "missing" {
			return Document{}, errors.New("source outside declared sensor/tenant/asset scope")
		}
		if v.EventTime.Before(b.Window.Start) || v.EventTime.After(b.Window.End) || v.IngestTime.After(b.ObservedAt) {
			return Document{}, errors.New("source outside case observation window")
		}
		source := tuple("events", v.TenantID, v.AssetID, v.SensorID, v.EventID)
		if old, ok := seen[source]; ok {
			if old != record.LineSHA {
				return Document{}, errors.New("ambiguous source identity has different raw bytes")
			}
			continue
		}
		seen[source] = record.LineSHA
		ref := Evidence{
			ID: tuple(source, record.LineSHA), Stream: "events", Tenant: v.TenantID, Asset: v.AssetID,
			Sensor: v.SensorID, SensorKind: s.Kind, EventID: v.EventID, LineSHA: record.LineSHA,
			Time: v.EventTime.UTC(), IngestTime: v.IngestTime.UTC(), RequestID: v.RequestID, RequestNamespace: s.RequestNamespace,
			Method: v.Method, Route: v.Route, KnownRoute: v.KnownRoute, Status: v.Status,
			Authorization: v.Authorization, Family: v.DetectorFamily, IdentityBasis: "unknown", Quality: v.DataQuality,
		}
		refs := []string{ref.ID}
		if v.Identity == "authenticated" && *s.IdentityAuthority && s.Status == "available" && v.DataQuality == "complete" && !v.IngestTime.Before(v.EventTime) {
			ref.Principal, ref.IdentityBasis = v.Principal, "registered_sensor_claim"
		} else {
			assertion("unknown", "identity_unresolved", ref.ID, refs)
		}
		if v.IngestTime.Before(v.EventTime) {
			ref.Quality = "partial"
			assertion("unknown", "clock_skew", ref.ID, refs)
		}
		if v.DataQuality != "complete" {
			assertion("unknown", "partial_observation", ref.ID, refs)
		}
		if v.Authorization == "unknown" {
			assertion("unknown", "authorization_unobserved", ref.ID, refs)
		}
		if !v.KnownRoute {
			assertion("unknown", "route_unresolved", ref.ID, refs)
		}
		if v.DetectorFamily == "unknown" {
			assertion("unknown", "detector_unobserved", ref.ID, refs)
		}
		counts[key]++
		incomplete[key] = incomplete[key] || ref.Quality != "complete"
		e.Evidence = append(e.Evidence, ref)
		assertion("observed_fact", "http_observation", ref.ID, refs)
	}
	sort.Slice(e.Evidence, func(i, j int) bool { return e.Evidence[i].ID < e.Evidence[j].ID })
	for key, s := range registry {
		status := "observed"
		switch {
		case s.Status == "missing":
			status = "missing"
		case counts[key] == 0:
			status = "silent"
		case s.Status == "degraded" || incomplete[key]:
			status = "degraded"
		}
		e.Coverage = append(e.Coverage, Coverage{key, s.ID, s.Tenant, s.Asset, s.Kind, s.Status, s.RequestNamespace, *s.IdentityAuthority, status, counts[key]})
		if status != "observed" {
			assertion("unknown", "sensor_"+status, key, nil)
		}
	}
	sort.Slice(e.Coverage, func(i, j int) bool { return e.Coverage[i].ID < e.Coverage[j].ID })
	grouped := map[string][]Evidence{}
	for _, ref := range e.Evidence {
		key := tuple(b.Tenant, ref.Asset, ref.RequestNamespace, ref.RequestID)
		if ref.RequestNamespace == "" {
			key = tuple("uncorrelated", ref.ID)
		}
		grouped[key] = append(grouped[key], ref)
	}
	// Principal relations only use trustworthy identity refs from nonconflicting
	// requests, scoped to the same tenant AND asset. NAT/IP/UA never join cases.
	principalRefs, principalGroups := map[string][]string{}, map[string]int{}
	for key, members := range grouped {
		g := Group{ID: key, Asset: members[0].Asset, Basis: "registered_request_namespace", Refs: []string{}, Countable: true}
		principals, methods, routes := map[string]bool{}, map[string]bool{}, map[string]bool{}
		trusted := []string{}
		for _, ref := range members {
			g.Refs = append(g.Refs, ref.ID)
			methods[ref.Method] = true
			if ref.KnownRoute {
				routes[ref.Route] = true
			}
			if ref.Principal != "" {
				principals[ref.Principal] = true
				trusted = append(trusted, ref.ID)
			}
			if ref.Quality != "complete" || registry[tuple(ref.Tenant, ref.Asset, ref.Sensor)].Status != "available" {
				g.Countable = false
			}
		}
		sort.Strings(g.Refs)
		if members[0].RequestNamespace == "" {
			g.Basis, g.Countable = "uncorrelated", false
			assertion("unknown", "request_origin_unverified", key, g.Refs)
		}
		conflict := len(principals) > 1 || len(methods) > 1 || len(routes) > 1
		if len(principals) > 1 {
			assertion("contradicted", "principal_conflict", key, g.Refs)
		}
		if len(methods) > 1 || len(routes) > 1 {
			assertion("contradicted", "request_metadata_conflict", key, g.Refs)
		}
		if conflict {
			g.Countable = false
		} else if g.Basis != "uncorrelated" && len(members) > 1 {
			assertion("derived_relation", "same_request", key, g.Refs)
		}
		if g.Countable {
			e.RequestCount++
		}
		e.Groups = append(e.Groups, g)
		if g.Countable && len(principals) == 1 {
			for principal := range principals {
				identity := tuple(b.Tenant, g.Asset, principal)
				principalRefs[identity] = append(principalRefs[identity], trusted...)
				principalGroups[identity]++
			}
		}
	}
	for key, refs := range principalRefs {
		if principalGroups[key] > 1 {
			assertion("derived_relation", "same_principal", key, refs)
		}
	}
	sort.Slice(e.Groups, func(i, j int) bool { return e.Groups[i].ID < e.Groups[j].ID })
	sort.Slice(e.Assertions, func(i, j int) bool { return e.Assertions[i].ID < e.Assertions[j].ID })
	if len(e.Evidence) == 0 || e.RequestCount == 0 {
		e.Quality = "not_evaluable"
	}
	encoded, err := json.Marshal(e)
	if err != nil || len(encoded) > MaxEnvelope {
		return Document{}, errors.New("case envelope byte limit")
	}
	return Document{Envelope: e, SHA256: hashBytes(encoded)}, nil
}
