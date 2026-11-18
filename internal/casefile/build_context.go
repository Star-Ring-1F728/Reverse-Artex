package casefile

import (
	"bytes"
	"encoding/json"
	"errors"
	"reverse-artex/internal/hostguard"
	"sort"
	"strings"
	"time"
)

func strictContext(data []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	return d.Decode(out)
}

func BuildContext(input ContextBundle, at time.Time) (ContextDocument, error) {
	if input.Schema != "case-context/1" || input.Assets == nil || input.Sensors == nil || input.Records == nil || input.Hypotheses == nil ||
		len(input.Assets) > MaxAssets || len(input.Sensors)+len(input.HTTP.Sensors) > MaxSensors || len(input.Records)+len(input.HTTP.Records) > MaxRecords || len(input.Hypotheses) > MaxHypotheses || (input.Previous != "" && !sha.MatchString(input.Previous)) {
		return ContextDocument{}, errors.New("invalid bounded context fixture")
	}
	// The direct Go API receives the same bounded data contract as the CLI.
	encoded, err := json.Marshal(input)
	if err != nil || len(encoded) > MaxBundle {
		return ContextDocument{}, errors.New("context fixture byte limit")
	}
	b := copyContext(input)
	http, err := Build(b.HTTP, at)
	if err != nil {
		return ContextDocument{}, err
	}
	e := ContextEnvelope{Schema: "case-context-envelope/1", Scope: "offline_fixture_registry", HTTP: http.Envelope, Previous: b.Previous,
		Assets: []AssetContext{}, Evidence: []HostEvidence{}, Coverage: []HostCoverage{}, Processes: []ProcessGroup{}, Assertions: []Assertion{}, Hypotheses: []Candidate{}, Quality: http.Envelope.Quality}
	assets := map[string]bool{}
	for _, a := range e.HTTP.Assets {
		assets[a] = true
	}
	contextSeen := map[string]bool{}
	add := func(kind, code, subject string, refs []string) {
		refs = append([]string{}, refs...)
		sort.Strings(refs)
		a := Assertion{Kind: kind, Code: code, Subject: subject, Refs: refs}
		a.ID = hash([]any{e.HTTP.Tenant, e.HTTP.CaseID, e.HTTP.Revision, a})
		e.Assertions = append(e.Assertions, a)
		if (kind == "unknown" || kind == "contradicted") && e.Quality == "complete" {
			e.Quality = "degraded"
		}
	}
	for _, a := range b.Assets {
		if !assets[a.Asset] || contextSeen[a.Asset] || (a.Owner != "" && !identifier.MatchString(a.Owner)) {
			return ContextDocument{}, errors.New("asset context scope conflict")
		}
		switch a.Criticality {
		case "unknown", "low", "medium", "high", "critical":
		default:
			return ContextDocument{}, errors.New("invalid asset criticality")
		}
		contextSeen[a.Asset] = true
		e.Assets = append(e.Assets, a)
		if a.Criticality == "unknown" || a.Owner == "" {
			add("unknown", "asset_context_incomplete", a.Asset, nil)
		}
	}
	if len(contextSeen) != len(assets) {
		return ContextDocument{}, errors.New("explicit context required for every asset")
	}
	registry := map[string]HostSensor{}
	for _, s := range b.Sensors {
		key := tuple(s.Tenant, s.Asset, s.ID)
		if !hostguard.ID.MatchString(s.ID) || s.Tenant != b.HTTP.Tenant || !assets[s.Asset] || !hostguard.ID.MatchString(s.Service) || !hostguard.ID.MatchString(s.Workload) || s.ProcessAuthority == nil || s.RequestAuthority == nil ||
			(s.Status != "available" && s.Status != "degraded" && s.Status != "missing") || (s.RequestNamespace != "" && !identifier.MatchString(s.RequestNamespace)) {
			return ContextDocument{}, errors.New("invalid host registry scope")
		}
		if _, ok := registry[key]; ok {
			return ContextDocument{}, errors.New("duplicate host registration")
		}
		for _, h := range b.HTTP.Sensors {
			if key == tuple(h.Tenant, h.Asset, h.ID) {
				return ContextDocument{}, errors.New("sensor reused across incompatible streams")
			}
		}
		registry[key] = s
	}
	seen := map[string]string{}
	counts := map[string]int{}
	partial := map[string]bool{}
	for _, r := range b.Records {
		if r.Process.validate() != nil || len(r.Line) == 0 || len(r.Line) > MaxLine || strings.ContainsAny(r.Line, "\r\n") || !sha.MatchString(r.LineSHA) || hashBytes([]byte(r.Line)) != r.LineSHA || wire([]byte(r.Line)) != nil {
			return ContextDocument{}, errors.New("invalid host line/hash or identity binding")
		}
		v, err := hostguard.Decode(strings.NewReader(r.Line), b.HTTP.ObservedAt)
		if err != nil {
			return ContextDocument{}, errors.New("host event contract rejected")
		}
		key := tuple(v.TenantID, v.AssetID, v.SensorID)
		s, ok := registry[key]
		if !ok || s.Status == "missing" || s.Service != v.ServiceID || s.Workload != v.WorkloadID {
			return ContextDocument{}, errors.New("host source outside declared scope")
		}
		if v.EventTime.Before(b.HTTP.Window.Start) || v.EventTime.After(b.HTTP.Window.End) || v.IngestTime.After(b.HTTP.ObservedAt) {
			return ContextDocument{}, errors.New("host source outside observation window")
		}
		source := tuple("host-events", v.TenantID, v.AssetID, v.SensorID, v.EventID)
		binding := hash(r.Process)
		combined := tuple(r.LineSHA, binding)
		if old, ok := seen[source]; ok {
			if old != combined {
				return ContextDocument{}, errors.New("ambiguous host source or identity enrichment")
			}
			continue
		}
		seen[source] = combined
		ref := HostEvidence{ID: tuple(source, combined), Stream: "host-events", Tenant: v.TenantID, Asset: v.AssetID, Sensor: v.SensorID, EventID: v.EventID, LineSHA: r.LineSHA, BindingSHA: binding, Time: v.EventTime.UTC(), IngestTime: v.IngestTime.UTC(), Type: v.EventType, Classification: v.Classification, Service: v.ServiceID, Workload: v.WorkloadID, ProcessKey: v.ProcessKey, ParentKey: v.ParentKey, Lineage: v.Lineage, RequestID: v.RequestID, Quality: v.DataQuality, Process: r.Process, IdentityBasis: "unknown"}
		if *s.ProcessAuthority && s.Status == "available" && v.DataQuality == "complete" && v.Lineage == "verified" && !v.IngestTime.Before(v.EventTime) && r.Process != (ProcessIdentity{}) {
			ref.IdentityBasis = "registered_process_claim"
		} else {
			add("unknown", "process_identity_unresolved", ref.ID, []string{ref.ID})
		}
		if v.IngestTime.Before(v.EventTime) {
			ref.Quality = "partial"
			add("unknown", "host_clock_skew", ref.ID, []string{ref.ID})
		}
		if v.DataQuality != "complete" {
			add("unknown", "partial_host_observation", ref.ID, []string{ref.ID})
		}
		e.Evidence = append(e.Evidence, ref)
		counts[key]++
		partial[key] = partial[key] || ref.Quality != "complete"
		add("observed_fact", "host_observation", ref.ID, []string{ref.ID})
	}
	for key, s := range registry {
		status := "observed"
		switch {
		case s.Status == "missing":
			status = "missing"
		case counts[key] == 0:
			status = "silent"
		case s.Status == "degraded" || partial[key]:
			status = "degraded"
		}
		e.Coverage = append(e.Coverage, HostCoverage{s, status, counts[key]})
		if status != "observed" {
			add("unknown", "host_sensor_"+status, key, nil)
		}
	}
	// A reused opaque process key with different complete identities is a
	// contradiction, not proof that two PID instances are the same process.
	keyIDs := map[string]map[string]bool{}
	keyRefs := map[string][]string{}
	for _, r := range e.Evidence {
		if r.IdentityBasis == "unknown" {
			continue
		}
		key := tuple(r.Tenant, r.Asset, r.Sensor, r.Service, r.Workload, r.ProcessKey)
		if keyIDs[key] == nil {
			keyIDs[key] = map[string]bool{}
		}
		keyIDs[key][r.BindingSHA] = true
		keyRefs[key] = append(keyRefs[key], r.ID)
	}
	conflicted := map[string]bool{}
	for key, ids := range keyIDs {
		if len(ids) > 1 {
			add("contradicted", "process_key_conflict", key, keyRefs[key])
			for _, ref := range keyRefs[key] {
				conflicted[ref] = true
			}
		}
	}
	groups := map[string]*ProcessGroup{}
	for _, r := range e.Evidence {
		s := registry[tuple(r.Tenant, r.Asset, r.Sensor)]
		if r.IdentityBasis == "unknown" || conflicted[r.ID] {
			continue
		}
		key := tuple(r.Tenant, r.Asset, r.Service, r.Workload, r.BindingSHA)
		if groups[key] == nil {
			groups[key] = &ProcessGroup{ID: key, Asset: r.Asset, Refs: []string{}}
		}
		groups[key].Refs = append(groups[key].Refs, r.ID)
		linked := false
		if *s.RequestAuthority && s.RequestNamespace != "" && r.RequestID != "" {
			requestKey := tuple(r.Tenant, r.Asset, s.RequestNamespace, r.RequestID)
			for _, g := range e.HTTP.Groups {
				if g.ID == requestKey && g.Countable {
					refs := append([]string{r.ID}, g.Refs...)
					add("derived_relation", "shared_request_process_tag", r.ID, refs)
					linked = true
				}
			}
		}
		if !linked {
			add("unknown", "http_host_link_unresolved", r.ID, []string{r.ID})
		}
	}
	for _, g := range groups {
		sort.Strings(g.Refs)
		e.Processes = append(e.Processes, *g)
		if len(g.Refs) > 1 {
			add("derived_relation", "same_process", g.ID, g.Refs)
		}
	}
	refs := map[string]string{}
	types := map[string]string{}
	for _, r := range e.HTTP.Evidence {
		refs[r.ID] = r.Asset
		types[r.ID] = "http"
	}
	for _, r := range e.Evidence {
		refs[r.ID] = r.Asset
		types[r.ID] = r.Type
	}
	hypotheses := map[string]bool{}
	for _, h := range b.Hypotheses {
		if !identifier.MatchString(h.ID) || hypotheses[h.ID] || !assets[h.Asset] || len(h.Supporting) == 0 || len(h.Supporting) > 16 || h.Contradicting == nil || len(h.Contradicting) > 16 {
			return ContextDocument{}, errors.New("invalid bounded hypothesis")
		}
		hypotheses[h.ID] = true
		seen := map[string]bool{}
		supportTypes := map[string]bool{}
		for _, ref := range h.Supporting {
			if refs[ref] != h.Asset || seen[ref] {
				return ContextDocument{}, errors.New("unbound or repeated supporting ref")
			}
			seen[ref] = true
			supportTypes[types[ref]] = true
		}
		for _, ref := range h.Contradicting {
			if refs[ref] != h.Asset || seen[ref] {
				return ContextDocument{}, errors.New("unbound, repeated or overlapping contradicting ref")
			}
			seen[ref] = true
		}
		valid := h.Code == "process_activity" && supportTypes["process_start"] || h.Code == "possible_egress" && supportTypes["network_connect"] || h.Code == "request_process_link" && supportTypes["http"] && (supportTypes["process_start"] || supportTypes["network_connect"] || supportTypes["canary_access"])
		if !valid {
			return ContextDocument{}, errors.New("unsupported hypothesis code or source type")
		}
		sort.Strings(h.Supporting)
		sort.Strings(h.Contradicting)
		status := "unverified"
		if len(h.Contradicting) > 0 {
			status = "contested"
		}
		e.Hypotheses = append(e.Hypotheses, Candidate{h, "hypothesis", status})
	}
	sort.Slice(e.Assets, func(i, j int) bool { return e.Assets[i].Asset < e.Assets[j].Asset })
	sort.Slice(e.Evidence, func(i, j int) bool { return e.Evidence[i].ID < e.Evidence[j].ID })
	sort.Slice(e.Coverage, func(i, j int) bool {
		return tuple(e.Coverage[i].Sensor.Tenant, e.Coverage[i].Sensor.Asset, e.Coverage[i].Sensor.ID) < tuple(e.Coverage[j].Sensor.Tenant, e.Coverage[j].Sensor.Asset, e.Coverage[j].Sensor.ID)
	})
	sort.Slice(e.Processes, func(i, j int) bool { return e.Processes[i].ID < e.Processes[j].ID })
	sort.Slice(e.Assertions, func(i, j int) bool { return e.Assertions[i].ID < e.Assertions[j].ID })
	sort.Slice(e.Hypotheses, func(i, j int) bool { return e.Hypotheses[i].Hypothesis.ID < e.Hypotheses[j].Hypothesis.ID })
	encoded, err = json.Marshal(e)
	if err != nil || len(encoded) > MaxEnvelope {
		return ContextDocument{}, errors.New("context envelope byte limit")
	}
	return ContextDocument{e, hashBytes(encoded)}, nil
}
