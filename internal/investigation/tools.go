package investigation

import (
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"time"

	"reverse-artex/internal/casefile"
	"reverse-artex/internal/caseledger"
)

var ErrToolQuery = errors.New("invalid bounded tool query")
var ErrToolScope = errors.New("tool snapshot changed")
var toolDigest = regexp.MustCompile(`^[a-f0-9]{64}$`)

// Query ranges over one immutable case, never a tenant-wide or raw-log search.
// Offset is bound to Scope and all filters; every page is reauthorized.
type Query struct {
	Start  time.Time `json:"start,omitempty"`
	End    time.Time `json:"end,omitempty"`
	Asset  string    `json:"asset,omitempty"`
	Sensor string    `json:"sensor,omitempty"`
	Stream string    `json:"stream,omitempty"`
	Offset int       `json:"offset"`
	Limit  int       `json:"limit"`
}
type ToolRequest struct {
	Scope Scope  `json:"scope"`
	Tool  string `json:"tool"`
	Query Query  `json:"query"`
}
type Event struct {
	Fact
	Sensor         string    `json:"sensor"`
	Time           time.Time `json:"event_time"`
	IngestTime     time.Time `json:"ingest_time"`
	Type           string    `json:"event_type"`
	Classification string    `json:"classification"`
	Quality        string    `json:"quality"`
}
type AssetContext struct {
	Asset       string `json:"asset"`
	Criticality string `json:"criticality"`
}
type SensorCoverage struct {
	Sensor   string `json:"sensor"`
	Asset    string `json:"asset"`
	Kind     string `json:"kind"`
	Declared string `json:"declared_status"`
	Coverage string `json:"coverage"`
	Records  int    `json:"unique_records"`
}
type Hypothesis struct {
	ID            string   `json:"id"`
	Asset         string   `json:"asset"`
	Kind          string   `json:"kind"`
	Code          string   `json:"code"`
	Status        string   `json:"status"`
	Supporting    []string `json:"supporting_refs"`
	Contradicting []string `json:"contradicting_refs"`
}
type PolicyOperation struct {
	Policy    string    `json:"policy"`
	Asset     string    `json:"asset"`
	Operation string    `json:"recorded_operation"`
	At        time.Time `json:"operation_at"`
	Issued    time.Time `json:"issued_at"`
	Expires   time.Time `json:"expires_at"`
	Rule      string    `json:"rule_version_sha256"`
	Epoch     string    `json:"audit_epoch_sha256"`
	Version   uint64    `json:"audit_version"`
	LineSHA   string    `json:"audit_line_sha256"`
	Refs      []string  `json:"supporting_refs"`
}
type ToolResponse struct {
	Policies         []PolicyOperation `json:"policy_operations,omitempty"`
	PolicyBindingSHA string            `json:"policy_binding_sha256,omitempty"`
	PolicyAsOf       *time.Time        `json:"policy_as_of,omitempty"`
	PolicySelection  string            `json:"policy_selection,omitempty"`
	Schema           string            `json:"schema"`
	Request          ToolRequest       `json:"request"`
	Available        bool              `json:"available"`
	Reason           string            `json:"unavailable_reason"`
	Window           casefile.Window   `json:"observed_window"`
	ObservedAt       time.Time         `json:"observed_at"`
	ExpiresAt        time.Time         `json:"expires_at"`
	Quality          string            `json:"quality"`
	Gaps             bool              `json:"observation_gaps"`
	Contested        bool              `json:"contested"`
	Historical       bool              `json:"historical_snapshot"`
	Total            int               `json:"matching_rows"`
	NextOffset       int               `json:"next_offset"` // -1 means this query is exhausted.
	Facts            []Event           `json:"facts"`
	Assets           []AssetContext    `json:"assets"`
	Sensors          []SensorCoverage  `json:"sensors"`
	Hypotheses       []Hypothesis      `json:"hypotheses"`
}
type detail struct {
	policyHistory     *caseledger.PolicyReview
	policies          []PolicyOperation
	window            casefile.Window
	observed, expires time.Time
	events            []Event
	assets            []AssetContext
	sensors           []SensorCoverage
	hypotheses        []Hypothesis
}

func (c *Case) buildDetail(r caseledger.Review) error {
	e := r.Plan.Context.Document.Envelope
	c.detail = detail{window: e.HTTP.Window, observed: e.HTTP.ObservedAt, expires: e.HTTP.ExpiresAt}
	byRef := map[string]Fact{}
	for _, f := range c.facts {
		byRef[f.Ref] = f
	}
	for _, v := range e.HTTP.Evidence {
		c.detail.events = append(c.detail.events, Event{byRef[v.ID], hash(v.Sensor), v.Time, v.IngestTime, "http", "", v.Quality})
	}
	for _, v := range e.Evidence {
		c.detail.events = append(c.detail.events, Event{byRef[v.ID], hash(v.Sensor), v.Time, v.IngestTime, v.Type, v.Classification, v.Quality})
	}
	for _, a := range r.Plan.Commit.Assets {
		v := AssetContext{hash(a), "unknown"}
		for _, x := range e.Assets {
			if x.Asset == a {
				v.Criticality = x.Criticality
			}
		}
		c.detail.assets = append(c.detail.assets, v)
	}
	for _, v := range e.HTTP.Coverage {
		c.detail.sensors = append(c.detail.sensors, SensorCoverage{hash(v.Sensor), hash(v.Asset), v.Kind, v.DeclaredStatus, v.Status, v.Records})
	}
	for _, v := range e.Coverage {
		s := v.Sensor
		c.detail.sensors = append(c.detail.sensors, SensorCoverage{hash(s.ID), hash(s.Asset), "host", s.Status, v.Status, v.Records})
	}
	for _, v := range e.Hypotheses {
		h := v.Hypothesis
		c.detail.hypotheses = append(c.detail.hypotheses, Hypothesis{hash(h.ID), hash(h.Asset), v.Kind, h.Code, v.Status, append([]string{}, h.Supporting...), append([]string{}, h.Contradicting...)})
	}
	for _, v := range c.detail.events {
		if v.Ref == "" || v.Time.IsZero() {
			return errors.New("event binding required")
		}
	}
	sort.Slice(c.detail.events, func(i, j int) bool {
		a, b := c.detail.events[i], c.detail.events[j]
		if !a.Time.Equal(b.Time) {
			return a.Time.Before(b.Time)
		}
		return a.Ref < b.Ref
	})
	sort.Slice(c.detail.assets, func(i, j int) bool { return c.detail.assets[i].Asset < c.detail.assets[j].Asset })
	sort.Slice(c.detail.sensors, func(i, j int) bool {
		a, b := c.detail.sensors[i], c.detail.sensors[j]
		return a.Asset+":"+a.Sensor+":"+a.Kind < b.Asset+":"+b.Sensor+":"+b.Kind
	})
	sort.Slice(c.detail.hypotheses, func(i, j int) bool { return c.detail.hypotheses[i].ID < c.detail.hypotheses[j].ID })
	return nil
}

func (r ToolRequest) Validate() error {
	q := r.Query
	if r.Scope.Tenant == "" || r.Scope.Case == "" || r.Scope.Revision < 1 || r.Scope.Revision > 1000000 || !toolDigest.MatchString(r.Scope.Commit) || q.Limit < 1 || q.Limit > 8 || q.Offset < 0 || q.Offset > 128 {
		return ErrToolQuery
	}
	if (q.Asset != "" && !toolDigest.MatchString(q.Asset)) || (q.Sensor != "" && !toolDigest.MatchString(q.Sensor)) {
		return ErrToolQuery
	}
	if r.Tool != "query_events" && (!q.Start.IsZero() || !q.End.IsZero() || q.Stream != "") {
		return ErrToolQuery
	}
	if r.Tool != "query_events" && r.Tool != "get_sensor_health" && q.Sensor != "" {
		return ErrToolQuery
	}
	switch r.Tool {
	case "get_case", "get_asset_context", "get_sensor_health":
	case "get_policy_history":
	case "query_events":
		if q.Start.IsZero() || q.End.IsZero() || q.End.Before(q.Start) || (q.Stream != "" && q.Stream != "events" && q.Stream != "host-events") {
			return ErrToolQuery
		}
	default:
		return ErrToolQuery
	}
	return nil
}
func (c *Case) DefaultRequest(tool string) ToolRequest {
	q := Query{Limit: 8}
	if tool == "query_events" {
		q.Start, q.End = c.detail.window.Start, c.detail.window.End
	}
	return ToolRequest{c.scope, tool, q}
}

// ReadTool returns only bounded canonical JSON. Hypothesis references do not
// count as observed evidence: only event rows become final-citation candidates.
func (c *Case) ReadTool(r ToolRequest) ([]byte, []string, error) {
	if c == nil || r.Validate() != nil {
		return nil, nil, ErrToolQuery
	}
	if r.Scope != c.scope {
		return nil, nil, ErrToolScope
	}
	r.Query.Start, r.Query.End = r.Query.Start.UTC(), r.Query.End.UTC()
	q := r.Query
	if r.Tool == "query_events" && (q.Start.Before(c.detail.window.Start) || q.End.After(c.detail.window.End)) {
		return nil, nil, ErrToolQuery
	}
	if q.Asset != "" {
		found := false
		for _, a := range c.detail.assets {
			found = found || a.Asset == q.Asset
		}
		if !found {
			return nil, nil, ErrToolQuery
		}
	}
	if q.Sensor != "" {
		found := false
		for _, s := range c.detail.sensors {
			found = found || (s.Sensor == q.Sensor && (q.Asset == "" || s.Asset == q.Asset))
		}
		if !found {
			return nil, nil, ErrToolQuery
		}
	}
	v := ToolResponse{Schema: "case-tools/1", Request: r, Available: true, Window: c.detail.window, ObservedAt: c.detail.observed, ExpiresAt: c.detail.expires, Quality: c.quality, Gaps: c.gaps, Contested: c.contested, Historical: true, NextOffset: -1, Facts: []Event{}, Assets: []AssetContext{}, Sensors: []SensorCoverage{}, Hypotheses: []Hypothesis{}}
	// Bound rows and bytes together, so a page never silently drops a row.
	type row struct {
		policy     *PolicyOperation
		event      *Event
		asset      *AssetContext
		sensor     *SensorCoverage
		hypothesis *Hypothesis
	}
	var rows []row
	for _, e := range c.detail.events {
		if r.Tool == "query_events" && !e.Time.Before(q.Start) && !e.Time.After(q.End) && (q.Asset == "" || e.Asset == q.Asset) && (q.Sensor == "" || e.Sensor == q.Sensor) && (q.Stream == "" || e.Stream == q.Stream) {
			x := e
			rows = append(rows, row{event: &x})
		}
	}
	for _, a := range c.detail.assets {
		if r.Tool == "get_asset_context" && (q.Asset == "" || a.Asset == q.Asset) {
			x := a
			rows = append(rows, row{asset: &x})
		}
	}
	for _, s := range c.detail.sensors {
		if r.Tool == "get_sensor_health" && (q.Asset == "" || s.Asset == q.Asset) && (q.Sensor == "" || s.Sensor == q.Sensor) {
			x := s
			rows = append(rows, row{sensor: &x})
		}
	}
	for _, h := range c.detail.hypotheses {
		if r.Tool == "get_case" && (q.Asset == "" || h.Asset == q.Asset) {
			x := h
			rows = append(rows, row{hypothesis: &x})
		}
	}
	if r.Tool == "get_case" {
		for _, a := range c.detail.assets {
			if q.Asset == "" || q.Asset == a.Asset {
				v.Assets = append(v.Assets, a)
			}
		}
	}
	if r.Tool == "get_policy_history" {
		if c.detail.policyHistory == nil {
			v.Available = false
			v.Reason = "not_bound_to_verified_case"
		} else {
			v.PolicyBindingSHA = c.detail.policyHistory.SHA256
			at := c.detail.policyHistory.Binding.AsOf
			v.PolicyAsOf = &at
			v.PolicySelection = "explicit_selection"
			for _, p := range c.detail.policies {
				if q.Asset == "" || p.Asset == q.Asset {
					x := p
					rows = append(rows, row{policy: &x})
				}
			}
		}
	}
	v.Total = len(rows)
	if q.Offset > len(rows) {
		return nil, nil, ErrToolQuery
	}
	var refs []string
	count := 0
	for i := q.Offset; i < len(rows) && count < q.Limit; i++ {
		x := rows[i]
		before := v
		if x.policy != nil {
			v.Policies = append(v.Policies, *x.policy)
		}
		if x.event != nil {
			v.Facts = append(v.Facts, *x.event)
		}
		if x.asset != nil {
			v.Assets = append(v.Assets, *x.asset)
		}
		if x.sensor != nil {
			v.Sensors = append(v.Sensors, *x.sensor)
		}
		if x.hypothesis != nil {
			v.Hypotheses = append(v.Hypotheses, *x.hypothesis)
		}
		v.NextOffset = i + 1
		if i+1 == len(rows) {
			v.NextOffset = -1
		}
		raw, _ := json.Marshal(v)
		if len(raw) > MaxProjection {
			v = before
			break
		}
		if x.event != nil {
			refs = append(refs, x.event.Ref)
		}
		count++
	}
	if count == 0 && q.Offset < len(rows) {
		return nil, nil, errors.New("tool row exceeds byte limit")
	}
	if q.Offset+count < len(rows) {
		v.NextOffset = q.Offset + count
	} else {
		v.NextOffset = -1
	}
	raw, e := json.Marshal(v)
	if len(raw) > MaxProjection {
		return nil, nil, errors.New("tool response limit")
	}
	return raw, refs, e
}

func ProjectToolVerified(s caseledger.Stored, r ToolRequest) ([]byte, error) {
	c, e := verifiedHead(s)
	if e != nil {
		return nil, e
	}
	raw, _, e := c.ReadTool(r)
	return raw, e
}

// ParseToolRequest rejects duplicate/unknown/empty parameters before DB work.
func ParseToolRequest(tenant, caseID, tool, raw string) (ToolRequest, error) {
	r := ToolRequest{Scope: Scope{Tenant: tenant, Case: caseID}, Tool: tool}
	if len(raw) > 2048 {
		return r, ErrToolQuery
	}
	v, e := url.ParseQuery(raw)
	if e != nil {
		return r, ErrToolQuery
	}
	for k, values := range v {
		if len(values) != 1 || values[0] == "" {
			return r, ErrToolQuery
		}
		switch k {
		case "revision", "commit", "start", "end", "asset", "sensor", "stream", "offset", "limit":
		default:
			return r, ErrToolQuery
		}
	}
	integer := func(k string) (int, error) {
		s := v.Get(k)
		n, e := strconv.Atoi(s)
		if e != nil || strconv.Itoa(n) != s {
			return 0, ErrToolQuery
		}
		return n, nil
	}
	r.Scope.Revision, e = integer("revision")
	if e != nil {
		return r, e
	}
	r.Scope.Commit = v.Get("commit")
	r.Query.Offset, e = integer("offset")
	if e != nil {
		return r, e
	}
	r.Query.Limit, e = integer("limit")
	if e != nil {
		return r, e
	}
	r.Query.Asset, r.Query.Sensor, r.Query.Stream = v.Get("asset"), v.Get("sensor"), v.Get("stream")
	for k, dst := range map[string]*time.Time{"start": &r.Query.Start, "end": &r.Query.End} {
		if s := v.Get(k); s != "" {
			*dst, e = time.Parse(time.RFC3339Nano, s)
			if e != nil {
				return r, ErrToolQuery
			}
			*dst = dst.UTC()
		}
	}
	return r, r.Validate()
}
func (r ToolRequest) Values() url.Values {
	v := url.Values{"revision": {strconv.Itoa(r.Scope.Revision)}, "commit": {r.Scope.Commit}, "offset": {strconv.Itoa(r.Query.Offset)}, "limit": {strconv.Itoa(r.Query.Limit)}}
	q := r.Query
	if !q.Start.IsZero() {
		v.Set("start", q.Start.UTC().Format(time.RFC3339Nano))
	}
	if !q.End.IsZero() {
		v.Set("end", q.End.UTC().Format(time.RFC3339Nano))
	}
	for k, s := range map[string]string{"asset": q.Asset, "sensor": q.Sensor, "stream": q.Stream} {
		if s != "" {
			v.Set(k, s)
		}
	}
	return v
}
