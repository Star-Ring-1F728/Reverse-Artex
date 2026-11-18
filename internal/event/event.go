// Package event defines the sensor contract. It intentionally has no raw headers,
// bodies, credentials, query strings, or ground-truth labels.
package event

import (
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"reverse-artex/internal/actioncontext"
	"strings"
	"time"
)

type Event struct {
	Context            *actioncontext.Observation `json:"action_context,omitempty"`
	ExportApproval     *ExportApproval            `json:"export_approval,omitempty"`
	ResponseBudget     *ResponseBudget            `json:"response_budget,omitempty"`
	SearchPage         *SearchPage                `json:"search_page,omitempty"`
	Budget             *Budget                    `json:"export_budget,omitempty"`
	RequestBudget      *RequestBudget             `json:"request_budget,omitempty"`
	SearchResultBudget *SearchResultBudget        `json:"search_result_budget,omitempty"`
	CanaryID           string                     `json:"canary_id,omitempty"`
	SchemaVersion      string                     `json:"schema_version"`
	EventID            string                     `json:"event_id"`
	EventTime          time.Time                  `json:"event_time"`
	IngestTime         time.Time                  `json:"ingest_time"`
	SensorID           string                     `json:"sensor_id"`
	TenantID           string                     `json:"tenant_id"`
	AssetID            string                     `json:"asset_id"`
	EventType          string                     `json:"event_type"`
	RequestID          string                     `json:"request_id"`
	Method             string                     `json:"method"`
	Route              string                     `json:"route_template"`
	Status             int                        `json:"status"`
	Bytes              int64                      `json:"response_bytes"`
	Duration           float64                    `json:"duration_ms"`
	Principal          string                     `json:"principal_id"`
	SessionHMAC        string                     `json:"session_hmac"`
	SrcIP              string                     `json:"src_ip"`
	Identity           string                     `json:"identity_confidence"`
	TrustedProxy       bool                       `json:"trusted_proxy"`
	Authorization      string                     `json:"authorization_result"`
	Reason             string                     `json:"authorization_reason"`
	ResourceClass      string                     `json:"resource_class"`
	ResourceHMAC       string                     `json:"resource_hmac"`
	PathHMAC           string                     `json:"path_hmac"`
	KnownRoute         bool                       `json:"known_route"`
	DetectorFamily     string                     `json:"detector_family"`
	UAHint             string                     `json:"ua_hint"`
	DataQuality        string                     `json:"data_quality"`
	ProcessID          string                     `json:"process_id"`
	ContainerID        string                     `json:"container_id"`
}

var identifier = regexp.MustCompile(`^[A-Za-z0-9_.:/{}-]{1,128}$`)

// DecodeBatch applies the same required-field contract to every bounded item.
func DecodeBatch(r io.Reader) ([]Event, error) {
	return DecodeBatchLimit(r, 16)
}

// DecodeBatchLimit retains the full per-item contract for the explicit group route.
func DecodeBatchLimit(r io.Reader, limit int) ([]Event, error) {
	if limit != 16 && limit != 64 {
		return nil, errors.New("unsupported batch limit")
	}
	var raw []json.RawMessage
	d := json.NewDecoder(r)
	if err := d.Decode(&raw); err != nil {
		return nil, err
	}
	var extra any
	if d.Decode(&extra) != io.EOF || len(raw) == 0 || len(raw) > limit {
		return nil, errors.New("one bounded event batch required")
	}
	result := make([]Event, 0, len(raw))
	for _, item := range raw {
		e, err := Decode(strings.NewReader(string(item)))
		if err != nil {
			return nil, err
		}
		result = append(result, e)
	}
	return result, nil
}

func Decode(r io.Reader) (Event, error) {
	return decode(r, func() time.Time { return time.Now().UTC() })
}

// DecodeAt applies the event contract at an explicit observation time for
// offline replay. Live ingestion must continue to use Decode/DecodeBatch.
func DecodeAt(r io.Reader, now time.Time) (Event, error) {
	if now.IsZero() {
		return Event{}, errors.New("explicit event validation time required")
	}
	return decode(r, func() time.Time { return now })
}

func decode(r io.Reader, now func() time.Time) (Event, error) {
	var e Event
	var raw json.RawMessage
	first := json.NewDecoder(r)
	if err := first.Decode(&raw); err != nil {
		return e, err
	}
	var extra any
	if first.Decode(&extra) != io.EOF {
		return e, errors.New("one event required")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return e, err
	}
	for _, name := range []string{"schema_version", "event_id", "event_time", "ingest_time", "sensor_id", "tenant_id", "asset_id", "event_type", "request_id", "method", "route_template", "status", "response_bytes", "duration_ms", "identity_confidence", "trusted_proxy", "authorization_result", "known_route", "data_quality", "ua_hint", "detector_family"} {
		v, ok := fields[name]
		if !ok || string(v) == "null" {
			return e, errors.New("missing required field")
		}
	}
	if context, ok := fields["action_context"]; ok && string(context) == "null" {
		return e, errors.New("null action context")
	}
	d := json.NewDecoder(strings.NewReader(string(raw)))
	d.DisallowUnknownFields()
	if err := d.Decode(&e); err != nil {
		return e, err
	}
	return e, e.Validate(now())
}
func (e Event) Validate(now time.Time) error {
	if e.Context != nil {
		if err := e.Context.ValidateShape(e.ContextBinding()); err != nil {
			return err
		}
	}
	if err := e.validateExportApproval(); err != nil {
		return err
	}
	if err := e.validateResponseBudget(); err != nil {
		return err
	}
	if e.SearchPage != nil && e.SearchPage.Validate(e.SearchResultBudget) != nil {
		return errors.New("invalid search page evidence")
	}
	if e.SearchResultBudget != nil {
		b := e.SearchResultBudget
		if b.Validate() != nil || e.SensorID != "lab-app" || e.Route != "/api/search" || e.Identity != "authenticated" || e.DataQuality != "complete" || e.Budget != nil || e.CanaryID != "" ||
			(b.Decision == "deny" && (e.Status != 429 || e.Authorization != "deny" || e.Reason != "search-result-budget")) ||
			(b.Decision == "allow" && (e.Authorization != "allow" || (e.Status != 200 && e.Status != 499 && e.Status != 503) || (e.Status == 200 && e.Bytes != b.RequestedBytes))) ||
			(e.RequestBudget != nil && e.RequestBudget.Decision != "allow") {
			return errors.New("invalid search result evidence")
		}
	}
	if e.RequestBudget != nil {
		b := e.RequestBudget
		if b.Validate() != nil || e.SensorID != "lab-app" || e.Route != "/api/search" || e.Identity != "authenticated" || e.DataQuality != "complete" || e.Budget != nil || e.CanaryID != "" ||
			(b.Decision == "deny" && (e.Status != 429 || e.Authorization != "deny" || e.Reason != "request-budget")) ||
			(b.Decision == "allow" && (e.Status == 429 || e.Authorization != "allow") &&
				!(e.SearchResultBudget != nil && e.SearchResultBudget.Decision == "deny" && e.Status == 429 && e.Authorization == "deny" && e.Reason == "search-result-budget") &&
				!(e.ResponseBudget != nil && e.ResponseBudget.Decision == "deny" && e.Status == 429 && e.Authorization == "deny" && e.Reason == "response-budget")) {
			return errors.New("invalid request budget evidence")
		}
	}
	if e.Budget != nil {
		if e.Budget.Validate() != nil || e.Route != "/api/export" || e.Identity != "authenticated" || (e.Budget.Decision == "deny" && (e.Status != 429 || e.Authorization != "deny")) || (e.Budget.Decision == "allow" && (e.Status != 200 || e.Authorization != "allow")) {
			return errors.New("invalid export budget evidence")
		}
	}
	if e.CanaryID != "" && (!identifier.MatchString(e.CanaryID) || e.ResourceClass != "canary" || e.Authorization != "deny" || e.Route != "/internal/canary/{id}" || e.Budget != nil) {
		return errors.New("invalid canary evidence")
	}

	if e.SchemaVersion != "1.0" || e.EventType != "http" {
		return errors.New("unsupported schema/type")
	}
	for _, s := range []string{e.EventID, e.SensorID, e.TenantID, e.AssetID, e.RequestID, e.Route, e.Method} {
		if !identifier.MatchString(s) {
			return errors.New("invalid required identifier")
		}
	}
	for _, s := range []string{e.Principal, e.SessionHMAC, e.ResourceHMAC, e.PathHMAC, e.SrcIP, e.Method, e.Reason, e.ResourceClass, e.DetectorFamily, e.ProcessID, e.ContainerID} {
		if s != "" && !identifier.MatchString(s) {
			return errors.New("invalid optional identifier")
		}
	}
	if e.Status < 100 || e.Status > 599 || e.Bytes < 0 || e.Bytes > 1<<30 || e.Duration < 0 || e.Duration > 60000 {
		return errors.New("invalid HTTP measurements")
	}
	if e.IngestTime.IsZero() || e.EventTime.IsZero() || e.EventTime.After(now.Add(30*time.Second)) || e.EventTime.Before(now.Add(-time.Hour)) {
		return errors.New("event outside accepted one-hour window")
	}
	if e.Identity != "authenticated" && e.Identity != "anonymous" {
		return errors.New("invalid identity confidence")
	}
	if e.Identity == "authenticated" && (e.Principal == "" || e.SessionHMAC == "") {
		return errors.New("verified identity required")
	}
	if e.Authorization != "allow" && e.Authorization != "deny" && e.Authorization != "unknown" {
		return errors.New("explicit authorization required")
	}
	if e.DataQuality != "complete" && e.DataQuality != "partial" {
		return errors.New("explicit quality required")
	}
	if e.UAHint != "none" && e.UAHint != "enrich" && e.UAHint != "norma-unverified" {
		return errors.New("invalid UA hint")
	}
	return nil
}

// ContextBinding contains only authenticated request facts, never truth labels.
func (e Event) ContextBinding() actioncontext.Binding {
	canonical := e
	canonical.Context = nil
	canonical.IngestTime = time.Time{}
	return actioncontext.Binding{EventSHA: actioncontext.Digest(canonical), EventID: e.EventID, Tenant: e.TenantID, Asset: e.AssetID, Sensor: e.SensorID, Principal: e.Principal, Session: e.SessionHMAC, Route: e.Route, Method: e.Method, Resource: e.ResourceHMAC, ResourceClass: e.ResourceClass, Authorization: e.Authorization, Status: e.Status, ValidationFamily: e.DetectorFamily, CanaryID: e.CanaryID, Identity: e.Identity, Quality: e.DataQuality, At: e.EventTime}
}
