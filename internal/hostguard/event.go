// Package hostguard consumes normalized Linux observations, never shell commands
// or raw command lines, credentials, file contents, or attacker-selected targets.
package hostguard

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"time"
)

var ID = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)

type Event struct {
	SchemaVersion  string    `json:"schema_version"`
	EventID        string    `json:"event_id"`
	EventTime      time.Time `json:"event_time"`
	IngestTime     time.Time `json:"ingest_time"`
	SensorID       string    `json:"sensor_id"`
	TenantID       string    `json:"tenant_id"`
	AssetID        string    `json:"asset_id"`
	EventType      string    `json:"event_type"`
	ServiceID      string    `json:"service_id"`
	WorkloadID     string    `json:"workload_id"`
	ProcessKey     string    `json:"process_key"`
	ParentKey      string    `json:"parent_key"`
	Lineage        string    `json:"lineage"`
	Classification string    `json:"classification"`
	CanaryID       string    `json:"canary_id,omitempty"`
	RequestID      string    `json:"request_id,omitempty"`
	DataQuality    string    `json:"data_quality"`
}

func Decode(r io.Reader, now time.Time) (Event, error) {
	var e Event
	raw, err := io.ReadAll(io.LimitReader(r, 16385))
	if err != nil {
		return e, err
	}
	if len(raw) > 16384 {
		return e, errors.New("host event too large")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&e); err != nil {
		return e, err
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return e, errors.New("one bounded host event required")
	}
	return e, e.Validate(now)
}
func (e Event) Validate(now time.Time) error {
	if e.SchemaVersion != "host/1.0" {
		return errors.New("unsupported host schema")
	}
	for _, s := range []string{e.EventID, e.SensorID, e.TenantID, e.AssetID, e.ServiceID, e.WorkloadID, e.ProcessKey, e.ParentKey} {
		if !ID.MatchString(s) {
			return errors.New("invalid host identifier")
		}
	}
	if e.RequestID != "" && !ID.MatchString(e.RequestID) {
		return errors.New("invalid optional request link")
	}
	if e.EventTime.IsZero() || e.IngestTime.IsZero() || e.EventTime.Before(now.Add(-time.Hour)) || e.EventTime.After(now.Add(30*time.Second)) {
		return errors.New("host event outside accepted window")
	}
	if e.Lineage != "verified" && e.Lineage != "unknown" {
		return errors.New("explicit lineage required")
	}
	if e.DataQuality != "complete" && e.DataQuality != "partial" {
		return errors.New("explicit host quality required")
	}
	valid := false
	switch e.EventType {
	case "process_start":
		valid = e.Classification == "unexpected_child" || e.Classification == "expected_child"
	case "network_connect":
		valid = e.Classification == "unapproved_destination" || e.Classification == "allowed_destination"
	case "canary_access":
		valid = e.Classification == "canary" && ID.MatchString(e.CanaryID)
	}
	if !valid || (e.EventType != "canary_access" && e.CanaryID != "") {
		return errors.New("inconsistent host observation")
	}
	return nil
}
