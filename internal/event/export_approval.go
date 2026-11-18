package event

import (
	"bytes"
	"encoding/json"
	"errors"
	"regexp"
)

var approvalID = regexp.MustCompile(`^[0-9a-f]{32}$`)
var approvalJob = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// ExportApproval is a committed, one-use reservation in a separate local
// operator grant ledger. It does not grant object permissions or policy power.
type ExportApproval struct {
	Schema      string `json:"schema"`
	ApprovalID  string `json:"approval_id"`
	JobID       string `json:"job_id"`
	IssuedAt    int64  `json:"issued_at"`
	ExpiresAt   int64  `json:"expires_at"`
	ConsumedAt  int64  `json:"consumed_at"`
	LimitRows   int64  `json:"limit_rows"`
	LimitBytes  int64  `json:"limit_bytes"`
	Rows        int64  `json:"rows"`
	Bytes       int64  `json:"bytes"`
	SingleUse   bool   `json:"single_use"`
	PreResponse bool   `json:"pre_response"`
}

func (a *ExportApproval) UnmarshalJSON(data []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	for _, name := range []string{"schema", "approval_id", "job_id", "issued_at", "expires_at", "consumed_at", "limit_rows", "limit_bytes", "rows", "bytes", "single_use", "pre_response"} {
		if value, ok := fields[name]; !ok || bytes.Equal(value, []byte("null")) {
			return errors.New("missing export approval field")
		}
	}
	type plain ExportApproval
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	return d.Decode((*plain)(a))
}

func (e Event) validateExportApproval() error {
	a := e.ExportApproval
	if a == nil && e.Reason != "export-approval" {
		return nil
	}
	if e.SensorID != "lab-app" || e.AssetID != "lab-api" || e.Route != "/api/export" || e.Method != "GET" ||
		e.Identity != "authenticated" || e.DataQuality != "complete" || e.CanaryID != "" ||
		e.Budget != nil || e.ResponseBudget != nil || e.RequestBudget != nil || e.SearchResultBudget != nil || e.SearchPage != nil ||
		e.Reason != "export-approval" {
		return errors.New("invalid approval scope or mixed reservation")
	}
	if a == nil {
		if (e.Status != 403 && e.Status != 429) || e.Authorization != "deny" {
			return errors.New("missing committed export approval")
		}
		return nil
	}
	if a.Schema != "export-approval/1" || !approvalID.MatchString(a.ApprovalID) || !approvalJob.MatchString(a.JobID) ||
		!a.SingleUse || !a.PreResponse || e.Status != 200 || e.Authorization != "allow" || e.Bytes != a.Bytes ||
		a.IssuedAt < 0 || a.IssuedAt > 1<<53-3600 || a.ExpiresAt <= a.IssuedAt || a.ExpiresAt-a.IssuedAt > 3600 ||
		a.ConsumedAt < a.IssuedAt || a.ConsumedAt >= a.ExpiresAt || a.ConsumedAt > e.EventTime.Unix() || a.ConsumedAt < e.EventTime.Unix()-60 ||
		a.LimitRows < 1 || a.LimitRows > 10000 || a.LimitBytes < 12 || a.LimitBytes > 16777216 ||
		a.Rows < 0 || a.Rows > a.LimitRows || a.Bytes < 12 || a.Bytes > a.LimitBytes {
		return errors.New("invalid committed export approval")
	}
	return nil
}
