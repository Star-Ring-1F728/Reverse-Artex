package event

import "errors"

// ResponseBudget is shared by all supported data routes in one tenant/account.
// It includes the entire JSON body and is committed with route result debits.
type ResponseBudget struct {
	Budget
	Schema        string `json:"schema"`
	ResponseRows  int64  `json:"response_rows"`
	ResponseBytes int64  `json:"response_bytes"`
}

func (b ResponseBudget) Exceeded() bool {
	return b.Budget.Exceeded() || b.RequestedRows > b.ResponseRows || b.RequestedBytes > b.ResponseBytes
}

func (b ResponseBudget) Validate() error {
	if b.Schema != "response-budget/1" || !b.PreResponse ||
		b.ResponseRows < 1 || b.ResponseRows > 10000 || b.ResponseRows > b.LimitRows ||
		b.ResponseBytes < 15 || b.ResponseBytes > 16777216 || b.ResponseBytes > b.LimitBytes ||
		b.LimitRows > 1000000 || b.LimitBytes > 1073741824 || b.WindowSeconds < 1 || b.WindowSeconds > 86400 {
		return errors.New("invalid response budget profile")
	}
	for _, n := range []int64{b.RequestedRows, b.RequestedBytes, b.UsedRows, b.UsedBytes, b.LimitRows, b.LimitBytes} {
		if n < 0 || n > 1<<30 {
			return errors.New("invalid response measurement")
		}
	}
	if b.RequestedRows > 10000 || b.RequestedBytes < 12 || b.UsedRows > b.LimitRows || b.UsedBytes > b.LimitBytes ||
		(b.Measurement != "exact" && b.Measurement != "lower_bound") ||
		(b.Decision != "allow" && b.Decision != "deny") || (b.Decision == "allow" && b.Measurement != "exact") ||
		(b.Decision == "deny") != b.Exceeded() {
		return errors.New("inconsistent response reservation")
	}
	return nil
}

func (e Event) validateResponseBudget() error {
	b := e.ResponseBudget
	if b == nil {
		return nil
	}
	if b.Validate() != nil || e.SensorID != "lab-app" || e.Identity != "authenticated" || e.DataQuality != "complete" || e.CanaryID != "" {
		return errors.New("invalid shared response evidence")
	}
	switch e.Route {
	case "/api/search", "/api/export", "/api/objects/{id}", "/legacy/objects/{id}":
	default:
		return errors.New("unsupported response budget route")
	}
	if b.Decision == "deny" {
		if e.Status != 429 || e.Authorization != "deny" || e.Reason != "response-budget" || e.Budget != nil || e.SearchResultBudget != nil || e.SearchPage != nil {
			return errors.New("invalid shared response denial")
		}
	} else {
		if e.Authorization != "allow" || (e.Status != 200 && e.Status != 499 && e.Status != 503) ||
			(e.Status == 200 && e.Bytes != b.RequestedBytes) {
			return errors.New("invalid shared response allowance")
		}
		if e.Status == 200 && ((e.Route == "/api/search" && e.SearchResultBudget == nil) || (e.Route == "/api/export" && e.Budget == nil)) {
			return errors.New("missing route reservation")
		}
		if r := e.SearchResultBudget; r != nil && (r.Decision != "allow" || r.RequestedRows != b.RequestedRows || r.RequestedBytes != b.RequestedBytes) {
			return errors.New("inconsistent search/shared reservation")
		}
		if r := e.Budget; r != nil && (r.Decision != "allow" || r.RequestedRows != b.RequestedRows || r.RequestedBytes != b.RequestedBytes) {
			return errors.New("inconsistent export/shared reservation")
		}
	}
	return nil
}
