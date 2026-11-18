package event

import "errors"

// SearchResultBudget records account totals before this reservation. Bytes
// include the uncompressed JSON envelope, independently of request tokens.
type SearchResultBudget struct {
	Budget
	Schema        string `json:"schema"`
	ResponseRows  int64  `json:"response_rows"`
	ResponseBytes int64  `json:"response_bytes"`
}

func (b SearchResultBudget) Exceeded() bool {
	return b.Budget.Exceeded() || b.RequestedRows > b.ResponseRows || b.RequestedBytes > b.ResponseBytes
}

func (b SearchResultBudget) Validate() error {
	if b.Schema != "search-result-budget/1" || !b.PreResponse ||
		b.ResponseRows < 1 || b.ResponseRows > 10000 || b.ResponseRows > b.LimitRows ||
		b.ResponseBytes < 15 || b.ResponseBytes > 16777216 || b.ResponseBytes > b.LimitBytes ||
		b.LimitRows > 1000000 || b.LimitBytes > 1073741824 ||
		b.WindowSeconds < 1 || b.WindowSeconds > 86400 {
		return errors.New("invalid search result profile")
	}
	for _, n := range []int64{b.RequestedRows, b.RequestedBytes, b.UsedRows, b.UsedBytes, b.LimitRows, b.LimitBytes} {
		if n < 0 || n > 1<<30 {
			return errors.New("invalid search result measurement")
		}
	}
	if b.UsedRows > b.LimitRows || b.UsedBytes > b.LimitBytes ||
		b.RequestedRows > b.ResponseRows+1 || b.RequestedBytes < 15 ||
		(b.Measurement != "exact" && b.Measurement != "lower_bound") ||
		(b.Decision != "allow" && b.Decision != "deny") ||
		(b.Decision == "allow" && b.Measurement != "exact") ||
		(b.Decision == "deny") != b.Exceeded() {
		return errors.New("inconsistent search result reservation")
	}
	return nil
}
