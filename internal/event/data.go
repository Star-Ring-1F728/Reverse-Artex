package event

import "errors"

// Budget describes a server-side reservation checked before response bytes.
// Used values are the account totals BEFORE this request; sessions are irrelevant.
type Budget struct {
	Measurement    string `json:"measurement"`
	Decision       string `json:"decision"`
	RequestedRows  int64  `json:"requested_rows"`
	RequestedBytes int64  `json:"requested_bytes"`
	UsedRows       int64  `json:"used_rows"`
	UsedBytes      int64  `json:"used_bytes"`
	LimitRows      int64  `json:"limit_rows"`
	LimitBytes     int64  `json:"limit_bytes"`
	WindowSeconds  int64  `json:"window_seconds"`
	PreResponse    bool   `json:"pre_response"`
}

func (b Budget) Exceeded() bool {
	return b.RequestedRows > b.LimitRows-b.UsedRows || b.RequestedBytes > b.LimitBytes-b.UsedBytes
}
func (b Budget) Validate() error {
	if (b.Measurement != "exact" && b.Measurement != "lower_bound") || (b.Decision == "allow" && b.Measurement != "exact") {
		return errors.New("explicit budget measurement required")
	}

	if b.Decision != "allow" && b.Decision != "deny" {
		return errors.New("invalid budget decision")
	}
	for _, n := range []int64{b.RequestedRows, b.RequestedBytes, b.UsedRows, b.UsedBytes, b.LimitRows, b.LimitBytes} {
		if n < 0 || n > 1<<30 {
			return errors.New("invalid bounded budget measurement")
		}
	}
	if b.LimitRows < 1 || b.LimitBytes < 1 || b.WindowSeconds < 1 || b.WindowSeconds > 86400 || b.UsedRows > b.LimitRows || b.UsedBytes > b.LimitBytes || !b.PreResponse || (b.Decision == "deny") != b.Exceeded() {
		return errors.New("inconsistent pre-response budget")
	}
	return nil
}
