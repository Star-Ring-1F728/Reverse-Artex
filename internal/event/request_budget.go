package event

import "errors"

// RequestBudget is one account-scoped search token reservation, separate from
// export bytes/rows and temporary policy denies. Credit is measured in ns: one
// request costs RefillSeconds * 1e9 units. No session or query is retained here.
type RequestBudget struct {
	Schema            string `json:"schema"`
	Action            string `json:"action"`
	Decision          string `json:"decision"`
	Capacity          int64  `json:"capacity"`
	RefillSeconds     int64  `json:"refill_seconds"`
	CreditNS          int64  `json:"credit_ns"`
	RetryAfterSeconds int64  `json:"retry_after_seconds"`
	PreResponse       bool   `json:"pre_response"`
}

func (b RequestBudget) Validate() error {
	if b.Schema != "search-request-budget/1" || !b.PreResponse || b.Capacity < 1 || b.Capacity > 10000 || b.RefillSeconds < 1 || b.RefillSeconds > 3600 {
		return errors.New("invalid search request budget profile")
	}
	unit := b.RefillSeconds * 1_000_000_000
	if b.CreditNS < 0 || b.CreditNS > b.Capacity*unit {
		return errors.New("invalid search request credit")
	}
	switch b.Decision {
	case "allow":
		if b.Action != "request_budget_admit" || b.RetryAfterSeconds != 0 || b.CreditNS > (b.Capacity-1)*unit {
			return errors.New("inconsistent request admission")
		}
	case "deny":
		minimum := (unit - b.CreditNS + 999_999_999) / 1_000_000_000
		// A conservative clock-rollback delay may make Retry-After larger.
		if b.Action != "request_rate_limit" || b.CreditNS >= unit || b.RetryAfterSeconds < minimum || b.RetryAfterSeconds > 86400 {
			return errors.New("inconsistent request rate limit")
		}
	default:
		return errors.New("invalid request budget decision")
	}
	return nil
}
