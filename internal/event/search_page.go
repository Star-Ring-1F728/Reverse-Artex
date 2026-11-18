package event

import (
	"bytes"
	"encoding/json"
	"errors"
)

// SearchPage contains aggregate pagination metadata, never cursor/row IDs,
// query fingerprints, query text, result values or additional policy authority.
type SearchPage struct {
	Schema    string `json:"schema"`
	PageLimit int64  `json:"page_limit"`
	Continued bool   `json:"continued"`
	HasMore   bool   `json:"has_more"`
}

func (p *SearchPage) UnmarshalJSON(data []byte) error {
	type plain SearchPage
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	for _, name := range []string{"schema", "page_limit", "continued", "has_more"} {
		value, ok := fields[name]
		if !ok || bytes.Equal(value, []byte("null")) {
			return errors.New("missing search page field")
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	return decoder.Decode((*plain)(p))
}

func (p SearchPage) Validate(b *SearchResultBudget) error {
	if p.Schema != "search-page/1" || b == nil || b.Decision != "allow" ||
		p.PageLimit < 1 || p.PageLimit > 10000 || p.PageLimit > b.ResponseRows ||
		b.RequestedRows > p.PageLimit || (p.HasMore && b.RequestedRows != p.PageLimit) {
		return errors.New("invalid search page observation")
	}
	return nil
}
