package investigation

import (
	"errors"
	"reverse-artex/internal/caseledger"
)

// FromPreparedPolicyHistory is explicit opt-in to a second sealed offline
// proof. An arbitrary server JSON response cannot enable policy history.
func FromPreparedPolicyHistory(p *caseledger.Prepared, h *caseledger.PreparedPolicyHistory) (*Case, error) {
	if p == nil || h == nil {
		return nil, errors.New("replayed case and policy history required")
	}
	c, err := FromPrepared(p)
	if err != nil {
		return nil, err
	}
	if err = c.bindPolicy(p.Review(), h.Review()); err != nil {
		return nil, err
	}
	return c, nil
}
func (c *Case) bindPolicy(r caseledger.Review, h caseledger.PolicyReview) error {
	rows, err := caseledger.ValidatePolicyHistory(r, h)
	if err != nil {
		return err
	}
	c.detail.policyHistory = &h
	for _, v := range rows {
		p := v.Policy
		c.detail.policies = append(c.detail.policies, PolicyOperation{hash(p.ID), hash(p.Asset), v.Operation, v.Time, p.Issued, p.Expires, hash(p.RuleVersion), hash(v.Epoch), v.Version, v.LineSHA, append([]string{}, v.Refs...)})
	}
	return nil
}
func (c *Case) PolicyHistorySHA() string {
	if c == nil || c.detail.policyHistory == nil {
		return ""
	}
	return c.detail.policyHistory.SHA256
}
