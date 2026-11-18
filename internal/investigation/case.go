// Package investigation implements fake-only investigations with offline replay
// and an optional explicitly configured authenticated case API reader.
package investigation

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"

	"reverse-artex/internal/caseledger"
)

const MaxView = 16384

type Scope struct {
	Tenant   string `json:"tenant"`
	Case     string `json:"case"`
	Revision int    `json:"revision"`
	Commit   string `json:"commit"`
}
type Fact struct {
	Ref     string `json:"ref"`
	Asset   string `json:"asset"`
	Stream  string `json:"stream"`
	LineSHA string `json:"line_sha256"`
	Status  int    `json:"http_status"`
}
type Case struct {
	detail     detail
	firstAsset string
	scope      Scope
	facts      []Fact
	assets     []string
	quality    string
	gaps       bool
	contested  bool
}

func hash(v any) string {
	b, _ := json.Marshal(v)
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// Only a private Prepared produced by B04 replay can enter this boundary.
// JSON plans/read API dumps are not accepted as replay proofs.
func FromPrepared(p *caseledger.Prepared) (*Case, error) {
	if p == nil {
		return nil, errors.New("replayed case required")
	}
	return fromReview(p.Review())
}

func fromReview(r caseledger.Review) (*Case, error) {
	v := r.Plan
	if r.SHA256 == "" || v.Schema != "case-ledger-plan/1" || len(v.Commit.Assets) == 0 {
		return nil, errors.New("replayed case required")
	}
	e := v.Context.Document.Envelope
	c := &Case{firstAsset: v.Commit.Assets[0], scope: Scope{v.Commit.Tenant, v.Commit.CaseID, v.Commit.Revision, v.CommitSHA}, quality: e.Quality, gaps: e.Quality != "complete"}
	// Asset names, owner IDs, request IDs, principals and free text are withheld.
	for _, a := range v.Commit.Assets {
		c.assets = append(c.assets, hash(a))
	}
	statuses := map[string]int{}
	for _, x := range e.HTTP.Evidence {
		statuses[x.ID] = x.Status
	}
	for _, x := range v.Source.Bindings {
		c.facts = append(c.facts, Fact{x.RefID, hash(x.Asset), x.Stream, x.LineSHA, statuses[x.RefID]})
	}
	if len(c.facts) == 0 || len(c.facts) > 128 {
		return nil, errors.New("bounded evidence required")
	}
	for _, x := range e.HTTP.Coverage {
		if x.Status != "observed" {
			c.gaps = true
		}
	}
	for _, x := range e.Coverage {
		if x.Status != "observed" {
			c.gaps = true
		}
	}
	for _, x := range e.Hypotheses {
		if x.Status == "contested" {
			c.contested = true
		}
	}
	sort.Strings(c.assets)
	if e := c.buildDetail(r); e != nil {
		return nil, e
	}
	return c, nil
}
func (c *Case) Scope() Scope { return c.scope }

type toolView struct {
	Scope     Scope    `json:"scope"`
	Tool      string   `json:"tool"`
	Available bool     `json:"available"`
	Quality   string   `json:"quality"`
	Gaps      bool     `json:"observation_gaps"`
	Contested bool     `json:"contested"`
	Assets    []string `json:"assets"`
	Facts     []Fact   `json:"facts"`
}

func (c *Case) read(scope Scope, tool string) ([]byte, []string, error) {
	if scope != c.scope {
		return nil, nil, errors.New("scope refused")
	}
	v := toolView{Scope: c.scope, Tool: tool, Available: true, Quality: c.quality, Gaps: c.gaps, Contested: c.contested, Assets: []string{}, Facts: []Fact{}}
	var refs []string
	switch tool {
	case "get_case":
	case "query_events":
		v.Facts = append(v.Facts, c.facts...)
		for _, f := range c.facts {
			refs = append(refs, f.Ref)
		}
	case "get_asset_context":
		v.Assets = append(v.Assets, c.assets...)
	case "get_sensor_health": // Snapshot coverage, never a live health assertion.
	case "get_policy_history":
		v.Available = false
	default:
		return nil, nil, errors.New("tool refused")
	}
	data, _ := json.Marshal(v)
	if len(data) > MaxView {
		return nil, nil, errors.New("tool view limit")
	}
	return data, refs, nil
}

// CoordinatorMetadata is for the trusted ledger, never sent to the provider.
func (c *Case) CoordinatorMetadata() (Scope, string, []string) {
	refs := []string{}
	for _, f := range c.facts {
		refs = append(refs, f.Ref)
	}
	return c.scope, c.firstAsset, refs
}
