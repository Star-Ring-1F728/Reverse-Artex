package investigation

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"reverse-artex/internal/caseledger"
)

const MaxProjection = 4096

// ProjectVerified is used only after the server's DB/RLS/full-history read.
// A projection alone is not a replay or authentication proof.
func ProjectVerified(s caseledger.Stored) ([]byte, error) {
	c, e := verifiedHead(s)
	if e != nil {
		return nil, e
	}
	return c.projection()
}
func verifiedHead(s caseledger.Stored) (*Case, error) {
	if len(s.Revisions) == 0 {
		return nil, errors.New("verified history required")
	}
	r := s.Revisions[len(s.Revisions)-1]
	if s.Head.CommitSHA != r.Plan.CommitSHA || s.Head.Tenant != r.Plan.Commit.Tenant || s.Head.Revision != r.Plan.Commit.Revision {
		return nil, errors.New("head mismatch")
	}
	c, e := fromReview(r)
	if e != nil {
		return nil, e
	}
	if s.PolicyHistory != nil {
		if e = c.bindPolicy(r, *s.PolicyHistory); e != nil {
			return nil, e
		}
	}
	return c, nil
}
func (c *Case) projection() ([]byte, error) {
	raw, _, e := c.read(c.scope, "query_events")
	if e != nil {
		return nil, e
	}
	var v toolView
	_ = json.Unmarshal(raw, &v)
	v.Assets = append([]string{}, c.assets...)
	raw, e = json.Marshal(v)
	if len(raw) > MaxProjection {
		return nil, errors.New("projection too large")
	}
	return raw, e
}

// APIClient has a pinned literal-IP origin, no proxy, redirects or cookies.
// The token never enters a provider input, ledger or returned error.
type APIClient struct {
	origin string
	token  string
	http   *http.Client
}

func NewAPIClient(origin, token string) (*APIClient, error) {
	u, e := url.Parse(origin)
	if e != nil || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" || (u.Path != "" && u.Path != "/") || u.RawPath != "" {
		return nil, errors.New("literal API origin required")
	}
	ip := net.ParseIP(u.Hostname())
	if ip == nil || !((u.Scheme == "http" && ip.IsLoopback()) || u.Scheme == "https") {
		return nil, errors.New("HTTPS or loopback HTTP required")
	}
	raw, e := base64.RawURLEncoding.Strict().DecodeString(token)
	if e != nil || len(raw) != 32 || len(token) != 43 {
		return nil, errors.New("bounded API token required")
	}
	tr := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: time.Second}).DialContext, ResponseHeaderTimeout: 2 * time.Second, TLSHandshakeTimeout: 2 * time.Second, DisableCompression: true, MaxResponseHeaderBytes: 8192, MaxConnsPerHost: 2, MaxIdleConnsPerHost: 2, IdleConnTimeout: 5 * time.Second}
	return &APIClient{u.Scheme + "://" + u.Host, token, &http.Client{Transport: tr, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func (a *APIClient) Close() { a.http.CloseIdleConnections() }
func (a *APIClient) read(ctx context.Context, c *Case, scope Scope, tool string) ([]byte, []string, error) {
	if scope != c.scope {
		return nil, nil, errors.New("scope refused")
	}
	// Check tool locally before emitting even an authenticated HTTP request.
	view, refs, e := c.read(scope, tool)
	if e != nil {
		return nil, nil, e
	}
	expected, e := c.projection()
	if e != nil {
		return nil, nil, e
	}
	target := a.origin + "/v1/tenants/" + url.PathEscape(scope.Tenant) + "/cases/" + url.PathEscape(scope.Case) + "/investigation"
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if e != nil {
		return nil, nil, errors.New("API request refused")
	}
	req.Header.Set("Authorization", "Bearer "+a.token)
	res, e := a.http.Do(req)
	if e != nil {
		return nil, nil, errors.New("case API unavailable")
	}
	defer res.Body.Close()
	if res.StatusCode != 200 || res.Header.Get("Content-Encoding") != "" {
		return nil, nil, errors.New("case API read refused")
	}
	raw, e := io.ReadAll(io.LimitReader(res.Body, MaxProjection+1))
	if e != nil || len(raw) > MaxProjection {
		return nil, nil, errors.New("case API response limit")
	}
	var v toolView
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&v) != nil {
		return nil, nil, errors.New("case API response refused")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return nil, nil, errors.New("case API response refused")
	}
	canonical, _ := json.Marshal(v)
	if !bytes.Equal(canonical, expected) {
		return nil, nil, errors.New("case API snapshot changed")
	}
	return view, refs, nil
}
func RunAPIFake(ctx context.Context, c *Case, b *Budget, a *APIClient, scenario string) (Report, error) {
	if a == nil {
		return Report{}, errors.New("case API required")
	}
	if !validScenario(scenario) {
		return Report{}, errors.New("unknown fake scenario")
	}
	return runWithReader(ctx, c, b, &fake{scenario: scenario}, func(ctx context.Context, s Scope, t string, q *Query) ([]byte, []string, error) {
		if q != nil {
			return nil, nil, ErrToolQuery
		}
		return a.read(ctx, c, s, t)
	}, 15*time.Second)
}

// ReadTool reauthorizes a typed query and compares the complete canonical page
// to the sealed replay before returning it. No remote free text enters a model.
func (a *APIClient) ReadTool(ctx context.Context, c *Case, r ToolRequest) ([]byte, []string, error) {
	expected, refs, e := c.ReadTool(r)
	if e != nil {
		return nil, nil, e
	}
	target := a.origin + "/v1/tenants/" + url.PathEscape(r.Scope.Tenant) + "/cases/" + url.PathEscape(r.Scope.Case) + "/investigation/tools/" + r.Tool + "?" + r.Values().Encode()
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if e != nil {
		return nil, nil, errors.New("tool request refused")
	}
	req.Header.Set("Authorization", "Bearer "+a.token)
	res, e := a.http.Do(req)
	if e != nil {
		return nil, nil, errors.New("case tool unavailable")
	}
	defer res.Body.Close()
	if res.StatusCode != 200 || res.Header.Get("Content-Encoding") != "" {
		return nil, nil, errors.New("case tool refused")
	}
	raw, e := io.ReadAll(io.LimitReader(res.Body, MaxProjection+1))
	if e != nil || len(raw) > MaxProjection {
		return nil, nil, errors.New("case tool response limit")
	}
	if !bytes.Equal(bytes.TrimSpace(raw), expected) {
		return nil, nil, errors.New("case tool snapshot changed")
	}
	return expected, refs, nil
}
