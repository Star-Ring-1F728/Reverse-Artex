package actionapproval

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
	"os"
	"time"

	"reverse-artex/internal/actionproposal"
	"reverse-artex/internal/caseledger"
	"reverse-artex/internal/control"
	"reverse-artex/internal/decisions"
)

// ExecutionAuthority is an operator-owned, reloadable public-key grant store.
// Removal/revocation is effective at the next read; it does not retract an
// already admitted remote request. Human identity/SSO is outside this contract.
type ExecutionAuthority struct {
	Schema    string `json:"schema"`
	Epoch     int    `json:"config_epoch"`
	AdapterID string `json:"adapter_id"`
	Trust     Trust  `json:"trust"`
}

type ExecutionServices struct {
	caseOrigin, controlOrigin, caseToken, adminToken, readerToken, authorityPath string
	http                                                                         *http.Client
}

func NewExecutionServices(caseOrigin, controlOrigin, caseToken, adminToken, readerToken, authorityPath string) (*ExecutionServices, error) {
	canonical := func(origin string) (string, error) {
		u, e := url.Parse(origin)
		if e != nil || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" || u.RawPath != "" || (u.Path != "" && u.Path != "/") {
			return "", errors.New("explicit service origin required")
		}
		ip := net.ParseIP(u.Hostname())
		if ip == nil || !(u.Scheme == "https" || (u.Scheme == "http" && ip.IsLoopback())) {
			return "", errors.New("literal HTTPS or loopback HTTP service required")
		}
		return u.Scheme + "://" + u.Host, nil
	}
	co, err := canonical(caseOrigin)
	if err != nil {
		return nil, err
	}
	po, err := canonical(controlOrigin)
	if err != nil {
		return nil, err
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(caseToken)
	validToken := func(s string) bool {
		if len(s) < 32 || len(s) > 512 {
			return false
		}
		for _, c := range s {
			if c < 33 || c > 126 {
				return false
			}
		}
		return true
	}
	if err != nil || len(raw) != 32 || len(caseToken) != 43 || !validToken(adminToken) || !validToken(readerToken) || adminToken == readerToken || caseToken == adminToken || caseToken == readerToken || authorityPath == "" || co == po {
		return nil, errors.New("distinct bounded service credentials and authority store required")
	}
	tr := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: time.Second}).DialContext, ResponseHeaderTimeout: time.Second, TLSHandshakeTimeout: time.Second, DisableCompression: true, MaxResponseHeaderBytes: 8192, MaxConnsPerHost: 2, MaxIdleConnsPerHost: 2, IdleConnTimeout: 5 * time.Second}
	return &ExecutionServices{co, po, caseToken, adminToken, readerToken, authorityPath, &http.Client{Transport: tr, Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func (s *ExecutionServices) Close() {
	if s != nil {
		s.http.CloseIdleConnections()
	}
}

func (s *ExecutionServices) authority() (ExecutionAuthority, error) {
	var a ExecutionAuthority
	info, err := os.Lstat(s.authorityPath)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 20<<10 {
		return a, errors.New("bounded operator authority file unavailable")
	}
	f, err := os.Open(s.authorityPath)
	if err != nil {
		return a, errors.New("authority store unavailable")
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, (20<<10)+1))
	if err != nil || decode(data, &a, 20<<10) != nil || a.Schema != "action-execution-authority/1" || a.Epoch < 1 || a.Epoch > 64 || !identifier.MatchString(a.AdapterID) || a.Trust.Validate() != nil {
		return a, errors.New("current execution authority rejected")
	}
	return a, nil
}

func (s *ExecutionServices) exchange(ctx context.Context, origin, path, token string, input, output any, limit int) error {
	var body io.Reader
	method := http.MethodGet
	if input != nil {
		raw, err := json.Marshal(input)
		if err != nil {
			return errors.New("service input rejected")
		}
		body = bytes.NewReader(raw)
		method = http.MethodPost
	}
	req, err := http.NewRequestWithContext(ctx, method, origin+path, body)
	if err != nil {
		return errors.New("service request rejected")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if input != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := s.http.Do(req)
	if err != nil {
		return errors.New("service transport unavailable; outcome unconfirmed")
	}
	defer res.Body.Close()
	if res.StatusCode != 200 || res.Header.Get("Content-Encoding") != "" {
		return errors.New("service request refused; outcome unconfirmed")
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, int64(limit+1)))
	if err != nil || decode(raw, output, limit) != nil {
		return errors.New("bounded service response rejected; outcome unconfirmed")
	}
	return nil
}

func (s *ExecutionServices) currentCase(ctx context.Context, r actionproposal.Request) (caseledger.ResponseContext, error) {
	var c caseledger.ResponseContext
	path := "/v1/tenants/" + url.PathEscape(r.Snapshot.Tenant) + "/cases/" + url.PathEscape(r.Snapshot.CaseID) + "/response-context"
	if err := s.exchange(ctx, s.caseOrigin, path, s.caseToken, nil, &c, 64<<10); err != nil {
		return c, err
	}
	if c.Schema != "case-response-context/1" || c.Head.Tenant != r.Snapshot.Tenant || c.Head.CaseID != r.Snapshot.CaseID || c.Head.Revision != r.Snapshot.Revision || c.Head.CommitSHA != r.Snapshot.SourceCommit || c.Quality != "complete" || len(c.Bindings) > 128 || r.Snapshot.Observation == nil || !c.Window.Start.Equal(r.Snapshot.Observation.From) || !c.Window.End.Equal(r.Snapshot.Observation.To) {
		return c, errors.New("current authenticated case differs from approved observation")
	}
	seen := map[string]bool{}
	for _, e := range r.Events {
		matched := 0
		for _, b := range c.Bindings {
			if b.Stream == "events" && b.EventID == e.EventID && b.Tenant == e.TenantID && b.Asset == e.AssetID && b.Sensor == e.SensorID && b.LineSHA == decisions.Hash(e) && b.Result == "accepted" {
				matched++
			}
		}
		if matched != 1 || seen[e.EventID] {
			return c, errors.New("proposal event differs from authenticated case source")
		}
		seen[e.EventID] = true
	}
	// No unrelated HTTP event for this asset may be omitted from the snapshot.
	for _, b := range c.Bindings {
		if b.Stream == "events" && b.Tenant == r.Snapshot.Tenant && b.Asset == r.Snapshot.Asset && !seen[b.EventID] {
			return c, errors.New("case contains additional unreviewed evidence")
		}
	}
	return c, nil
}

func (s *ExecutionServices) status(ctx context.Context, a control.ApprovedPolicy, apply bool) (control.ApprovedStatus, error) {
	var v control.ApprovedStatus
	path, token := "/v1/approved-policies/status", s.readerToken
	if apply {
		path, token = "/v1/approved-policies", s.adminToken
	}
	if err := s.exchange(ctx, s.controlOrigin, path, token, a, &v, 8<<10); err != nil {
		return v, err
	}
	if v.Schema != "approved-policy-status/1" || v.AdapterID != a.AdapterID || v.CommandSHA != decisions.Hash(a) || v.PolicyID != a.Policy.ID || v.Observed.IsZero() || (v.State != "not_applied" && v.State != "active" && v.State != "released") {
		return v, errors.New("adapter status binding rejected")
	}
	now := time.Now().UTC()
	if v.Observed.After(now.Add(time.Second)) || v.Observed.Before(now.Add(-3*time.Second)) || (v.State == "active" && !now.Before(a.Policy.Expires)) {
		return v, errors.New("adapter status expired")
	}
	return v, nil
}
