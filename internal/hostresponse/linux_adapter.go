package hostresponse

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"regexp"
	"reverse-artex/internal/decisions"
	"strconv"
	"time"
)

// LinuxScope is operator-pinned deployment identity, never a model or request
// supplied network target. Only one private interface/netns is supported.
type LinuxScope struct {
	Schema         string `json:"schema"`
	AgentID        string `json:"agent_id"`
	Namespace      string `json:"network_namespace"`
	BootID         string `json:"boot_id"`
	Tenant         string `json:"tenant_id"`
	Asset          string `json:"asset_id"`
	Workload       string `json:"workload_id"`
	Interface      string `json:"interface"`
	Index          int    `json:"interface_index"`
	ManagementIP   string `json:"management_ipv4"`
	ManagementPort int    `json:"management_port"`
}

func (s LinuxScope) Valid() bool {
	ip := net.ParseIP(s.ManagementIP)
	return s.Schema == "linux-isolation-scope/1" && regexp.MustCompile(`^[a-f0-9]{32}$`).MatchString(s.AgentID) && regexp.MustCompile(`^net:\[[0-9]+\]$`).MatchString(s.Namespace) && regexp.MustCompile(`^[a-f0-9-]{36}$`).MatchString(s.BootID) &&
		regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`).MatchString(s.Tenant) && regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`).MatchString(s.Asset) && regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`).MatchString(s.Workload) && regexp.MustCompile(`^[A-Za-z0-9_]{1,15}$`).MatchString(s.Interface) && s.Interface != "lo" && s.Index > 0 && ip != nil && ip.To4() != nil && !ip.IsLoopback() && !ip.IsUnspecified() && !ip.IsMulticast() && ip.String() == s.ManagementIP && s.ManagementPort > 0 && s.ManagementPort <= 65535
}
func (s LinuxScope) SHA() string {
	return digest([]string{s.Schema, s.AgentID, s.Namespace, s.BootID, s.Tenant, s.Asset, s.Workload, s.Interface, strconv.Itoa(s.Index), s.ManagementIP, strconv.Itoa(s.ManagementPort)})
}
func DecodeLinuxScope(raw []byte) (LinuxScope, error) {
	var s LinuxScope
	if decisions.DecodeStrict(raw, &s, 4096) != nil || !s.Valid() {
		return s, errors.New("pinned Linux network namespace scope required")
	}
	return s, nil
}

type LinuxAdapter struct {
	scope            LinuxScope
	reader, operator string
	http             *http.Client
}
type linuxReply struct {
	Schema   string `json:"schema"`
	ScopeSHA string `json:"scope_sha256"`
	Lease    Lease  `json:"lease"`
}

func NewLinuxAdapter(socket string, s LinuxScope, reader, operator string) (*LinuxAdapter, error) {
	if !s.Valid() || socket == "" || len(reader) < 32 || len(operator) < 32 || reader == operator {
		return nil, errors.New("explicit Linux socket, scope and distinct credentials required")
	}
	dialer := &net.Dialer{Timeout: 500 * time.Millisecond}
	tr := &http.Transport{Proxy: nil, DisableKeepAlives: true, DisableCompression: true, ResponseHeaderTimeout: time.Second, MaxResponseHeaderBytes: 4096, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return dialer.DialContext(ctx, "unix", socket)
	}}
	return &LinuxAdapter{s, reader, operator, &http.Client{Transport: tr, Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func (a *LinuxAdapter) Mode() string { return "linux-nftables-netns" }
func (a *LinuxAdapter) call(path, token string, input any) (Lease, error) {
	data, err := json.Marshal(input)
	if err != nil {
		return Lease{}, err
	}
	r, err := http.NewRequest("POST", "http://unix"+path, bytes.NewReader(data))
	if err != nil {
		return Lease{}, err
	}
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Content-Type", "application/json")
	res, err := a.http.Do(r)
	if err != nil {
		return Lease{}, errors.New("Linux isolation transport unavailable; outcome unknown")
	}
	defer res.Body.Close()
	if res.StatusCode != 200 || res.Header.Get("Content-Encoding") != "" {
		return Lease{}, errors.New("Linux isolation operation refused; outcome unknown")
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, 16385))
	if err != nil || len(raw) > 16384 {
		return Lease{}, errors.New("bounded Linux adapter response required")
	}
	var v linuxReply
	if decisions.DecodeStrict(raw, &v, 16384) != nil || v.Schema != "linux-isolation-reply/1" || v.ScopeSHA != a.scope.SHA() {
		return Lease{}, errors.New("Linux adapter scope binding changed")
	}
	return v.Lease, nil
}
func (a *LinuxAdapter) scopeMatches(l Lease) bool {
	return l.Tenant == a.scope.Tenant && l.Asset == a.scope.Asset && l.Workload == a.scope.Workload
}
func (a *LinuxAdapter) Status(l Lease, now time.Time) (Lease, error) {
	if !a.scopeMatches(l) {
		return Lease{}, errors.New("Linux lease outside pinned workload")
	}
	v, err := a.call("/v1/status", a.reader, l)
	if err == nil && !sameBinding(v, l) {
		err = errors.New("Linux status lease mismatch")
	}
	return v, err
}
func (a *LinuxAdapter) Apply(l Lease) error {
	if !a.scopeMatches(l) {
		return errors.New("Linux lease outside pinned workload")
	}
	v, err := a.call("/v1/apply", a.operator, l)
	if err == nil && (!sameBinding(v, l) || v.State != "active") {
		err = errors.New("Linux apply not confirmed")
	}
	return err
}
func (a *LinuxAdapter) Release(id string) error {
	_, err := a.call("/v1/release", a.operator, map[string]string{"action_id": id})
	return err
}
