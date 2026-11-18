// defense-v2 accesses the explicit local V2 runtime; V1 defense-mode is unchanged.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"reverse-artex/internal/responsev2"
	"time"
)

type l3ManagementCommand struct {
	Tenant     string `json:"tenant,omitempty"`
	CaseID     string `json:"case_id,omitempty"`
	CaseSHA    string `json:"case_sha256,omitempty"`
	RequestID  string `json:"request_id,omitempty"`
	Mode       string `json:"mode,omitempty"`
	SourceRun  string `json:"source_run,omitempty"`
	Run        string `json:"run_id,omitempty"`
	Epoch      int    `json:"epoch,omitempty"`
	Generation int    `json:"generation,omitempty"`
}

func run(args []string, out io.Writer) error {
	f := flag.NewFlagSet("defense-v2", flag.ContinueOnError)
	endpoint := f.String("endpoint", "http://127.0.0.1:9086", "literal loopback V2 management origin")
	action := f.String("action", "status", "status|cases|case|policies|run-decisions|job|apply|release|pause|resume|run-l3|l3-run|cancel-l3|release-l3|outcome")
	tokenEnv := f.String("token-env", "RA_V2_OPERATOR_TOKEN", "server operator or reader credential environment variable")
	tenant := f.String("tenant", "", "exact configured tenant")
	caseID := f.String("case", "", "current case ID")
	sha := f.String("case-sha", "", "current case SHA")
	id := f.String("id", "", "exact job, run, or policy ID")
	candidate := f.String("candidate", "", "server candidate ID")
	requestID := f.String("request-id", "", "stable request/intent ID; generated if empty")
	ownerRun := f.String("owner-run", "", "operator-owned response run")
	mode := f.String("mode", "analyze", "L3 mode: analyze|contain|release")
	sourceRun := f.String("source-run", "", "exact source L3 run for release")
	episode := f.String("episode", "", "exact policy episode for outcome")
	epoch := f.Int("epoch", 0, "current cancellation epoch")
	generation := f.Int("generation", 0, "exact policy generation for release")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return errors.New("unexpected arguments")
	}
	u, err := url.Parse(*endpoint)
	if err != nil || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" || u.Port() == "" {
		return errors.New("literal loopback origin required")
	}
	ip := net.ParseIP(u.Hostname())
	if ip == nil || !ip.IsLoopback() {
		return errors.New("local management endpoint required")
	}
	method := "GET"
	path := "/v2/" + *action
	values := url.Values{"tenant": []string{*tenant}}
	if *caseID != "" {
		values.Set("id", *caseID)
	}
	if *action == "job" {
		values.Set("id", *id)
	}
	if *action == "l3-run" {
		if *tenant == "" || *id == "" {
			return errors.New("tenant and exact L3 run ID are required")
		}
		path = "/v2/l3-run"
		values.Set("id", *id)
	}
	if *action == "outcome" {
		if *tenant == "" || *id == "" || *episode == "" {
			return errors.New("tenant, exact policy ID, and episode are required")
		}
		path = "/v2/outcome"
		values.Set("id", *id)
		values.Set("episode", *episode)
	}
	c := responsev2.Command{Tenant: *tenant, CaseID: *caseID, CaseSHA: *sha, RequestID: *requestID, PolicyID: *id, Owner: "operator", Run: *ownerRun, Generation: *generation}
	var payload any
	switch *action {
	case "status", "cases", "case", "policies", "job", "l3-run", "outcome":
	case "run-decisions", "apply", "release", "pause", "resume", "run-l3", "cancel-l3", "release-l3":
		method = "POST"
		if *action != "cancel-l3" && c.RequestID == "" {
			raw := make([]byte, 16)
			if _, err = rand.Read(raw); err != nil {
				return err
			}
			c.RequestID = "cli-" + hex.EncodeToString(raw)
		}
		switch *action {
		case "run-decisions":
			path = "/v2/decisions"
			payload = c
		case "apply":
			c.Intent = &responsev2.Intent{ID: c.RequestID, CaseID: *caseID, CaseSHA: *sha, CandidateID: *candidate, Owner: "operator", Run: *ownerRun, Epoch: *epoch}
			payload = c
		case "run-l3":
			if *tenant == "" || *caseID == "" || *sha == "" {
				return errors.New("tenant, case, and case SHA are required")
			}
			if *mode != "analyze" && *mode != "contain" && *mode != "release" {
				return errors.New("L3 mode must be analyze, contain, or release")
			}
			if (*mode == "release") != (*sourceRun != "") {
				return errors.New("release mode requires exactly one source run")
			}
			path = "/v2/l3"
			payload = l3ManagementCommand{Tenant: *tenant, CaseID: *caseID, CaseSHA: *sha, RequestID: c.RequestID, Mode: *mode, SourceRun: *sourceRun}
		case "cancel-l3":
			if *tenant == "" || *id == "" {
				return errors.New("tenant and exact L3 run ID are required")
			}
			path = "/v2/l3-cancel"
			payload = l3ManagementCommand{Tenant: *tenant, Run: *id}
		case "release-l3":
			if *tenant == "" || *sourceRun == "" || *sha == "" || *epoch < 1 || *generation < 1 {
				return errors.New("tenant, source run, case SHA, positive epoch, and generation are required")
			}
			path = "/v2/l3-release"
			payload = l3ManagementCommand{Tenant: *tenant, SourceRun: *sourceRun, CaseSHA: *sha, RequestID: c.RequestID, Epoch: *epoch, Generation: *generation}
		default:
			payload = c
		}
	default:
		return errors.New("unsupported action")
	}
	var body io.Reader
	if method == "POST" {
		raw, _ := json.Marshal(payload)
		body = bytes.NewReader(raw)
	} else {
		path += "?" + values.Encode()
	}
	token := os.Getenv(*tokenEnv)
	if len(token) < 32 {
		return errors.New("management credential not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, method, *endpoint+path, body)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	resp, err := client.Do(req)
	if err != nil {
		return errors.New("management outcome unknown; inspect exact intent before retry")
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if err != nil || len(raw) > 1<<20 {
		return errors.New("invalid management response")
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("v2 management rejected request (HTTP %d)", resp.StatusCode)
	}
	_, err = out.Write(raw)
	return err
}
func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "defense-v2:", err)
		os.Exit(2)
	}
}
