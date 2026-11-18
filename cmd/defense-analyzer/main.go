// defense-analyzer replays owned evidence and runs a bounded fake investigator.
// Optional case-api mode reauthorizes tool reads with a durable B02 ledger.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"reverse-artex/internal/assistance"
	"reverse-artex/internal/casefile"
	"reverse-artex/internal/caseledger"
	"reverse-artex/internal/evidence"
	"reverse-artex/internal/investigation"
	"strings"
	"syscall"
	"time"
)

func bounded(path string, max int64) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	s, e := f.Stat()
	if e != nil || !s.Mode().IsRegular() || s.Size() > max {
		return nil, errors.New("bounded regular input required")
	}
	b, e := io.ReadAll(io.LimitReader(f, max+1))
	if len(b) > int(max) {
		return nil, errors.New("input limit")
	}
	return b, e
}
func run(args []string, out, errout io.Writer) error {
	f := flag.NewFlagSet("defense-analyzer", flag.ContinueOnError)
	f.SetOutput(errout)
	state := f.String("state", "", "B02-C durable ledger; required with case-api")
	api := f.String("case-api", "", "literal authenticated case API origin")
	tools := f.Bool("tools", false, "typed bounded case/time-window tools; optional authenticated API")
	input := f.String("input", "", "B03 context fixture")
	dir := f.String("evidence", "", "unchanged detector snapshot")
	ns := f.String("source-id", "", "offline source namespace")
	tenant := f.String("tenant", "", "explicit local operator scope; not authentication")
	at := f.String("at", "", "explicit historical RFC3339Nano as-of")
	scenario := f.String("fake", "ok", "bounded fake scenario; no model provider")
	previous := f.String("previous", "", "explicit B03 predecessor")
	head := f.String("expected-head", "", "DB predecessor commitment, not B03 parent")
	wal := f.String("policy-wal", "", "offline actions.jsonl for explicit policy replay")
	auditSource := f.String("audit-source", "", "existing legacy audit import identity")
	policyIDs := f.String("policy-ids", "", "comma-separated explicit policy selection")
	policyAt := f.String("policy-at", "", "explicit historical policy snapshot cutoff")
	agentDir := f.String("agent-dir", "", "private directory for host-operated sub-agent handoff")
	agentLabel := f.String("agent-label", "", "operator-declared hosted agent label; not verified identity")
	if e := f.Parse(args); e != nil {
		return e
	}
	if *agentDir != "" {
		if !*tools || *state == "" || *agentLabel == "" || *scenario != "ok" {
			return errors.New("hosted agent requires tools, state, agent-label and no fake scenario")
		}
	} else if *agentLabel != "" {
		return errors.New("agent label requires explicit handoff directory")
	} else if (*state == "") != (*api == "") {
		return errors.New("state and case-api required together")
	}
	if (*wal != "" && (!*tools || *auditSource == "" || *policyIDs == "" || *policyAt == "")) || (*wal == "" && (*auditSource != "" || *policyIDs != "" || *policyAt != "")) {
		return errors.New("policy replay requires tools, WAL, audit-source, policy-ids and policy-at")
	}
	when, e := time.Parse(time.RFC3339Nano, *at)
	if e != nil || f.NArg() != 0 || *input == "" || *dir == "" || *ns == "" || *tenant == "" {
		return errors.New("input, evidence, source-id, tenant and historical at required")
	}
	raw, e := bounded(*input, casefile.MaxBundle)
	if e != nil {
		return e
	}
	// Reuse strict B03 decode; never accept a serialized Prepared as proof.
	b, e := casefile.DecodeContext(bytes.NewReader(raw))
	if e != nil {
		return errors.New("case fixture refused")
	}
	var prior *casefile.ContextResult
	if *previous != "" {
		raw, e = bounded(*previous, casefile.MaxPrevious)
		if e != nil {
			return e
		}
		v, e := casefile.DecodePrevious(bytes.NewReader(raw))
		if e != nil {
			return errors.New("predecessor refused")
		}
		prior = &v
	}
	snap, e := evidence.Capture(*dir)
	if e != nil {
		return errors.New("evidence capture refused")
	}
	p, e := caseledger.Prepare(*ns, *tenant, b, prior, *head, when, snap)
	if e != nil {
		return errors.New("case replay refused")
	}
	c, e := investigation.FromPrepared(p)
	if e != nil {
		return e
	}
	if *wal != "" {
		cut, err := time.Parse(time.RFC3339Nano, *policyAt)
		if err != nil {
			return errors.New("valid policy cutoff required")
		}
		h, err := caseledger.PreparePolicyHistory(p, snap, *wal, *auditSource, strings.Split(*policyIDs, ","), cut)
		if err != nil {
			return err
		}
		c, e = investigation.FromPreparedPolicyHistory(p, h)
		if e != nil {
			return e
		}
	}
	if *agentDir != "" {
		return runHostedAgent(*state, *api, *agentDir, *agentLabel, c, out)
	}
	if *api != "" {
		return runBridge(*state, *api, *scenario, c, out, *tools)
	}
	var report investigation.Report
	if *tools {
		report, e = investigation.RunToolsFake(context.Background(), c, investigation.NewBudget(), nil, *scenario)
	} else {
		report, e = investigation.RunFake(context.Background(), c, investigation.NewBudget(), *scenario)
	}
	if e != nil {
		return e
	}
	if e = json.NewEncoder(out).Encode(report); e != nil {
		return e
	}
	if !report.Completed {
		return errors.New("investigation incomplete; review required")
	}
	return nil
}

func runHostedAgent(state, origin, directory, label string, source *investigation.Case, out io.Writer) error {
	absolute, err := filepath.Abs(directory)
	if err != nil {
		return errors.New("private agent directory required")
	}
	agent, err := investigation.NewAgentHandoff(absolute, label)
	if err != nil {
		return err
	}
	var client *investigation.APIClient
	if origin != "" {
		client, err = investigation.NewAPIClient(origin, os.Getenv("RA_CASE_READER_TOKEN"))
		if err != nil {
			return err
		}
		defer client.Close()
	}
	controller, err := assistance.OpenHostedAgent(state, client, source, agent)
	if err != nil {
		return err
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = controller.Close(ctx)
	}()
	cfg := assistance.DefaultConfig()
	cfg.Assistance.Investigator.Enabled = true
	cfg.Assistance.Investigator.Provider = assistance.FakeSpec{Kind: assistance.HostedAgent, Scenario: "hosted"}
	if _, err = controller.Apply(cfg, "hosted-agent-operator"); err != nil {
		return err
	}
	job, err := controller.SubmitHostedAgent()
	if err != nil {
		return err
	}
	stopCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(stopCtx, 60*time.Second)
	defer cancel()
	if err = controller.Wait(ctx); err != nil {
		return errors.New("hosted agent investigation deadline or unavailable")
	}
	view := controller.Inspect()
	for _, j := range view.State.Jobs {
		if j.ID == job.ID {
			job = j
			break
		}
	}
	mode := "hosted-agent-offline-replay"
	if client != nil {
		mode = "hosted-agent-authenticated-case"
	}
	err = json.NewEncoder(out).Encode(struct {
		Scope    string           `json:"scope"`
		Job      assistance.Job   `json:"job"`
		Usage    assistance.Usage `json:"shared_usage"`
		Requests int64            `json:"hosted_handoff_requests"`
	}{mode, job, view.State.Window.Usage, view.HostedRequests})
	if err != nil {
		return err
	}
	if job.Phase != "done" || len(job.Attempts) == 0 || job.Attempts[len(job.Attempts)-1].Result == nil {
		return errors.New("hosted agent investigation incomplete; review required")
	}
	return nil
}
func main() {
	if e := run(os.Args[1:], os.Stdout, os.Stderr); e != nil {
		fmt.Fprintln(os.Stderr, "defense-analyzer refused:", e)
		os.Exit(2)
	}
}

func runBridge(state, origin, scenario string, source *investigation.Case, out io.Writer, tools bool) error {
	client, e := investigation.NewAPIClient(origin, os.Getenv("RA_CASE_READER_TOKEN"))
	if e != nil {
		return e
	}
	defer client.Close()
	var controller *assistance.Controller
	if tools {
		controller, e = assistance.OpenCaseTools(state, client, source)
	} else {
		controller, e = assistance.OpenCaseAPI(state, client, source)
	}
	if e != nil {
		return e
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = controller.Close(ctx)
	}()
	config := assistance.DefaultConfig()
	config.Assistance.Investigator.Enabled = true
	config.Assistance.Investigator.Provider.Kind = assistance.CaseAPI
	if tools {
		config.Assistance.Investigator.Provider.Kind = assistance.CaseTools
	}
	config.Assistance.Investigator.Provider.Scenario = scenario
	if _, e = controller.Apply(config, "local-case-api"); e != nil {
		return e
	}
	job, e := controller.SubmitCaseAPI()
	if e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if e = controller.Wait(ctx); e != nil {
		return errors.New("case API investigation wait failed")
	}
	view := controller.Inspect()
	for _, j := range view.State.Jobs {
		if j.ID == job.ID {
			job = j
			break
		}
	}
	label := "authenticated-case-api-fake"
	if tools {
		label = "authenticated-case-tools-fake"
	}
	if e = json.NewEncoder(out).Encode(struct {
		Scope string           `json:"scope"`
		Job   assistance.Job   `json:"job"`
		Usage assistance.Usage `json:"shared_usage"`
	}{label, job, view.State.Window.Usage}); e != nil {
		return e
	}
	if job.Phase != "done" || len(job.Attempts) == 0 || job.Attempts[len(job.Attempts)-1].Result == nil {
		return errors.New("investigation incomplete; review required")
	}
	return nil
}
