package assistance

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"

	"reverse-artex/internal/investigation"
)

const CaseAPI = "case-api-fake"
const CaseTools = "case-tools-fake"

type bridgeOptions struct {
	agent    *investigation.AgentHandoff
	client   *investigation.APIClient
	source   *investigation.Case
	snapshot Snapshot
	tools    bool
}

// OpenCaseAPI is explicit opt-in. It accepts a replay-verified source and a
// restricted client, never an arbitrary provider factory. Caller owns client.
func OpenCaseAPI(path string, client *investigation.APIClient, source *investigation.Case) (*Controller, error) {
	return openCaseReader(path, client, source, false)
}
func OpenCaseTools(path string, client *investigation.APIClient, source *investigation.Case) (*Controller, error) {
	return openCaseReader(path, client, source, true)
}
func openCaseReader(path string, client *investigation.APIClient, source *investigation.Case, tools bool) (*Controller, error) {
	return openCaseReaderAgent(path, client, source, tools, nil)
}
func openCaseReaderAgent(path string, client *investigation.APIClient, source *investigation.Case, tools bool, agent *investigation.AgentHandoff) (*Controller, error) {
	if (client == nil && agent == nil) || source == nil {
		return nil, errors.New("replayed source and case API required")
	}
	scope, asset, refs := source.CoordinatorMetadata()
	snapshot := Snapshot{CaseID: scope.Case, Revision: scope.Revision, QuestionSet: "case-api-v1", Tenant: scope.Tenant, Asset: asset, Evidence: refs, RequiresInvestigation: true, SourceCommit: scope.Commit}
	if tools {
		snapshot.QuestionSet = "case-tools-v1"
		if sha := source.PolicyHistorySHA(); sha != "" {
			snapshot.QuestionSet = "case-tools-v2"
			snapshot.PolicyHistorySHA = sha
		}
	}
	if agent != nil {
		snapshot.QuestionSet = "case-agent-v1"
		snapshot.AgentSpecSHA = agent.Spec().SHA256()
	}
	if snapshot.Validate() != nil {
		return nil, errors.New("case exceeds coordinator scope")
	}
	s, e := openStore(path)
	if e != nil {
		return nil, e
	}
	opts := options{bridge: &bridgeOptions{client: client, source: source, snapshot: snapshot, tools: tools, agent: agent}}
	c, e := openController(s, opts)
	if e != nil {
		s.close()
	}
	return c, e
}
func (c *Controller) SubmitCaseAPI() (Job, error) {
	if c.options.bridge == nil {
		return Job{}, errors.New("case API bridge required")
	}
	return c.Submit(c.options.bridge.snapshot)
}
func bridgeFactories(m *metrics, b *bridgeOptions) factories {
	f := fakeFactories(m)
	fallback := f.investigation
	f.investigation = func(s FakeSpec) (InvestigationProvider, error) {
		if s.Kind == HostedAgent {
			if b.agent == nil {
				return nil, errors.New("explicit hosted agent open required")
			}
			m.investigationInit.Add(1)
			return &hostedInvestigator{b, m}, nil
		}
		if s.Kind != CaseAPI && s.Kind != CaseTools {
			return fallback(s)
		}
		if (s.Kind == CaseTools) != b.tools {
			// Forward upgrade reads the existing ledger without discarding its
			// legacy charges. Submit still requires an explicit matching mode.
			if b.tools && s.Kind == CaseAPI {
				old := *b
				old.tools = false
				old.snapshot.QuestionSet = "case-api-v1"
				old.snapshot.PolicyHistorySHA = ""
				old.snapshot.AgentSpecSHA = ""
				m.investigationInit.Add(1)
				return &apiInvestigator{&old, s.Scenario, m}, nil
			}
			return nil, errors.New("explicit matching case reader required")
		}
		if b.agent != nil {
			old := *b
			old.agent = nil
			old.snapshot.AgentSpecSHA = ""
			old.snapshot.QuestionSet = "case-tools-v1"
			if old.snapshot.PolicyHistorySHA != "" {
				old.snapshot.QuestionSet = "case-tools-v2"
			}
			m.investigationInit.Add(1)
			return &apiInvestigator{&old, s.Scenario, m}, nil
		}
		m.investigationInit.Add(1)
		return &apiInvestigator{b, s.Scenario, m}, nil
	}
	return f
}

type apiInvestigator struct {
	b        *bridgeOptions
	scenario string
	m        *metrics
}

func (p *apiInvestigator) Investigate(ctx context.Context, call Call) ([]byte, error) {
	p.m.investigationCalls.Add(1)
	if !reflect.DeepEqual(call.Snapshot, p.b.snapshot) {
		return nil, errors.New("bound replay scope required")
	}
	var report investigation.Report
	var e error
	if p.b.tools {
		report, e = investigation.RunToolsFake(ctx, p.b.source, investigation.NewBudget(), p.b.client, p.scenario)
	} else {
		report, e = investigation.RunAPIFake(ctx, p.b.source, investigation.NewBudget(), p.b.client, p.scenario)
	}
	if e != nil || !report.Completed || ctx.Err() != nil {
		return nil, errors.New("case API investigation incomplete")
	}
	// Semantic model quality is unmeasured; never upgrade to supported/benign.
	r := Result{Schema: "mock-assistance-result/1", Kind: Investigation, Epoch: call.Epoch, Hash: call.Hash, Conclusion: "unknown", Complete: true, Evidence: report.Refs}
	if p.b.tools {
		r.Reads = &ReadSummary{Trace: report.Trace, ObservationGaps: report.ObservationGaps, Contested: report.Contested, Historical: true, PartialRead: report.PartialRead, UnavailableTools: report.UnavailableTools, PolicyHistoryAvailable: report.PolicyHistoryAvailable, PolicyBindingSHA: report.PolicyBindingSHA}
	}
	return json.Marshal(r)
}
func chargeFor(kind string, s Snapshot, module Module) Usage {
	if kind == Investigation && module.Provider.Kind == HostedAgent {
		return Usage{HostedRequests: 4, Calls: 4, Tools: 8, InputBytes: 4 * investigation.MaxAgentPacket, OutputBytes: 4 * MaxOutput}
	}
	if kind == Investigation && (module.Provider.Kind == CaseAPI || module.Provider.Kind == CaseTools) {
		return Usage{Calls: 4, Tools: 8, Tokens: 2048, Cost: 400, InputBytes: 4 * MaxSnapshot, OutputBytes: 4 * MaxOutput}
	}
	return charge(kind, s)
}

func bridgeScenario(s string) bool {
	switch s {
	case "ok", "unknown", "malformed", "injection", "cross-tenant", "stale", "forged-ref", "early-final", "timeout", "refusal", "panic":
		return true
	}
	return false
}
