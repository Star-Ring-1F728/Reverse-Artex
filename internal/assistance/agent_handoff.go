package assistance

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"

	"reverse-artex/internal/investigation"
)

const HostedAgent = "hosted-agent-handoff"

// OpenHostedAgent opts in to a host-operated file transport. A nil API client
// means explicitly replayed offline evidence, not authenticated remote data.
func OpenHostedAgent(path string, client *investigation.APIClient, source *investigation.Case, agent *investigation.AgentHandoff) (*Controller, error) {
	if agent == nil {
		return nil, errors.New("explicit hosted agent handoff required")
	}
	return openCaseReaderAgent(path, client, source, true, agent)
}
func (c *Controller) SubmitHostedAgent() (Job, error) {
	if c.options.bridge == nil || c.options.bridge.agent == nil {
		return Job{}, errors.New("explicit hosted agent controller required")
	}
	return c.SubmitCaseAPI()
}

type hostedInvestigator struct {
	b *bridgeOptions
	m *metrics
}

func (p *hostedInvestigator) Investigate(ctx context.Context, call Call) ([]byte, error) {
	p.m.investigationCalls.Add(1)
	if !reflect.DeepEqual(call.Snapshot, p.b.snapshot) {
		return nil, errors.New("bound hosted agent scope required")
	}
	report, err := investigation.RunAgentHandoff(ctx, p.b.source, investigation.NewBudget(), p.b.client, p.b.agent)
	if err != nil || !report.Completed || ctx.Err() != nil || report.Agent == nil {
		return nil, errors.New("hosted agent investigation incomplete")
	}
	r := Result{Schema: "mock-assistance-result/1", Kind: Investigation, Epoch: call.Epoch, Hash: call.Hash, Conclusion: "unknown", Complete: true, Evidence: report.Refs, Agent: report.Agent, AgentDisposition: report.Outcome}
	r.Reads = &ReadSummary{Trace: report.Trace, ObservationGaps: report.ObservationGaps, Contested: report.Contested, Historical: true, PartialRead: report.PartialRead, UnavailableTools: report.UnavailableTools, PolicyHistoryAvailable: report.PolicyHistoryAvailable, PolicyBindingSHA: report.PolicyBindingSHA}
	return json.Marshal(r)
}
