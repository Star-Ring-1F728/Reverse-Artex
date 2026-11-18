package assistance

import (
	"context"
	"encoding/json"
	"errors"
	"reverse-artex/internal/decisions"
	"sort"
	"sync"
	"time"
)

var ErrUnavailable = errors.New("assistance unavailable; base path is independent")
var ErrCapacity = errors.New("bounded assistance capacity exhausted")

type options struct {
	bridge                                *bridgeOptions
	clock                                 func() time.Time
	decisionTimeout, investigationTimeout time.Duration
	factories                             factories
	noWorkers                             bool
}
type lease struct {
	job           string
	index, epoch  int
	kind, tenant  string
	call          Call
	ctx           context.Context
	cancel        context.CancelFunc
	decision      DecisionProvider
	investigation InvestigationProvider
}
type Controller struct {
	mu              sync.Mutex
	applyMu         sync.Mutex
	state           State
	store           stateStore
	options         options
	metrics         *metrics
	decision        DecisionProvider
	investigation   InvestigationProvider
	active          map[string]*lease
	lastTenant      map[string]string
	parentClocks    map[string]time.Time
	decisionClocks  map[string]time.Time
	wake            map[string]chan struct{}
	stop            chan struct{}
	changed         chan struct{}
	workersDone     chan struct{}
	wg              sync.WaitGroup
	closing, closed bool
	storageErr      error
}

func Open(path string) (*Controller, error) {
	s, err := openStore(path)
	if err != nil {
		return nil, err
	}
	c, err := openController(s, options{})
	if err != nil {
		s.close()
	}
	return c, err
}
func openController(store stateStore, o options) (*Controller, error) {
	if o.clock == nil {
		o.clock = func() time.Time { return time.Now().UTC() }
	}
	if o.decisionTimeout == 0 {
		o.decisionTimeout = 3 * time.Second
	}
	if o.investigationTimeout == 0 {
		o.investigationTimeout = 20 * time.Second
	}
	m := &metrics{}
	if o.bridge != nil {
		o.factories = bridgeFactories(m, o.bridge)
	}
	if o.factories.decision == nil && o.factories.investigation == nil {
		o.factories = fakeFactories(m)
	}
	c := &Controller{store: store, options: o, metrics: m, active: map[string]*lease{}, lastTenant: map[string]string{}, wake: map[string]chan struct{}{Decision: make(chan struct{}, 1), Investigation: make(chan struct{}, 1)}, stop: make(chan struct{}), changed: make(chan struct{}), workersDone: make(chan struct{})}
	c.parentClocks, c.decisionClocks = map[string]time.Time{}, map[string]time.Time{}
	s, exists, err := store.load()
	if err != nil {
		return nil, err
	}
	if !exists {
		cfg := DefaultConfig()
		s = State{Schema: "assistance-state/1", Epoch: 1, Config: cfg, Activations: []Activation{{1, cfg, "local-bootstrap"}}, Jobs: []Job{}, Parents: map[string]Parent{}, Window: Window{Tenants: map[string]Usage{}}, Breakers: map[string]Breaker{Decision: {}, Investigation: {}}}
	}
	if err = validateState(s); err != nil {
		return nil, err
	}
	recovered := false
	for i := range s.Jobs {
		j := &s.Jobs[i]
		if pending(j.Phase) {
			recovered = true
			j.Phase, j.Outcome, j.PendingReview = "interrupted", "unknown", true
			for a := range j.Attempts {
				if j.Attempts[a].Outcome == "running" {
					j.Attempts[a].Outcome = "interrupted"
				}
			}
		}
	}
	if !exists || recovered {
		if err = store.save(s); err != nil {
			return nil, err
		}
	}
	d, p, err := c.prepare(s.Config)
	if err != nil {
		return nil, err
	}
	c.state, c.decision, c.investigation = s, d, p
	if !o.noWorkers {
		for _, kind := range []string{Decision, Investigation} {
			c.wg.Add(1)
			go c.loop(kind)
		}
	}
	go func() { c.wg.Wait(); close(c.workersDone) }()
	return c, nil
}
func (c *Controller) prepare(cfg Config) (DecisionProvider, InvestigationProvider, error) {
	var d DecisionProvider
	var p InvestigationProvider
	var err error
	if cfg.Assistance.Decisions.Enabled {
		if c.options.factories.decision == nil {
			return nil, nil, ErrUnavailable
		}
		d, err = c.options.factories.decision(cfg.Assistance.Decisions.Provider)
		if err != nil || d == nil {
			return nil, nil, errors.New("decisions preparation failed")
		}
	}
	if cfg.Assistance.Investigator.Enabled {
		if c.options.factories.investigation == nil {
			return nil, nil, ErrUnavailable
		}
		p, err = c.options.factories.investigation(cfg.Assistance.Investigator.Provider)
		if err != nil || p == nil {
			return nil, nil, errors.New("investigator preparation failed")
		}
	}
	return d, p, nil
}
func (c *Controller) notifyLocked() {
	close(c.changed)
	c.changed = make(chan struct{})
	for _, kind := range []string{Decision, Investigation} {
		select {
		case c.wake[kind] <- struct{}{}:
		default:
		}
	}
}
func (c *Controller) commitLocked(s State) error {
	if err := c.store.save(s); err != nil {
		c.storageErr = err
		c.notifyLocked()
		return ErrUnavailable
	}
	c.state = s
	c.notifyLocked()
	return nil
}

// Apply is a local operator action. Prepare first, persist the new epoch and
// cancellations together, publish only on success, then signal cancellation.
func (c *Controller) Apply(cfg Config, actor string) (int, error) {
	if cfg.Validate() != nil || !identifier.MatchString(actor) {
		return 0, errors.New("invalid local mode activation")
	}
	c.applyMu.Lock()
	defer c.applyMu.Unlock()
	c.mu.Lock()
	if c.closing || c.storageErr != nil {
		c.mu.Unlock()
		return 0, ErrUnavailable
	}
	if cfg == c.state.Config {
		epoch := c.state.Epoch
		c.mu.Unlock()
		return epoch, nil
	}
	if c.state.Epoch >= MaxEpochs {
		c.mu.Unlock()
		return 0, ErrCapacity
	}
	c.mu.Unlock()
	d, p, err := c.prepare(cfg)
	if err != nil {
		return 0, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closing || c.storageErr != nil {
		return 0, ErrUnavailable
	}
	next := cloneState(c.state)
	next.Epoch++
	next.Config = cfg
	next.Activations = append(next.Activations, Activation{next.Epoch, cfg, actor})
	next.Breakers = map[string]Breaker{Decision: {}, Investigation: {}}
	for i := range next.Jobs {
		j := &next.Jobs[i]
		if pending(j.Phase) {
			j.Phase, j.Outcome, j.PendingReview = "cancelled", "unknown", true
			for a := range j.Attempts {
				if j.Attempts[a].Outcome == "running" {
					j.Attempts[a].Outcome = "cancelled"
				}
			}
		}
	}
	if err = c.commitLocked(next); err != nil {
		return 0, err
	}
	c.decision, c.investigation = d, p
	for _, lease := range c.active {
		lease.cancel()
	}
	return next.Epoch, nil
}

func (c *Controller) Submit(s Snapshot) (Job, error) {
	if err := s.Validate(); err != nil {
		return Job{}, err
	}
	// Freeze slices owned by the caller before queuing or hashing.
	s = freezeSnapshot(s)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closing || c.storageErr != nil {
		return Job{}, ErrUnavailable
	}
	id := s.key(c.state.Epoch)
	if c.options.bridge != nil && s.SourceCommit != "" && (s.QuestionSet == "case-api-v1" || s.QuestionSet == "case-tools-v1" || s.QuestionSet == "case-tools-v2" || s.QuestionSet == "case-agent-v1") {
		expected := CaseAPI
		if s.QuestionSet == "case-tools-v1" || s.QuestionSet == "case-tools-v2" {
			expected = CaseTools
		}
		if s.QuestionSet == "case-agent-v1" {
			expected = HostedAgent
		}
		if !c.state.Config.Assistance.Investigator.Enabled || c.state.Config.Assistance.Investigator.Provider.Kind != expected {
			return Job{}, errors.New("matching case reader mode required")
		}
	}
	for _, j := range c.state.Jobs {
		if (s.SourceCommit != "" || j.Snapshot.SourceCommit != "") && s.Tenant == j.Snapshot.Tenant && s.CaseID == j.Snapshot.CaseID && s.Asset != j.Snapshot.Asset {
			return Job{}, errors.New("case asset identity changed")
		}
		if j.ID == id {
			if j.Hash != hash(s) {
				return Job{}, errors.New("snapshot identity reused with changed evidence")
			}
			return copyJob(j), nil
		}
	}
	if len(c.state.Jobs) >= MaxJobs {
		return Job{}, ErrCapacity
	}
	if _, ok := c.state.Parents[s.parent()]; !ok && len(c.state.Parents) >= MaxParents {
		return Job{}, ErrCapacity
	}
	phase, outcome := "done", "base_only"
	cfg := c.state.Config
	if cfg.Assistance.Investigator.Enabled && (!cfg.Assistance.Decisions.Enabled || s.HighRisk) {
		phase = "queued_investigator"
		outcome = "queued"
	} else if cfg.Assistance.Decisions.Enabled {
		phase = "queued_decisions"
		outcome = "queued"
	}
	if phase != "done" && !queueHasCapacity(c.state.Jobs, s) {
		return Job{}, ErrCapacity
	}
	now := c.options.clock().UTC()
	parent, exists := c.state.Parents[s.parent()]
	if !exists {
		parent = Parent{Deadline: now.Add(60 * time.Second)}
	}
	if !now.Before(parent.Deadline) {
		return Job{}, ErrCapacity
	}
	j := Job{ID: id, Epoch: c.state.Epoch, Snapshot: s, Hash: hash(s), Enqueued: now, Deadline: parent.Deadline, Phase: phase, Outcome: outcome, PendingReview: s.RequiresInvestigation, Attempts: []Attempt{}}
	if s.QuestionSet == decisions.QuestionVersion && sampleAudit(s) {
		j.PendingReview = true
	}
	next := cloneState(c.state)
	next.Jobs = append(next.Jobs, j)
	if _, ok := next.Parents[s.parent()]; !ok {
		next.Parents[s.parent()] = parent
	}
	if err := c.commitLocked(next); err != nil {
		return Job{}, err
	}
	if _, ok := c.parentClocks[s.parent()]; !ok {
		remaining := parent.Deadline.Sub(now)
		if remaining > 60*time.Second {
			remaining = 60 * time.Second
		}
		c.parentClocks[s.parent()] = time.Now().Add(remaining)
	}
	c.decisionClocks[j.ID] = time.Now().Add(5 * time.Second)
	return copyJob(j), nil
}

func queueHasCapacity(jobs []Job, s Snapshot) bool {
	queued, tenantQueued, normal := 0, 0, 0
	for _, j := range jobs {
		if j.Phase != "queued_decisions" && j.Phase != "queued_investigator" {
			continue
		}
		queued++
		if j.Snapshot.Tenant == s.Tenant {
			tenantQueued++
		}
		if !j.Snapshot.HighRisk {
			normal++
		}
	}
	return queued < MaxQueue && tenantQueued < TenantQueue && (s.HighRisk || normal < MaxQueue-HighReserve)
}

// The caller has removed j from its previous queued/running phase. A
// continuation shares admission limits with new submissions; completed work
// and its charge remain recorded even when no queue slot is available.
func queueInvestigation(s *State, j *Job) {
	if queueHasCapacity(s.Jobs, j.Snapshot) {
		j.Phase, j.Outcome = "queued_investigator", "queued"
		return
	}
	j.Phase, j.Outcome, j.PendingReview = "done", "queue_capacity", true
	b := s.Breakers[Investigation]
	b.Last = "queue_capacity"
	s.Breakers[Investigation] = b
}

func copyJob(j Job) Job {
	data, _ := json.Marshal(j)
	var out Job
	_ = json.Unmarshal(data, &out)
	return out
}
func (c *Controller) loop(kind string) {
	defer c.wg.Done()
	for {
		if lease := c.next(kind); lease != nil {
			c.execute(lease)
			continue
		}
		select {
		case <-c.stop:
			return
		case <-c.wake[kind]:
		}
	}
}

func (c *Controller) pickLocked(kind string) int {
	if len(c.active) >= 2 || c.active[kind] != nil {
		return -1
	}
	busy := map[string]bool{}
	for _, lease := range c.active {
		busy[lease.tenant] = true
	}
	eligible := map[string]int{}
	for i, j := range c.state.Jobs {
		if j.Phase != "queued_"+kind || busy[j.Snapshot.Tenant] {
			continue
		}
		old, ok := eligible[j.Snapshot.Tenant]
		if !ok || (j.Snapshot.HighRisk && !c.state.Jobs[old].Snapshot.HighRisk) {
			eligible[j.Snapshot.Tenant] = i
		}
	}
	keys := []string{}
	for tenant := range eligible {
		keys = append(keys, tenant)
	}
	sort.Strings(keys)
	if len(keys) == 0 {
		return -1
	}
	for _, tenant := range keys {
		if tenant > c.lastTenant[kind] {
			return eligible[tenant]
		}
	}
	return eligible[keys[0]]
}
func (c *Controller) next(kind string) *lease {
	c.mu.Lock()
	defer c.mu.Unlock()
	for {
		if c.closing || c.storageErr != nil {
			return nil
		}
		index := c.pickLocked(kind)
		if index < 0 {
			return nil
		}
		next := cloneState(c.state)
		j := &next.Jobs[index]
		now := c.options.clock().UTC()
		deadline := j.Deadline
		limit := c.options.investigationTimeout
		if kind == Investigation && next.Config.Assistance.Investigator.Provider.Kind == HostedAgent {
			limit = 60 * time.Second
		}
		if kind == Decision {
			d := j.Enqueued.Add(5 * time.Second)
			if d.Before(deadline) {
				deadline = d
			}
			limit = c.options.decisionTimeout
		}
		blocked := ""
		if !now.Before(deadline) {
			blocked = "queue_deadline"
		}
		if b := next.Breakers[kind]; now.Before(b.Until) {
			blocked = "circuit_open"
		}
		if next.Window.Start.IsZero() || !now.Before(next.Window.Start.Add(time.Hour)) {
			next.Window = Window{Start: now, Tenants: map[string]Usage{}}
		}
		u := chargeFor(kind, j.Snapshot, next.Config.module(kind))
		parent := next.Parents[j.Snapshot.parent()]
		parent.Usage = parent.Usage.add(u)
		global := next.Window.Usage.add(u)
		tenant := next.Window.Tenants[j.Snapshot.Tenant].add(u)
		remaining := deadline.Sub(now)
		if real, ok := c.parentClocks[j.Snapshot.parent()]; ok && time.Until(real) < remaining {
			remaining = time.Until(real)
		}
		if real, ok := c.decisionClocks[j.ID]; kind == Decision && ok && time.Until(real) < remaining {
			remaining = time.Until(real)
		}
		if remaining <= 0 {
			blocked = "queue_deadline"
		}
		if !parentAllows(parent.Usage) || !windowAllows(global) || tenant.Calls > 30 ||
			(next.Window.Tenants[j.Snapshot.Tenant].Calls == 0 && len(next.Window.Tenants) >= 16) {
			blocked = "budget_exhausted"
		}
		if blocked != "" {
			b := next.Breakers[kind]
			b.Last = blocked
			next.Breakers[kind] = b
			j.Phase, j.Outcome, j.PendingReview = "done", blocked, true
			if kind == Decision && next.Config.Assistance.Investigator.Enabled {
				queueInvestigation(&next, j)
			}
			if c.commitLocked(next) != nil {
				return nil
			}
			continue
		}
		j.Phase = "running_" + kind
		j.Outcome = "running"
		j.Attempts = append(j.Attempts, Attempt{Kind: kind, Started: now, Window: next.Window.Start, Charge: u, Outcome: "running"})
		next.Parents[j.Snapshot.parent()] = parent
		next.Window.Usage = global
		next.Window.Tenants[j.Snapshot.Tenant] = tenant
		if remaining > limit {
			remaining = limit
		}
		ctx, cancel := context.WithTimeout(context.Background(), remaining)
		lease := &lease{job: j.ID, index: len(j.Attempts) - 1, epoch: j.Epoch, kind: kind, tenant: j.Snapshot.Tenant, call: Call{Snapshot: j.Snapshot, Epoch: j.Epoch, Hash: j.Hash, Enqueued: j.Enqueued, Expires: decisionDeadline(*j)}, ctx: ctx, cancel: cancel, decision: c.decision, investigation: c.investigation}
		if c.commitLocked(next) != nil {
			cancel()
			return nil
		}
		c.active[kind] = lease
		c.lastTenant[kind] = j.Snapshot.Tenant
		c.notifyLocked()
		return lease
	}
}

type returned struct {
	data     []byte
	err      error
	panicked bool
}

func (c *Controller) execute(lease *lease) {
	defer lease.cancel()
	done := make(chan returned, 1)
	go func() {
		r := returned{}
		providerCall := lease.call
		providerCall.Snapshot = freezeSnapshot(lease.call.Snapshot)
		defer func() {
			if recover() != nil {
				r.panicked = true
			}
			done <- r
		}()
		if lease.kind == Decision {
			r.data, r.err = lease.decision.Decide(lease.ctx, providerCall)
		} else {
			r.data, r.err = lease.investigation.Investigate(lease.ctx, providerCall)
		}
	}()
	var result returned
	late := false
	select {
	case result = <-done:
		if lease.ctx.Err() != nil {
			late = true
			result.err = lease.ctx.Err()
		}
		c.finish(lease, result)
	case <-lease.ctx.Done():
		c.finish(lease, returned{err: lease.ctx.Err()})
		result = <-done
		late = true
	}
	// A timeout/cancel does not release physical concurrency while a provider
	// still runs. The result channel and the number of such calls stay bounded.
	c.mu.Lock()
	defer c.mu.Unlock()
	if late {
		next := cloneState(c.state)
		for i := range next.Jobs {
			if next.Jobs[i].ID == lease.job {
				next.Jobs[i].Attempts[lease.index].Late = true
			}
		}
		_ = c.commitLocked(next)
	}
	delete(c.active, lease.kind)
	c.notifyLocked()
}
func (c *Controller) finish(lease *lease, r returned) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.storageErr != nil {
		return
	}
	next := cloneState(c.state)
	var j *Job
	for i := range next.Jobs {
		if next.Jobs[i].ID == lease.job {
			j = &next.Jobs[i]
			break
		}
	}
	if j == nil {
		return
	}
	a := &j.Attempts[lease.index]
	if j.Epoch != next.Epoch || j.Phase == "cancelled" || c.closing {
		a.Late = true
		_ = c.commitLocked(next)
		return
	}
	outcome := "ok"
	var parsed *Result
	switch {
	case r.panicked:
		outcome = "panic"
	case errors.Is(r.err, context.DeadlineExceeded):
		outcome = "timeout"
	case errors.Is(r.err, context.Canceled):
		outcome = "cancelled"
	case errors.Is(r.err, errRefusal):
		outcome = "refusal"
	case errors.Is(r.err, errRateLimited):
		outcome = "rate_limited"
	case errors.Is(r.err, decisions.ErrStale):
		outcome = "stale"
	case r.err != nil:
		outcome = "error"
	default:
		v, err := decodeResult(r.data, lease.kind, lease.call)
		if err != nil {
			outcome = "invalid"
			if errors.Is(err, decisions.ErrStale) {
				outcome = "stale"
			}
		} else {
			parsed = &v
		}
	}
	a.Outcome, a.Result = outcome, parsed
	b := next.Breakers[lease.kind]
	b.Last = outcome
	if outcome == "ok" {
		b.Failures = 0
		b.Until = time.Time{}
	} else {
		b.Failures++
		if b.Failures >= 3 {
			b.Failures = 3
			b.Until = c.options.clock().Add(5 * time.Second)
		}
	}
	next.Breakers[lease.kind] = b
	j.Phase, j.Outcome = "done", outcome
	if outcome != "ok" {
		j.PendingReview = true
	}
	if parsed != nil && (!parsed.Complete || parsed.Conclusion == "unknown" || parsed.Conclusion == "insufficient" || (lease.kind == Decision && parsed.Conclusion == "review")) {
		j.PendingReview = true
		if parsed.Conclusion == "unknown" || parsed.Conclusion == "insufficient" {
			j.Outcome = "unknown"
		}
	}
	if j.Outcome == "unknown" {
		b := next.Breakers[lease.kind]
		b.Last = "unknown"
		next.Breakers[lease.kind] = b
	}
	if lease.kind == Decision {
		audit := j.Snapshot.QuestionSet == decisions.QuestionVersion && sampleAudit(j.Snapshot)
		if audit {
			j.PendingReview = true
		}
		if next.Config.Assistance.Investigator.Enabled && (audit || j.Snapshot.RequiresInvestigation || outcome != "ok" || (parsed != nil && parsed.Conclusion != "benign")) {
			queueInvestigation(&next, j)
		}
	} else if outcome == "ok" && parsed != nil && !parsed.Complete {
		if len(j.Attempts) < 4 && next.Parents[j.Snapshot.parent()].Usage.Calls < 4 {
			queueInvestigation(&next, j)
		} else {
			j.Outcome, j.PendingReview = "budget_exhausted", true
		}
	}
	_ = c.commitLocked(next)
}

type Health struct {
	Status  string  `json:"status"`
	Active  int     `json:"active"`
	Breaker Breaker `json:"breaker"`
}
type View struct {
	DecisionRouting             []RoutingReceipt `json:"decision_routing,omitempty"`
	HostedRequests              int64            `json:"hosted_handoff_requests,omitempty"`
	State                       State            `json:"state"`
	Profile                     string           `json:"profile"`
	BaseRequired                bool             `json:"base_required"`
	BaseHealth                  string           `json:"base_health"`
	EvidenceHealth              string           `json:"evidence_health"`
	ResponseHealth              string           `json:"response_health"`
	StorageHealth               string           `json:"assistance_storage_health"`
	Decisions                   Health           `json:"decisions_health"`
	Investigator                Health           `json:"investigator_health"`
	DecisionInitializations     int64            `json:"decision_initializations"`
	InvestigatorInitializations int64            `json:"investigator_initializations"`
	DecisionCalls               int64            `json:"mock_decision_calls"`
	InvestigatorCalls           int64            `json:"mock_investigator_calls"`
	ExternalCalls               int              `json:"external_model_calls"`
	PolicyMutations             int              `json:"policy_mutations"`
}

func (c *Controller) Inspect() View {
	c.mu.Lock()
	defer c.mu.Unlock()
	health := func(kind string) Health {
		h := Health{Status: "off", Breaker: c.state.Breakers[kind]}
		if c.state.Config.module(kind).Enabled {
			h.Status = "ready"
			if h.Breaker.Failures > 0 || h.Breaker.Last == "unknown" || h.Breaker.Last == "budget_exhausted" || h.Breaker.Last == "queue_deadline" || h.Breaker.Last == "queue_capacity" {
				h.Status = "degraded"
			}
		}
		if c.active[kind] != nil {
			h.Active = 1
		}
		return h
	}
	storage := "ready"
	if c.storageErr != nil {
		storage = "degraded"
	}
	var hosted int64
	if c.options.bridge != nil && c.options.bridge.agent != nil {
		hosted = c.options.bridge.agent.Requests()
	}
	return View{DecisionRouting: routingFor(c.state), HostedRequests: hosted, State: cloneState(c.state), Profile: c.state.Config.Profile(), BaseRequired: true, BaseHealth: "not_monitored", EvidenceHealth: "not_monitored", ResponseHealth: "not_monitored", StorageHealth: storage, Decisions: health(Decision), Investigator: health(Investigation), DecisionInitializations: c.metrics.decisionInit.Load(), InvestigatorInitializations: c.metrics.investigationInit.Load(), DecisionCalls: c.metrics.decisionCalls.Load(), InvestigatorCalls: c.metrics.investigationCalls.Load()}
}
func (c *Controller) Wait(ctx context.Context) error {
	for {
		c.mu.Lock()
		busy := len(c.active) > 0
		for _, j := range c.state.Jobs {
			busy = busy || pending(j.Phase)
		}
		changed := c.changed
		err := c.storageErr
		c.mu.Unlock()
		if err != nil {
			return ErrUnavailable
		}
		if !busy {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-changed:
		}
	}
}
func (c *Controller) Close(ctx context.Context) error {
	c.applyMu.Lock()
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		c.applyMu.Unlock()
		return nil
	}
	if !c.closing {
		c.closing = true
		next := cloneState(c.state)
		for i := range next.Jobs {
			j := &next.Jobs[i]
			if pending(j.Phase) {
				j.Phase, j.Outcome, j.PendingReview = "cancelled", "unknown", true
				for a := range j.Attempts {
					if j.Attempts[a].Outcome == "running" {
						j.Attempts[a].Outcome = "cancelled"
					}
				}
			}
		}
		_ = c.commitLocked(next)
		for _, l := range c.active {
			l.cancel()
		}
		close(c.stop)
		c.notifyLocked()
	}
	c.mu.Unlock()
	c.applyMu.Unlock()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.workersDone:
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	return c.store.close()
}
