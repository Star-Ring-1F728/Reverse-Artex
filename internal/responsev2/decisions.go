package responsev2

import (
	"context"
	"encoding/json"
	"errors"
	"reverse-artex/internal/decisions"
	api "reverse-artex/internal/decisions/openai"
	"reverse-artex/internal/identity"
	"sort"
	"strings"
	"sync"
	"time"
)

type Job struct {
	ID              string      `json:"job_id"`
	Tenant          string      `json:"tenant"`
	CaseID          string      `json:"case_id"`
	CaseSHA         string      `json:"case_sha256"`
	Epoch           int         `json:"config_epoch"`
	ConfigSHA       string      `json:"provider_config_sha256"`
	Mode            string      `json:"mode"`
	Status          string      `json:"status"`
	Input           api.Input   `json:"redacted_input"`
	ReservedAt      time.Time   `json:"reserved_at"`
	ReservedTokens  int         `json:"reserved_tokens"`
	Result          *api.Result `json:"result,omitempty"`
	Receipt         *Receipt    `json:"policy_receipt,omitempty"`
	ReviewPreserved bool        `json:"mandatory_review_preserved"`
}
type Runner struct {
	store             *Store
	cfg               api.Config
	provider          api.Decider
	key               []byte
	queue             chan string
	ctx               context.Context
	cancel            context.CancelFunc
	wg                sync.WaitGroup
	mu                sync.Mutex
	failures          int
	circuit           time.Time
	credentialBlocked bool
	probe             string
}

func NewRunner(s *Store, cfg api.Config, pseudonymKey []byte, provider api.Decider) (*Runner, error) {
	if cfg.Validate() != nil || len(pseudonymKey) < 32 {
		return nil, api.ErrConfig
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := &Runner{store: s, cfg: cfg, key: append([]byte{}, pseudonymKey...), provider: provider, queue: make(chan string, 16), ctx: ctx, cancel: cancel}
	if cfg.Mode != "off" && cfg.Mode != "fake" && provider == nil {
		r.provider = api.New(func() string { return api.ResolveKey(cfg) })
	}
	s.mu.Lock()
	for _, j := range s.jobs {
		if j.ConfigSHA == decisions.Hash(cfg) && j.Result != nil && (j.Result.Status == "credential_error" || j.Status == "usage_over_reservation") {
			r.credentialBlocked = true
		}
	}
	history := []Job{}
	for _, j := range s.jobs {
		if j.ConfigSHA == decisions.Hash(cfg) {
			history = append(history, j)
		}
	}
	sort.Slice(history, func(i, j int) bool { return history[i].ReservedAt.Before(history[j].ReservedAt) })
	for _, j := range history {
		if j.Result == nil {
			continue
		}
		status := j.Result.Status
		if status == "ok" {
			r.failures = 0
			r.circuit = time.Time{}
		}
		if status == "transport_unknown" || status == "provider_error" || status == "rate_limited" {
			r.failures++
			if r.failures >= 3 {
				r.circuit = j.Result.Completed.Add(time.Minute)
			}
		}
	}
	s.mu.Unlock()
	if cfg.Mode != "off" {
		for n := 0; n < 2; n++ {
			r.wg.Add(1)
			go r.worker()
		}
	}
	return r, nil
}
func (r *Runner) Close() {
	r.cancel()
	r.wg.Wait()
	if c, ok := r.provider.(*api.Client); ok {
		c.Close()
	}
}
func (r *Runner) Enqueue(tenant, caseID, sha, id string) (Job, error) {
	if r.cfg.Mode == "off" {
		return Job{Status: "off", ReviewPreserved: true}, nil
	}
	if id == "" || len(id) > 128 || strings.IndexFunc(id, func(x rune) bool {
		return !((x >= 'a' && x <= 'z') || (x >= 'A' && x <= 'Z') || (x >= '0' && x <= '9') || x == '-' || x == '_')
	}) >= 0 {
		return Job{}, ErrStale
	}
	r.mu.Lock()
	blocked := r.credentialBlocked || time.Now().Before(r.circuit)
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		if r.probe == id {
			r.probe = ""
		}
		r.mu.Unlock()
	}()
	if blocked {
		return Job{}, errors.New("Decisions circuit open; no new dispatch")
	}
	s := r.store
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if err := s.check(now); err != nil {
		return Job{}, err
	}
	if old, ok := s.jobs[id]; ok {
		if old.Tenant != tenant || old.CaseID != caseID || old.CaseSHA != sha || old.ConfigSHA != decisions.Hash(r.cfg) {
			return Job{}, ErrStale
		}
		return clone(old), nil
	}
	if s.paused || r.ctx.Err() != nil || len(s.jobs) >= 1024 {
		return Job{}, ErrLimit
	}
	v, err := s.viewLocked(tenant, caseID, now)
	if err != nil || v.Case.SHA != sha {
		return Job{}, ErrStale
	}
	pending, tenantPending, calls, tokens := 0, 0, 0, 0
	day := now.UTC().Format("2006-01-02")
	for _, j := range s.jobs {
		if j.Status == "reserved" || j.Status == "dispatched" {
			pending++
			if j.Tenant == tenant {
				tenantPending++
			}
		}
		if j.ReservedAt.UTC().Format("2006-01-02") == day && !j.ResultSimulated() {
			calls++
			actual := j.ReservedTokens
			if j.Result != nil && j.Result.Usage != nil && j.Result.Usage.Total > actual {
				actual = j.Result.Usage.Total
			}
			tokens += actual
		}
	}
	if pending >= 16 || tenantPending >= 4 {
		return Job{}, ErrLimit
	}
	if r.cfg.Mode != "fake" && (calls >= r.cfg.DailyCalls || tokens+r.cfg.ReserveTokens > r.cfg.DailyTokens) {
		return Job{}, ErrLimit
	}
	input := api.Input{Schema: "decision-input/2", CaseID: caseID, CaseSHA: sha, Revision: v.Case.Revision, Epoch: s.epoch, Tenant: identity.Pseudonym("tenant:"+tenant, r.key), Asset: identity.Pseudonym("asset:"+tenant+":"+v.Case.Asset, r.key), Facts: []api.Fact{}, Candidates: []string{}, Coverage: "registered_sdk_edge_only", Truncated: v.Case.Revision > 32, PendingReview: v.PendingReview, Enqueued: now.UTC(), Expires: now.Add(5 * time.Second).UTC(), QuestionSHA: api.QuestionSHA()}
	for _, e := range v.Evidence {
		age := now.Sub(e.At).Milliseconds()
		if age < 0 || age > 86400000 {
			input.Truncated = true
			continue
		}
		input.Facts = append(input.Facts, api.Fact{EvidenceID: e.ID, Kind: e.Kind, Route: identity.Pseudonym("route:"+tenant+":"+e.Scope.Route, r.key), Resource: e.Scope.Resource, AgeMS: age})
	}
	for _, c := range v.Candidates {
		input.Candidates = append(input.Candidates, c.ID)
	}
	sort.Strings(input.Candidates)
	for {
		data, _ := json.Marshal(input)
		if len(data) <= 8192 {
			break
		}
		if len(input.Facts) <= 1 {
			return Job{}, api.ErrInput
		}
		input.Facts = input.Facts[1:]
		input.Truncated = true
	}
	if input.Validate() != nil {
		return Job{}, api.ErrInput
	}
	j := Job{ID: id, Tenant: tenant, CaseID: caseID, CaseSHA: sha, Epoch: s.epoch, ConfigSHA: decisions.Hash(r.cfg), Mode: r.cfg.Mode, Status: "reserved", Input: input, ReservedAt: now.UTC(), ReservedTokens: r.cfg.ReserveTokens, ReviewPreserved: true}
	if err = s.commit(record{At: now.UTC(), Operation: "reserve-decisions-budget", Job: &j}); err != nil {
		return Job{}, err
	}
	select {
	case r.queue <- id:
		return clone(j), nil
	default:
		j.Status = "queue_unavailable"
		_ = s.commit(record{Operation: "decisions-not-dispatched", Job: &j})
		return Job{}, ErrLimit
	}
}
func (j Job) ResultSimulated() bool { return j.Mode == "fake" }
func (r *Runner) worker() {
	defer r.wg.Done()
	for {
		select {
		case <-r.ctx.Done():
			return
		case id := <-r.queue:
			r.execute(id)
		}
	}
}
func (r *Runner) execute(id string) {
	r.mu.Lock()
	blocked := r.credentialBlocked || time.Now().Before(r.circuit)
	if !blocked && r.failures >= 3 && !r.circuit.IsZero() {
		if r.probe != "" {
			blocked = true
		} else {
			r.probe = id
		}
	}
	r.mu.Unlock()
	if blocked {
		s := r.store
		s.mu.Lock()
		j, ok := s.jobs[id]
		if ok {
			j.Status = "circuit_suppressed"
			_ = s.commit(record{Operation: "decisions-suppressed", Job: &j})
		}
		s.mu.Unlock()
		return
	}
	s := r.store
	s.mu.Lock()
	j, ok := s.jobs[id]
	if !ok {
		s.mu.Unlock()
		return
	}
	now := time.Now()
	current := s.cases[j.CaseID]
	if s.check(now) != nil || s.paused || j.Epoch != s.epoch || current.SHA != j.CaseSHA || !now.Before(j.Input.Expires) || r.ctx.Err() != nil {
		j.Status = "cancelled_or_stale"
		_ = s.commit(record{Operation: "decisions-suppressed", Job: &j})
		s.mu.Unlock()
		return
	}
	j.Status = "dispatched"
	if s.commit(record{Operation: "decisions-dispatch-fence", Job: &j}) != nil {
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()
	ctx, cancel := context.WithDeadline(r.ctx, j.Input.Expires)
	defer cancel()
	var result api.Result
	if r.cfg.Mode == "fake" {
		result = api.Result{Schema: "decision-result/2", Status: "ok", InputSHA: decisions.Hash(j.Input), Model: "scripted-v2", Origin: "none", Started: time.Now().UTC(), Completed: time.Now().UTC(), Simulated: true, Answers: []api.Answer{}}
	} else {
		result = r.provider.Decide(ctx, j.Input)
	}
	r.mu.Lock()
	if r.probe == id {
		r.probe = ""
	}
	if result.Status == "credential_error" {
		r.credentialBlocked = true
	}
	if result.Status == "transport_unknown" || result.Status == "provider_error" || result.Status == "rate_limited" {
		r.failures++
		if r.failures >= 3 {
			r.circuit = time.Now().Add(time.Minute)
		}
	} else if result.Status == "ok" {
		r.failures = 0
		r.circuit = time.Time{}
	}
	r.mu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	j.Result = &result
	j.Status = result.Status
	stale := s.paused || j.Epoch != s.epoch || s.cases[j.CaseID].SHA != j.CaseSHA || !time.Now().Before(j.Input.Expires) || ctx.Err() != nil
	if stale {
		j.Status = "stale_result"
	}
	if result.Usage != nil && result.Usage.Total > j.ReservedTokens && r.cfg.Mode != "fake" {
		j.Status = "usage_over_reservation"
		r.mu.Lock()
		r.credentialBlocked = true
		r.mu.Unlock()
	}
	// Only a fresh, nonpartial real result may select an existing server candidate.
	// The independently required review remains true for every result/disposition.
	if j.Status == "ok" && r.cfg.Mode == "enforce-gated" && !j.Input.Truncated && result.InputSHA == decisions.Hash(j.Input) && result.Candidate(r.cfg.Threshold) && len(j.Input.Candidates) > 0 {
		intent := Intent{ID: "decisions-" + decisions.Hash([]string{j.ID, j.CaseSHA, j.ConfigSHA})[:48], CaseID: j.CaseID, CaseSHA: j.CaseSHA, CandidateID: j.Input.Candidates[0], Owner: "decisions", Run: j.ID, Epoch: j.Epoch}
		receipt, err := s.applyLocked(ctx, j.Tenant, intent, time.Now())
		if err == nil {
			j.Receipt = &receipt
		} else {
			j.Status = "candidate_rejected"
		}
	}
	_ = s.commit(record{Operation: "decisions-result", Job: &j})
}
func (r *Runner) Job(tenant, id string) (Job, error) {
	s := r.store
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.jobs[id]
	if !ok || j.Tenant != tenant {
		return Job{}, ErrStale
	}
	return clone(j), nil
}
func (r *Runner) Status() map[string]any {
	r.mu.Lock()
	circuit, blocked := r.circuit, r.credentialBlocked
	r.mu.Unlock()
	s := r.store
	s.mu.Lock()
	defer s.mu.Unlock()
	queued := 0
	for _, j := range s.jobs {
		if j.Status == "reserved" || j.Status == "dispatched" {
			queued++
		}
	}
	return map[string]any{"mode": r.cfg.Mode, "model": api.Model, "origin": api.Endpoint, "queued": queued, "key_lookup_disabled": r.cfg.Mode == "off" || r.cfg.Mode == "fake", "circuit_until": circuit, "credential_or_usage_blocked": blocked, "calls_recorded": len(s.jobs), "epoch": s.epoch, "paused": s.paused, "calibration_gate": "operator-declared; independent quality acceptance not implied", "transmitted_fields": []string{"case SHA/revision", "tenant/asset/route pseudonyms", "typed verified facts and ages", "server candidate IDs", "coverage/truncation/review", "5-second deadline and question hash"}}
}
