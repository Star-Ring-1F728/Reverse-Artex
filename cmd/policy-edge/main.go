package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"reverse-artex/internal/decisions"
	api "reverse-artex/internal/decisions/openai"
	"reverse-artex/internal/delivery"
	"reverse-artex/internal/edge"
	"reverse-artex/internal/evidence"
	"reverse-artex/internal/identity"
	"reverse-artex/internal/policy"
	"reverse-artex/internal/protection"
	"reverse-artex/internal/responsev2"
	"reverse-artex/internal/routecoverage"
	"sync/atomic"
	"syscall"
	"time"
)

type emission struct {
	kind  string
	value any
}

func main() {
	if err := run(); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}

func run() (runErr error) {
	closers := &edgeClosers{}
	handedOff := false
	defer func() {
		if !handedOff {
			ctx, cancel := context.WithTimeout(context.Background(), edgeShutdownTimeout)
			defer cancel()
			runErr = errors.Join(runErr, closers.Close(ctx))
		}
	}()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	addr := flag.String("listen", "127.0.0.1:9080", "public ingress")
	management := flag.String("status-listen", "127.0.0.1:9086", "private read-only status")
	upstream := flag.String("upstream", "http://127.0.0.1:8080", "fixed WAF destination")
	controller := flag.String("controller", "http://127.0.0.1:9084", "private controller")
	collector := flag.String("collector", "http://127.0.0.1:9081", "private sensor receiver")
	out := flag.String("out", "artifacts/edge", "edge enforcement evidence")
	orderedID := flag.Bool("time-ordered-request-id", false, "explicit UUIDv7 trace IDs for retained outbox index locality")
	profilePath := flag.String("protection-registry", "", "explicit object-read protection manifest; default off")
	oidcPath := flag.String("oidc-config", "", "pinned offline issuer/audience/subject/public-key configuration; default lab identity")
	coveragePath := flag.String("route-coverage", "", "explicit ingress inventory; unregistered routes denied; default off")
	checkProfile := flag.Bool("protection-check", false, "validate registry, print digest and exit without credentials or network")
	asset := flag.String("asset", "lab-api", "registered upstream asset")
	v2State := flag.String("v2-state", "", "explicit owned V2 journal; enables local single-writer incident/policy runtime")
	v2Native := flag.Bool("v2-native", false, "opt-in deterministic exact-resource responses from fresh SDK denials")
	v2Combined := flag.Bool("v2-combined-prepare", false, "opt-in atomic durable SDK observation and response preparation; native/automatic denial handling keeps its original order")
	v2Retention := flag.Bool("v2-retention", false, "opt-in Linux durable V2 checkpoints and retained segments; default 8GiB journal and 512MiB per-stream edge evidence budgets")
	retentionPath := flag.String("v2-retention-config", "", "optional JSON sizing for retained V2; must match the existing journal")
	v2Window := flag.Duration("v2-batch-window", 0, "opt-in 1..25ms durable V2 response batching; requires v2-state and combined preparation; default per-record Sync")
	auditWindow := flag.Duration("evidence-batch-window", 0, "opt-in 1..25ms evidence batching; every caller waits for batch Sync; default per-request Sync")
	protectionMetricsEnabled := flag.Bool("protection-metrics", false, "fixed-bucket private diagnostic timings; contains no identities or payloads")
	reuseProtected := flag.Bool("reuse-protected-buffers", false, "opt-in cleared protected response buffers under the existing 32-request bound")
	l3Path := flag.String("l3-config", "", "bounded pinned local Qwen/L3 configuration; default disabled")
	decisionsPath := flag.String("decisions-config", "", "bounded V2 Decisions provider JSON; default off")
	decisionsAuto := flag.Bool("decisions-auto", false, "explicitly enqueue real Decisions on new V2 denial case revisions")
	flag.Parse()
	retentionConfig := responsev2.DefaultRetentionConfig()
	if *retentionPath != "" {
		if !*v2Retention || *v2State == "" {
			return errors.New("V2 retention config requires v2-retention and v2-state")
		}
		var err error
		retentionConfig, err = loadRetentionConfig(*retentionPath)
		if err != nil {
			return err
		}
	}
	if *auditWindow != 0 && (*auditWindow < time.Millisecond || *auditWindow > 25*time.Millisecond) {
		return errors.New("evidence batch window must be zero or 1..25ms")
	}
	if *v2Window != 0 && (*v2Window < time.Millisecond || *v2Window > 25*time.Millisecond || *v2State == "" || !*v2Combined) {
		return errors.New("V2 batch window requires 1..25ms, v2-state and v2-combined-prepare")
	}
	var registry *protection.Registry
	if *profilePath != "" {
		var err error
		registry, err = loadProtection(*profilePath)
		if err != nil {
			return errors.New("invalid object-read protection registry")
		}
		if registry.Asset() != *asset {
			return errors.New("protection registry asset differs from edge asset")
		}
	}
	var oidcVerifier *identity.OIDCVerifier
	if *oidcPath != "" {
		var err error
		oidcVerifier, err = loadOIDC(*oidcPath)
		if err != nil {
			return errors.New("invalid pinned OIDC configuration")
		}
	}
	if registry != nil && registry.AuthAdapter() == identity.OIDCAdapter {
		if oidcVerifier == nil || registry.IdentityDigest() != oidcVerifier.Digest() {
			return errors.New("OIDC configuration and registry identity pin differ")
		}
	} else if oidcVerifier != nil {
		return errors.New("OIDC requires matching OIDC registered protection contract")
	}
	var coveragePolicy *routecoverage.Policy
	if *coveragePath != "" {
		var err error
		coveragePolicy, err = loadCoverage(*coveragePath, registry)
		if err != nil {
			return errors.New("invalid route coverage inventory or registry pin")
		}
	}
	dc := api.Config{Mode: "off"}
	if *decisionsPath != "" {
		var err error
		dc, err = loadDecisions(*decisionsPath)
		if err != nil {
			return errors.New("invalid Decisions configuration")
		}
	}
	lc := responsev2.L3Config{}
	if *l3Path != "" {
		var err error
		lc, err = loadL3(*l3Path)
		if err != nil {
			return errors.New("invalid local L3 configuration")
		}
	}
	if (*l3Path != "" || *v2Native || *v2Combined || *v2Retention || *decisionsPath != "" || *decisionsAuto) && *v2State == "" {
		return errors.New("V2 state required")
	}
	if *v2State != "" && registry == nil {
		return errors.New("V2 requires registered protection contract")
	}
	if *checkProfile {
		if registry == nil {
			return errors.New("protection registry required")
		}
		result := map[string]any{"schema": "protection-config-check/1", "asset": registry.Asset(), "registry_digest": registry.Digest(), "trust_epoch": registry.Epoch(), "enforcer_id": registry.Enforcer(), "runtime_effect_verified": false}
		if oidcVerifier != nil {
			result["identity_config_sha256"] = oidcVerifier.Digest()
			result["auth_adapter_version"] = identity.OIDCAdapter
		}
		if coveragePolicy != nil {
			result["coverage_digest"] = coveragePolicy.Digest()
			result["unregistered_action"] = "deny"
		}
		if *v2Retention {
			result["v2_retention_limits"] = retentionConfig
		}
		json.NewEncoder(os.Stdout).Encode(result)
		return nil
	}
	keys := map[string]string{}
	for _, n := range []string{"RA_POLICY_READER_TOKEN", "RA_POLICY_SNAPSHOT_KEY", "RA_WAF_SENSOR_TOKEN", "RA_EDGE_STATUS_TOKEN", "LAB_IDENTITY_KEY", "LAB_HMAC_KEY", "LAB_INGRESS_TOKEN"} {
		v := os.Getenv(n)
		if n == "LAB_IDENTITY_KEY" && oidcVerifier != nil {
			keys[n] = ""
			continue
		}
		if len(v) < 32 {
			return errors.New("edge credentials required")
		}
		keys[n] = v
	}
	for _, raw := range []string{*upstream, *controller, *collector} {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "http" || u.User != nil || u.Path != "" || u.RawQuery != "" || net.ParseIP(u.Hostname()) == nil {
			return errors.New("fixed literal HTTP destination required")
		}
	}
	var v2 *responsev2.Store
	var v2Responses *responsev2.ResponseBatcher
	var runner *responsev2.Runner
	var l3 *responsev2.L3Engine
	var report func(protection.ResponseWrite) error
	var gate func(string, protection.RequestBinding, int, []byte, time.Time) (protection.GateDecision, error)
	operatorToken := ""
	if *v2State != "" {
		host, _, err := net.SplitHostPort(*management)
		if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
			return errors.New("V2 management must bind literal loopback")
		}
		operatorToken = os.Getenv("RA_V2_OPERATOR_TOKEN")
		if len(operatorToken) < 32 || operatorToken == keys["RA_EDGE_STATUS_TOKEN"] {
			return errors.New("distinct V2 operator credential required")
		}
		if *v2Retention {
			v2, err = responsev2.OpenRetained(*v2State, registry, retentionConfig)
		} else {
			v2, err = responsev2.Open(*v2State, registry)
		}
		if err != nil {
			return errors.New("V2 journal unavailable; preserve and inspect original journal")
		}
		closers.stores = append(closers.stores, v2.Close)
		if *protectionMetricsEnabled {
			v2.EnableTimingMetrics()
		}
		if *v2Window > 0 {
			v2Responses, err = responsev2.NewResponseBatcher(v2, *v2Window)
			if err != nil {
				return errors.New("V2 response batch unavailable")
			}
			closers.batchers = append(closers.batchers, v2Responses.Close)
		}
		runner, err = responsev2.NewRunner(v2, dc, []byte(keys["LAB_HMAC_KEY"]), nil)
		if err != nil {
			return errors.New("V2 Decisions unavailable")
		}
		closers.producers = append(closers.producers, runner.Close)
		l3, err = responsev2.NewL3(v2, lc, nil)
		if err != nil {
			return errors.New("V2 local L3 unavailable")
		}
		closers.producers = append(closers.producers, l3.Close)
		report = v2.CompleteResponse
		prepareCurrent := v2.ObserveAndPrepareCurrent
		if v2Responses != nil {
			report = v2Responses.CompleteResponse
			prepareCurrent = v2Responses.ObserveAndPrepareCurrent
		}
		gate = func(raw string, b protection.RequestBinding, status int, body []byte, at time.Time) (protection.GateDecision, error) {
			if *v2Combined && (status != 403 || (!*v2Native && !*decisionsAuto)) {
				return prepareCurrent(raw, b, status, body)
			}
			g, err := v2.ObserveCurrent(raw, b, status, body)
			if err != nil {
				return protection.GateDecision{}, err
			}
			if *v2Native && status == 403 {
				err = v2.Native(b.Tenant, g.CaseID, g.CaseSHA)
				if errors.Is(err, responsev2.ErrUnavailable) {
					return protection.GateDecision{}, err
				}
				// Re-read the exact current match; no second event or revision.
				g, err = v2.ObserveCurrent(raw, b, status, body)
				if err != nil {
					return protection.GateDecision{}, err
				}
			}
			if *decisionsAuto && status == 403 {
				_, _ = runner.Enqueue(b.Tenant, g.CaseID, g.CaseSHA, "auto-"+decisions.Hash(g.CaseSHA)[:48])
			}
			return v2.PrepareResponseCurrent(b.Tenant, decisions.Hash(raw))
		}
	}
	evidenceBudget := int64(64 << 20)
	if *v2Retention {
		evidenceBudget = 512 << 20
	}
	store, err := evidence.NewPersistentRotating(*out, evidenceBudget, 8<<20)
	if err != nil {
		return errors.New("edge evidence unavailable")
	}
	closers.stores = append(closers.stores, store.Close)
	var coverageGate *routecoverage.Gate
	var coverageStore *evidence.Store
	var coverageBatch, guardBatch *evidence.BatchAppender
	if coveragePolicy != nil {
		coverageStore, err = evidence.NewPersistentRotating(*out+"/coverage", evidenceBudget, 8<<20)
		if err != nil {
			return errors.New("route coverage audit unavailable")
		}
		closers.stores = append(closers.stores, coverageStore.Close)
		if *protectionMetricsEnabled {
			coverageStore.EnableTimingMetrics()
		}
		coverageAppend := func(o routecoverage.Observation) error { return coverageStore.Append("actions", o) }
		if *auditWindow > 0 {
			coverageBatch, err = evidence.NewBatchAppender(coverageStore, "actions", *auditWindow)
			if err != nil {
				return errors.New("route coverage batch unavailable")
			}
			closers.batchers = append(closers.batchers, coverageBatch.Close)
			coverageAppend = func(o routecoverage.Observation) error { return coverageBatch.Append(o) }
		}
		coverageGate = routecoverage.NewGate(coveragePolicy, coverageAppend)
	}
	var audit func(protection.Observation) error
	var guardStore *evidence.Store
	if registry != nil {
		// Every Append Syncs before release. Retain this separate store for
		// opt-in diagnostic snapshots of its own lock, write and sync timings.
		guardStore, err = evidence.NewPersistentRotating(*out+"/protection", evidenceBudget, 8<<20)
		if err != nil {
			return errors.New("protection audit unavailable")
		}
		closers.stores = append(closers.stores, guardStore.Close)
		if *protectionMetricsEnabled {
			guardStore.EnableTimingMetrics()
		}
		audit = func(v protection.Observation) error { return guardStore.Append("actions", v) }
		if *auditWindow > 0 {
			guardBatch, err = evidence.NewBatchAppender(guardStore, "actions", *auditWindow)
			if err != nil {
				return errors.New("protection evidence batch unavailable")
			}
			closers.batchers = append(closers.batchers, guardBatch.Close)
			audit = func(v protection.Observation) error { return guardBatch.Append(v) }
		}
	}
	client := &http.Client{Timeout: 500 * time.Millisecond, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(r *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
	cache := policy.NewReplica()
	q := make(chan emission, 2048)
	var dropped, failures, pollFailures atomic.Uint64
	var evidenceRetries atomic.Uint64
	var pending atomic.Int64
	emit := func(kind string, v any) {
		// Count before publishing so even an immediately consumed item is visible.
		pending.Add(1)
		select {
		case q <- emission{kind, v}:
		default:
			dropped.Add(1)
			pending.Add(-1)
		}
	}
	emitterDone := make(chan struct{})
	go func() {
		defer close(emitterDone)
		for e := range q {
			stream := "actions"
			if e.kind == "waf-events" {
				stream = "events"
			}
			if store.Append(stream, e.value) != nil {
				failures.Add(1)
				pending.Add(-1)
				continue
			}
			if e.kind == "waf-events" {
				b, _ := json.Marshal(e.value)
				ok, retries := delivery.Post(client, *collector+"/v1/events", keys["RA_WAF_SENSOR_TOKEN"], b)
				evidenceRetries.Add(retries)
				if !ok {
					failures.Add(1)
				}
			}
			pending.Add(-1)
		}
	}()
	pollCtx, stopPoll := context.WithCancel(context.Background())
	pollDone := make(chan struct{})
	go func() {
		defer close(pollDone)
		for {
			if pollCtx.Err() != nil {
				return
			}
			r, _ := http.NewRequestWithContext(pollCtx, "GET", *controller+"/v1/snapshot", nil)
			r.Header.Set("Authorization", "Bearer "+keys["RA_POLICY_READER_TOKEN"])
			resp, err := client.Do(r)
			if err == nil {
				var s policy.Snapshot
				d := json.NewDecoder(http.MaxBytesReader(nil, resp.Body, 1<<20))
				d.DisallowUnknownFields()
				if resp.StatusCode != 200 || d.Decode(&s) != nil || cache.Replace(s, []byte(keys["RA_POLICY_SNAPSHOT_KEY"]), time.Now()) != nil {
					pollFailures.Add(1)
				}
				resp.Body.Close()
			} else {
				pollFailures.Add(1)
			}
			select {
			case <-pollCtx.Done():
				return
			case <-time.After(250 * time.Millisecond):
			}
		}
	}()
	closers.background = func() {
		stopPoll()
		close(q)
		<-emitterDone
		<-pollDone
		client.CloseIdleConnections()
	}
	var protectionMetrics *edge.ProtectionMetrics
	if *protectionMetricsEnabled {
		protectionMetrics = &edge.ProtectionMetrics{}
	}
	status := http.NewServeMux()
	if v2 != nil {
		status.Handle("/v2/", responsev2.Handler(v2, runner, keys["RA_EDGE_STATUS_TOKEN"], operatorToken, l3))
	}

	status.HandleFunc("GET /v1/status", func(w http.ResponseWriter, r *http.Request) {
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+keys["RA_EDGE_STATUS_TOKEN"])) != 1 {
			http.Error(w, "unauthorized", 401)
			return
		}
		v := cache.Status(time.Now())
		// Read pending first: a zero after drain must include completed failures.
		v["evidence_pending"] = pending.Load()
		v["queue_dropped"] = dropped.Load()
		v["evidence_failures"] = failures.Load()
		v["evidence_retries"] = evidenceRetries.Load()
		v["evidence_storage"] = store.Stats()
		v["protection_timings"] = protectionMetrics.Snapshot()
		if coverageStore != nil {
			v["coverage_evidence_storage"] = coverageStore.Stats()
		}
		if guardStore != nil {
			v["protection_evidence_storage"] = guardStore.Stats()
		}
		if *protectionMetricsEnabled {
			if coverageStore != nil {
				v["coverage_evidence_timings"] = coverageStore.TimingSnapshot()
			}
			if guardStore != nil {
				v["protection_evidence_timings"] = guardStore.TimingSnapshot()
			}
			if v2 != nil {
				v["v2_timings"] = v2.TimingSnapshot()
			}
		}
		v["reuse_protected_buffers"] = *reuseProtected
		v["v2_retention_configured"] = *v2Retention
		v["v2_batch_window_ms"] = float64(*v2Window) / float64(time.Millisecond)
		if v2Responses != nil {
			v["v2_response_batch"] = v2Responses.Stats()
		}
		v["evidence_batch_window_ms"] = float64(*auditWindow) / float64(time.Millisecond)
		if coverageBatch != nil {
			v["coverage_audit_batch"] = coverageBatch.Stats()
		}
		if guardBatch != nil {
			v["protection_audit_batch"] = guardBatch.Stats()
		}
		v["poll_failures"] = pollFailures.Load()
		v["object_read_protection_configured"] = registry != nil
		v["route_coverage_configured"] = coverageGate != nil
		if oidcVerifier != nil {
			v["identity_adapter"] = identity.OIDCAdapter
			v["identity_config_sha256"] = oidcVerifier.Digest()
		} else {
			v["identity_adapter"] = "lab-hmac-v1"
		}
		if coverageGate != nil {
			v["route_coverage"] = coverageGate.State()
		}
		if registry != nil {
			v["protection_registry_digest"] = registry.Digest()
			v["protection_effect_verified"] = false
		}
		v["time_ordered_request_id"] = *orderedID
		json.NewEncoder(w).Encode(v)
	})
	u, _ := url.Parse(*upstream)
	h := edge.Handler(edge.Config{Upstream: u, OIDC: oidcVerifier, Coverage: coverageGate, Protection: registry, ProtectionAudit: audit, ProtectionGate: gate, ProtectionReport: report, Asset: *asset, IngressToken: keys["LAB_INGRESS_TOKEN"], IdentityKey: []byte(keys["LAB_IDENTITY_KEY"]), HMACKey: []byte(keys["LAB_HMAC_KEY"]), Cache: cache, Emit: emit, TimeOrderedRequestID: *orderedID, ReuseProtectedBuffers: *reuseProtected, ProtectionMetrics: protectionMetrics})
	// Secrets and client-selected request strings are never logged.
	s := &http.Server{Addr: *addr, Handler: h, ReadHeaderTimeout: time.Second, ReadTimeout: 3 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 8192}
	handedOff = true
	err = serveEdgeServers(ctx, s, newManagementServer(*management, status), closers.Close, edgeShutdownTimeout)
	log.Printf("edge stopped: evidence_pending=%d evidence_failures=%d queue_dropped=%d", pending.Load(), failures.Load(), dropped.Load())
	return err
}

// Management reads and acknowledgements can wait for a durable V2 journal Sync.
// This bounded window does not change object proof, model or lease deadlines.
func newManagementServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{Addr: addr, Handler: handler, ReadHeaderTimeout: time.Second, ReadTimeout: time.Second, WriteTimeout: 5 * time.Second, MaxHeaderBytes: 8192}
}

func loadProtection(path string) (*protection.Registry, error) {
	st, err := os.Lstat(path)
	if err != nil || !st.Mode().IsRegular() || st.Size() > 64<<10 {
		return nil, fmt.Errorf("invalid registry file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, (64<<10)+1))
	if err != nil {
		return nil, err
	}
	return protection.Parse(raw)
}

func loadRetentionConfig(path string) (responsev2.RetentionConfig, error) {
	const limit = 4096
	var cfg responsev2.RetentionConfig
	invalid := errors.New("invalid V2 retention config")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return cfg, invalid
	}
	f, err := os.Open(path)
	if err != nil {
		return cfg, invalid
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return cfg, invalid
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || decisions.DecodeStrict(raw, &cfg, limit) != nil || cfg.Validate() != nil {
		return cfg, invalid
	}
	return cfg, nil
}

func loadDecisions(path string) (api.Config, error) {
	var cfg api.Config
	st, err := os.Lstat(path)
	if err != nil || !st.Mode().IsRegular() || st.Size() > 4096 {
		return cfg, api.ErrConfig
	}
	f, err := os.Open(path)
	if err != nil {
		return cfg, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || decisions.DecodeStrict(raw, &cfg, 4096) != nil || cfg.Validate() != nil {
		return cfg, api.ErrConfig
	}
	return cfg, nil
}

func loadL3(path string) (responsev2.L3Config, error) {
	var cfg responsev2.L3Config
	file, err := os.Open(path)
	if err != nil {
		return cfg, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, 16385))
	if err != nil {
		return cfg, err
	}
	if decisions.DecodeStrict(raw, &cfg, 16384) != nil || cfg.Validate() != nil {
		return cfg, errors.New("invalid L3 config")
	}
	return cfg, nil
}

func loadCoverage(path string, registry *protection.Registry) (*routecoverage.Policy, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 64<<10 {
		return nil, routecoverage.ErrContract
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, (64<<10)+1))
	if err != nil {
		return nil, err
	}
	return routecoverage.Parse(raw, registry)
}

func loadOIDC(path string) (*identity.OIDCVerifier, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 64<<10 {
		return nil, identity.ErrOIDC
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, (64<<10)+1))
	if err != nil {
		return nil, err
	}
	return identity.ParseOIDC(raw)
}
