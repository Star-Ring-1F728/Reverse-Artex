package main

import (
	"bufio"
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
	"path/filepath"
	"reverse-artex/internal/actioncontext"
	"reverse-artex/internal/casememory"
	"reverse-artex/internal/contextactivation"
	"reverse-artex/internal/contextlearning"
	"reverse-artex/internal/contextrelease"
	"reverse-artex/internal/contextshadow"
	"reverse-artex/internal/contractjson"
	"reverse-artex/internal/detect"
	"reverse-artex/internal/event"
	"reverse-artex/internal/evidence"
	"reverse-artex/internal/hostguard"
	"reverse-artex/internal/localassistant"
	console "reverse-artex/web"
	"runtime"
	"strings"
	"syscall"
	"time"
)

func main() {
	addr := flag.String("listen", "127.0.0.1:9081", "private sensor listener")
	out := flag.String("out", "artifacts/observe", "evidence directory")
	replay := flag.String("replay", "", "JSONL offline replay (no network)")
	correlation := flag.String("correlation", "session", "observe correlation: session or principal (verified account across sessions)")
	criticalReserve := flag.Bool("critical-reserve", false, "opt-in bounded RA-007/008 observe reserve when correlation capacity is full; use a new evidence directory")
	tenantFairness := flag.Bool("tenant-fairness", false, "opt-in configured RA_TENANTS minimum correlation shares and shared capacity; use a new evidence directory")
	hostReplay := flag.String("host-replay", "", "normalized host JSONL offline replay; no host actions")
	recoverCheck := flag.Bool("recover-check", false, "verify live evidence recovery and exit without network or policy delivery")
	recoverAcked := flag.Int64("recover-acked", -1, "additional checkpoint ACK prefix count; signed operations recovery only")
	recoverAckedIDs := flag.String("recover-acked-ids-sha256", "", "SHA-256 of length-prefixed checkpoint ACK event IDs")
	policyResume := flag.Bool("policy-resume", false, "explicitly resume durable pending policy evidence after recovery")
	storageRoot := flag.String("storage-budget-root", "", "opt-in dedicated local shared app/collector/backup root")
	storageBytes := flag.Int64("storage-budget-bytes", 0, "shared sum of regular file lengths; all writers must cooperate")
	operationsPath := flag.String("operations-state", "", "opt-in signed operations anchor outside managed root")
	consoleMode := flag.Bool("console", len(os.Args) == 1, "local web console and config.json bootstrap")
	configPath := flag.String("config", "config.json", "local console configuration file")
	contextPath := flag.String("context-trust", "", "opt-in pinned public action-context trust; new evidence profile required")
	contextShadowProfile := flag.String("context-shadow-profile", "", "operator-installed v2 shadow candidate profile; console and context-trust required")
	contextCanaryProfile := flag.String("context-canary-profile", "", "operator-installed signed v2 canary release profile; console and context-trust required")
	contextCanaryInterval := flag.Int("context-canary-interval-seconds", 2, "operator v2 canary observation cadence in seconds (2-300)")
	contextProductionProfile := flag.String("context-production-profile", "", "separately approved full-coverage v2 triage; console and context-trust required")
	flag.Parse()
	if *contextCanaryInterval < 2 || *contextCanaryInterval > 300 {
		log.Fatal("context canary interval must be between 2 and 300 seconds")
	}
	if (*contextShadowProfile != "" || *contextCanaryProfile != "" || *contextProductionProfile != "") && (!*consoleMode || *contextPath == "") {
		log.Fatal("context shadow or canary requires console and pinned context trust")
	}
	profiles := 0
	for _, p := range []string{*contextShadowProfile, *contextCanaryProfile, *contextProductionProfile} {
		if p != "" {
			profiles++
		}
	}
	if profiles > 1 {
		log.Fatal("select one v2 shadow, canary or production profile")
	}
	var contextTrust *actioncontext.Trust
	if *contextPath != "" {
		raw, e := os.ReadFile(*contextPath)
		if e != nil {
			log.Fatal(e)
		}
		var t actioncontext.Trust
		if contractjson.Decode(raw, &t, 4096, 32) != nil || t.Validate() != nil {
			log.Fatal("invalid action context trust")
		}
		contextTrust = &t
	}
	var consoleKey string
	if *consoleMode {
		if *replay != "" || *hostReplay != "" || *recoverCheck {
			log.Fatal("console cannot be combined with offline replay or recovery check")
		}
		_, key, err := configureDesktop(*configPath, addr, out, correlation)
		if err != nil {
			log.Fatal(err)
		}
		consoleKey = key
	}
	if *criticalReserve && *operationsPath != "" {
		log.Fatal("critical reserve is not supported by the signed operations profile")
	}
	if *tenantFairness && *operationsPath != "" {
		log.Fatal("tenant fairness is not supported by the signed operations profile")
	}
	checkpointFloor, err := recoveryACKFloor(*recoverAcked, *recoverAckedIDs, *recoverCheck, *operationsPath)
	if err != nil {
		log.Fatal(err)
	}
	if *operationsPath != "" && *storageRoot == "" {
		log.Fatal("operations state requires shared storage")
	}
	if (*storageRoot == "") != (*storageBytes == 0) {
		log.Fatal("shared storage root and limit required together")
	}
	if *storageRoot != "" && (os.Getenv("RA_POLICY_CONTROL_URL") != "" || *replay != "" || *hostReplay != "") {
		log.Fatal("shared storage profile requires live observe-only collector without policy forwarding")
	}
	var sharedBudget *evidence.Budget
	var operations *operationsState
	if *storageRoot != "" {
		var err error
		sharedBudget, err = evidence.NewBudget(*storageRoot, *storageBytes)
		if err != nil {
			log.Fatal(err)
		}
		if err = sharedBudget.Contains(*out); err != nil {
			log.Fatal(err)
		}
	} else if _, err := os.Lstat(filepath.Join(*out, ".storage-binding.json")); err == nil || !os.IsNotExist(err) {
		log.Fatal("collector requires its bound shared storage configuration")
	}
	if sharedBudget != nil {
		// Hold the lifetime lease before reading the generation gate so an
		// offline operation cannot replace that state between validation and use.
		if !*recoverCheck {
			lease, err := sharedBudget.ServiceLease("collector")
			if err != nil {
				log.Fatal(err)
			}
			defer lease.Close()
		}
		root, _ := filepath.Abs(*storageRoot)
		if *operationsPath == "" {
			if _, err := os.Lstat(filepath.Join(root, ".operations.json")); err == nil || !os.IsNotExist(err) {
				log.Fatal("bound operations state required")
			}
		} else {
			path, err := filepath.Abs(*operationsPath)
			if err != nil {
				log.Fatal("invalid operations anchor")
			}
			relative, err := filepath.Rel(root, path)
			if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
				log.Fatal("operations anchor must be outside managed data root")
			}
			*operationsPath = path
			state, err := loadOperations(path, root, *storageBytes, *recoverCheck)
			if err != nil {
				log.Fatal(err)
			}
			operations = state
			if state.Profile.Correlation != *correlation {
				log.Fatal("operations correlation mismatch")
			}
			actualOut, _ := filepath.Abs(*out)
			if !*recoverCheck && actualOut != filepath.Join(root, "collector") {
				log.Fatal("operations profile requires fixed collector layout")
			}
			wantCanaries := strings.Join(state.Profile.Canaries, ",")
			if wantCanaries != os.Getenv("RA_CANARY_IDS") {
				log.Fatal("operations canary configuration mismatch")
			}
		}
	}
	if *hostReplay != "" && *replay != "" {
		log.Fatal("choose HTTP or host replay")
	}
	if *recoverCheck && (*replay != "" || *hostReplay != "") {
		log.Fatal("recovery check cannot run with offline replay")
	}
	if *policyResume && (*recoverCheck || *replay != "" || *hostReplay != "") {
		log.Fatal("policy resume requires live collector mode")
	}
	controlURL := os.Getenv("RA_POLICY_CONTROL_URL")
	controlKey := os.Getenv("RA_POLICY_EVIDENCE_TOKEN")
	if controlURL != "" && *replay == "" && *hostReplay == "" {
		u, err := url.Parse(controlURL)
		var ip net.IP
		if err == nil {
			ip = net.ParseIP(u.Hostname())
		}
		if err != nil || u.Scheme != "http" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || ip == nil || (!ip.IsPrivate() && !ip.IsLoopback()) || len(controlKey) < 32 {
			log.Fatal("private literal controller and evidence credential required")
		}
	} else if *policyResume {
		log.Fatal("policy resume requires a configured controller")
	}
	tenants := os.Getenv("RA_TENANTS")
	if tenants == "" {
		tenants = "alpha,beta,public"
	}
	allowed := map[string]bool{}
	for _, v := range strings.Split(tenants, ",") {
		allowed[v] = true
	}
	engine := detect.New()
	if *correlation == "principal" {
		engine = detect.NewPrincipal()
	} else if *correlation != "session" {
		log.Fatal("correlation must be session or principal")
	}
	if *tenantFairness {
		engine, err = detect.NewWithTenantFairness(*correlation == "principal", *criticalReserve, strings.Split(tenants, ","))
		if err != nil {
			log.Fatal(err)
		}
	} else if *criticalReserve {
		engine = detect.NewWithCriticalReserve(*correlation == "principal")
	}
	engine.Canaries = map[string]bool{}
	var canaryIDs []string
	for _, id := range strings.Split(os.Getenv("RA_CANARY_IDS"), ",") {
		if id != "" {
			if !hostguard.ID.MatchString(id) {
				log.Fatal("invalid configured canary ID")
			}
			engine.Canaries[id] = true
			canaryIDs = append(canaryIDs, id)
		}
	}
	hostEngine := hostguard.New(canaryIDs)
	store, err := evidence.NewPersistentRotating(*out, 64<<20, 8<<20)
	if err != nil {
		log.Fatal(err)
	}
	defer store.Close()
	if sharedBudget != nil {
		if err = store.UseBudget(sharedBudget); err != nil {
			log.Fatal(err)
		}
	}
	if *replay != "" || *hostReplay != "" {
		if err := checkOfflineOutput(*out); err != nil {
			log.Fatal(err)
		}
	}
	if *replay == "" && *hostReplay == "" {
		if err := store.LimitRecords(maxRecoveryRecords); err != nil {
			log.Fatalf("collector recovery refused for %q; preserve original evidence and restore a verified checkpoint to a new directory; replay budget: %v", *out, err)
		}
		if err := restoreState(store, *out, *correlation, canaryIDs, engine, hostEngine, contextTrust); err != nil {
			log.Fatalf("collector recovery refused for %q; preserve original evidence and restore a verified checkpoint to a new directory: %v", *out, err)
		}
		if err := verifyCollectorFloor(store, operations); err != nil {
			log.Fatal(err)
		}
		if checkpointFloor != nil {
			if err := verifyCollectorACKPrefix(store, operations.CollectorScope["RA_SENSOR_ID"], checkpointFloor); err != nil {
				log.Fatal(err)
			}
		}
	}
	var outbox *policyOutbox
	if *replay == "" && *hostReplay == "" {
		pending, err := loadPolicyPending(store)
		if err != nil {
			log.Fatalf("policy delivery recovery refused: %v", err)
		}
		if *recoverCheck {
			fmt.Printf("collector recovery verified; policy evidence pending: %d\n", len(pending))
			return
		}
		if controlURL != "" {
			if len(pending) != 0 && !*policyResume {
				log.Fatalf("%d policy evidence records require explicit -policy-resume after recovery", len(pending))
			}
			// ACKs have their own stream and ordered worker. Their durable flush
			// must not hold the ingress store lock between event/evaluation writes.
			ackStore, err := evidence.NewPersistentStream(*out, 64<<20, 8<<20, "policy-delivery-acks")
			if err != nil {
				log.Fatal(err)
			}
			defer ackStore.Close()
			if err := ackStore.LimitRecords(maxRecoveryRecords); err != nil {
				log.Fatalf("policy ack replay budget refused: %v", err)
			}
			outbox = newPolicyOutbox(ackStore, pending)
		}
	}
	ingest := &ingester{store: store, engine: engine, hostEngine: hostEngine, contextTrust: contextTrust}
	if outbox != nil {
		ingest.forwardReady = outbox.ready
		ingest.forwardBatchReady = outbox.readyBatch
		ingest.forward = outbox.enqueue
	}
	if *hostReplay != "" {
		f, err := os.Open(*hostReplay)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		scan := bufio.NewScanner(f)
		scan.Buffer(make([]byte, 4096), 16384)
		for scan.Scan() {
			e, err := hostguard.Decode(strings.NewReader(scan.Text()), time.Now().UTC())
			if err != nil {
				log.Fatal(err)
			}
			status, err := ingest.processHost(e)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Println(status)
		}
		if err := scan.Err(); err != nil {
			log.Fatal(err)
		}
		return
	}
	if *replay != "" {
		f, err := os.Open(*replay)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		scan := bufio.NewScanner(f)
		scan.Buffer(make([]byte, 4096), 16384)
		n := 0
		for scan.Scan() {
			e, err := event.Decode(strings.NewReader(scan.Text()))
			if err != nil {
				log.Fatalf("line %d: %v", n+1, err)
			}
			if err := contextTrust.Verify(e.Context, e.ContextBinding()); err != nil {
				log.Fatal("untrusted action context")
			}
			result, err := ingest.process(e)
			if err != nil {
				log.Fatal(err)
			}
			n++
			fmt.Println(result)
		}
		if err := scan.Err(); err != nil {
			log.Fatal(err)
		}
		return
	}
	// A credential is held in environment only; never logged or included in artifacts.
	token := os.Getenv("RA_SENSOR_TOKEN")
	if len(token) < 32 {
		log.Fatal("RA_SENSOR_TOKEN must be at least 32 characters")
	}
	wafToken := os.Getenv("RA_WAF_SENSOR_TOKEN")
	if wafToken != "" && (len(wafToken) < 32 || wafToken == token) {
		log.Fatal("distinct WAF sensor credential required")
	}
	hostToken := os.Getenv("RA_HOST_SENSOR_TOKEN")
	if hostToken != "" && (len(hostToken) < 32 || hostToken == token || hostToken == wafToken) {
		log.Fatal("distinct host sensor credential required")
	}
	sensor := os.Getenv("RA_SENSOR_ID")
	if sensor == "" {
		sensor = "lab-app"
	}
	asset := os.Getenv("RA_ASSET_ID")
	if asset == "" {
		asset = "lab-api"
	}
	mux := http.NewServeMux()
	// Liveness/backlog view without detector/store locks or directory scans.
	// /health retains the detailed inventory contract for existing clients.
	mux.HandleFunc("GET /v1/runtime-health", func(w http.ResponseWriter, r *http.Request) {
		var pending map[string]any
		if outbox != nil {
			pending = outbox.flowStats()
		}
		json.NewEncoder(w).Encode(map[string]any{"mode": "observe", "ingest_degraded": ingest.degraded(), "policy_delivery": pending, "ingest_timing": ingest.batchTiming(), "goroutines": runtime.NumGoroutine()})
	})
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		pending, retries, failures, deliveryFailed := 0, uint64(0), uint64(0), false
		if outbox != nil {
			pending, retries, failures, deliveryFailed = outbox.stats()
		}
		retrying, retryRounds := false, uint64(0)
		if outbox != nil {
			retrying, retryRounds = outbox.retryStats()
		}
		json.NewEncoder(w).Encode(map[string]any{"mode": "observe", "correlation_scope": *correlation, "policy_forwarding_configured": outbox != nil, "ingest_degraded": ingest.degraded(), "ingest_timing": ingest.batchTiming(), "host_sensor_configured": hostToken != "", "host_rules": map[string]string{"RA-006": "requires_verified_linux_process_network_observations", "RA-008": "requires_configured_canary_observation"}, "rules": detect.Evaluability(), "policy_evidence_pending": pending, "policy_evidence_retries": retries, "policy_evidence_degraded": deliveryFailed, "detector": engine.Stats(), "critical_reserve": engine.CriticalReserveStats(), "tenant_fairness": engine.TenantFairnessStats(), "evidence": store.Stats(), "policy_evidence_retrying": retrying, "policy_evidence_retry_rounds": retryRounds, "policy_evidence_failures": failures, "policy_evidence_queue_dropped": 0})
	})
	mux.HandleFunc("GET /v1/delivery-health", deliveryHealthHandler(token, outbox != nil, ingest.degraded))
	sem := make(chan struct{}, 32)
	mux.HandleFunc("POST /v1/events/batch", appBatchHandler(ingest, token, sensor, asset, allowed, sem))
	mux.HandleFunc("POST /v1/events/group", appBatchHandlerLimit(ingest, token, sensor, asset, allowed, sem, 64))
	mux.HandleFunc("POST /v1/host-events", func(w http.ResponseWriter, r *http.Request) {
		if len(hostToken) < 32 || subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+hostToken)) != 1 {
			io.Copy(io.Discard, io.LimitReader(r.Body, 16384))
			http.Error(w, "unauthorized", 401)
			return
		}
		select {
		case sem <- struct{}{}:
			defer func() { <-sem }()
		default:
			http.Error(w, "host ingest capacity", 429)
			return
		}
		e, err := hostguard.Decode(http.MaxBytesReader(w, r.Body, 16384), time.Now().UTC())
		if err != nil {
			http.Error(w, "invalid host event", 400)
			return
		}
		value := func(k, f string) string {
			if v := os.Getenv(k); v != "" {
				return v
			}
			return f
		}
		if e.SensorID != value("RA_HOST_SENSOR_ID", "lab-host") || e.AssetID != asset || e.TenantID != value("RA_HOST_TENANT", "alpha") || !allowed[e.TenantID] || e.ServiceID != value("RA_HOST_SERVICE_ID", "lab-web") || e.WorkloadID != value("RA_HOST_WORKLOAD_ID", "lab-workload") {
			http.Error(w, "host scope denied", 403)
			return
		}
		status, err := ingest.processHost(e)
		if err != nil {
			http.Error(w, "host evidence unavailable", 503)
			return
		}
		if status == "capacity_rejected" {
			http.Error(w, "host correlation capacity", 429)
			return
		}
		w.WriteHeader(202)
		json.NewEncoder(w).Encode(map[string]string{"result": status, "mode": "observe"})
	})
	mux.HandleFunc("POST /v1/events", func(w http.ResponseWriter, r *http.Request) {
		appAuthorized := subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+token)) == 1
		wafAuthorized := len(wafToken) >= 32 && subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+wafToken)) == 1
		if !appAuthorized && !wafAuthorized {
			// Drain a bounded body so Windows clients can read the denial without
			// a reset caused by closing a socket with unread request bytes.
			io.Copy(io.Discard, io.LimitReader(r.Body, 16384))
			http.Error(w, "unauthorized", 401)
			return
		}
		select {
		case sem <- struct{}{}:
			defer func() { <-sem }()
		default:
			http.Error(w, "ingest capacity", 429)
			return
		}
		e, err := event.Decode(http.MaxBytesReader(w, r.Body, 16384))
		if err != nil {
			http.Error(w, "invalid event", 400)
			return
		}
		if !(appAuthorized && e.SensorID == sensor || wafAuthorized && e.SensorID == "lab-waf") || e.AssetID != asset || !allowed[e.TenantID] {
			http.Error(w, "sensor scope denied", 403)
			return
		}
		if wafAuthorized && !appAuthorized && (e.Budget != nil || e.RequestBudget != nil || e.ExportApproval != nil || e.CanaryID != "" || e.Context != nil) {
			http.Error(w, "application data sensor required", 403)
			return
		}
		if err := contextTrust.Verify(e.Context, e.ContextBinding()); err != nil {
			http.Error(w, "untrusted action context", 400)
			return
		}
		result, err := ingest.process(e)
		if err != nil {
			http.Error(w, "evidence unavailable", 503)
			return
		}
		if result == "capacity_rejected" {
			http.Error(w, "correlation capacity", 429)
			return
		}
		w.WriteHeader(202)
		json.NewEncoder(w).Encode(map[string]string{"result": result, "mode": "observe"})
	})
	if *consoleMode {
		var memory *casememory.Store
		if sharedBudget == nil {
			memory, err = casememory.Open(filepath.Join(*out, "case-memory", "journal.jsonl"))
			if err != nil {
				log.Fatal(err)
			}
			defer memory.Close()
		}
		var contextCanary contextrelease.RuntimeService
		canaryUnavailable := ""
		if *contextCanaryProfile != "" {
			cfg, _, e := contextrelease.LoadProfile(*contextCanaryProfile)
			if e == nil && (!allowed[cfg.Policy.Tenant] || sharedBudget != nil) {
				e = errors.New("canary requires configured tenant and separate storage budget")
			}
			if e == nil {
				capture := func(ctx context.Context) (*evidence.Snapshot, error) {
					return captureContextSnapshot(ctx, ingest, *out)
				}
				contextCanary, e = openContextCanary(*contextCanaryProfile, contextlearning.Digest(*contextTrust), time.Duration(*contextCanaryInterval)*time.Second, capture)
			}
			if e != nil {
				canaryUnavailable = "configured canary release unavailable; preserve journal and history"
				log.Printf("%s: %v", canaryUnavailable, e)
			}
			if contextCanary != nil {
				defer contextCanary.Close()
			}
		}
		var contextProduction *contextactivation.Service
		productionUnavailable := ""
		if *contextProductionProfile != "" {
			p, _, _, _, e := contextactivation.LoadProfile(*contextProductionProfile)
			if e == nil && (!allowed[p.Tenant] || sharedBudget != nil) {
				e = errors.New("production triage requires configured tenant and separate storage budget")
			}
			if e == nil {
				contextProduction, e = contextactivation.OpenProfileService(*contextProductionProfile, contextlearning.Digest(*contextTrust), memory, func(ctx context.Context) (*evidence.Snapshot, error) {
					return captureContextSnapshot(ctx, ingest, *out)
				})
			}
			if e != nil {
				productionUnavailable = "configured production triage unavailable; preserve evidence"
				log.Printf("%s: %v", productionUnavailable, e)
			}
			if contextProduction != nil {
				defer contextProduction.Close()
			}
		}
		var assistant *localassistant.Service
		var shadowObserver *casememory.Observer
		if memory != nil {
			shadowObserver = casememory.StartObserver(memory, func(ctx context.Context) (int, error) { return syncCases(ctx, ingest, *out, memory, allowed) })
			defer shadowObserver.Close()
			assistant, err = localassistant.Open(filepath.Join(*out, "qwen-runs"), localassistant.Config{
				Origin: os.Getenv("RA_OLLAMA_ORIGIN"), ControlOrigin: os.Getenv("RA_POLICY_CONTROL_URL"),
				AdminToken: os.Getenv("RA_POLICY_ADMIN_TOKEN"), ReaderToken: os.Getenv("RA_POLICY_READER_TOKEN"), SnapshotKey: os.Getenv("RA_POLICY_SNAPSHOT_KEY"), AllowDefense: os.Getenv("RA_CONSOLE_DEFENSE_ENABLED") == "1",
			}, func(ctx context.Context, tenant, id string) (localassistant.BoundCase, error) {
				bound, e := assistantCase(ctx, ingest, *out, memory, allowed, tenant, id)
				if e == nil && contextCanary != nil {
					bound.ContextCanary = contextCanary.Advice(bound.View.Current.Case, bound.SnapshotSHA)
				}
				if e == nil && contextProduction != nil {
					bound.ContextProduction = contextProduction.Advice(bound.View.Current.Case, bound.SnapshotSHA)
				}
				return bound, e
			})
			if err != nil {
				log.Fatal(err)
			}
			defer assistant.Close()
		}
		var contextObserver *contextshadow.Live
		if *contextShadowProfile != "" {
			if sharedBudget != nil {
				log.Fatal("context shadow history requires a separate non-shared-budget console profile")
			}
			c, a, e := contextshadow.LoadProfile(*contextShadowProfile, *contextTrust)
			if e != nil {
				log.Fatal(e)
			}
			if !allowed[c.Tenant] {
				log.Fatal("context shadow candidate tenant outside configured scope")
			}
			var profile contextshadow.Profile
			if e = contextshadow.ReadPublic(*contextShadowProfile, &profile); e != nil {
				log.Fatal(e)
			}
			limits := contextshadow.DefaultStorageLimits()
			if profile.Storage != nil {
				limits = *profile.Storage
			}
			contextObserver, e = contextshadow.OpenLiveWithStorage(filepath.Join(*out, "context-shadow"), c, a, *contextTrust, func(ctx context.Context) (*evidence.Snapshot, error) {
				return captureContextSnapshot(ctx, ingest, *out)
			}, limits)
			if e != nil {
				log.Fatalf("context shadow recovery refused for %q; preserve original history before creating a new observation session: %v", filepath.Join(*out, "context-shadow"), e)
			}
			defer contextObserver.Close()
		}
		console.Register(mux, console.Options{
			ContextCanary: contextCanary, ContextCanaryUnavailable: canaryUnavailable,
			ContextProduction: contextProduction, ContextProductionUnavailable: productionUnavailable,
			ContextShadow: contextObserver,
			Assistant:     assistant, Cases: memory, Tenants: strings.Split(tenants, ","),
			SyncCases: func(ctx context.Context) (int, error) { return syncCases(ctx, ingest, *out, memory, allowed) },
			AutomaticStatus: func() any {
				if shadowObserver == nil {
					return nil
				}
				return shadowObserver.Status()
			},
			Token: consoleKey, Listen: *addr, Directory: *out, SensorToken: token,
			Settings: map[string]any{"endpoint": "http://" + *addr, "sensor_id": sensor, "asset_id": asset, "tenants": tenants, "data_dir": *out, "correlation_scope": *correlation},
			Status: func() any {
				return map[string]any{"mode": "observe", "data_dir": *out, "correlation_scope": *correlation, "policy_forwarding_configured": outbox != nil, "ingest_degraded": ingest.degraded(), "detector": engine.Stats(), "evidence": store.Stats(), "rules": detect.Evaluability()}
			},
		})
	}
	absRoot, _ := filepath.Abs(*storageRoot)
	server := &http.Server{Addr: *addr, Handler: operationsHandler(mux, *operationsPath, absRoot, *storageBytes), ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 3 * time.Second, WriteTimeout: 3 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 8192}
	if outbox != nil {
		client := &http.Client{Timeout: time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(r *http.Request, v []*http.Request) error { return http.ErrUseLastResponse }}
		go outbox.run(client, controlURL, controlKey)
		if pending, _, _, _ := outbox.stats(); pending != 0 {
			outbox.wake <- struct{}{}
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdownContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownContext); err != nil {
			log.Printf("shutdown: %v", err)
		}
	}()
	log.Printf("observe collector listening on %s", *addr)
	if *consoleMode {
		fmt.Printf("\nReverse Artex console: http://%s/#token=%s\nKeep this local access link private. Press Ctrl+C to stop.\n\n", *addr, consoleKey)
	}
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}

}
