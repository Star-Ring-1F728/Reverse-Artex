package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reverse-artex/internal/actioncontext"
	"reverse-artex/internal/casememory"
	"reverse-artex/internal/contextlearning"
	"reverse-artex/internal/contextshadow"
	"reverse-artex/internal/detect"
	"reverse-artex/internal/event"
	"reverse-artex/internal/evidence"
	"reverse-artex/internal/hostguard"
	"reverse-artex/internal/recovery"
	console "reverse-artex/web"
	"strings"
	"testing"
	"time"
)

type fixture struct {
	sensor                                     ed25519.PrivateKey
	event                                      event.Event
	dir, source, candidate, authorities, trust string
	c                                          contextlearning.Candidate
	a                                          casememory.LearningTrust
	t                                          actioncontext.Trust
}

func put(t *testing.T, path string, v any) {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(path, b, 0600); e != nil {
		t.Fatal(e)
	}
}
func makeFixture(t *testing.T) fixture {
	t.Helper()
	f := fixture{dir: t.TempDir()}
	f.source = filepath.Join(f.dir, "evidence")
	f.candidate = filepath.Join(f.dir, "candidate.json")
	f.authorities = filepath.Join(f.dir, "authorities.json")
	f.trust = filepath.Join(f.dir, "context-trust.json")
	f.a = casememory.LearningTrust{Schema: "case-learning-trust/1", Tenant: "alpha", Revision: 1, Keys: []casememory.LearningKey{}}
	for _, role := range []string{"label_reviewer", "evaluation_custodian", "independent_evaluator"} {
		pub, _, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		f.a.Keys = append(f.a.Keys, casememory.LearningKey{ID: role, Actor: role, Role: role, PublicKey: base64.StdEncoding.EncodeToString(pub)})
	}
	pub, sensor, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	issuer, _, _ := ed25519.GenerateKey(rand.Reader)
	f.t = actioncontext.Trust{Schema: "action-context-trust/2", Revision: 1, RevokedPermits: []string{}, Keys: []actioncontext.Key{{ID: "sensor", Role: "observation_sensor", Tenant: "alpha", Asset: "api", Sensor: "app", PublicKey: base64.StdEncoding.EncodeToString(pub)}, {ID: "issuer", Role: "scope_issuer", Tenant: "alpha", Asset: "api", Sensor: "app", PublicKey: base64.StdEncoding.EncodeToString(issuer)}}}
	digest := contextlearning.Digest
	f.c = contextlearning.Candidate{Schema: "case-context-candidate/2", Tenant: "alpha", Model: contextlearning.Model{Kind: "context-metadata-stump/2", Feature: 14, Threshold: 1, Above: true}, FeatureSHA: digest(contextlearning.FeatureNames), RuntimeSHA: contextlearning.RuntimeSHA(), TrainingInputsSHA: digest("training inputs"), TrainingGoldSHA: digest("training gold"), TrainingSourceSHA: digest("training source"), TrainingRecipeSHA: digest("recipe"), ContextTrustSHA: digest(f.t), ReviewSHA: digest("review"), ReviewTrustSHA: casememory.LearningTrustDigest(f.a), TrainingEvidence: []string{digest("training evidence")}, CreatedAt: time.Now().UTC()}
	f.sensor = sensor
	f.c.ModelSHA = digest(f.c.Model)
	f.c.SHA = contextlearning.CandidateSHA(f.c)
	put(t, f.candidate, f.c)
	put(t, f.authorities, f.a)
	put(t, f.trust, f.t)
	store, e := evidence.New(f.source, 4<<20)
	if e != nil {
		t.Fatal(e)
	}
	meta := recovery.Metadata{Version: recovery.Version, Ruleset: recovery.Ruleset, Correlation: "session", Canaries: []string{"canary"}, ContextTrust: &f.t}
	b, _ := json.Marshal(meta)
	if e = store.CreateMetadata("recovery.meta.json", b); e != nil {
		t.Fatal(e)
	}
	now := time.Now().UTC()
	ev := event.Event{SchemaVersion: "1.0", EventID: "event-1", EventTime: now, IngestTime: now, SensorID: "app", TenantID: "alpha", AssetID: "api", EventType: "http", RequestID: "request-1", Method: "GET", Route: "/internal/canary/{id}", Status: 403, Principal: "opaque-principal", SessionHMAC: "opaque-session", Identity: "authenticated", Authorization: "deny", ResourceClass: "canary", ResourceHMAC: "opaque-resource", KnownRoute: true, DetectorFamily: "unknown", UAHint: "none", DataQuality: "complete", CanaryID: "canary"}
	if e := ev.Validate(now); e != nil {
		t.Fatal("invalid fixture event", e)
	}
	obs := actioncontext.Observation{Schema: "action-observation/2", Binding: ev.ContextBinding(), KeyID: "sensor"}
	obs.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(sensor, actioncontext.ObservationBytes(obs)))
	ev.Context = &obs
	f.event = ev
	engine := detect.New()
	engine.Canaries = map[string]bool{"canary": true}
	alerts, status := engine.Process(ev, now)
	if len(alerts) != 1 {
		t.Fatalf("fixture alerts: %v", alerts)
	}
	if e = store.Append("events", ev); e != nil {
		t.Fatal(e)
	}
	if e = store.Append("evaluations", recovery.Evaluation{EventID: ev.EventID, Result: status, Rules: engine.EvaluabilityForResult(ev, status), ProcessTime: now}); e != nil {
		t.Fatal(e)
	}
	for _, a := range alerts {
		if e = store.Append("alerts", a); e != nil {
			t.Fatal(e)
		}
	}
	if e = store.Close(); e != nil {
		t.Fatal(e)
	}
	return f
}

func waitContextIdle(t *testing.T, s *contextshadow.Live, checks int) contextshadow.LiveStatus {
	t.Helper()
	end := time.Now().Add(5 * time.Second)
	for time.Now().Before(end) {
		v := s.Status()
		if !v.Busy && !v.Queued && v.Checks >= checks {
			return v
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("shadow worker did not finish")
	return contextshadow.LiveStatus{}
}
func TestContextShadowLiveConsoleAndRestart(t *testing.T) {
	f := makeFixture(t)
	store, e := evidence.New(f.source, 4<<20)
	if e != nil {
		t.Fatal(e)
	}
	defer store.Close()
	i := &ingester{store: store, engine: detect.New(), hostEngine: hostguard.New([]string{"canary"}), contextTrust: &f.t}
	history := filepath.Join(f.dir, "history")
	capture := func(ctx context.Context) (*evidence.Snapshot, error) { return captureContextSnapshot(ctx, i, f.source) }
	live, e := contextshadow.OpenLive(history, f.c, f.a, f.t, capture)
	if e != nil {
		t.Fatal(e)
	}
	defer live.Close()
	if _, e = contextshadow.OpenLive(history, f.c, f.a, f.t, capture); e == nil {
		t.Fatal("second owner accepted")
	}
	key := strings.Repeat("a", 64)
	mux := http.NewServeMux()
	console.Register(mux, console.Options{ContextShadow: live, Tenants: []string{"alpha", "beta"}, Token: key, Listen: "127.0.0.1:9081", Status: func() any { return nil }})
	call := func(method, path, body, auth, origin string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "http://127.0.0.1:9081/console/api/cases/context-shadow/"+path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		if auth != "" {
			r.Header.Set("Authorization", "Bearer "+auth)
		}
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}
	pin := fmt.Sprintf(`{"candidate_sha256":%q}`, f.c.SHA)
	for _, q := range []struct {
		method, path, body, auth, origin string
		code                             int
	}{{"GET", "status?tenant=alpha", "", "", "", 401}, {"POST", "start?tenant=alpha", pin, key, "https://foreign.invalid", 403}, {"GET", "status?tenant=beta", "", key, "", 404}, {"GET", "status?tenant=alpha&tenant=alpha", "", key, "", 400}, {"POST", "start?tenant=alpha", `{"candidate_sha256":"bad"}`, key, "", 400}, {"POST", "start?tenant=alpha", `{"candidate_sha256":"x","gold":"x"}`, key, "", 400}} {
		if w := call(q.method, q.path, q.body, q.auth, q.origin); w.Code != q.code {
			t.Fatal(q, w.Code, w.Body.String())
		}
	}
	if w := call("POST", "capture?tenant=alpha", pin, key, ""); w.Code != 202 {
		t.Fatal(w.Code, w.Body.String())
	}
	status := waitContextIdle(t, live, 1)
	if status.Enabled || status.Latest == nil || status.Latest.Receipt.Observed != 1 {
		t.Fatal(status)
	}
	first := status.Latest.SHA
	status.Latest.Receipt.Rows[0].Prediction = "changed"
	if live.Status().Latest.SHA != first || live.Status().Latest.Receipt.Rows[0].Prediction == "changed" {
		t.Fatal("status leaked mutable state")
	}
	if w := call("GET", "history?tenant=alpha&sequence=1", "", key, ""); w.Code != 200 || !strings.Contains(w.Body.String(), first) {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := call("POST", "start?tenant=alpha", pin, key, ""); w.Code != 202 {
		t.Fatal(w.Code, w.Body.String())
	}
	status = waitContextIdle(t, live, 2)
	if !status.Enabled || len(status.History) != 1 {
		t.Fatal("unchanged snapshot duplicated", status)
	}
	i.mu.Lock()
	i.fail(errors.New("injected collector failure"))
	i.mu.Unlock()
	if w := call("POST", "stop?tenant=alpha", "{}", key, ""); w.Code != 202 {
		t.Fatal("stop needs source", w.Code, w.Body.String())
	}
	if w := call("POST", "capture?tenant=alpha", pin, key, ""); w.Code != 202 {
		t.Fatal(w.Code, w.Body.String())
	}
	status = waitContextIdle(t, live, 3)
	if status.Enabled || status.Error == "" || status.Latest.Receipt != nil || len(status.History) != 2 {
		t.Fatal("failed capture was hidden", status)
	}
	live.Close()
	restored, e := contextshadow.OpenLive(history, f.c, f.a, f.t, capture)
	if e != nil {
		t.Fatal(e)
	}
	if restored.Status().Enabled || len(restored.Status().History) != 2 || restored.Status().Error == "" {
		t.Fatal("restart lost state")
	}
	restored.Close()
	path := filepath.Join(history, "attempt-000001.json")
	b, _ := os.ReadFile(path)
	os.WriteFile(path, []byte(strings.Replace(string(b), "suspicious", "benign", 1)), 0600)
	if _, e = contextshadow.OpenLive(history, f.c, f.a, f.t, capture); e == nil {
		t.Fatal("tampered history reopened")
	}
}

type pausedContextAppender struct {
	store          *evidence.Store
	wrote, release chan struct{}
}

func (p *pausedContextAppender) Append(name string, v any) error {
	if e := p.store.Append(name, v); e != nil {
		return e
	}
	if name == "events" {
		close(p.wrote)
		<-p.release
	}
	return nil
}
func TestContextShadowCaptureWaitsForFullCommitAndReplaysAfterUnlock(t *testing.T) {
	f := makeFixture(t)
	store, e := evidence.New(f.source, 4<<20)
	if e != nil {
		t.Fatal(e)
	}
	defer store.Close()
	engine := detect.New()
	engine.Canaries = map[string]bool{"canary": true}
	host := hostguard.New([]string{"canary"})
	if e = restoreState(store, f.source, "session", []string{"canary"}, engine, host, &f.t); e != nil {
		t.Fatal(e)
	}
	p := &pausedContextAppender{store: store, wrote: make(chan struct{}), release: make(chan struct{})}
	i := &ingester{store: p, engine: engine, hostEngine: host, contextTrust: &f.t}
	ev := f.event
	ev.EventID = "second-event"
	ev.RequestID = "second-request"
	ev.SessionHMAC = "second-session"
	ev.EventTime = time.Now().UTC()
	ev.IngestTime = ev.EventTime
	obs := actioncontext.Observation{Schema: "action-observation/2", Binding: ev.ContextBinding(), KeyID: "sensor"}
	obs.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(f.sensor, actioncontext.ObservationBytes(obs)))
	ev.Context = &obs
	done := make(chan error, 1)
	go func() { _, err := i.process(ev); done <- err }()
	<-p.wrote
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	if _, e = captureContextSnapshot(ctx, i, f.source); !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal("captured an incomplete commit", e)
	}
	close(p.release)
	if e = <-done; e != nil {
		t.Fatal(e)
	}
	snapshot, e := captureContextSnapshot(context.Background(), i, f.source)
	if e != nil {
		t.Fatal(e)
	}
	if !i.mu.TryLock() {
		t.Fatal("capture retained ingester mutex")
	}
	i.mu.Unlock()
	result, e := contextshadow.ObserveSnapshot(snapshot, f.c, f.c.SHA, f.a, f.t)
	if e != nil || result.Observed != 2 {
		t.Fatal(result, e)
	}
}
func TestContextShadowStopCancelsInflightAndSavesFailure(t *testing.T) {
	f := makeFixture(t)
	started := make(chan struct{})
	live, e := contextshadow.OpenLive(filepath.Join(f.dir, "history"), f.c, f.a, f.t, func(ctx context.Context) (*evidence.Snapshot, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	})
	if e != nil {
		t.Fatal(e)
	}
	defer live.Close()
	if e = live.Request(f.c.SHA, true); e != nil {
		t.Fatal(e)
	}
	<-started
	live.Stop()
	status := waitContextIdle(t, live, 1)
	if status.Enabled || status.Latest == nil || status.Latest.Receipt != nil || status.Error == "" {
		t.Fatal("cancel published a prediction", status)
	}
}
func TestContextShadowExportBrowserFixture(t *testing.T) {
	export := os.Getenv("CONTEXT_SHADOW_LIVE_EXPORT")
	if export == "" {
		t.Skip("opt-in browser fixture export")
	}
	f := makeFixture(t)
	if e := os.Mkdir(export, 0700); e != nil {
		t.Fatal(e)
	}
	put(t, filepath.Join(export, "candidate.json"), f.c)
	put(t, filepath.Join(export, "authorities.json"), f.a)
	put(t, filepath.Join(export, "context-trust.json"), f.t)
	put(t, filepath.Join(export, "profile.json"), contextshadow.Profile{CandidatePath: "candidate.json", CandidateSHA: f.c.SHA, AuthoritiesPath: "authorities.json"})
	events := []event.Event{}
	for n := 0; n < 4; n++ {
		e := f.event
		e.EventID = fmt.Sprint("browser-event-", n)
		e.RequestID = fmt.Sprint("browser-request-", n)
		e.SessionHMAC = fmt.Sprint("browser-session-", n)
		e.EventTime = time.Now().UTC()
		e.IngestTime = e.EventTime
		obs := actioncontext.Observation{Schema: "action-observation/2", Binding: e.ContextBinding(), KeyID: "sensor"}
		obs.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(f.sensor, actioncontext.ObservationBytes(obs)))
		e.Context = &obs
		events = append(events, e)
	}
	put(t, filepath.Join(export, "events.json"), events)
}

func TestContextShadowStorageAmbiguityBlocksFurtherDispatch(t *testing.T) {
	f := makeFixture(t)
	snapshot, e := evidence.Capture(f.source)
	if e != nil {
		t.Fatal(e)
	}
	dir := filepath.Join(f.dir, "history")
	live, e := contextshadow.OpenLive(dir, f.c, f.a, f.t, func(ctx context.Context) (*evidence.Snapshot, error) { return snapshot, nil })
	if e != nil {
		t.Fatal(e)
	}
	defer live.Close()
	if e = os.WriteFile(filepath.Join(dir, "attempt-000001.json"), []byte("injected conflicting file"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = live.Request(f.c.SHA, true); e != nil {
		t.Fatal(e)
	}
	status := waitContextIdle(t, live, 1)
	if status.Enabled || status.Error == "" || status.Latest != nil {
		t.Fatal(status)
	}
	if e = live.Request(f.c.SHA, true); !errors.Is(e, contextshadow.ErrConflict) {
		t.Fatal("dispatch after ambiguous save", e)
	}
}

func TestContextShadowArchiveQuotaPreservesHistoryAndCollector(t *testing.T) {
	f := makeFixture(t)
	store, e := evidence.New(f.source, 4<<20)
	if e != nil {
		t.Fatal(e)
	}
	defer store.Close()
	engine := detect.New()
	engine.Canaries = map[string]bool{"canary": true}
	host := hostguard.New([]string{"canary"})
	if e = restoreState(store, f.source, "session", []string{"canary"}, engine, host, &f.t); e != nil {
		t.Fatal(e)
	}
	i := &ingester{store: store, engine: engine, hostEngine: host, contextTrust: &f.t}
	dir := filepath.Join(f.dir, "history")
	limits := contextshadow.StorageLimits{ActiveAttempts: 4, ActiveBytes: 64 << 10, ArchiveSegments: 1, TotalBytes: 192 << 10}
	capture := func(ctx context.Context) (*evidence.Snapshot, error) { return captureContextSnapshot(ctx, i, f.source) }
	live, e := contextshadow.OpenLiveWithStorage(dir, f.c, f.a, f.t, capture, limits)
	if e != nil {
		t.Fatal(e)
	}
	defer live.Close()
	send := func(n int) {
		ev := f.event
		ev.EventID = fmt.Sprint("quota-", n)
		ev.RequestID = ev.EventID
		ev.SessionHMAC = ev.EventID
		ev.EventTime = time.Now().UTC()
		ev.IngestTime = ev.EventTime
		obs := actioncontext.Observation{Schema: "action-observation/2", Binding: ev.ContextBinding(), KeyID: "sensor"}
		obs.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(f.sensor, actioncontext.ObservationBytes(obs)))
		ev.Context = &obs
		if _, e = i.process(ev); e != nil {
			t.Fatal(e)
		}
	}
	var first string
	for n := 1; n <= 8; n++ {
		send(n)
		if e = live.Request(f.c.SHA, false); e != nil {
			t.Fatal(n, e)
		}
		status := waitContextIdle(t, live, n)
		if status.Latest == nil || status.Latest.Sequence != n {
			t.Fatal(status)
		}
		if n == 1 {
			first = status.Latest.SHA
		}
	}
	status := live.Status()
	if status.Storage.ArchiveSegments != 1 || status.Storage.ArchivedAttempts != 4 || status.Storage.ActiveAttempts != 4 {
		t.Fatal(status.Storage)
	}
	if a, e := live.History(1); e != nil || a.SHA != first {
		t.Fatal("archived history lost", e)
	}
	if e = live.Request(f.c.SHA, true); !errors.Is(e, contextshadow.ErrLimit) {
		t.Fatal("quota not paused", e)
	}
	status = live.Status()
	if status.Enabled || status.Storage.State != "full" {
		t.Fatal(status)
	}
	send(99)
	snapshot, e := capture(context.Background())
	if e != nil {
		t.Fatal("quota stopped collector", e)
	}
	if e = recovery.VerifySnapshot(snapshot); e != nil {
		t.Fatal(e)
	}
	live.Close()
	restored, e := contextshadow.OpenLiveWithStorage(dir, f.c, f.a, f.t, capture, limits)
	if e != nil {
		t.Fatal(e)
	}
	if restored.Status().Storage.State != "full" || restored.Status().Enabled {
		t.Fatal("capacity pause not restored")
	}
	if a, e := restored.History(1); e != nil || a.SHA != first {
		t.Fatal(e)
	}
	restored.Close()
	if e = os.WriteFile(filepath.Join(dir, "rotation.pending.json"), []byte("interrupted intent"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = contextshadow.OpenLiveWithStorage(dir, f.c, f.a, f.t, capture, limits); e == nil {
		t.Fatal("unfinished rotation auto recovered")
	}
}
func TestContextShadowExportLoadFixture(t *testing.T) {
	export := os.Getenv("CONTEXT_SHADOW_LOAD_EXPORT")
	if export == "" {
		t.Skip("opt-in load fixture export")
	}
	f := makeFixture(t)
	if e := os.Mkdir(export, 0700); e != nil {
		t.Fatal(e)
	}
	put(t, filepath.Join(export, "candidate.json"), f.c)
	put(t, filepath.Join(export, "authorities.json"), f.a)
	put(t, filepath.Join(export, "context-trust.json"), f.t)
	put(t, filepath.Join(export, "profile.json"), contextshadow.Profile{CandidatePath: "candidate.json", CandidateSHA: f.c.SHA, AuthoritiesPath: "authorities.json"})
	events := []event.Event{}
	for n := 0; n < 12000; n++ {
		e := f.event
		e.EventID = fmt.Sprint("load-event-", n)
		e.RequestID = e.EventID
		e.SessionHMAC = "load-session"
		if n < 4 {
			e.SessionHMAC = fmt.Sprint("load-canary-", n)
		} else {
			e.CanaryID = ""
			e.ResourceClass = "business"
			e.Authorization = "allow"
			e.Status = 200
			e.Route = "/objects/{id}"
			e.PathHMAC = "load-known-path"
		}
		e.EventTime = time.Now().UTC()
		e.IngestTime = e.EventTime
		obs := actioncontext.Observation{Schema: "action-observation/2", Binding: e.ContextBinding(), KeyID: "sensor"}
		obs.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(f.sensor, actioncontext.ObservationBytes(obs)))
		e.Context = &obs
		events = append(events, e)
	}
	put(t, filepath.Join(export, "events.json"), events)
}

func TestContextShadowExportBoundaryFixture(t *testing.T) {
	export := os.Getenv("CONTEXT_SHADOW_BOUNDARY_EXPORT")
	if export == "" {
		t.Skip("opt-in boundary fixture export")
	}
	f := makeFixture(t)
	if e := os.Mkdir(export, 0700); e != nil {
		t.Fatal(e)
	}
	put(t, filepath.Join(export, "candidate.json"), f.c)
	put(t, filepath.Join(export, "authorities.json"), f.a)
	put(t, filepath.Join(export, "context-trust.json"), f.t)
	put(t, filepath.Join(export, "profile.json"), contextshadow.Profile{CandidatePath: "candidate.json", CandidateSHA: f.c.SHA, AuthoritiesPath: "authorities.json"})
	sign := func(e event.Event) event.Event {
		e.EventTime = time.Now().UTC()
		e.IngestTime = e.EventTime
		obs := actioncontext.Observation{Schema: "action-observation/2", Binding: e.ContextBinding(), KeyID: "sensor"}
		obs.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(f.sensor, actioncontext.ObservationBytes(obs)))
		e.Context = &obs
		return e
	}
	events := []event.Event{}
	for n := 0; n < 24000; n++ {
		e := f.event
		e.EventID = fmt.Sprint("boundary-event-", n)
		e.RequestID = e.EventID
		e.SessionHMAC = "boundary-business"
		if n < 512 {
			e.SessionHMAC = fmt.Sprint("boundary-canary-", n)
		} else {
			e.CanaryID = ""
			e.ResourceClass = "business"
			e.Authorization = "allow"
			e.Status = 200
			e.Route = "/objects/{id}"
			e.PathHMAC = "boundary-known-path"
		}
		events = append(events, sign(e))
	}
	put(t, filepath.Join(export, "events.json"), events)
	e := f.event
	e.EventID = "boundary-case-513"
	e.RequestID = e.EventID
	e.SessionHMAC = e.EventID
	put(t, filepath.Join(export, "case-513.json"), sign(e))
}
