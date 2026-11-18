package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type decodedSignal struct {
	io.Reader
	once sync.Once
	done chan struct{}
}

func TestMutationLockDeadlineAndConcurrentReuse(t *testing.T) {
	var gate mutationLock
	gate.Lock()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := gate.LockContext(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("deadline not observed", err)
	}
	gate.Unlock()
	if err := gate.LockContext(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("expired context took free writer", err)
	}
	var inside atomic.Int32
	var count int
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			for range 200 {
				if err := gate.LockContext(context.Background()); err != nil {
					t.Error(err)
					return
				}
				if inside.Add(1) != 1 {
					t.Error("overlapping writer admission")
				}
				count++
				inside.Add(-1)
				gate.Unlock()
			}
		})
	}
	workers.Wait()
	if count != 1600 {
		t.Fatal("writer lock lost updates", count)
	}
}

func TestControlMutationSlotsRecoverBeforeSlowSyncFinishes(t *testing.T) {
	m := manager(t)
	now := time.Now().UTC()
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	var syncs atomic.Int32
	m.syncFile = func(f *os.File) error {
		if syncs.Add(1) == 1 {
			close(entered)
			<-release
		}
		return f.Sync()
	}
	h := Handler(m, Tokens{Evidence: strings.Repeat("e", 32)})
	type pending struct {
		cancel        context.CancelFunc
		decoded, done chan struct{}
		w             *httptest.ResponseRecorder
	}
	start := func(id string) pending {
		body, _ := json.Marshal(specimen(id, "lab-app", now))
		ctx, cancel := context.WithCancel(context.Background())
		decoded, done := make(chan struct{}), make(chan struct{})
		r := httptest.NewRequest(http.MethodPost, "/v1/evidence", bytes.NewReader(body)).WithContext(ctx)
		r.Body = io.NopCloser(&decodedSignal{Reader: bytes.NewReader(body), done: decoded})
		r.Header.Set("Authorization", "Bearer "+strings.Repeat("e", 32))
		w := httptest.NewRecorder()
		go func() { defer close(done); h.ServeHTTP(w, r) }()
		return pending{cancel, decoded, done, w}
	}
	first := start("admitted")
	defer first.cancel()
	<-entered
	waiters := make([]pending, 15)
	for i := range waiters {
		waiters[i] = start("queued-" + string(rune('a'+i)))
		defer waiters[i].cancel()
		<-waiters[i].decoded
	}
	// All sixteen existing mutation slots are occupied; overflow is retryable.
	body, _ := json.Marshal(specimen("overflow", "lab-app", now))
	r := httptest.NewRequest(http.MethodPost, "/v1/evidence", bytes.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+strings.Repeat("e", 32))
	overflow := httptest.NewRecorder()
	h.ServeHTTP(overflow, r)
	if overflow.Code != 429 || overflow.Header().Get("Retry-After") != "1" || overflow.Header().Get("X-RA-Delivery-Permanent") != "" {
		t.Fatal("bad slot backpressure", overflow.Code)
	}
	for _, waiter := range waiters {
		waiter.cancel()
	}
	first.cancel() // already admitted: cancellation must not skip Sync/commit
	for _, waiter := range waiters {
		select {
		case <-waiter.done:
		case <-time.After(500 * time.Millisecond):
			t.Fatal("cancelled waiter retained slot")
		}
		if waiter.w.Code != 503 || waiter.w.Header().Get("X-RA-Delivery-Permanent") != "" {
			t.Fatal("cancellation was permanent", waiter.w.Code)
		}
	}
	select {
	case <-first.done:
		t.Fatal("admitted Sync was interrupted")
	default:
	}
	retry := start("queued-a")
	defer retry.cancel()
	select {
	case <-retry.decoded:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("cancelled slots were not reusable")
	}
	if syncs.Load() != 1 {
		t.Fatal("waiting requests started I/O")
	}
	unblock()
	<-first.done
	<-retry.done
	if first.w.Code != 202 || retry.w.Code != 202 || syncs.Load() != 2 || m.version != 3 || len(m.events) != 2 {
		t.Fatal("admitted commit/retry mismatch", first.w.Code, retry.w.Code, m.version, syncs.Load())
	}
	assertEvidenceIndexes(t, m)
	restored, err := Open(m.dir)
	if err != nil || len(restored.events) != 2 || restored.version != 3 {
		t.Fatal("recovery lost admitted writes", err)
	}
}

func TestCancelledControlWaiterOverRealHTTP(t *testing.T) {
	m := manager(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	var syncs atomic.Int32
	m.syncFile = func(f *os.File) error {
		if syncs.Add(1) == 1 {
			close(entered)
			<-release
		}
		return f.Sync()
	}
	h := Handler(m, Tokens{Evidence: strings.Repeat("e", 32)})
	decoded, finished := make(chan struct{}), make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery == "waiting" {
			defer close(finished)
			body := r.Body
			defer body.Close()
			r.Body = io.NopCloser(&decodedSignal{Reader: body, done: decoded})
		}
		h.ServeHTTP(w, r)
	}))
	defer server.Close()
	// Ensure deferred server.Close can never wait on our injected Sync gate.
	defer unblock()
	client := &http.Client{Timeout: 3 * time.Second}
	defer client.CloseIdleConnections()
	post := func(ctx context.Context, id, query string) error {
		body, _ := json.Marshal(specimen(id, "lab-app", time.Now().UTC()))
		r, _ := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+"/v1/evidence"+query, bytes.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+strings.Repeat("e", 32))
		res, err := client.Do(r)
		if err != nil {
			return err
		}
		defer res.Body.Close()
		_, err = io.Copy(io.Discard, res.Body)
		if err == nil && res.StatusCode != 202 {
			return errors.New("unexpected HTTP status")
		}
		return err
	}
	firstDone := make(chan error, 1)
	go func() { firstDone <- post(context.Background(), "http-admitted", "") }()
	<-entered
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	waiterDone := make(chan error, 1)
	go func() { waiterDone <- post(ctx, "http-cancelled", "?waiting") }()
	<-decoded
	cancel()
	if err := <-waiterDone; !errors.Is(err, context.Canceled) {
		t.Fatal("client cancellation outcome", err)
	}
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("server retained disconnected waiter")
	}
	if syncs.Load() != 1 {
		t.Fatal("cancelled waiter wrote before release")
	}
	unblock()
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
	if err := post(context.Background(), "http-retry", ""); err != nil {
		t.Fatal(err)
	}
	if syncs.Load() != 2 || m.version != 3 || len(m.events) != 2 {
		t.Fatal("disconnected waiter changed durable state")
	}
	if _, ok := m.events["http-cancelled"]; ok {
		t.Fatal("disconnected event persisted")
	}
	assertEvidenceIndexes(t, m)
}

func (r *decodedSignal) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if err == io.EOF {
		r.once.Do(func() { close(r.done) })
	}
	return n, err
}

func TestCancelledControlMutationWaiterDoesNotCommit(t *testing.T) {
	for _, operation := range []string{"evidence", "policies", "revoke", "rollback", "auto"} {
		t.Run(operation, func(t *testing.T) {
			m := manager(t)
			now := time.Now().UTC()
			if _, err := m.Evidence(specimen("subject", "lab-app", now), now); err != nil {
				t.Fatal(err)
			}
			p, err := m.Approve(approval("seed-approval", "subject"), now)
			if err != nil {
				t.Fatal(err)
			}
			var value any
			switch operation {
			case "evidence":
				value = specimen("cancelled-waiter", "lab-app", now)
			case "policies":
				value = approval("cancelled-approval", "subject")
			case "revoke":
				value = Revoke{"cancelled-revoke", p.PolicyID, "experiment"}
			case "rollback":
				value = Rollback{"cancelled-rollback", 1, "rollback"}
			case "auto":
				value = map[string]any{"idempotency_key": "cancelled-auto", "enabled": true}
			}
			body, _ := json.Marshal(value)
			decoded := make(chan struct{})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			r := httptest.NewRequest(http.MethodPost, "/v1/"+operation, bytes.NewReader(body)).WithContext(ctx)
			r.Body = io.NopCloser(&decodedSignal{Reader: bytes.NewReader(body), done: decoded})
			r.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 32))
			w := httptest.NewRecorder()
			h := Handler(m, Tokens{Admin: strings.Repeat("a", 32), Evidence: strings.Repeat("a", 32)})
			before, err := os.ReadFile(filepath.Join(m.dir, "actions.jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			version := m.version
			m.mu.Lock()
			done := make(chan struct{})
			go func() { defer close(done); h.ServeHTTP(w, r) }()
			<-decoded
			cancel()
			prompt := false
			select {
			case <-done:
				prompt = true
			case <-time.After(250 * time.Millisecond):
			}
			m.mu.Unlock()
			<-done
			after, err := os.ReadFile(filepath.Join(m.dir, "actions.jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			if !prompt || w.Code != 503 || w.Header().Get("X-RA-Delivery-Permanent") != "" || !bytes.Equal(before, after) || m.version != version {
				t.Fatalf("cancelled waiter committed or stayed blocked: prompt=%v status=%d version=%d/%d audit_equal=%v", prompt, w.Code, m.version, version, bytes.Equal(before, after))
			}
		})
	}
}
