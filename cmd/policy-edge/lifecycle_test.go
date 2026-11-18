package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reverse-artex/internal/edge"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func freeEdgeAddress(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := l.Addr().String()
	l.Close()
	return address
}

func getWhenListening(t *testing.T, address string, result chan<- error) {
	t.Helper()
	go func() {
		deadline := time.Now().Add(time.Second)
		for {
			client := &http.Client{Timeout: 2 * time.Second}
			response, err := client.Get("http://" + address + "/")
			if err != nil && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
				continue
			}
			if err == nil {
				body, readErr := io.ReadAll(response.Body)
				response.Body.Close()
				if readErr != nil {
					err = readErr
				} else if response.StatusCode != 200 || string(body) != "complete" {
					err = errors.New("incomplete admitted response")
				}
			}
			result <- err
			return
		}
	}()
}

func TestLifecycleDrainsBothHTTPServersBeforeClosingResources(t *testing.T) {
	entered, release := make(chan struct{}, 2), make(chan struct{})
	var active atomic.Int64
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		active.Add(1)
		defer active.Add(-1)
		entered <- struct{}{}
		<-release
		io.WriteString(w, "complete")
	})
	public := &http.Server{Addr: freeEdgeAddress(t), Handler: handler}
	private := &http.Server{Addr: freeEdgeAddress(t), Handler: handler}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var cleanupCalls atomic.Int64
	done := make(chan error, 1)
	go func() {
		done <- serveEdgeServers(ctx, public, private, func(context.Context) error {
			cleanupCalls.Add(1)
			if active.Load() != 0 {
				return errors.New("resources closed before handlers drained")
			}
			return nil
		}, time.Second)
	}()
	responses := make(chan error, 2)
	getWhenListening(t, public.Addr, responses)
	getWhenListening(t, private.Addr, responses)
	for n := 0; n < 2; n++ {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("request did not enter")
		}
	}
	cancel()
	select {
	case err := <-done:
		t.Fatal("shutdown returned before admitted requests completed", err)
	case <-time.After(10 * time.Millisecond):
	}
	if cleanupCalls.Load() != 0 {
		t.Fatal("early resource cleanup")
	}
	close(release)
	for n := 0; n < 2; n++ {
		if err := <-responses; err != nil {
			t.Fatal(err)
		}
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if cleanupCalls.Load() != 1 {
		t.Fatal("cleanup not exactly once")
	}
	for _, address := range []string{public.Addr, private.Addr} {
		connection, err := net.DialTimeout("tcp", address, 50*time.Millisecond)
		if err == nil {
			connection.Close()
			t.Fatal("listener remained after shutdown")
		}
	}
}

func TestLifecycleTimeoutFailsWithoutClosingLiveHandlerStores(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	public := &http.Server{Addr: freeEdgeAddress(t), Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(entered); <-release })}
	private := &http.Server{Addr: freeEdgeAddress(t), Handler: http.NotFoundHandler()}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var cleaned atomic.Bool
	done := make(chan error, 1)
	go func() {
		done <- serveEdgeServers(ctx, public, private, func(context.Context) error { cleaned.Store(true); return nil }, 25*time.Millisecond)
	}()
	response := make(chan error, 1)
	getWhenListening(t, public.Addr, response)
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("request did not enter")
	}
	started := time.Now()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("timeout not reported", err)
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown was unbounded")
	}
	if cleaned.Load() || time.Since(started) > time.Second {
		t.Fatal("false drain or closed live handler stores")
	}
	close(release)
	<-response
}

func TestLifecycleStartupListenerFailureCleansIdleResourcesAndOwnedListener(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	public := &http.Server{Addr: freeEdgeAddress(t), Handler: http.NotFoundHandler()}
	private := &http.Server{Addr: occupied.Addr().String(), Handler: http.NotFoundHandler()}
	cleaned := false
	err = serveEdgeServers(context.Background(), public, private, func(context.Context) error { cleaned = true; return nil }, time.Second)
	if err == nil || !cleaned {
		t.Fatal("startup failure leaked idle resources", err)
	}
	if connection, err := net.DialTimeout("tcp", public.Addr, 50*time.Millisecond); err == nil {
		connection.Close()
		t.Fatal("first owned listener leaked")
	}
	if connection, err := net.DialTimeout("tcp", private.Addr, 50*time.Millisecond); err != nil {
		t.Fatal("unrelated occupied listener was closed")
	} else {
		connection.Close()
	}
}

func TestLifecycleCancellationBeforeAdmissionStillClosesResources(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cleaned := false
	err := serveEdgeServers(ctx, &http.Server{Addr: "invalid"}, &http.Server{Addr: "invalid"}, func(context.Context) error { cleaned = true; return nil }, time.Second)
	if err != nil || !cleaned {
		t.Fatal("cancelled startup attempted admission or leaked resources", err)
	}
}

func TestLifecycleProducerAndBatchWritesFinishBeforeStoreClose(t *testing.T) {
	var closed, late atomic.Bool
	var writes atomic.Int64
	write := func() {
		if closed.Load() {
			late.Store(true)
		}
		writes.Add(1)
	}
	stopModel, modelDone := make(chan struct{}), make(chan struct{})
	go func() { <-stopModel; write(); close(modelDone) }()
	closers := &edgeClosers{
		background: write,
		producers:  []func(){func() { close(stopModel); <-modelDone }},
		batchers:   []func() error{func() error { write(); return nil }},
		stores: []func() error{func() error {
			if writes.Load() != 3 {
				return errors.New("producer missing before store close")
			}
			closed.Store(true)
			return nil
		}},
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := closers.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if err := closers.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if !closed.Load() || late.Load() || writes.Load() != 3 {
		t.Fatal("unsafe or repeated cleanup")
	}
}

func TestLifecycleBlockedProducerFailsBoundedlyWithoutPrematureStoreClose(t *testing.T) {
	release, producerStarted := make(chan struct{}), make(chan struct{})
	var closed atomic.Bool
	closers := &edgeClosers{producers: []func(){func() { close(producerStarted); <-release }}, stores: []func() error{func() error { closed.Store(true); return nil }}}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := closers.Close(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("blocked producer did not fail", err)
	}
	<-producerStarted
	if closed.Load() {
		t.Fatal("store closed while producer alive")
	}
	close(release)
	ctx2, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if err := closers.Close(ctx2); err != nil || !closed.Load() {
		t.Fatal("eventual ordered closure failed", err)
	}
}

func TestLifecycleCloseErrorsPreventSuccessfulShutdown(t *testing.T) {
	want := errors.New("durable writer close failure")
	var mu sync.Mutex
	var order []string
	closers := &edgeClosers{batchers: []func() error{func() error { mu.Lock(); order = append(order, "batch"); mu.Unlock(); return want }}, stores: []func() error{func() error { mu.Lock(); order = append(order, "store"); mu.Unlock(); return nil }}}
	if err := closers.Close(context.Background()); !errors.Is(err, want) {
		t.Fatal("close failure hidden", err)
	}
	if len(order) != 2 || order[0] != "batch" || order[1] != "store" {
		t.Fatal("store order changed", order)
	}
}

func TestLifecycleDrainsWithinUpstreamHeaderDeadline(t *testing.T) {
	for _, test := range []struct {
		name   string
		delay  time.Duration
		status int
	}{
		{"headers-before-limit", 2 * time.Second, 200},
		{"headers-after-limit", 3200 * time.Millisecond, 503},
	} {
		t.Run(test.name, func(t *testing.T) {
			entered := make(chan struct{})
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				close(entered)
				timer := time.NewTimer(test.delay)
				defer timer.Stop()
				select {
				case <-timer.C:
					io.WriteString(w, "complete")
				case <-r.Context().Done():
				}
			}))
			defer upstream.Close()
			target, _ := url.Parse(upstream.URL)
			var active atomic.Int64
			proxy := edge.Handler(edge.Config{Upstream: target})
			public := &http.Server{Addr: freeEdgeAddress(t), WriteTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				active.Add(1)
				defer active.Add(-1)
				proxy.ServeHTTP(w, r)
			})}
			private := &http.Server{Addr: freeEdgeAddress(t), Handler: http.NotFoundHandler()}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				done <- serveEdgeServers(ctx, public, private, func(context.Context) error {
					if active.Load() != 0 {
						return errors.New("closed resources before upstream deadline")
					}
					return nil
				}, 6*time.Second)
			}()
			response := make(chan error, 1)
			go func() {
				client := &http.Client{Timeout: 5 * time.Second}
				defer client.CloseIdleConnections()
				deadline := time.Now().Add(time.Second)
				for {
					res, err := client.Get("http://" + public.Addr + "/health")
					if err != nil && time.Now().Before(deadline) {
						time.Sleep(time.Millisecond)
						continue
					}
					if err == nil {
						body, readErr := io.ReadAll(res.Body)
						res.Body.Close()
						err = readErr
						if res.StatusCode != test.status {
							err = errors.New("unexpected slow-header status")
						}
						if test.status == 200 && string(body) != "complete" {
							err = errors.New("admitted body incomplete")
						}
						if test.status != 200 && string(body) == "complete" {
							err = errors.New("late response released")
						}
					}
					response <- err
					return
				}
			}()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("request never reached owned upstream")
			}
			cancel()
			if err := <-response; err != nil {
				t.Fatal(err)
			}
			if err := <-done; err != nil {
				t.Fatal("drain failed", err)
			}
		})
	}
}
