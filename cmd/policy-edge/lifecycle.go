package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

// Preserve request/proof deadlines. This is only the bounded process shutdown
// window: the public write window plus one second for coordinated cleanup.
const edgeShutdownTimeout = 6 * time.Second

// A store is closed only after every producer and batch writer has stopped.
// If cleanup cannot finish in time, main exits nonzero; an unfinished producer
// never sees an explicitly closed store. The OS then owns process termination.
type edgeClosers struct {
	background func()
	producers  []func()
	batchers   []func() error
	stores     []func() error
	once       sync.Once
	done       chan struct{}
	err        error
}

func (c *edgeClosers) Close(ctx context.Context) error {
	c.once.Do(func() {
		c.done = make(chan struct{})
		go func() {
			defer close(c.done)
			if c.background != nil {
				c.background()
			}
			var producers sync.WaitGroup
			for _, stop := range c.producers {
				producers.Add(1)
				go func(stop func()) { defer producers.Done(); stop() }(stop)
			}
			producers.Wait()
			for _, closeBatch := range c.batchers {
				c.err = errors.Join(c.err, closeBatch())
			}
			for _, closeStore := range c.stores {
				c.err = errors.Join(c.err, closeStore())
			}
		}()
	})
	select {
	case <-c.done:
		return c.err
	case <-ctx.Done():
		return fmt.Errorf("edge background cleanup did not drain: %w", ctx.Err())
	}
}

func serveEdgeServers(ctx context.Context, ingress, management *http.Server, cleanup func(context.Context) error, timeout time.Duration) error {
	cleanupIdle := func(cause error) error {
		shutdown, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		return errors.Join(cause, cleanup(shutdown))
	}
	if ctx.Err() != nil {
		return cleanupIdle(nil)
	}
	publicListener, err := net.Listen("tcp", ingress.Addr)
	if err != nil {
		return cleanupIdle(fmt.Errorf("public ingress listener failed: %w", err))
	}
	privateListener, err := net.Listen("tcp", management.Addr)
	if err != nil {
		publicListener.Close()
		return cleanupIdle(fmt.Errorf("private management listener failed: %w", err))
	}
	results := make(chan error, 2)
	go func() { results <- ingress.Serve(publicListener) }()
	go func() { results <- management.Serve(privateListener) }()
	var cause error
	select {
	case <-ctx.Done():
	case err := <-results:
		cause = fmt.Errorf("edge listener stopped unexpectedly: %w", err)
	}
	shutdown, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	drained := make(chan error, 2)
	go func() { drained <- ingress.Shutdown(shutdown) }()
	go func() { drained <- management.Shutdown(shutdown) }()
	var drainErr error
	for n := 0; n < 2; n++ {
		drainErr = errors.Join(drainErr, <-drained)
	}
	if drainErr != nil {
		// Closing sockets cancels request contexts. A buggy handler can still
		// be alive, so do not close its stores or claim graceful completion.
		ingress.Close()
		management.Close()
		return errors.Join(cause, fmt.Errorf("edge HTTP shutdown did not drain: %w", drainErr))
	}
	return errors.Join(cause, cleanup(shutdown))
}
