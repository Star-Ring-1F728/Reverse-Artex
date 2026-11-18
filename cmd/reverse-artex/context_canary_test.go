package main

import (
	"context"
	"errors"
	"path/filepath"
	"reverse-artex/internal/evidence"
	"testing"
	"time"
)

func TestUnavailableCanaryReturnsNilRuntimeInterface(t *testing.T) {
	for _, interval := range []time.Duration{2 * time.Second, 120 * time.Second} {
		t.Run(interval.String(), func(t *testing.T) {
			service, err := openContextCanary(filepath.Join(t.TempDir(), "missing.json"), "", interval, func(context.Context) (*evidence.Snapshot, error) { return nil, errors.New("must not capture") })
			if err == nil || service != nil {
				t.Fatal("failed optional canary left a typed nil runtime", service, err)
			}
		})
	}
}
