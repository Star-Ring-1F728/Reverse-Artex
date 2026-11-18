package main

import (
	"context"
	"reverse-artex/internal/contextrelease"
	"reverse-artex/internal/evidence"
	"time"
)

// Normalize constructor failures to a nil interface so an unavailable optional
// canary cannot leave a typed nil in console or shutdown callbacks.
func openContextCanary(profile, expectedContext string, interval time.Duration, capture func(context.Context) (*evidence.Snapshot, error)) (contextrelease.RuntimeService, error) {
	if interval == 2*time.Second {
		service, err := contextrelease.OpenProfileService(profile, expectedContext, capture)
		if err != nil {
			return nil, err
		}
		return service, nil
	}
	service, err := contextrelease.OpenCadencedProfileService(profile, expectedContext, interval, capture)
	if err != nil {
		return nil, err
	}
	return service, nil
}
