package main

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reverse-artex/internal/event"
	"time"
)

// The app credential retains its exact single-event sensor/asset/tenant scope.
func appBatchHandler(ingest *ingester, token, sensor, asset string, allowed map[string]bool, sem chan struct{}) http.HandlerFunc {
	return appBatchHandlerLimit(ingest, token, sensor, asset, allowed, sem, 16)
}

func appBatchHandlerLimit(ingest *ingester, token, sensor, asset string, allowed map[string]bool, sem chan struct{}, limit int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		defer ingest.timeBatch("http_total", started)
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+token)) != 1 {
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
		batch, err := event.DecodeBatchLimit(http.MaxBytesReader(w, r.Body, 256<<10), limit)
		ingest.timeBatch("http_decode", started)
		if err != nil {
			http.Error(w, "invalid event batch", 400)
			return
		}
		for _, e := range batch {
			if err := ingest.contextTrust.Verify(e.Context, e.ContextBinding()); err != nil {
				http.Error(w, "untrusted action context", 400)
				return
			}
			if e.SensorID != sensor || e.AssetID != asset || !allowed[e.TenantID] {
				http.Error(w, "sensor scope denied", 403)
				return
			}
		}
		results, err := ingest.processBatchContext(r.Context(), batch, limit)
		if err != nil {
			if ingest.degraded() || errors.Is(err, errPolicyDeliveryUnavailable) {
				w.Header().Set("X-RA-Delivery-Permanent", "1")
			}
			http.Error(w, "evidence unavailable", 503)
			return
		}
		for _, result := range results {
			if result == "capacity_rejected" {
				http.Error(w, "correlation capacity", 429)
				return
			}
		}
		w.WriteHeader(202)
		json.NewEncoder(w).Encode(map[string]any{"results": results, "mode": "observe"})
	}
}
