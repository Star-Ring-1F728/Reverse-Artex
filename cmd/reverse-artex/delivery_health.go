package main

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
)

// Delivery guard only. No store inventory or admission credit is returned.
// The subsequent POST performs its own synchronized admission and durable ACK.
func deliveryHealthHandler(token string, forwarding bool, degraded func() bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if len(token) < 32 || subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+token)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		json.NewEncoder(w).Encode(map[string]any{
			"schema": "ra-delivery-health/1", "mode": "observe",
			"policy_forwarding_configured": forwarding, "ingest_degraded": degraded(),
		})
	}
}
