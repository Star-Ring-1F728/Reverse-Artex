package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDeliveryHealthAuthenticationAndRecoveryGuard(t *testing.T) {
	token := strings.Repeat("a", 32)
	for _, forwarding := range []bool{false, true} {
		for _, failed := range []bool{false, true} {
			calls := 0
			handler := deliveryHealthHandler(token, forwarding, func() bool { calls++; return failed })
			for _, credential := range []string{"", "Bearer wrong", "Bearer " + token} {
				req := httptest.NewRequest(http.MethodGet, "/v1/delivery-health", nil)
				req.Header.Set("Authorization", credential)
				res := httptest.NewRecorder()
				before := calls
				handler.ServeHTTP(res, req)
				if credential != "Bearer "+token {
					if res.Code != http.StatusUnauthorized || calls != before {
						t.Fatal("unauthorized guard queried state")
					}
					if strings.Contains(res.Body.String(), token) {
						t.Fatal("credential leaked")
					}
					continue
				}
				var body map[string]any
				if res.Code != 200 || json.Unmarshal(res.Body.Bytes(), &body) != nil {
					t.Fatal("invalid authenticated response")
				}
				if len(body) != 4 || body["schema"] != "ra-delivery-health/1" || body["mode"] != "observe" || body["policy_forwarding_configured"] != forwarding || body["ingest_degraded"] != failed {
					t.Fatalf("invalid guard: %v", body)
				}
				if res.Header().Get("Cache-Control") != "no-store" {
					t.Fatal("guard must not be cached")
				}
			}
		}
	}
}
