package responsev2

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reverse-artex/internal/decisions"
	"strings"
	"testing"
	"time"
)

func TestApplyReceiptReplayRemainsTenantBoundAcrossLifecycle(t *testing.T) {
	for _, phase := range []string{"installed", "case-changed", "paused", "released", "restarted"} {
		t.Run(phase, func(t *testing.T) {
			s, reg, key, path := storeFixture(t)
			v := eligibleFixture(t, s, reg, key)
			first := intentFixture(s, v, "original", "operator", "owned")
			receipt, err := s.Apply(context.Background(), "alpha", first)
			if err != nil {
				t.Fatal(err)
			}
			duplicate := first
			duplicate.ID = "same-evidence-new-id"
			duplicateReceipt, err := s.Apply(context.Background(), "alpha", duplicate)
			if err != nil || duplicateReceipt.State != "already_installed_locally" {
				t.Fatal(duplicateReceipt, err)
			}
			switch phase {
			case "case-changed":
				observeFixture(t, s, reg, key, "later", "own", "alpha", "allow", time.Now())
			case "paused":
				if err = s.Pause(true); err != nil {
					t.Fatal(err)
				}
			case "released":
				p := s.Policies("alpha")[0]
				if _, err = s.Release(context.Background(), "alpha", p.ID, "operator", "owned", "release", p.Generation); err != nil {
					t.Fatal(err)
				}
			case "restarted":
				if err = s.Close(); err != nil {
					t.Fatal(err)
				}
				s, err = Open(path, reg)
				if err != nil {
					t.Fatal(err)
				}
				defer s.Close()
			}
			sequence := s.sequence
			for index, intent := range []Intent{first, duplicate} {
				want := []Receipt{receipt, duplicateReceipt}[index]
				if got, err := s.Apply(context.Background(), "beta", intent); !errors.Is(err, ErrStale) || got != (Receipt{}) {
					t.Errorf("cross-tenant replay returned receipt: intent=%s receipt=%+v err=%v", intent.ID, got, err)
				}
				if got, err := s.Apply(context.Background(), "alpha", intent); err != nil || got != want {
					t.Errorf("same-tenant historical receipt changed: got=%+v want=%+v err=%v", got, want, err)
				}
			}
			if s.sequence != sequence {
				t.Fatal("receipt lookup changed durable state")
			}
		})
	}
}

func TestManagementApplyReplayDoesNotReturnForeignTenantReceipt(t *testing.T) {
	s, reg, key, _ := storeFixture(t)
	v := eligibleFixture(t, s, reg, key)
	intent := intentFixture(s, v, "http-replay", "operator", "owned")
	runner, err := NewRunner(s, configFixture("fake"), []byte(strings.Repeat("p", 32)), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer runner.Close()
	operator := strings.Repeat("o", 40)
	server := httptest.NewServer(Handler(s, runner, strings.Repeat("r", 40), operator))
	defer server.Close()
	var first []byte
	for _, tenant := range []string{"alpha", "beta", "alpha"} {
		raw, _ := json.Marshal(Command{Tenant: tenant, Intent: &intent})
		req, _ := http.NewRequest("POST", server.URL+"/v2/apply", bytes.NewReader(raw))
		req.Header.Set("Authorization", "Bearer "+operator)
		response, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		var receipt Receipt
		decodeErr := json.NewDecoder(response.Body).Decode(&receipt)
		response.Body.Close()
		if tenant == "beta" {
			if response.StatusCode != 409 || decodeErr == nil {
				t.Fatalf("foreign tenant received a policy receipt over HTTP: status=%d receipt=%+v", response.StatusCode, receipt)
			}
			continue
		}
		if response.StatusCode != 200 || decodeErr != nil {
			t.Fatal(response.StatusCode, decodeErr)
		}
		encoded, _ := json.Marshal(receipt)
		if first == nil {
			first = encoded
		} else if !bytes.Equal(first, encoded) {
			t.Fatal("same-tenant replay changed historical receipt")
		}
	}
}

func TestReleaseLifecycleFencesAndOperatorRecovery(t *testing.T) {
	for _, phase := range []string{"current", "old-generation", "wrong-owner", "wrong-tenant", "expiry-boundary", "cancelled", "paused", "co-owner"} {
		t.Run(phase, func(t *testing.T) {
			s, reg, key, _ := storeFixture(t)
			v := eligibleFixture(t, s, reg, key)
			installed, err := s.Apply(context.Background(), "alpha", intentFixture(s, v, "install", "operator", "owned"))
			if err != nil {
				t.Fatal(err)
			}
			generation, tenant, owner := installed.Generation, "alpha", "operator"
			at := time.Now()
			ctx := context.Background()
			if phase == "old-generation" || phase == "co-owner" {
				joined, err := s.Apply(ctx, "alpha", intentFixture(s, v, "join", "native", "other"))
				if err != nil {
					t.Fatal(err)
				}
				if phase == "co-owner" {
					generation = joined.Generation
				}
			}
			switch phase {
			case "wrong-owner":
				owner = "l3"
			case "wrong-tenant":
				tenant = "beta"
			case "expiry-boundary":
				at = installed.Expires
			case "cancelled":
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelled
			case "paused":
				if err := s.Pause(true); err != nil {
					t.Fatal(err)
				}
			}
			if phase != "expiry-boundary" {
				at = time.Now()
			}
			before, sequence := clone(s.leases[installed.PolicyID]), s.sequence
			s.mu.Lock()
			receipt, err := s.releaseLocked(ctx, tenant, installed.PolicyID, owner, "owned", "release", generation, at)
			s.mu.Unlock()
			valid := phase == "current" || phase == "paused" || phase == "co-owner"
			if !valid {
				wantErr := ErrStale
				if phase == "cancelled" {
					wantErr = context.Canceled
				}
				if !errors.Is(err, wantErr) || receipt != (Receipt{}) || s.sequence != sequence || decisions.Hash(s.leases[installed.PolicyID]) != decisions.Hash(before) {
					t.Fatal("invalid release mutated lease or issued a receipt", receipt, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if phase == "co-owner" {
				remaining := s.Policies("alpha")
				if receipt.State != "retained_by_other_owner" || len(remaining) != 1 || len(remaining[0].Claims) != 1 || remaining[0].Claims[0].Owner != "native" {
					t.Fatal("other owner's protection removed", receipt, remaining)
				}
			} else if receipt.State != "no_effective_policy" || len(s.Policies("alpha")) != 0 {
				t.Fatal("valid release did not remove own last claim", receipt)
			}
		})
	}
}
