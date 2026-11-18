package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reverse-artex/internal/evidence"
	"strings"
	"testing"
)

func writeOperationsFixture(t *testing.T, path string, value any) {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, []byte(os.Getenv("RA_OPS_SIGNING_KEY")))
	mac.Write(payload)
	raw, _ := json.Marshal(map[string]string{"payload": base64.StdEncoding.EncodeToString(payload), "signature": hex.EncodeToString(mac.Sum(nil))})
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
}

func operationsFixture(t *testing.T) (string, string, *operationsState) {
	t.Helper()
	root := t.TempDir()
	path := filepath.Join(t.TempDir(), "anchor.json")
	t.Setenv("RA_OPS_SIGNING_KEY", strings.Repeat("k", 48))
	t.Setenv("RA_SENSOR_TOKEN", strings.Repeat("s", 48))
	t.Setenv("RA_WAF_SENSOR_TOKEN", "")
	t.Setenv("RA_HOST_SENSOR_TOKEN", "")
	state := &operationsState{Schema: operationsSchema, Deployment: strings.Repeat("d", 32), Root: root, Limit: 16 << 20,
		Generation: 1, AuthEpoch: 1, Phase: "active", Roles: map[string]string{"admin": operationsDigest(strings.Repeat("a", 48)), "reader": operationsDigest(strings.Repeat("r", 48))},
		Credentials: map[string]string{"RA_SENSOR_TOKEN": operationsDigest(os.Getenv("RA_SENSOR_TOKEN"))}}
	state.CollectorScope = map[string]string{}
	for name, fallback := range operationsCollectorDefaults {
		t.Setenv(name, "")
		state.CollectorScope[name] = fallback
	}
	writeOperationsFixture(t, path, state)
	writeOperationsFixture(t, filepath.Join(root, ".operations.json"), operationsMarker{operationsSchema, state.Deployment, path, state.Generation})
	return root, path, state
}

func TestOperationsHealthRolesAndSensorMinimalResponse(t *testing.T) {
	root, path, _ := operationsFixture(t)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && r.Header.Get("Authorization") != "Bearer "+os.Getenv("RA_SENSOR_TOKEN") {
			http.Error(w, "unauthorized", 401)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"private_detail": true})
	})
	handler := operationsHandler(next, path, root, 16<<20)
	for _, test := range []struct {
		token  string
		code   int
		detail bool
	}{
		{"", 401, false}, {strings.Repeat("x", 48), 401, false}, {strings.Repeat("r", 48), 200, true},
		{strings.Repeat("a", 48), 200, true}, {strings.Repeat("s", 48), 200, false},
	} {
		r := httptest.NewRequest("GET", "/health", nil)
		if test.token != "" {
			r.Header.Set("Authorization", "Bearer "+test.token)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != test.code || strings.Contains(w.Body.String(), "private_detail") != test.detail {
			t.Fatalf("status/detail %d %s", w.Code, w.Body.String())
		}
	}
	for _, token := range []string{strings.Repeat("r", 48), strings.Repeat("a", 48)} {
		r := httptest.NewRequest("POST", "/v1/events", strings.NewReader(`{}`))
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != 401 {
			t.Fatal("management role acquired sensor authority")
		}
	}
}

func TestOperationsRotationImmediatelyRevokesOldReader(t *testing.T) {
	root, path, state := operationsFixture(t)
	handler := operationsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }), path, root, 16<<20)
	state.Roles["reader"] = operationsDigest(strings.Repeat("n", 48))
	state.AuthEpoch++
	writeOperationsFixture(t, path, state)
	for _, test := range []struct {
		token  string
		status int
	}{{strings.Repeat("r", 48), 401}, {strings.Repeat("n", 48), 204}} {
		r := httptest.NewRequest("GET", "/health", nil)
		r.Header.Set("Authorization", "Bearer "+test.token)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != test.status {
			t.Fatalf("rotation: %d", w.Code)
		}
	}
}

func TestOperationsPendingRestoreAndOldGenerationCloseGate(t *testing.T) {
	root, path, state := operationsFixture(t)
	state.Phase = "restore_pending"
	writeOperationsFixture(t, path, state)
	if _, err := loadOperations(path, root, 16<<20, false); err == nil {
		t.Fatal("pending restore admitted")
	}
	if _, err := loadOperations(path, root, 16<<20, true); err == nil {
		t.Fatal("recovery check lacks admin")
	}
	t.Setenv("RA_OPS_ADMIN_TOKEN", strings.Repeat("a", 48))
	if _, err := loadOperations(path, root, 16<<20, true); err != nil {
		t.Fatal(err)
	}
	state.Phase = "active"
	state.Generation++
	writeOperationsFixture(t, path, state)
	if _, err := loadOperations(path, root, 16<<20, false); err == nil {
		t.Fatal("old root checkpoint admitted")
	}
	writeOperationsFixture(t, filepath.Join(root, ".operations.json"), operationsMarker{operationsSchema, state.Deployment, path, state.Generation})
	t.Setenv("RA_SENSOR_TOKEN", strings.Repeat("x", 48))
	if _, err := loadOperations(path, root, 16<<20, false); err == nil {
		t.Fatal("changed sensor binding admitted")
	}
}

func TestOperationsWrongSignatureOrMissingAnchorRefuses(t *testing.T) {
	root, path, _ := operationsFixture(t)
	t.Setenv("RA_OPS_SIGNING_KEY", strings.Repeat("x", 48))
	if _, err := loadOperations(path, root, 16<<20, false); err == nil {
		t.Fatal("wrong signing credential admitted")
	}
	if _, err := loadOperations(path+".missing", root, 16<<20, false); err == nil {
		t.Fatal("missing anchor admitted")
	}
}

func TestOperationsOptionalSensorAndTenantScopeAreBound(t *testing.T) {
	root, path, state := operationsFixture(t)
	t.Setenv("RA_HOST_SENSOR_TOKEN", strings.Repeat("h", 48))
	state.Credentials["RA_HOST_SENSOR_TOKEN"] = operationsDigest(os.Getenv("RA_HOST_SENSOR_TOKEN"))
	writeOperationsFixture(t, path, state)
	if _, err := loadOperations(path, root, 16<<20, false); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RA_HOST_SENSOR_TOKEN", strings.Repeat("x", 48))
	if _, err := loadOperations(path, root, 16<<20, false); err == nil {
		t.Fatal("changed host credential admitted")
	}
	t.Setenv("RA_HOST_SENSOR_TOKEN", strings.Repeat("h", 48))
	t.Setenv("RA_TENANTS", "alpha")
	if _, err := loadOperations(path, root, 16<<20, false); err == nil {
		t.Fatal("changed tenant scope admitted")
	}
}

func TestOperationsCollectorFloorRequiresExactAcknowledgedPrefix(t *testing.T) {
	_, _, state := operationsFixture(t)
	// Fixed cross-language vector for the length-prefixed IDs id-a, id-b.
	if err := json.Unmarshal([]byte(`{"floor":{"acked":2,"acked_ids_sha256":"d8f04baf5bbb90563cbd8efe2859e4e6f38d861a3c7111718c0c9fa379e2e842"}}`), state); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name     string
		ids      []string
		accepted bool
	}{
		{"exact", []string{"id-a", "id-b"}, true},
		{"later suffix", []string{"id-a", "id-b", "id-c"}, true},
		{"missing ACK", []string{"id-a"}, false},
		{"changed prefix", []string{"id-x", "id-b"}, false},
		{"reordered prefix", []string{"id-b", "id-a"}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			store, err := evidence.NewPersistentRotating(t.TempDir(), 64<<10, 4096)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			// Another sensor's records cannot satisfy or displace the app prefix.
			if err := store.Append("events", map[string]string{"event_id": "other", "sensor_id": "lab-host"}); err != nil {
				t.Fatal(err)
			}
			for _, id := range test.ids {
				if err := store.Append("events", map[string]string{"event_id": id, "sensor_id": "lab-app"}); err != nil {
					t.Fatal(err)
				}
			}
			if err := verifyCollectorFloor(store, state); (err == nil) != test.accepted {
				t.Fatalf("accepted=%v: %v", test.accepted, err)
			}
		})
	}
}

func TestCheckpointACKFloorRequiresAuthenticatedRecoveryAndCompleteBounds(t *testing.T) {
	if floor, err := recoveryACKFloor(-1, "", false, ""); err != nil || floor != nil {
		t.Fatalf("default mode changed: %v", err)
	}
	for _, test := range []struct {
		name     string
		count    int64
		digest   string
		recovery bool
		path     string
	}{
		{"live mode", 0, operationsDigest(""), false, "anchor"},
		{"unsigned recovery", 0, operationsDigest(""), true, ""},
		{"missing count", -1, operationsDigest(""), true, "anchor"},
		{"missing digest", 0, "", true, "anchor"},
		{"negative count", -2, operationsDigest(""), true, "anchor"},
		{"count limit", 200001, operationsDigest(""), true, "anchor"},
		{"invalid hex", 0, strings.Repeat("x", 64), true, "anchor"},
		{"short digest", 0, "00", true, "anchor"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := recoveryACKFloor(test.count, test.digest, test.recovery, test.path); err == nil {
				t.Fatal("invalid checkpoint ACK verification accepted")
			}
		})
	}
	for _, count := range []int64{0, 200000} {
		if floor, err := recoveryACKFloor(count, operationsDigest(""), true, "anchor"); err != nil || floor.Acked != count {
			t.Fatalf("bounded checkpoint rejected: %v", err)
		}
	}
}

func TestCheckpointACKFloorRejectsCollectorThatSatisfiesOnlyPreviousAnchor(t *testing.T) {
	_, _, state := operationsFixture(t)
	store, err := evidence.NewPersistentRotating(t.TempDir(), 64<<10, 4096)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	state.Floor = &operationsFloor{Acked: 0, AckedIDs: operationsDigest("")}
	current, err := recoveryACKFloor(2, "d8f04baf5bbb90563cbd8efe2859e4e6f38d861a3c7111718c0c9fa379e2e842", true, "anchor")
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyCollectorFloor(store, state); err != nil {
		t.Fatalf("previous anchor should still be valid: %v", err)
	}
	if err := verifyCollectorACKPrefix(store, "lab-app", current); err == nil {
		t.Fatal("stale collector approved for newer app checkpoint")
	}
	for _, id := range []string{"id-a", "id-b"} {
		if err := store.Append("events", map[string]string{"event_id": id, "sensor_id": "lab-app"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := verifyCollectorACKPrefix(store, "lab-app", current); err != nil {
		t.Fatalf("complete current checkpoint rejected: %v", err)
	}
	if state.Floor.Acked != 0 {
		t.Fatal("candidate verification changed previous anchor")
	}
}
