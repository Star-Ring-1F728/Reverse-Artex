package control

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reverse-artex/internal/storagebudget"
	"strings"
	"testing"
	"time"
)

func TestStorageSaturationKeepsSnapshotsClosedUntilDurableExpiryRecovery(t *testing.T) {
	for _, profile := range []string{"audit-limit", "shared-pool"} {
		t.Run(profile, func(t *testing.T) {
			root := t.TempDir()
			t.Setenv("RA_STORAGE_ROOT", "")
			t.Setenv("RA_STORAGE_LIMIT", "")
			if profile == "shared-pool" {
				t.Setenv("RA_STORAGE_ROOT", root)
				t.Setenv("RA_STORAGE_LIMIT", "1048576")
			}
			dir := filepath.Join(root, "control")
			m, err := OpenPersistent(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { m.Close() }()
			now := time.Now().UTC()
			e := specimen("durable-before-full", "lab-app", now)
			if _, err := m.Evidence(e, now); err != nil {
				t.Fatal(err)
			}
			a := approval("before-full", "durable-before-full")
			a.TTL = 1
			r, err := m.Approve(a, now)
			if err != nil {
				t.Fatal(err)
			}
			deadline := m.active[r.PolicyID].Expires
			version := m.version
			tokens := Tokens{Evidence: strings.Repeat("e", 32), Reader: strings.Repeat("r", 32), SnapshotKey: []byte(strings.Repeat("k", 32))}
			server := httptest.NewServer(Handler(m, tokens))
			defer func() { server.Close() }()
			client := &http.Client{Timeout: 2 * time.Second}
			defer client.CloseIdleConnections()
			request := func(method, path, token string, value any) (int, []byte, http.Header) {
				var body []byte
				if value != nil {
					body, _ = json.Marshal(value)
				}
				req, _ := http.NewRequest(method, server.URL+path, bytes.NewReader(body))
				req.Header.Set("Authorization", "Bearer "+token)
				res, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				defer res.Body.Close()
				data, err := io.ReadAll(res.Body)
				if err != nil {
					t.Fatal(err)
				}
				return res.StatusCode, data, res.Header
			}
			if code, _, _ := request("GET", "/v1/snapshot", tokens.Reader, nil); code != 200 {
				t.Fatal("initial snapshot", code)
			}
			before, err := os.ReadFile(filepath.Join(dir, "actions.jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			fill := filepath.Join(root, "test-only-fill")
			var budget *storagebudget.Budget
			wantStatus := 503
			if profile == "shared-pool" {
				budget, err = storagebudget.FromEnv(dir)
				if err != nil {
					t.Fatal(err)
				}
				stats, err := budget.Stats()
				if err != nil {
					t.Fatal(err)
				}
				if err := budget.WriteFile(fill, make([]byte, int(stats.Remaining))); err != nil {
					t.Fatal(err)
				}
				stats, err = budget.Stats()
				if err != nil || stats.Used != stats.Limit {
					t.Fatal("pool not exactly full", stats, err)
				}
				wantStatus = 429
			} else {
				m.Budget = int64(len(before))
			}
			refused := specimen("refused-while-full", "lab-app", now)
			code, _, headers := request("POST", "/v1/evidence", tokens.Evidence, refused)
			if code != wantStatus || headers.Get("X-RA-Delivery-Permanent") != "1" {
				t.Fatal("quota refusal ACKed or marked transient", code, headers)
			}
			// A duplicate of previously committed evidence is still a valid ACK.
			if code, _, _ := request("POST", "/v1/evidence", tokens.Evidence, e); code != 202 {
				t.Fatal("lost committed duplicate ACK", code)
			}
			if code, _, _ := request("GET", "/health", "", nil); code != 200 {
				t.Fatal("full storage blocked health", code)
			}
			if time.Now().Before(deadline) {
				if code, _, _ := request("GET", "/v1/snapshot", tokens.Reader, nil); code != 200 {
					t.Fatal("valid committed snapshot blocked", code)
				}
			}
			time.Sleep(time.Until(deadline.Add(10 * time.Millisecond)))
			if code, body, _ := request("GET", "/v1/snapshot", tokens.Reader, nil); code != 503 || bytes.Contains(body, []byte(r.PolicyID)) {
				t.Fatal("served expired policy without tombstone", code, string(body))
			}
			// A polling storm must not repeatedly attempt an unwritable expiry.
			ioBefore := m.IOStats()
			for range 8 {
				if code, _, _ := request("GET", "/v1/snapshot", tokens.Reader, nil); code != 503 {
					t.Fatal("latched expiry changed outcome", code)
				}
			}
			if !bytes.Equal(mustJSON(t, ioBefore), mustJSON(t, m.IOStats())) {
				t.Fatal("failed expiry poll duplicated I/O")
			}
			after, err := os.ReadFile(filepath.Join(dir, "actions.jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) || m.version != version || len(m.events) != 1 || len(m.active) != 1 || m.dead[r.PolicyID] {
				t.Fatal("quota refusal changed durable state")
			}
			assertEvidenceIndexes(t, m)
			assertPolicyExpiry(t, m)
			if profile == "shared-pool" {
				if err := os.Remove(fill); err != nil {
					t.Fatal(err)
				}
			} else {
				m.Budget = defaultAuditBudget
			}
			if code, _, _ := request("GET", "/v1/snapshot", tokens.Reader, nil); code != 503 {
				t.Fatal("failed expiry latch silently bypassed", code)
			}
			server.Close()
			if err := m.Close(); err != nil {
				t.Fatal(err)
			}
			m, err = OpenPersistent(dir)
			if err != nil {
				t.Fatal(err)
			}
			server = httptest.NewServer(Handler(m, tokens))
			code, body, _ := request("GET", "/v1/snapshot", tokens.Reader, nil)
			var snapshot struct {
				Version  uint64            `json:"version"`
				Policies []json.RawMessage `json:"policies"`
			}
			if code != 200 || json.Unmarshal(body, &snapshot) != nil || len(snapshot.Policies) != 0 || snapshot.Version != version+1 || !m.dead[r.PolicyID] {
				t.Fatal("expiry recovery failed", code, string(body))
			}
			if code, _, _ := request("POST", "/v1/evidence", tokens.Evidence, refused); code != 202 {
				t.Fatal("refused ID not recoverable", code)
			}
			committed := m.version
			if code, _, _ := request("POST", "/v1/evidence", tokens.Evidence, refused); code != 202 || m.version != committed {
				t.Fatal("recovered duplicate changed state", code)
			}
			assertEvidenceIndexes(t, m)
			assertPolicyExpiry(t, m)
			if budget != nil {
				stats, err := budget.Stats()
				if err != nil || stats.Used > stats.Limit {
					t.Fatal("recovery exceeded pool", stats, err)
				}
			}
			t.Logf("profile=%s refusal=%d permanent=1 full_snapshot=503 recovered_snapshot=200 evidence=2 active=0 version=%d", profile, wantStatus, m.version)
		})
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
