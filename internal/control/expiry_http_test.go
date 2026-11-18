package control

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"reverse-artex/internal/policy"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestHTTPExpiryDuringNonCancellableSync(t *testing.T) {
	for _, failed := range []bool{false, true} {
		t.Run(map[bool]string{false: "recovery", true: "audit_failure"}[failed], func(t *testing.T) {
			m, err := OpenPersistent(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer m.Close()
			now := time.Now().UTC()
			_, err = m.Evidence(specimen("subject", "lab-app", now), now)
			if err != nil {
				t.Fatal(err)
			}
			a := approval("expiry-http", "subject")
			a.TTL = 1
			r, err := m.Approve(a, now)
			if err != nil {
				t.Fatal(err)
			}
			p := m.active[r.PolicyID]
			tokens := Tokens{Reader: strings.Repeat("r", 32), Evidence: strings.Repeat("e", 32), SnapshotKey: []byte(strings.Repeat("k", 32))}
			server := httptest.NewServer(Handler(m, tokens))
			defer server.Close()
			client := &http.Client{Timeout: 2 * time.Second}
			get := func(path string) (int, policy.Snapshot) {
				req, _ := http.NewRequest("GET", server.URL+path, nil)
				req.Header.Set("Authorization", "Bearer "+tokens.Reader)
				resp, err := client.Do(req)
				if err != nil {
					t.Error(err)
					return 0, policy.Snapshot{}
				}
				defer resp.Body.Close()
				var s policy.Snapshot
				if resp.StatusCode == 200 && path == "/v1/snapshot" {
					_ = json.NewDecoder(resp.Body).Decode(&s)
				}
				return resp.StatusCode, s
			}
			if code, s := get("/v1/snapshot"); code != 200 || len(s.Policies) != 1 {
				t.Fatal("before expiry", code, s)
			}
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			defer once.Do(func() { close(release) })
			var syncs atomic.Int64
			m.syncFile = func(f *os.File) error {
				if syncs.Add(1) == 1 {
					close(entered)
					<-release
				}
				if failed {
					return errors.New("injected audit Sync failure")
				}
				return f.Sync()
			}
			done := make(chan error, 1)
			go func() {
				_, err := m.Evidence(specimen("blocked", "lab-app", time.Now().UTC()), time.Now().UTC())
				done <- err
			}()
			<-entered
			time.Sleep(time.Until(p.Expires.Add(5 * time.Millisecond)))
			// Twenty-four simultaneous real HTTP readers share one expiry job.
			var readers sync.WaitGroup
			for range 24 {
				readers.Go(func() {
					began := time.Now()
					if code, _ := get("/v1/snapshot"); code != 503 {
						t.Errorf("expired busy snapshot code %d", code)
					}
					if time.Since(began) > time.Second {
						t.Error("unbounded snapshot wait")
					}
				})
			}
			readers.Wait()
			if syncs.Load() != 1 {
				t.Fatal("wait timeouts started duplicate I/O")
			}
			if code, _ := get("/health"); code != 200 {
				t.Fatal("health blocked", code)
			}
			once.Do(func() { close(release) })
			if err := <-done; (err != nil) != failed {
				t.Fatal("write outcome", err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			s, err := m.SnapshotContext(ctx, tokens.SnapshotKey)
			if failed {
				if err == nil {
					t.Fatal("failed expiry returned success")
				}
			} else if err != nil || len(s.Policies) != 0 || s.Version <= r.Version {
				t.Fatal("expiry not committed", s, err)
			}
			if failed && syncs.Load() != 1 {
				t.Fatal("failed audit retried by readers")
			}
			// Process restart (same host, no power loss) must never serve an
			// expired policy, including an audit whose Sync outcome was unknown.
			if err := m.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := OpenPersistent(m.dir)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			s, err = reopened.SnapshotContext(ctx, tokens.SnapshotKey)
			if err != nil || len(s.Policies) != 0 {
				t.Fatal("expired policy after restart", s, err)
			}
		})
	}
}

func TestExpiryExactBoundaryRequiresDurableTombstone(t *testing.T) {
	m := manager(t)
	now := time.Now().UTC()
	_, _ = m.Evidence(specimen("boundary", "lab-app", now), now)
	r, err := m.Approve(approval("boundary-key", "boundary"), now)
	if err != nil {
		t.Fatal(err)
	}
	p := m.active[r.PolicyID]
	before, err := m.Snapshot(p.Expires.Add(-time.Nanosecond), nil)
	if err != nil || len(before.Policies) != 1 {
		t.Fatal(before, err)
	}
	at, err := m.Snapshot(p.Expires, nil)
	if err != nil || len(at.Policies) != 0 || !m.dead[p.ID] {
		t.Fatal(at, err)
	}
}
