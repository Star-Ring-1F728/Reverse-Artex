package edge

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reverse-artex/internal/protection"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Actual loopback sockets exercise capacity recovery and upstream replacement.
func TestProtectedOperationalFaultsRecoverWithoutReleasingUnverifiedBytes(t *testing.T) {
	for _, reuse := range []bool{false, true} {
		t.Run(fmt.Sprintf("reuse=%t", reuse), func(t *testing.T) {
			c, key := guardFixture(t)
			c.ReuseProtectedBuffers = reuse
			c.ProtectionMetrics = &ProtectionMetrics{}
			var holding, malformed atomic.Bool
			holding.Store(true)
			entered := make(chan struct{}, 32)
			release := make(chan struct{})
			var releaseOnce sync.Once
			unblock := func() { holding.Store(false); releaseOnce.Do(func() { close(release) }) }
			defer unblock()
			cancelEntered, cancelDone, handlerDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
			body := []byte(`{"secret":"OWNED_OPERATIONAL_CONTROL"}`)
			upstreamHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/cancel") {
					close(cancelEntered)
					<-r.Context().Done()
					close(cancelDone)
					return
				}
				if holding.Load() {
					entered <- struct{}{}
					select {
					case <-release:
					case <-r.Context().Done():
						return
					}
				}
				w.Header().Set("Content-Type", "application/json")
				proof := sdkProof(c, key, r, body, nil)
				if malformed.Load() {
					proof = "invalid-owned-test-proof"
				}
				w.Header().Set(protection.ProofHeader, proof)
				w.Write(body)
			})
			upstream := httptest.NewServer(upstreamHandler)
			defer upstream.Close()
			address := upstream.Listener.Addr().String()
			c.Upstream, _ = url.Parse(upstream.URL)
			handler := Handler(c)
			public := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/cancel") {
					defer close(handlerDone)
				}
				handler.ServeHTTP(w, r)
			}))
			defer public.Close()
			client := &http.Client{Timeout: 7 * time.Second}
			defer client.CloseIdleConnections()
			request := func(object string, want int) error {
				req := guardRequest(c, public.URL+"/legacy/objects/"+object, "GET")
				req.RequestURI = ""
				response, err := client.Do(req)
				if err != nil {
					return err
				}
				defer response.Body.Close()
				raw, err := io.ReadAll(response.Body)
				if err != nil {
					return err
				}
				if response.StatusCode != want {
					return fmt.Errorf("status %d want %d", response.StatusCode, want)
				}
				if want == 200 && string(raw) != string(body) {
					return errors.New("normal representation changed")
				}
				if want != 200 && strings.Contains(string(raw), "OWNED_OPERATIONAL_CONTROL") {
					return errors.New("unverified bytes released")
				}
				return nil
			}
			results := make(chan error, 32)
			for n := 0; n < 32; n++ {
				go func() { results <- request("one", 200) }()
			}
			for n := 0; n < 32; n++ {
				select {
				case <-entered:
				case <-time.After(2 * time.Second):
					unblock()
					t.Fatal("protected admission cohort incomplete")
				}
			}
			if err := request("one", 503); err != nil {
				t.Fatal(err)
			}
			unblock()
			for n := 0; n < 32; n++ {
				if err := <-results; err != nil {
					t.Fatal("admitted request failed", err)
				}
			}
			if err := request("one", 200); err != nil {
				t.Fatal("capacity did not recover", err)
			}
			malformed.Store(true)
			if err := request("one", 503); err != nil {
				t.Fatal(err)
			}
			malformed.Store(false)
			if err := request("one", 200); err != nil {
				t.Fatal("proof-failure recovery failed", err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			req := guardRequest(c, public.URL+"/legacy/objects/cancel", "GET")
			req.RequestURI = ""
			req = req.WithContext(ctx)
			result := make(chan error, 1)
			go func() {
				resp, err := client.Do(req)
				if resp != nil {
					resp.Body.Close()
				}
				result <- err
			}()
			select {
			case <-cancelEntered:
			case <-time.After(time.Second):
				t.Fatal("cancel request not admitted")
			}
			cancel()
			if err := <-result; !errors.Is(err, context.Canceled) {
				t.Fatal("client cancellation lost", err)
			}
			for _, done := range []chan struct{}{cancelDone, handlerDone} {
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Fatal("cancelled request retained upstream or admission")
				}
			}
			if err := request("one", 200); err != nil {
				t.Fatal("cancellation recovery failed", err)
			}
			upstream.Close()
			if err := request("one", 503); err != nil {
				t.Fatal("upstream outage released bytes", err)
			}
			listener, err := net.Listen("tcp", address)
			if err != nil {
				t.Fatal(err)
			}
			replacement := &http.Server{Handler: upstreamHandler}
			defer replacement.Close()
			go replacement.Serve(listener)
			if err := request("one", 200); err != nil {
				t.Fatal("upstream restart did not recover", err)
			}
			failures := c.ProtectionMetrics.upstreamFailureSnapshot()
			beforeConnection := failures["before_connection"].(map[string]uint64)
			afterConnection := failures["after_connection"].(map[string]uint64)
			// Transport may select a pooled connection just before observing
			// its closure, then retry the GET and fail to dial. In that case
			// GotConn has already fired on the first attempt.
			if beforeConnection["connection_refused"]+afterConnection["connection_refused"] == 0 {
				t.Fatal("outage cause lost", failures)
			}
			if afterConnection["context_cancelled"] == 0 {
				t.Fatal("cancel cause lost", failures)
			}
		})
	}
}
