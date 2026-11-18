package edge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/url"
	"os"
	"reverse-artex/internal/protection"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
)

// Downstream connection lifetime is hop-by-hop. Every protected representation
// remains independently signed, nonce-bound and audited on a reused upstream.
func TestProtectedDownstreamCloseDoesNotDisableSignedUpstreamReuse(t *testing.T) {
	c, key := guardFixture(t)
	body := []byte(`{"value":"owned-upstream-reuse"}`)
	var connections, forwardedClose, audits atomic.Int32
	var mu sync.Mutex
	requestIDs, nonces := map[string]bool{}, map[string]bool{}
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 1 || r.ProtoMinor != 1 {
			t.Error("expected real HTTP/1.1 upstream", r.Proto)
		}
		if r.Close {
			forwardedClose.Add(1)
		}
		mu.Lock()
		id, nonce := r.Header.Get("X-RA-Request-ID"), r.Header.Get("X-RA-Nonce")
		if id == "" || nonce == "" || requestIDs[id] || nonces[nonce] {
			t.Error("upstream proof binding reused")
		}
		requestIDs[id], nonces[nonce] = true, true
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", fmt.Sprint(len(body)))
		w.Header().Set(protection.ProofHeader, sdkProof(c, key, r, body, nil))
		_, _ = w.Write(body)
	}))
	upstream.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	upstream.Start()
	defer upstream.Close()
	c.Upstream, _ = url.Parse(upstream.URL)
	c.ProtectionAudit = func(observation protection.Observation) error { audits.Add(1); return nil }
	edgeServer := httptest.NewServer(Handler(c))
	defer edgeServer.Close()
	for n := 0; n < 3; n++ {
		request := guardRequest(c, edgeServer.URL+"/legacy/objects/one", http.MethodGet)
		request.RequestURI = ""
		request.Close = true
		request.Header.Set("Connection", "close")
		response, err := edgeServer.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		actual, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil || response.StatusCode != 200 || string(actual) != string(body) {
			t.Fatal("signed bytes changed", response.StatusCode, err, string(actual))
		}
		if response.Header.Get(protection.ProofHeader) != "" || strings.Contains(response.Header.Get("Connection"), "keep-alive") {
			t.Fatal("upstream metadata escaped")
		}
	}
	if connections.Load() != 1 || forwardedClose.Load() != 0 {
		t.Fatalf("downstream close forced upstream churn: connections=%d forwarded_close=%d; want1/0", connections.Load(), forwardedClose.Load())
	}
	if audits.Load() != 3 || len(requestIDs) != 3 || len(nonces) != 3 {
		t.Fatal("reuse bypassed independent proofs/audits", audits.Load(), len(requestIDs), len(nonces))
	}
}

func TestProtectedUpstreamFailureClassifiesWrappedCausesAndKeepsPrivacy(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want upstreamFailureClass
	}{
		{"refused", syscall.ECONNREFUSED, upstreamRefused}, {"unavailable", syscall.EADDRNOTAVAIL, upstreamAddressUnavailable},
		{"in-use", syscall.EADDRINUSE, upstreamAddressInUse}, {"buffers", syscall.ENOBUFS, upstreamResources},
		{"files", syscall.EMFILE, upstreamResources}, {"memory", syscall.ENOMEM, upstreamResources},
		{"reset", syscall.ECONNRESET, upstreamReset}, {"aborted", syscall.ECONNABORTED, upstreamReset},
		{"deadline", context.DeadlineExceeded, upstreamTimeout}, {"cancel", context.Canceled, upstreamCancelled},
		{"dns-timeout", &net.DNSError{Err: "PRIVATE_ERROR", Name: "private.example", IsTimeout: true}, upstreamTimeout},
		{"unknown", errors.New("PRIVATE_URL_TOKEN"), upstreamOther},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			wrapped := &url.Error{Op: "GET", URL: "http://private.example/?token=PRIVATE_URL_TOKEN", Err: &net.OpError{Op: "dial", Net: "tcp", Err: &os.SyscallError{Syscall: "connect", Err: test.err}}}
			if got := upstreamFailureCause(wrapped); got != test.want {
				t.Fatal("wrapped cause mismatch", got, test.want)
			}
			metrics := &ProtectionMetrics{}
			metrics.observeUpstreamFailure(wrapped, false)
			metrics.observeUpstreamFailure(wrapped, true)
			snapshot := metrics.Snapshot()["upstream_failures"].(map[string]any)
			for _, phase := range []string{"before_connection", "after_connection"} {
				counters := snapshot[phase].(map[string]uint64)
				if len(counters) != int(upstreamFailureClasses) || counters[upstreamFailureNames[test.want]] != 1 {
					t.Fatal("unbounded or lost cause counter", counters)
				}
			}
			raw, _ := json.Marshal(snapshot)
			if strings.Contains(string(raw), "PRIVATE") || strings.Contains(string(raw), "private.example") || strings.Contains(string(raw), "http:") {
				t.Fatal("transport diagnostics leaked raw error data", string(raw))
			}
		})
	}
	for _, test := range []struct {
		code syscall.Errno
		want upstreamFailureClass
	}{{10061, upstreamRefused}, {10049, upstreamAddressUnavailable}, {10048, upstreamAddressInUse}, {10055, upstreamResources}, {10024, upstreamResources}, {10054, upstreamReset}, {10053, upstreamReset}, {10060, upstreamTimeout}} {
		wrapped := fmt.Errorf("private wrapper: %w", test.code)
		if got := upstreamFailureForPlatform(wrapped, true); got != test.want {
			t.Fatal("native Winsock cause mismatch", test.code, got, test.want)
		}
	}
}

func TestProtectedUpstreamFailureRecordsRealRefusedDialBeforeConnection(t *testing.T) {
	c, _ := guardFixture(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err = listener.Close(); err != nil {
		t.Fatal(err)
	}
	c.Upstream, _ = url.Parse("http://" + address)
	c.ProtectionMetrics = &ProtectionMetrics{}
	c.ProtectionAudit = func(protection.Observation) error { t.Error("failed dial reached signed audit"); return nil }
	response := httptest.NewRecorder()
	Handler(c).ServeHTTP(response, guardRequest(c, "/legacy/objects/one", http.MethodGet))
	if response.Code != 503 || response.Body.String() != "Service Unavailable\n" {
		t.Fatal("failed dial did not remain closed", response.Code, response.Body.String())
	}
	counters := c.ProtectionMetrics.upstreamFailureSnapshot()
	if counters["before_connection"].(map[string]uint64)["connection_refused"] != 1 || counters["after_connection"].(map[string]uint64)["connection_refused"] != 0 {
		t.Fatal("real refused dial misclassified", counters)
	}
}

func TestProtectedUpstreamFailureUsesActualTraceStageAndAtomicCounters(t *testing.T) {
	c, _ := guardFixture(t)
	c.ProtectionMetrics = &ProtectionMetrics{}
	c.Transport = transport(func(request *http.Request) (*http.Response, error) {
		trace := httptrace.ContextClientTrace(request.Context())
		if trace == nil || trace.GotConn == nil {
			t.Fatal("actual connection trace missing")
		}
		trace.GotConn(httptrace.GotConnInfo{})
		return nil, &net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET}
	})
	response := httptest.NewRecorder()
	Handler(c).ServeHTTP(response, guardRequest(c, "/legacy/objects/one", http.MethodGet))
	if response.Code != 503 {
		t.Fatal(response.Code)
	}
	counters := c.ProtectionMetrics.upstreamFailureSnapshot()
	if counters["after_connection"].(map[string]uint64)["connection_reset_or_aborted"] != 1 || counters["before_connection"].(map[string]uint64)["connection_reset_or_aborted"] != 0 {
		t.Fatal("connected transport failure mislabeled dial failure", counters)
	}
	var workers sync.WaitGroup
	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for j := 0; j < 1000; j++ {
				c.ProtectionMetrics.observeUpstreamFailure(context.Canceled, false)
			}
		}()
	}
	workers.Wait()
	if c.ProtectionMetrics.upstreamFailureSnapshot()["before_connection"].(map[string]uint64)["context_cancelled"] != 8000 {
		t.Fatal("concurrent failure counters lost events")
	}
	var absent *ProtectionMetrics
	absent.observeUpstreamFailure(errors.New("PRIVATE"), false)
	c.ProtectionMetrics.observeUpstreamFailure(nil, false)
}
