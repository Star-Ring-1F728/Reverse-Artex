package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	api "reverse-artex/internal/decisions/openai"
	"reverse-artex/internal/protection"
	"reverse-artex/internal/responsev2"
)

func TestManagementServerKeepsBoundedRequestLimits(t *testing.T) {
	server := newManagementServer("127.0.0.1:0", http.NotFoundHandler())
	if server.ReadHeaderTimeout != time.Second || server.ReadTimeout != time.Second || server.WriteTimeout != 5*time.Second || server.MaxHeaderBytes != 8192 {
		t.Fatalf("unexpected private management bounds: header=%s read=%s write=%s bytes=%d", server.ReadHeaderTimeout, server.ReadTimeout, server.WriteTimeout, server.MaxHeaderBytes)
	}
}

func TestManagementDurableAckAndReadDoNotRepeatMutation(t *testing.T) {
	for _, oldControl := range []bool{true, false} {
		name := "bounded-five-second-ack"
		if oldControl {
			name = "old-one-second-ack-control"
		}
		t.Run(name, func(t *testing.T) {
			pub, _, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			registry, err := protection.New(protection.Manifest{Schema: "protection-registry/1", Asset: "app", Revision: "r1", TrustEpoch: "e1", Enforcer: "edge1", Tenants: []string{"alpha"}, Keys: map[string]string{"sdk": base64.RawURLEncoding.EncodeToString(pub)}, Routes: []protection.Route{{ID: "objects", Template: "/api/objects/{id}", Namespace: "objects", Mode: "enforce", MaxBody: 1024, AuthAdapter: "lab-hmac-v1", Resolver: "snapshot-v1"}}})
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "v2.jsonl")
			store, err := responsev2.Open(path, registry)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { store.Close() })
			runner, err := responsev2.NewRunner(store, api.Config{Mode: "off"}, bytes.Repeat([]byte("p"), 32), nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(runner.Close)
			reader, operator := strings.Repeat("r", 40), strings.Repeat("o", 40)
			native := responsev2.Handler(store, runner, reader, operator)
			completed := make(chan string, 2)
			// A bounded delay represents a slow durable journal/lock or response build.
			// The actual native handler still authenticates and commits the command.
			delayed := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				time.Sleep(1250 * time.Millisecond)
				native.ServeHTTP(w, r)
				completed <- r.Method
			})
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			server := newManagementServer(listener.Addr().String(), delayed)
			server.ErrorLog = log.New(io.Discard, "", 0)
			if oldControl {
				server.WriteTimeout = time.Second
			}
			t.Cleanup(func() { server.Close() })
			go server.Serve(listener)
			transport := &http.Transport{Proxy: nil, DisableKeepAlives: true}
			t.Cleanup(transport.CloseIdleConnections)
			client := &http.Client{Transport: transport, Timeout: 6 * time.Second}
			call := func(method, endpoint, token string, body []byte) ([]byte, error) {
				t.Helper()
				req, err := http.NewRequest(method, "http://"+listener.Addr().String()+endpoint, bytes.NewReader(body))
				if err != nil {
					t.Fatal(err)
				}
				req.Header.Set("Authorization", "Bearer "+token)
				req.Header.Set("Content-Type", "application/json")
				res, err := client.Do(req)
				if err != nil {
					return nil, err
				}
				defer res.Body.Close()
				raw, err := io.ReadAll(res.Body)
				if err == nil && res.StatusCode != http.StatusOK {
					t.Fatalf("unexpected HTTP %d", res.StatusCode)
				}
				return raw, err
			}
			// Exactly one mutating request. A lost acknowledgement is never retried.
			ack, ackErr := call("POST", "/v2/pause", operator, []byte(`{}`))
			if <-completed != "POST" {
				t.Fatal("mutation handler did not complete")
			}
			if oldControl && ackErr == nil {
				t.Fatal("old one-second control unexpectedly acknowledged slow command")
			}
			if !oldControl && ackErr != nil {
				t.Fatalf("durable acknowledgement lost: %v", ackErr)
			}
			if !oldControl {
				var got struct {
					Epoch  int  `json:"epoch"`
					Paused bool `json:"paused"`
				}
				if json.Unmarshal(ack, &got) != nil || got.Epoch != 2 || !got.Paused {
					t.Fatalf("incorrect durable acknowledgement: %s", ack)
				}
			}
			rawJournal, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			lines := bytes.Split(bytes.TrimSpace(rawJournal), []byte("\n"))
			if len(lines) != 1 || store.Epoch() != 2 {
				t.Fatalf("expected one durable mutation, journal=%d epoch=%d", len(lines), store.Epoch())
			}
			var record struct {
				Operation string `json:"operation"`
			}
			if json.Unmarshal(lines[0], &record) != nil || record.Operation != "cancel-epoch" {
				t.Fatal("native mutation was not committed")
			}
			read, readErr := call("GET", "/v2/status", reader, nil)
			if <-completed != "GET" {
				t.Fatal("read handler did not complete")
			}
			if oldControl && readErr == nil {
				t.Fatal("old one-second control unexpectedly returned slow read")
			}
			if !oldControl && readErr != nil {
				t.Fatalf("durable state read failed: %v", readErr)
			}
			if !oldControl {
				var got struct {
					Decisions struct {
						Epoch  int  `json:"epoch"`
						Paused bool `json:"paused"`
					} `json:"decisions"`
				}
				if json.Unmarshal(read, &got) != nil || got.Decisions.Epoch != 2 || !got.Decisions.Paused {
					t.Fatalf("incorrect native read result: %s", read)
				}
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(rawJournal, after) {
				t.Fatal("read repeated or changed the durable mutation")
			}
		})
	}
}
