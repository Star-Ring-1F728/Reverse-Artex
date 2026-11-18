package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reverse-artex/internal/control"
	"reverse-artex/internal/detect"
	"reverse-artex/internal/event"
	"reverse-artex/internal/hostguard"
	"strings"
	"testing"
	"time"
)

func TestPolicyOutboxAfterForcedProcessTermination(t *testing.T) {
	if os.Getenv("RA_OUTBOX_CRASH_HELPER") == "1" {
		dir := os.Getenv("RA_OUTBOX_CRASH_DIR")
		s := recoveryStore(t, dir)
		if err := restoreState(s, dir, "session", nil, detect.New(), hostguard.New(nil)); err != nil {
			t.Fatal(err)
		}
		i := &ingester{store: s, engine: detect.New(), hostEngine: hostguard.New(nil), forward: func(event.Event) {}}
		if result, err := i.process(recoveryHTTP("committed-before-kill", "session", "resource", time.Now().UTC())); result != "accepted" || err != nil {
			t.Fatal(result, err)
		}
		if err := os.WriteFile(filepath.Join(dir, "helper-ready"), []byte("ready"), 0600); err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Hour)
		return
	}
	dir := t.TempDir()
	t.Setenv("RA_POLICY_CONTROL_URL", "http://127.0.0.1:39081")
	cmd := exec.Command(os.Args[0], "-test.run=^TestPolicyOutboxAfterForcedProcessTermination$")
	cmd.Env = append(os.Environ(), "RA_OUTBOX_CRASH_HELPER=1", "RA_OUTBOX_CRASH_DIR="+dir)
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(dir, "helper-ready")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			cmd.Process.Kill()
			cmd.Wait()
			t.Fatal("helper did not commit evidence:", output.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	s := recoveryStore(t, dir)
	if err := restoreState(s, dir, "session", nil, detect.New(), hostguard.New(nil)); err != nil {
		t.Fatal(err)
	}
	pending, err := loadPolicyPending(s)
	if err != nil || len(pending) != 1 || pending[0].EventID != "committed-before-kill" {
		t.Fatal("forced termination lost committed delivery intent", err, len(pending))
	}
}

type outboxTransport struct{ handler http.Handler }

func (t outboxTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	w := httptest.NewRecorder()
	t.handler.ServeHTTP(w, r)
	return w.Result(), nil
}

func TestPolicyOutboxSurvivesRestartAndPersistsOrderedAck(t *testing.T) {
	dir := t.TempDir()
	s := recoveryStore(t, dir)
	if err := restoreState(s, dir, "session", nil, detect.New(), hostguard.New(nil)); err != nil {
		t.Fatal(err)
	}
	i := &ingester{store: s, engine: detect.New(), hostEngine: hostguard.New(nil), forward: func(event.Event) {}}
	for _, id := range []string{"one", "two"} {
		if result, err := i.process(recoveryHTTP(id, "session", id, time.Now().UTC())); result != "accepted" || err != nil {
			t.Fatal(result, err)
		}
	}
	s = recoveryStore(t, dir)
	if err := restoreState(s, dir, "session", nil, detect.New(), hostguard.New(nil)); err != nil {
		t.Fatal(err)
	}
	pending, err := loadPolicyPending(s)
	if err != nil || len(pending) != 2 {
		t.Fatal("committed outbox lost", err, len(pending))
	}
	calls := make(chan string, 2)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var e event.Event
		if err := json.NewDecoder(r.Body).Decode(&e); err != nil {
			t.Error(err)
		}
		calls <- e.EventID
		w.WriteHeader(202)
	})
	q := newPolicyOutbox(s, pending)
	go q.run(&http.Client{Transport: outboxTransport{h}}, "http://controller.test", "token")
	q.wake <- struct{}{}
	for _, want := range []string{"one", "two"} {
		select {
		case got := <-calls:
			if got != want {
				t.Fatalf("got %s want %s", got, want)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("policy worker stalled")
		}
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		remaining, err := loadPolicyPending(s)
		if err != nil {
			t.Fatal(err)
		}
		if len(remaining) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("ack was not synced")
		}
		time.Sleep(time.Millisecond)
	}
	close(q.wake)
	s = recoveryStore(t, dir)
	if remaining, err := loadPolicyPending(s); err != nil || len(remaining) != 0 {
		t.Fatal("ack cursor not recovered", err, len(remaining))
	}
}

func TestPolicyOutboxRejectsChangedAckAndUncommittedEvent(t *testing.T) {
	for _, variant := range []string{"changed-ack", "orphan-ack", "uncommitted"} {
		t.Run(variant, func(t *testing.T) {
			dir := t.TempDir()
			s := recoveryStore(t, dir)
			if err := restoreState(s, dir, "session", nil, detect.New(), hostguard.New(nil)); err != nil {
				t.Fatal(err)
			}
			i := &ingester{store: s, engine: detect.New(), hostEngine: hostguard.New(nil), forward: func(event.Event) {}}
			e := recoveryHTTP("one", "session", "resource", time.Now().UTC())
			if result, err := i.process(e); result != "accepted" || err != nil {
				t.Fatal(result, err)
			}
			switch variant {
			case "changed-ack":
				if err := s.Append("policy-delivery-acks", policyAck{EventID: "one", Hash: "wrong"}); err != nil {
					t.Fatal(err)
				}
			case "orphan-ack":
				for n := 0; n < 2; n++ {
					if err := s.Append("policy-delivery-acks", ackFor(e)); err != nil {
						t.Fatal(err)
					}
				}
			case "uncommitted":
				if err := os.WriteFile(filepath.Join(dir, "events.00000001.pending"), []byte("{}\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := loadPolicyPending(s); err == nil {
				t.Fatal("invalid outbox recovered")
			}
		})
	}
}

func TestPolicyDeliveryFailureKeepsCommittedEventPending(t *testing.T) {
	dir := t.TempDir()
	s := recoveryStore(t, dir)
	if err := restoreState(s, dir, "session", nil, detect.New(), hostguard.New(nil)); err != nil {
		t.Fatal(err)
	}
	q := newPolicyOutbox(s, nil)
	i := &ingester{store: s, engine: detect.New(), hostEngine: hostguard.New(nil), forward: q.enqueue, forwardReady: q.ready}
	if result, err := i.process(recoveryHTTP("pending", "session", "resource", time.Now().UTC())); result != "accepted" || err != nil {
		t.Fatal(result, err)
	}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(401) })
	go q.run(&http.Client{Transport: outboxTransport{h}}, "http://controller.test", "token")
	deadline := time.Now().Add(2 * time.Second)
	for {
		_, _, failures, failed := q.stats()
		if failed && failures == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("failed delivery did not stop worker")
		}
		time.Sleep(time.Millisecond)
	}
	if _, err := i.process(recoveryHTTP("after-failure", "session", "resource", time.Now().UTC())); err == nil {
		t.Fatal("ingestion continued after delivery failed")
	}
	close(q.wake)
	s = recoveryStore(t, dir)
	if pending, err := loadPolicyPending(s); err != nil || len(pending) != 1 || pending[0].EventID != "pending" {
		t.Fatal("failed delivery was lost", err, len(pending))
	}
}

func TestPolicyAckBatchFailurePersistsConfirmedPrefix(t *testing.T) {
	dir := t.TempDir()
	s := recoveryStore(t, dir)
	if err := restoreState(s, dir, "session", nil, detect.New(), hostguard.New(nil)); err != nil {
		t.Fatal(err)
	}
	q := newPolicyOutbox(s, nil)
	i := &ingester{store: s, engine: detect.New(), hostEngine: hostguard.New(nil), forward: q.enqueue}
	for _, id := range []string{"one", "two"} {
		if _, err := i.process(recoveryHTTP(id, "session", id, time.Now().UTC())); err != nil {
			t.Fatal(err)
		}
	}
	oneAccepted := false
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var e event.Event
		if err := json.NewDecoder(r.Body).Decode(&e); err != nil {
			t.Error(err)
		}
		if e.EventID == "one" {
			oneAccepted = true
			w.WriteHeader(202)
		} else {
			w.WriteHeader(401)
		}
	})
	go q.run(&http.Client{Transport: outboxTransport{h}}, "http://controller.test", "token")
	defer close(q.wake)
	deadline := time.Now().Add(3 * time.Second)
	for {
		_, _, _, failed := q.stats()
		if failed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("batch delivery did not stop")
		}
		time.Sleep(time.Millisecond)
	}
	if !oneAccepted {
		t.Fatal("successful controller prefix was not exercised")
	}
	remaining, err := loadPolicyPending(s)
	if err != nil || len(remaining) != 1 || remaining[0].EventID != "two" {
		t.Fatalf("only unconfirmed suffix must replay: %v %v", remaining, err)
	}
}

func TestUnversionedPolicyAckDoesNotCreateRecoveryMetadata(t *testing.T) {
	dir := t.TempDir()
	s := recoveryStore(t, dir)
	if err := s.Append("policy-delivery-acks", policyAck{EventID: "unknown", Hash: "unknown"}); err != nil {
		t.Fatal(err)
	}
	if err := restoreState(s, dir, "session", nil, detect.New(), hostguard.New(nil)); err == nil {
		t.Fatal("unversioned policy ack accepted")
	}
	if _, err := os.Stat(filepath.Join(dir, "recovery.meta.json")); !os.IsNotExist(err) {
		t.Fatal("failed recovery created metadata", err)
	}
}

func TestControllerAuditBudgetRetainsOutboxUntilRecovered(t *testing.T) {
	dir := t.TempDir()
	s := recoveryStore(t, dir)
	if err := restoreState(s, dir, "session", nil, detect.New(), hostguard.New(nil)); err != nil {
		t.Fatal(err)
	}
	q := newPolicyOutbox(s, nil)
	i := &ingester{store: s, engine: detect.New(), hostEngine: hostguard.New(nil), forward: q.enqueue, forwardReady: q.ready}
	if result, err := i.process(recoveryHTTP("budget-pending", "session", "resource", time.Now().UTC())); result != "accepted" || err != nil {
		t.Fatal(result, err)
	}
	controlDir := t.TempDir()
	m, err := control.Open(controlDir)
	if err != nil {
		t.Fatal(err)
	}
	m.Budget = 1
	token := strings.Repeat("e", 32)
	client := &http.Client{Transport: outboxTransport{control.Handler(m, control.Tokens{Evidence: token})}}
	go q.run(client, "http://controller.test", token)
	deadline := time.Now().Add(2 * time.Second)
	for {
		_, _, _, failed := q.stats()
		if failed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("audit budget failure not observed")
		}
		time.Sleep(time.Millisecond)
	}
	close(q.wake)
	if pending, err := loadPolicyPending(s); err != nil || len(pending) != 1 {
		t.Fatal("budget failure lost event", err, len(pending))
	}
	m, err = control.Open(controlDir)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := loadPolicyPending(s)
	if err != nil {
		t.Fatal(err)
	}
	resumed := newPolicyOutbox(s, pending)
	client = &http.Client{Transport: outboxTransport{control.Handler(m, control.Tokens{Evidence: token})}}
	go resumed.run(client, "http://controller.test", token)
	resumed.wake <- struct{}{}
	deadline = time.Now().Add(2 * time.Second)
	for {
		remaining, err := loadPolicyPending(s)
		if err != nil {
			t.Fatal(err)
		}
		if len(remaining) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("budget recovery did not drain outbox")
		}
		time.Sleep(time.Millisecond)
	}
	close(resumed.wake)
}
