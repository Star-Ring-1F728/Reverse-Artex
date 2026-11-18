package main

import (
	"errors"
	"reverse-artex/internal/detect"
	"reverse-artex/internal/event"
	"reverse-artex/internal/hostguard"
	"testing"
	"time"
)

type recordingStore struct {
	fail    string
	streams []string
}

func (s *recordingStore) Append(name string, _ any) error {
	if name == s.fail {
		return errors.New("injected storage failure")
	}
	s.streams = append(s.streams, name)
	return nil
}

func sampleHTTP(id string) event.Event {
	return event.Event{EventID: id, EventTime: time.Now().UTC(), TenantID: "alpha", AssetID: "lab-api", Principal: "user", SessionHMAC: "session", Identity: "authenticated", RequestID: id, UAHint: "norma-unverified", DataQuality: "complete"}
}

func sampleHost(id string) hostguard.Event {
	return hostguard.Event{SchemaVersion: "host/1.0", EventID: id, EventTime: time.Now().UTC(), SensorID: "lab-host", TenantID: "alpha", AssetID: "lab-api", EventType: "canary_access", ServiceID: "lab-web", WorkloadID: "lab-workload", ProcessKey: "boot:1:1", ParentKey: "boot:1:0", Lineage: "verified", DataQuality: "complete", Classification: "canary", CanaryID: "fixture"}
}

func TestIngestFailureStopsBothFeedsBeforeFurtherMutation(t *testing.T) {
	for _, stream := range []string{"events", "evaluations", "alerts", "host-events", "host-evaluations", "host-alerts"} {
		t.Run(stream, func(t *testing.T) {
			s := &recordingStore{fail: stream}
			i := &ingester{store: s, engine: detect.New(), hostEngine: hostguard.New([]string{"fixture"})}
			forwarded := 0
			i.forward = func(event.Event) { forwarded++ }
			var err error
			if len(stream) >= 5 && stream[:5] == "host-" {
				_, err = i.processHost(sampleHost("first"))
			} else {
				_, err = i.process(sampleHTTP("first"))
			}
			if err == nil || !i.degraded() || forwarded != 0 {
				t.Fatalf("failure not contained: err=%v degraded=%v forwarded=%d", err, i.degraded(), forwarded)
			}
			before := len(s.streams)
			if _, err = i.process(sampleHTTP("retry")); err == nil {
				t.Fatal("HTTP retry accepted after uncertain commit")
			}
			if _, err = i.processHost(sampleHost("retry")); err == nil {
				t.Fatal("host retry accepted after uncertain commit")
			}
			if len(s.streams) != before {
				t.Fatal("degraded ingester wrote further evidence")
			}
		})
	}
}

func TestLostResponseRetryDoesNotForwardTwice(t *testing.T) {
	s := &recordingStore{}
	i := &ingester{store: s, engine: detect.New(), hostEngine: hostguard.New(nil)}
	forwarded := 0
	i.forward = func(event.Event) { forwarded++ }
	e := sampleHTTP("same-event")
	first, err := i.process(e)
	if err != nil || first != "accepted" {
		t.Fatalf("initial ingest: %s %v", first, err)
	}
	// The client did not receive the response and resends the same event ID.
	second, err := i.process(e)
	if err != nil || second != "duplicate" || forwarded != 1 {
		t.Fatalf("retry: %s %v forwarded=%d", second, err, forwarded)
	}
}
