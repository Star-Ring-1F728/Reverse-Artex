package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"reverse-artex/internal/actioncontext"
	"reverse-artex/internal/detect"
	"reverse-artex/internal/event"
	"reverse-artex/internal/evidence"
	"reverse-artex/internal/hostguard"
	"testing"
	"time"
)

func TestContextBatchPreflightDoesNotWriteOrPoisonAndProfileCannotDowngrade(t *testing.T) {
	dir := t.TempDir()
	store, err := evidence.NewPersistentRotating(dir, 64<<20, 8<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	issuer, _, _ := ed25519.GenerateKey(rand.Reader)
	trust := actioncontext.Trust{Schema: "action-context-trust/2", Revision: 1, RevokedPermits: []string{}, Keys: []actioncontext.Key{{ID: "sensor", Role: "observation_sensor", Tenant: "alpha", Asset: "api", Sensor: "app", PublicKey: base64.StdEncoding.EncodeToString(pub)}, {ID: "issuer", Role: "scope_issuer", Tenant: "alpha", Asset: "api", Sensor: "app", PublicKey: base64.StdEncoding.EncodeToString(issuer)}}}
	engine := detect.New()
	host := hostguard.New(nil)
	if err = restoreState(store, dir, "session", nil, engine, host, &trust); err != nil {
		t.Fatal(err)
	}
	i := &ingester{store: store, engine: engine, hostEngine: host, contextTrust: &trust}
	now := time.Now().UTC()
	e := event.Event{SchemaVersion: "1.0", EventID: "event-a", EventTime: now, IngestTime: now, SensorID: "app", TenantID: "alpha", AssetID: "api", EventType: "http", RequestID: "req", Method: "GET", Route: "/api/{id}", Status: 403, Principal: "principal", SessionHMAC: "session", Identity: "authenticated", Authorization: "deny", ResourceHMAC: "resource", KnownRoute: true, DetectorFamily: "unknown", UAHint: "enrich", DataQuality: "complete"}
	o := actioncontext.Observation{Schema: "action-observation/2", Binding: e.ContextBinding(), KeyID: "sensor"}
	o.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, actioncontext.ObservationBytes(o)))
	e.Context = &o
	bad := e
	bad.EventID = "event-b"
	if _, err = i.processBatch([]event.Event{e, bad}); err == nil || i.degraded() {
		t.Fatal("bad batch not rejected before staging", err)
	}
	count := 0
	store.VisitRecords("events", func([]byte) error { count++; return nil })
	if count != 0 {
		t.Fatal("rejected batch wrote evidence")
	}
	if _, err = i.process(e); err != nil {
		t.Fatal("valid context rejected after bad batch", err)
	}
	if err = restoreState(store, dir, "session", nil, detect.New(), hostguard.New(nil)); err == nil {
		t.Fatal("context trust profile silently removed")
	}
}
