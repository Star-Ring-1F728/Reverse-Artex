package control

import (
	"errors"
	"os"
	"reverse-artex/internal/event"
	"testing"
	"time"
)

func TestSnapshotDuringAuditSyncPublishesOnlyCommittedVersion(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "commit", true: "failure"}[fail], func(t *testing.T) {
			m, err := OpenPersistent(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer m.Close()
			now := time.Now().UTC()
			key := []byte("01234567890123456789012345678901")
			before, err := m.Snapshot(now, key)
			if err != nil {
				t.Fatal(err)
			}
			entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
			m.syncFile = func(f *os.File) error {
				close(entered)
				<-release
				if fail {
					return errors.New("injected audit sync failure")
				}
				return f.Sync()
			}
			e := event.Event{SchemaVersion: "1.0", EventID: "slow-event", EventTime: now, IngestTime: now, SensorID: "lab-app", TenantID: "alpha", AssetID: "lab-api", EventType: "http", RequestID: "request", Method: "GET", Route: "/api/search", Status: 200, Principal: "alice", SessionHMAC: "s", Identity: "authenticated", Authorization: "allow", Reason: "none", ResourceClass: "business", PathHMAC: "p", KnownRoute: true, UAHint: "none", DataQuality: "complete", ProcessID: "unknown", ContainerID: "unknown", SrcIP: "127.0.0.1"}
			go func() { _, err := m.Evidence(e, now); done <- err }()
			select {
			case <-entered:
			case err := <-done:
				t.Fatalf("did not enter Sync: %v", err)
			case <-time.After(time.Second):
				t.Fatal("no Sync")
			}
			read := make(chan uint64, 1)
			go func() { s, _ := m.Snapshot(now.Add(time.Millisecond), key); read <- s.Version }()
			select {
			case v := <-read:
				if v != before.Version {
					t.Error("published unsynced version")
				}
			case <-time.After(200 * time.Millisecond):
				close(release)
				<-done
				t.Fatal("snapshot blocked on evidence Sync")
			}
			close(release)
			err = <-done
			if (err != nil) != fail {
				t.Fatalf("commit error %v", err)
			}
			after, err := m.Snapshot(now.Add(2*time.Millisecond), key)
			if err != nil {
				t.Fatal(err)
			}
			want := before.Version
			if !fail {
				want++
			}
			if after.Version != want {
				t.Fatalf("version %d want %d", after.Version, want)
			}
		})
	}
}
