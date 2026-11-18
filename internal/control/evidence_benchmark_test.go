package control

import (
	"fmt"
	"reverse-artex/internal/event"
	"testing"
	"time"
)

// A duplicate still performs the production admission/pruning path, without
// measuring disk Sync or changing the audit during the timed loop.
func BenchmarkEvidenceDuplicateWindow(b *testing.B) {
	for _, count := range []int{1, 256, 1024, 16384} {
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			m, err := Open(b.TempDir())
			if err != nil {
				b.Fatal(err)
			}
			defer m.Close()
			now := time.Now().UTC()
			var last event.Event
			for i := 0; i < count; i++ {
				last = specimen(fmt.Sprint("bench-", i), "lab-app", now)
				// Replay is the post-Sync state transition also used at startup.
				m.replay(record{Version: m.version + 1, Epoch: m.epoch, Evidence: &last})
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := m.Evidence(last, now); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
