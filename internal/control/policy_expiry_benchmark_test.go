package control

import (
	"fmt"
	"reverse-artex/internal/policy"
	"testing"
	"time"
)

// No policy is due: measures the production expiry check without audit I/O.
func BenchmarkPolicyExpiryNotDue(b *testing.B) {
	for _, count := range []int{0, 1, 256, 1024} {
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			m, err := Open(b.TempDir())
			if err != nil {
				b.Fatal(err)
			}
			defer m.Close()
			now := time.Now().UTC()
			for i := 0; i < count; i++ {
				p := policy.Policy{ID: fmt.Sprint("bench-", i), Expires: now.Add(time.Minute)}
				m.replay(record{Epoch: m.epoch, Version: m.version + 1, Policy: &p})
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := m.expire(now); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
