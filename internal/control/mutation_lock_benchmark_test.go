package control

import "testing"

// Compare the manager's actual writer gate without audit I/O or HTTP work.
func BenchmarkControlMutationLock(b *testing.B) {
	m := &Manager{}
	m.mu.Lock()
	m.mu.Unlock()
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		m.mu.Lock()
		m.mu.Unlock()
	}
}
