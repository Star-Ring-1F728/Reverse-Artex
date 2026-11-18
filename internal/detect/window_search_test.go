package detect

import (
	"fmt"
	"testing"
	"time"

	"reverse-artex/internal/event"
)

func TestWindowStartMatchesInclusiveLinearScan(t *testing.T) {
	// Duplicate timestamps and cutoffs between timestamps exercise the stable
	// witness boundary, including empty/all-expired and future event histories.
	for _, count := range []int{0, 1, 2, 8, 128, 512} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			es := make([]event.Event, count)
			for i := range es {
				es[i].EventTime = detectTestNow.Add(time.Duration(i/3-100) * time.Nanosecond)
			}
			for offset := -102; offset <= 74; offset++ {
				cutoff := detectTestNow.Add(time.Duration(offset) * time.Nanosecond)
				want := 0
				for want < len(es) && es[want].EventTime.Before(cutoff) {
					want++
				}
				if got := windowStart(es, cutoff); got != want {
					t.Fatalf("offset %d: start = %d, want %d", offset, got, want)
				}
			}
		})
	}
}

var windowSearchResult int

func BenchmarkWindowPrefixSelection(b *testing.B) {
	es := make([]event.Event, 512)
	for i := range es {
		es[i].EventTime = detectTestNow.Add(time.Duration(i) * time.Second)
	}
	for _, expired := range []int{0, 64, 256, 512} {
		cutoff := detectTestNow.Add(time.Duration(expired) * time.Second)
		b.Run(fmt.Sprint(expired), func(b *testing.B) {
			b.Run("linear", func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					start := 0
					for start < len(es) && es[start].EventTime.Before(cutoff) {
						start++
					}
					windowSearchResult = start
				}
			})
			b.Run("search", func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					windowSearchResult = windowStart(es, cutoff)
				}
			})
		})
	}
}
