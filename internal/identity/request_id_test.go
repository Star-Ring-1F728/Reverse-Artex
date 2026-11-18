package identity

import (
	"encoding/hex"
	"testing"
	"time"
)

func TestRequestIDUUID7LayoutDefaultAndClockRollback(t *testing.T) {
	raw, _ := hex.DecodeString("0000000000000cc318c4dc0c0c07398f")
	var value [16]byte
	copy(value[:], raw)
	got, err := formatRequestID(time.UnixMilli(0x017f22e279b0), value, true)
	if err != nil || got != "017f22e279b07cc398c4dc0c0c07398f" {
		t.Fatal(got, err)
	}
	legacy, err := formatRequestID(time.Time{}, value, false)
	if err != nil || legacy != hex.EncodeToString(raw) {
		t.Fatal("default changed", legacy, err)
	}
	previous, err := formatRequestID(time.UnixMilli(999), value, true)
	if err != nil || previous[:12] != "0000000003e7" {
		t.Fatal("clock rollback retimed", previous, err)
	}
	for _, ms := range []int64{-1, 1 << 48} {
		if _, err := formatRequestID(time.UnixMilli(ms), value, true); err == nil {
			t.Fatal("out of range accepted")
		}
	}
}
func TestRequestIDRandomTailUniqueAtSameMillisecond(t *testing.T) {
	ids := map[string]bool{}
	at := time.UnixMilli(1000)
	for n := 0; n < 1000; n++ {
		id, err := NewRequestID(at, true)
		if err != nil || len(id) != 32 || ids[id] {
			t.Fatal("invalid/duplicate trace ID", err)
		}
		ids[id] = true
	}
}
