package identity

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"
)

// NewRequestID keeps the default random32-hex contract. The explicit ordered
// mode uses RFC9562 section5.7 UUIDv7 for index locality; it is not a secret or
// authorization token. Clock rollback may reorder new IDs, never old evidence.
func NewRequestID(at time.Time, ordered bool) (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return formatRequestID(at, value, ordered)
}
func formatRequestID(at time.Time, value [16]byte, ordered bool) (string, error) {
	if ordered {
		ms := at.UnixMilli()
		if ms < 0 || ms >= 1<<48 {
			return "", errors.New("request timestamp out of range")
		}
		for n := 0; n < 6; n++ {
			value[5-n] = byte(ms >> (8 * n))
		}
		value[6] = (value[6] & 15) | 112
		value[8] = (value[8] & 63) | 128
	}
	return hex.EncodeToString(value[:]), nil
}
