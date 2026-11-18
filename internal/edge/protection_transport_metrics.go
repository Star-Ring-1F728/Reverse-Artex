package edge

import (
	"context"
	"errors"
	"net"
	"runtime"
	"sync/atomic"
	"syscall"
)

// Fixed enums only: no error string, address, URL, identity, or request data is
// retained. These counters diagnose transport availability, never authority.
type upstreamFailureClass uint8

const (
	upstreamRefused upstreamFailureClass = iota
	upstreamAddressUnavailable
	upstreamAddressInUse
	upstreamResources
	upstreamReset
	upstreamTimeout
	upstreamCancelled
	upstreamOther
	upstreamFailureClasses
)

var upstreamFailureNames = [upstreamFailureClasses]string{"connection_refused", "address_unavailable", "address_in_use", "resource_exhausted", "connection_reset_or_aborted", "timeout", "context_cancelled", "other"}

type upstreamFailureCounters struct {
	before, after [upstreamFailureClasses]atomic.Uint64
}

func upstreamFailureCause(err error) upstreamFailureClass {
	return upstreamFailureForPlatform(err, runtime.GOOS == "windows")
}
func upstreamFailureForPlatform(err error, winsock bool) upstreamFailureClass {
	if errors.Is(err, context.Canceled) {
		return upstreamCancelled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return upstreamTimeout
	}
	for _, item := range []struct {
		err   error
		class upstreamFailureClass
	}{
		{syscall.ECONNREFUSED, upstreamRefused}, {syscall.EADDRNOTAVAIL, upstreamAddressUnavailable},
		{syscall.EADDRINUSE, upstreamAddressInUse}, {syscall.ENOBUFS, upstreamResources},
		{syscall.EMFILE, upstreamResources}, {syscall.ENFILE, upstreamResources}, {syscall.ENOMEM, upstreamResources},
		{syscall.ECONNRESET, upstreamReset}, {syscall.ECONNABORTED, upstreamReset}, {syscall.ETIMEDOUT, upstreamTimeout},
	} {
		if errors.Is(err, item.err) {
			return item.class
		}
	}
	if winsock {
		// Winsock's stable native error numbers differ from Go's portable Windows
		// APPLICATION_ERROR sentinels. Unwrap by identity, never by message text.
		for _, item := range []struct {
			code  syscall.Errno
			class upstreamFailureClass
		}{
			{10061, upstreamRefused}, {10049, upstreamAddressUnavailable}, {10048, upstreamAddressInUse},
			{10055, upstreamResources}, {10024, upstreamResources}, {10054, upstreamReset}, {10053, upstreamReset}, {10060, upstreamTimeout},
		} {
			if errors.Is(err, item.code) {
				return item.class
			}
		}
	}
	var timeout net.Error
	if errors.As(err, &timeout) && timeout.Timeout() {
		return upstreamTimeout
	}
	return upstreamOther
}
func (m *ProtectionMetrics) observeUpstreamFailure(err error, connected bool) {
	if m == nil || err == nil {
		return
	}
	class := upstreamFailureCause(err)
	if connected {
		m.upstreamFailures.after[class].Add(1)
	} else {
		m.upstreamFailures.before[class].Add(1)
	}
}
func (m *ProtectionMetrics) upstreamFailureSnapshot() map[string]any {
	before, after := map[string]uint64{}, map[string]uint64{}
	for class, name := range upstreamFailureNames {
		before[name] = m.upstreamFailures.before[class].Load()
		after[name] = m.upstreamFailures.after[class].Load()
	}
	return map[string]any{"before_connection": before, "after_connection": after, "schema": "protected-upstream-failures/1", "raw_errors_retained": false, "diagnostic_only": true}
}
