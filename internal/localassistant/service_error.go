package localassistant

import (
	"context"
	"errors"
	"net"
)

// ServiceError exposes bounded diagnostics without retaining a URL or response body.
type ServiceError struct {
	Kind       string `json:"kind"`
	HTTPStatus int    `json:"http_status,omitempty"`
	cause      error
}

func (e *ServiceError) Error() string {
	switch e.Kind {
	case "http_status", "content_encoding":
		return "local service rejected request"
	case "read", "decode":
		return "invalid bounded local service response"
	default:
		return "local service transport unavailable or timed out"
	}
}
func (e *ServiceError) Unwrap() error { return e.cause }

// Valid also validates diagnostic records recovered from a journal.
func (e *ServiceError) Valid() bool {
	if e.Kind == "http_status" {
		return e.HTTPStatus >= 100 && e.HTTPStatus <= 599 && e.HTTPStatus != 200
	}
	if e.HTTPStatus != 0 {
		return false
	}
	switch e.Kind {
	case "transport", "timeout", "cancelled", "content_encoding", "read", "decode":
		return true
	}
	return false
}

func serviceFailure(ctx context.Context, err error, fallback string) error {
	if errors.Is(ctx.Err(), context.Canceled) {
		return &ServiceError{Kind: "cancelled", cause: context.Canceled}
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return &ServiceError{Kind: "timeout", cause: context.DeadlineExceeded}
	}
	var timeout net.Error
	if errors.As(err, &timeout) && timeout.Timeout() {
		return &ServiceError{Kind: "timeout", cause: context.DeadlineExceeded}
	}
	return &ServiceError{Kind: fallback}
}
