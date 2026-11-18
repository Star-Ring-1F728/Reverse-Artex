// Package delivery provides bounded retries for idempotent event-ID ingestion.
package delivery

import (
	"bytes"
	"io"
	"net/http"
	"time"
)

type Outcome struct {
	Accepted  bool
	Retryable bool
	Retries   uint64
	Status    int
	Attempts  AttemptStats
}

// AttemptStats counts observations, not unique events or durable ACKs. HTTP
// status is counted before reading the body, including unsuccessful reads.
// Fixed fields bound memory and never retain URLs, bodies or credentials.
type AttemptStats struct {
	Requests           uint64 `json:"requests"`
	HTTP202            uint64 `json:"http_202"`
	HTTP429            uint64 `json:"http_429"`
	HTTP500            uint64 `json:"http_500"`
	HTTP502            uint64 `json:"http_502"`
	HTTP503            uint64 `json:"http_503"`
	HTTP504            uint64 `json:"http_504"`
	HTTPOther          uint64 `json:"http_other"`
	TransportErrors    uint64 `json:"transport_errors"`
	BodyReadErrors     uint64 `json:"body_read_errors"`
	OversizedResponses uint64 `json:"oversized_responses"`
	InvalidRequests    uint64 `json:"invalid_requests"`
}

func (s *AttemptStats) Add(v AttemptStats) {
	s.Requests += v.Requests
	s.HTTP202 += v.HTTP202
	s.HTTP429 += v.HTTP429
	s.HTTP500 += v.HTTP500
	s.HTTP502 += v.HTTP502
	s.HTTP503 += v.HTTP503
	s.HTTP504 += v.HTTP504
	s.HTTPOther += v.HTTPOther
	s.TransportErrors += v.TransportErrors
	s.BodyReadErrors += v.BodyReadErrors
	s.OversizedResponses += v.OversizedResponses
	s.InvalidRequests += v.InvalidRequests
}

func (s *AttemptStats) response(status int) {
	switch status {
	case http.StatusAccepted:
		s.HTTP202++
	case http.StatusTooManyRequests:
		s.HTTP429++
	case http.StatusInternalServerError:
		s.HTTP500++
	case http.StatusBadGateway:
		s.HTTP502++
	case http.StatusServiceUnavailable:
		s.HTTP503++
	case http.StatusGatewayTimeout:
		s.HTTP504++
	default:
		s.HTTPOther++
	}
}

func Post(client *http.Client, url, token string, b []byte) (bool, uint64) {
	r := PostDetailed(client, url, token, b)
	return r.Accepted, r.Retries
}

// Three bounded attempts per round. A durable outbox can retain the unchanged
// request for another paced round; permanent receiver faults stay closed.
func PostDetailed(client *http.Client, url, token string, b []byte) (out Outcome) {
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			out.Retries++
			time.Sleep(time.Duration(attempt) * 20 * time.Millisecond)
		}
		r, err := http.NewRequest("POST", url, bytes.NewReader(b))
		if err != nil {
			out.Attempts.InvalidRequests++
			return out
		}
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Content-Type", "application/json")
		out.Attempts.Requests++
		resp, err := client.Do(r)
		if err != nil {
			out.Attempts.TransportErrors++
			out.Retryable = true
			continue
		}
		out.Attempts.response(resp.StatusCode)
		n, readErr := io.Copy(io.Discard, io.LimitReader(resp.Body, 16385))
		resp.Body.Close()
		out.Status = resp.StatusCode
		if readErr != nil {
			out.Attempts.BodyReadErrors++
		}
		if n > 16384 {
			out.Attempts.OversizedResponses++
		}
		// A broken body cannot turn a known permanent denial into a retry.
		// Size and body-read observations are independent when both occur.
		retryableStatus := resp.StatusCode == 429 || resp.StatusCode == 500 || resp.StatusCode == 502 || resp.StatusCode == 503 || resp.StatusCode == 504
		if n > 16384 || resp.Header.Get("X-RA-Delivery-Permanent") == "1" || (resp.StatusCode != http.StatusAccepted && !retryableStatus) {
			out.Retryable = false
			return out
		}
		if readErr != nil {
			out.Retryable = true
			continue
		}
		if resp.StatusCode == http.StatusAccepted {
			out.Accepted = true
			out.Retryable = false
			return out
		}
		out.Retryable = retryableStatus
		if !out.Retryable {
			return out
		}
	}
	return out
}
