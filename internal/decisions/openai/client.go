package openai

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"regexp"
	"reverse-artex/internal/decisions"
	"time"
)

var ErrConfig = errors.New("invalid Decisions provider configuration")
var ErrInput = errors.New("invalid bounded Decisions input")

type Client struct {
	http *http.Client
	key  func() string
}
type Decider interface {
	Decide(context.Context, Input) Result
}

func New(key func() string) *Client {
	t := &http.Transport{Proxy: nil, DisableCompression: true, MaxConnsPerHost: 2, MaxIdleConnsPerHost: 2, MaxResponseHeaderBytes: 16384, DialContext: (&net.Dialer{Timeout: time.Second}).DialContext, TLSHandshakeTimeout: time.Second, ResponseHeaderTimeout: 4 * time.Second}
	return &Client{http: &http.Client{Transport: t, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, key: key}
}
func (c *Client) Close() { c.http.CloseIdleConnections() }

var safeRequestID = regexp.MustCompile("^[A-Za-z0-9_-]{1,128}$")

func (c *Client) Decide(ctx context.Context, input Input) Result {
	result := Result{Schema: "decision-result/2", Status: "invalid", InputSHA: decisions.Hash(input), Model: Model, Origin: Endpoint, Started: time.Now().UTC(), Answers: []Answer{}}
	finish := func(status string) Result { result.Status = status; result.Completed = time.Now().UTC(); return result }
	if input.Validate() != nil {
		return finish("invalid")
	}
	data, _ := json.Marshal(input)
	if len(data) > 8192 {
		return finish("invalid")
	}
	if !time.Now().Before(input.Expires) || input.Enqueued.After(time.Now()) {
		return finish("stale")
	}
	ctx, cancel := context.WithDeadline(ctx, input.Expires)
	defer cancel()
	if ctx.Err() != nil {
		return finish("cancelled")
	}
	key := ""
	if c.key != nil {
		key = c.key()
	}
	if len(key) < 16 || len(key) > 4096 {
		return finish("credential_missing")
	}
	// Input is sent as structured data only; no untrusted message roles, URLs,
	// images or tool instructions are accepted from an incident.
	requestBody, _ := json.Marshal(map[string]any{"model": Model, "input": []any{map[string]any{"role": "user", "content": []any{map[string]any{"type": "input_json", "data": input}}}}, "questions": Questions()})
	result.RequestSHA = protectionHash(requestBody)
	req, err := http.NewRequestWithContext(ctx, "POST", Endpoint, bytes.NewReader(requestBody))
	if err != nil {
		return finish("invalid")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Accept-Encoding", "identity")
	resp, err := c.http.Do(req)
	if err != nil {
		return finish("transport_unknown")
	}
	defer resp.Body.Close()
	result.HTTPStatus = resp.StatusCode
	if id := resp.Header.Get("X-Request-ID"); safeRequestID.MatchString(id) {
		result.RequestID = id
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 65537))
	if err != nil || len(raw) > 65536 {
		return finish("invalid")
	}
	result.ResponseSHA = protectionHash(raw)
	// Error bodies may contain credentials or provider details. Retain only hash.
	switch resp.StatusCode {
	case 401, 403:
		return finish("credential_error")
	case 429:
		return finish("rate_limited")
	}
	if resp.StatusCode >= 500 {
		return finish("provider_error")
	}
	if resp.StatusCode != 200 || resp.Header.Get("Content-Encoding") != "" {
		return finish("invalid")
	}
	var wire struct {
		Model   string            `json:"model"`
		Answers []json.RawMessage `json:"answers"`
		Usage   *Usage            `json:"usage"`
	}
	if decisions.DecodeStrict(raw, &wire, 65536) != nil || wire.Model != Model || wire.Usage == nil || len(wire.Answers) != 3 {
		return finish("invalid")
	}
	var required map[string]json.RawMessage
	var usageFields map[string]json.RawMessage
	json.Unmarshal(raw, &required)
	json.Unmarshal(required["usage"], &usageFields)
	for _, field := range []string{"input_tokens", "output_tokens", "total_tokens"} {
		if len(usageFields[field]) == 0 || string(usageFields[field]) == "null" {
			return finish("invalid")
		}
	}
	u := wire.Usage
	if u.Input < 0 || u.Output < 0 || u.Total < 0 || u.Input > 2147483647 || u.Output > 2147483647 || u.Total > 2147483647 || u.Total != u.Input+u.Output || u.InputDetails.Cached < 0 || u.InputDetails.Write < 0 || u.OutputDetails.Reasoning < 0 || u.InputDetails.Cached > u.Input || u.OutputDetails.Reasoning > u.Output {
		return finish("invalid")
	}
	result.Usage = u
	partial := false
	seen := map[string]bool{}
	expected := map[string]string{"ongoing_abuse": "predicate", "candidate_action": "choice", "priority": "score"}
	for _, rawAnswer := range wire.Answers {
		var answer Answer
		if decisions.DecodeStrict(rawAnswer, &answer, 16384) != nil || seen[answer.Name] || expected[answer.Name] == "" {
			return finish("invalid")
		}
		seen[answer.Name] = true
		if answer.Type == "refusal" {
			if answer.Probability != nil || answer.Choice != nil || answer.Score != nil || answer.Confidence != nil || len(answer.Probabilities) != 0 {
				return finish("invalid")
			}
			partial = true
			result.Answers = append(result.Answers, answer)
			continue
		}
		if answer.Type != expected[answer.Name] || !validAnswer(answer) {
			return finish("invalid")
		}
		result.Answers = append(result.Answers, answer)
	}
	if ctx.Err() != nil || time.Now().After(input.Expires) {
		return finish("stale")
	}
	if partial {
		return finish("partial_refusal")
	}
	return finish("ok")
}
func protectionHash(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }
func finite(v float64, min, max float64) bool {
	return !math.IsNaN(v) && !math.IsInf(v, 0) && v >= min && v <= max
}
func validAnswer(a Answer) bool {
	if a.Type == "predicate" {
		return a.Probability != nil && finite(*a.Probability, 0, 1) && a.Choice == nil && a.Score == nil && a.Confidence == nil && len(a.Probabilities) == 0
	}
	if a.Confidence == nil || !finite(*a.Confidence, 0, 1) || a.Probability != nil {
		return false
	}
	sum := 0.0
	seen := map[string]bool{}
	if a.Type == "choice" {
		if a.Choice == nil || a.Score != nil || len(a.Probabilities) != 4 {
			return false
		}
		options := map[string]bool{"observe": true, "request_evidence": true, "request_review": true, "temporary_limit_candidate": true}
		if !options[*a.Choice] {
			return false
		}
		for _, p := range a.Probabilities {
			v, ok := p.Value.(string)
			if !ok || !options[v] || seen[v] || p.Label != "" || !finite(p.Probability, 0, 1) {
				return false
			}
			seen[v] = true
			sum += p.Probability
		}
	} else if a.Type == "score" {
		if a.Score == nil || a.Choice != nil || !finite(*a.Score, 0, 3) || len(a.Probabilities) != 4 {
			return false
		}
		labels := []string{"routine", "noteworthy", "review", "urgent"}
		weighted := 0.0
		for _, p := range a.Probabilities {
			v, ok := p.Value.(float64)
			if !ok || v != math.Trunc(v) || v < 0 || v > 3 || p.Label != labels[int(v)] || seen[p.Label] || !finite(p.Probability, 0, 1) {
				return false
			}
			seen[p.Label] = true
			sum += p.Probability
			weighted += v * p.Probability
		}
		if math.Abs(weighted-*a.Score) > 1e-5 {
			return false
		}
	} else {
		return false
	}
	return math.Abs(sum-1) < 1e-5
}
