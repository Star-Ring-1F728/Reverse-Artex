// Package localassistant connects installed local Ollama models to bounded,
// case-scoped tools. It never trains or downloads models.
package localassistant

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"reverse-artex/internal/decisions"
	"sort"
	"strings"
	"time"
)

func origin(value string) (string, error) {
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" || (u.Path != "" && u.Path != "/") {
		return "", errors.New("literal loopback HTTP origin required")
	}
	ip := net.ParseIP(u.Hostname())
	if ip == nil || !ip.IsLoopback() || u.Port() == "" {
		return "", errors.New("literal loopback HTTP origin and port required")
	}
	return u.Scheme + "://" + u.Host, nil
}
func client(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, Transport: &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 2 * time.Second}).DialContext, ResponseHeaderTimeout: timeout, MaxResponseHeaderBytes: 8192, DisableCompression: true, MaxConnsPerHost: 2, IdleConnTimeout: 10 * time.Second}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func exchange(ctx context.Context, c *http.Client, base, path, token string, input, output any, limit int) error {
	method := http.MethodGet
	var body io.Reader
	if input != nil {
		raw, err := json.Marshal(input)
		if err != nil || len(raw) > 48<<10 {
			return errors.New("request byte limit")
		}
		body = bytes.NewReader(raw)
		method = http.MethodPost
	}
	req, err := http.NewRequestWithContext(ctx, method, base+path, body)
	if err != nil {
		return err
	}
	if input != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := c.Do(req)
	if err != nil {
		return serviceFailure(ctx, err, "transport")
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return &ServiceError{Kind: "http_status", HTTPStatus: res.StatusCode}
	}
	if res.Header.Get("Content-Encoding") != "" {
		return &ServiceError{Kind: "content_encoding"}
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, int64(limit+1)))
	if err != nil {
		return serviceFailure(ctx, err, "read")
	}
	if decisions.DecodeStrict(raw, output, limit) != nil {
		return &ServiceError{Kind: "decode"}
	}
	return nil
}

type Model struct {
	Name   string `json:"name"`
	Digest string `json:"digest"`
}
type provider struct {
	origin string
	http   *http.Client
}

func (p *provider) models(ctx context.Context) ([]Model, error) {
	var result map[string]json.RawMessage
	if err := exchange(ctx, p.http, p.origin, "/api/tags", "", nil, &result, 64<<10); err != nil {
		return nil, err
	}
	var rows []map[string]json.RawMessage
	if json.Unmarshal(result["models"], &rows) != nil || len(rows) > 128 {
		return nil, errors.New("invalid installed model catalog")
	}
	out := []Model{}
	for _, row := range rows {
		var m Model
		json.Unmarshal(row["name"], &m.Name)
		json.Unmarshal(row["digest"], &m.Digest)
		if validModel(m.Name) && decisions.ValidHash(m.Digest) && !remoteName(m.Name) {
			out = append(out, m)
		}
	}
	return out, nil
}
func validModel(name string) bool {
	return len(name) > 0 && len(name) <= 128 && strings.IndexFunc(name, func(r rune) bool { return r < 33 || r > 126 }) < 0
}
func remoteName(name string) bool {
	return strings.HasSuffix(name, ":cloud") || strings.HasSuffix(name, "-cloud")
}
func (p *provider) check(ctx context.Context, name string) (Model, error) {
	models, err := p.models(ctx)
	if err != nil {
		return Model{}, err
	}
	var installed Model
	for _, m := range models {
		if m.Name == name {
			installed = m
			break
		}
	}
	if installed.Name == "" {
		return Model{}, errors.New("requested local model is not installed")
	}
	var show map[string]json.RawMessage
	if err = exchange(ctx, p.http, p.origin, "/api/show", "", map[string]string{"model": name}, &show, 64<<10); err != nil {
		return Model{}, err
	}
	for _, key := range []string{"remote_host", "remote_model"} {
		if raw := show[key]; len(raw) > 0 && string(raw) != "null" && string(raw) != `""` {
			return Model{}, errors.New("remote model is not allowed")
		}
	}
	var caps []string
	json.Unmarshal(show["capabilities"], &caps)
	for _, c := range caps {
		if c == "tools" {
			return installed, nil
		}
	}
	return Model{}, errors.New("installed model does not support tools")
}

type toolCall struct {
	Function struct {
		Index     int             `json:"index,omitempty"`
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	} `json:"function"`
	Type string `json:"type,omitempty"`
	ID   string `json:"id,omitempty"`
}
type message struct {
	Role     string     `json:"role"`
	Content  string     `json:"content"`
	ToolName string     `json:"tool_name,omitempty"`
	Calls    []toolCall `json:"tool_calls,omitempty"`
}
type toolDefinition struct {
	Type     string `json:"type"`
	Function struct {
		Name        string         `json:"name"`
		Description string         `json:"description"`
		Parameters  map[string]any `json:"parameters"`
	} `json:"function"`
}

func tool(name, description string, properties map[string]any) toolDefinition {
	t := toolDefinition{Type: "function"}
	t.Function.Name = name
	t.Function.Description = description
	keys := []string{}
	for k := range properties {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	t.Function.Parameters = map[string]any{"type": "object", "properties": properties, "required": keys, "additionalProperties": false}
	return t
}
func (p *provider) next(ctx context.Context, m Model, history []message, tools []toolDefinition) (toolCall, int, error) {
	// Pin the installed alias for the entire run; never pull or accept a cloud alias.
	models, err := p.models(ctx)
	if err != nil {
		return toolCall{}, 0, err
	}
	pinned := false
	for _, current := range models {
		if current == m {
			pinned = true
		}
	}
	if !pinned {
		return toolCall{}, 0, errors.New("installed model revision changed")
	}
	payload := chatRequest(m, history, tools)
	raw, _ := json.Marshal(payload)
	if len(raw) > 48<<10 {
		return toolCall{}, 0, errors.New("model input byte limit")
	}
	var result map[string]json.RawMessage
	if err = exchange(ctx, p.http, p.origin, "/api/chat", "", payload, &result, 64<<10); err != nil {
		return toolCall{}, len(raw), err
	}
	var done bool
	json.Unmarshal(result["done"], &done)
	if !done {
		return toolCall{}, len(raw), errors.New("model response incomplete")
	}
	var msg map[string]json.RawMessage
	if json.Unmarshal(result["message"], &msg) != nil {
		return toolCall{}, len(raw), errors.New("model response has no message")
	}
	var calls []toolCall
	if decisions.DecodeStrict(msg["tool_calls"], &calls, 8192) != nil || len(calls) != 1 {
		return toolCall{}, len(raw), errors.New("exactly one tool call required")
	}
	call := calls[0]
	var args map[string]json.RawMessage
	if decisions.DecodeStrict(call.Function.Arguments, &args, 4096) != nil || args == nil {
		return toolCall{}, len(raw), errors.New("tool arguments must be a JSON object")
	}
	allowed := false
	for _, t := range tools {
		if t.Function.Name == call.Function.Name {
			allowed = true
		}
	}
	if !allowed {
		return toolCall{}, len(raw), errors.New("model requested an unavailable tool")
	}
	// Discard natural text, thinking and provider extensions, retaining only tools.
	call.ID = ""
	call.Type = "function"
	return call, len(raw), nil
}

func chatRequest(m Model, history []message, tools []toolDefinition) map[string]any {
	return map[string]any{"model": m.Name, "messages": history, "tools": tools, "stream": false, "think": false, "keep_alive": "5m", "options": map[string]any{"temperature": 0, "num_predict": 512, "num_ctx": 8192}}
}
