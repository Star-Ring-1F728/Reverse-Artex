package localassistant

import (
	"context"
	"encoding/json"
	"time"
)

// LocalClient exposes only the existing bounded loopback Ollama transport.
// It does not start/pull models, accept credentials, or choose a cloud fallback.
type LocalClient struct{ provider *provider }
type Message = message
type ToolCall = toolCall
type ToolDefinition = toolDefinition

func NewLocalClient(base string) (*LocalClient, error) {
	normalized, err := origin(base)
	if err != nil {
		return nil, err
	}
	return &LocalClient{&provider{origin: normalized, http: client(30 * time.Second)}}, nil
}
func (c *LocalClient) Check(ctx context.Context, name string) (Model, error) {
	return c.provider.check(ctx, name)
}
func (c *LocalClient) Next(ctx context.Context, m Model, history []Message, tools []ToolDefinition) (ToolCall, int, error) {
	return c.provider.next(ctx, m, history, tools)
}
func (c *LocalClient) Close() { c.provider.http.CloseIdleConnections() }
func Tool(name, description string, properties map[string]any) ToolDefinition {
	return tool(name, description, properties)
}

func InputBytes(m Model, h []Message, t []ToolDefinition) (int, error) {
	raw, err := json.Marshal(chatRequest(m, h, t))
	return len(raw), err
}
