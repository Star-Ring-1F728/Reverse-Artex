package openai

import "net/http"

// NewProtocolTestClient replaces transport only in the test build. Production
// clients keep the fixed TLS destination and cannot configure a test endpoint.
func NewProtocolTestClient(transport http.RoundTripper, key func() string) *Client {
	c := New(key)
	c.http.Transport = transport
	return c
}

func ProtocolResponseFixture() map[string]any { return responseFixture() }
