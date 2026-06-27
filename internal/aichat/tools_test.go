package aichat

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// roundTrip swaps the shared client transport to hit a test server, capturing
// the request body the adapter produced.
type captureTransport struct {
	body   []byte
	url    string
	header http.Header
	resp   string
}

func (c *captureTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	c.body, _ = io.ReadAll(r.Body)
	c.url = r.URL.String()
	c.header = r.Header.Clone()
	return &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(strings.NewReader(c.resp)),
		Header:     make(http.Header),
	}, nil
}

func withTransport(t *testing.T, resp string) *captureTransport {
	t.Helper()
	orig := httpClient.Transport
	ct := &captureTransport{resp: resp}
	httpClient.Transport = ct
	t.Cleanup(func() { httpClient.Transport = orig })
	return ct
}

var sampleTools = []ToolSpec{{
	Name:        "list_nodes",
	Description: "list nodes",
	Schema:      json.RawMessage(`{"type":"object","properties":{}}`),
}}

func TestAnthropicChatWithToolsPayload(t *testing.T) {
	ct := withTransport(t, `{"content":[{"type":"tool_use","id":"tu_1","name":"list_nodes","input":{"limit":5}}]}`)
	c := &anthropicClient{apiKey: "k"}
	turn, err := c.ChatWithTools(context.Background(), []Message{{Role: RoleUser, Content: "hi"}}, Options{Temperature: -1}, sampleTools)
	if err != nil {
		t.Fatalf("ChatWithTools: %v", err)
	}
	// Request payload must declare the tool with input_schema.
	var req anthropicReq
	if err := json.Unmarshal(ct.body, &req); err != nil {
		t.Fatalf("unmarshal req: %v", err)
	}
	if len(req.Tools) != 1 || req.Tools[0].Name != "list_nodes" {
		t.Fatalf("tools not serialized: %+v", req.Tools)
	}
	if len(req.Tools[0].InputSchema) == 0 {
		t.Fatalf("input_schema empty")
	}
	if req.Stream {
		t.Fatalf("ChatWithTools must be non-streaming")
	}
	// Response parsed into a ToolCall.
	if len(turn.ToolCalls) != 1 || turn.ToolCalls[0].Name != "list_nodes" || turn.ToolCalls[0].ID != "tu_1" {
		t.Fatalf("tool call not parsed: %+v", turn.ToolCalls)
	}
}

func TestAnthropicToolResultRoundTrip(t *testing.T) {
	ct := withTransport(t, `{"content":[{"type":"text","text":"done"}]}`)
	c := &anthropicClient{apiKey: "k"}
	msgs := []Message{
		{Role: RoleUser, Content: "list nodes"},
		{Role: RoleAssistant, ToolCalls: []ToolCall{{ID: "tu_1", Name: "list_nodes", Arguments: json.RawMessage(`{}`)}}},
		{Role: RoleTool, ToolCallID: "tu_1", Content: `{"nodes":[]}`},
	}
	turn, err := c.ChatWithTools(context.Background(), msgs, Options{Temperature: -1}, sampleTools)
	if err != nil {
		t.Fatalf("ChatWithTools: %v", err)
	}
	if turn.Text != "done" {
		t.Fatalf("final text = %q", turn.Text)
	}
	// The tool_result block must be sent under the user role.
	if !strings.Contains(string(ct.body), `"tool_result"`) || !strings.Contains(string(ct.body), `"tool_use_id":"tu_1"`) {
		t.Fatalf("tool_result not serialized: %s", ct.body)
	}
	if !strings.Contains(string(ct.body), `"tool_use"`) {
		t.Fatalf("assistant tool_use not serialized: %s", ct.body)
	}
}

func TestOpenAIChatWithToolsPayload(t *testing.T) {
	ct := withTransport(t, `{"choices":[{"message":{"tool_calls":[{"id":"call_1","type":"function","function":{"name":"list_nodes","arguments":"{\"limit\":3}"}}]}}]}`)
	c := &openaiClient{apiKey: "k"}
	turn, err := c.ChatWithTools(context.Background(), []Message{{Role: RoleUser, Content: "hi"}}, Options{Temperature: -1}, sampleTools)
	if err != nil {
		t.Fatalf("ChatWithTools: %v", err)
	}
	var req oaiReq
	if err := json.Unmarshal(ct.body, &req); err != nil {
		t.Fatalf("unmarshal req: %v", err)
	}
	if len(req.Tools) != 1 || req.Tools[0].Type != "function" || req.Tools[0].Function.Name != "list_nodes" {
		t.Fatalf("tools not serialized: %+v", req.Tools)
	}
	if req.Stream {
		t.Fatalf("ChatWithTools must be non-streaming")
	}
	if len(turn.ToolCalls) != 1 || turn.ToolCalls[0].ID != "call_1" || turn.ToolCalls[0].Name != "list_nodes" {
		t.Fatalf("tool call not parsed: %+v", turn.ToolCalls)
	}
	if string(turn.ToolCalls[0].Arguments) != `{"limit":3}` {
		t.Fatalf("arguments = %s", turn.ToolCalls[0].Arguments)
	}
}

func TestOpenAIToolResultSerialization(t *testing.T) {
	ct := withTransport(t, `{"choices":[{"message":{"content":"ok"}}]}`)
	c := &openaiClient{apiKey: "k"}
	msgs := []Message{
		{Role: RoleAssistant, ToolCalls: []ToolCall{{ID: "call_1", Name: "list_nodes", Arguments: json.RawMessage(`{}`)}}},
		{Role: RoleTool, ToolCallID: "call_1", Content: `{"nodes":[]}`},
	}
	turn, err := c.ChatWithTools(context.Background(), msgs, Options{Temperature: -1}, sampleTools)
	if err != nil {
		t.Fatalf("ChatWithTools: %v", err)
	}
	if turn.Text != "ok" {
		t.Fatalf("text = %q", turn.Text)
	}
	body := string(ct.body)
	if !strings.Contains(body, `"role":"tool"`) || !strings.Contains(body, `"tool_call_id":"call_1"`) {
		t.Fatalf("role:tool result not serialized: %s", body)
	}
	if !strings.Contains(body, `"tool_calls"`) {
		t.Fatalf("assistant tool_calls not serialized: %s", body)
	}
}

func TestGeminiToolsUnsupported(t *testing.T) {
	c := &geminiClient{apiKey: "k"}
	_, err := c.ChatWithTools(context.Background(), nil, Options{}, sampleTools)
	if err != ErrToolsUnsupported {
		t.Fatalf("want ErrToolsUnsupported, got %v", err)
	}
}

// guard: a non-tools StreamChat call must still produce a plain-string content
// (regression on the json.RawMessage content change for anthropic).
func TestAnthropicPlainBuildBodyStringContent(t *testing.T) {
	c := &anthropicClient{apiKey: "k"}
	body := c.buildBody([]Message{{Role: RoleUser, Content: "hello"}}, Options{Temperature: -1}, true)
	raw, _ := json.Marshal(body)
	if !strings.Contains(string(raw), `"content":"hello"`) {
		t.Fatalf("plain content should be a JSON string: %s", raw)
	}
}
