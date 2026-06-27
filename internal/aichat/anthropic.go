package aichat

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

const (
	anthropicURL          = "https://api.anthropic.com/v1/messages"
	anthropicVersion      = "2023-06-01"
	anthropicDefaultModel = "claude-3-5-haiku-latest"
)

// anthropicClient talks to the Anthropic Messages API (streaming SSE).
type anthropicClient struct{ apiKey string }

func (c *anthropicClient) Provider() string { return "anthropic" }

// anthropicReq is the Messages API request shape. System is a top-level field,
// not a message role. Content is json.RawMessage so a message can be a plain
// string (chat) or an array of content blocks (tool round-trip).
type anthropicReq struct {
	Model       string          `json:"model"`
	MaxTokens   int             `json:"max_tokens"`
	System      string          `json:"system,omitempty"`
	Messages    []anthropicMsg  `json:"messages"`
	Tools       []anthropicTool `json:"tools,omitempty"`
	Stream      bool            `json:"stream,omitempty"`
	Temperature *float64        `json:"temperature,omitempty"`
}

type anthropicMsg struct {
	Role    string          `json:"role"`
	Content json.RawMessage `json:"content"`
}

// anthropicTool is the Messages API tool declaration. input_schema is the
// JSON-schema object for the tool's parameters.
type anthropicTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"input_schema"`
}

// buildReq splits the system prompt out and maps roles. Consecutive same-role
// turns are left as-is; the API tolerates them. Tool round-trip messages
// (assistant ToolCalls, RoleTool results) are encoded as content blocks.
func (c *anthropicClient) buildBody(msgs []Message, opts Options, stream bool) anthropicReq {
	body := anthropicReq{
		Model:     defaultStr(opts.Model, anthropicDefaultModel),
		MaxTokens: maxToks(opts),
		Stream:    stream,
	}
	if opts.Temperature >= 0 {
		t := opts.Temperature
		body.Temperature = &t
	}
	for _, m := range msgs {
		if m.Role == RoleSystem {
			if body.System != "" {
				body.System += "\n\n"
			}
			body.System += m.Content
			continue
		}
		body.Messages = append(body.Messages, anthropicMessage(m))
	}
	return body
}

// anthropicTextContent wraps plain text as a JSON string (the simple content form).
func anthropicTextContent(text string) json.RawMessage {
	b, _ := json.Marshal(text)
	return b
}

// anthropicMessage encodes one Message into the Messages API shape. Assistant
// turns with tool calls and RoleTool results become content-block arrays.
func anthropicMessage(m Message) anthropicMsg {
	switch {
	case m.Role == RoleTool:
		// tool_result blocks must be sent under the "user" role.
		blocks := []map[string]any{{
			"type":        "tool_result",
			"tool_use_id": m.ToolCallID,
			"content":     m.Content,
		}}
		raw, _ := json.Marshal(blocks)
		return anthropicMsg{Role: "user", Content: raw}
	case m.Role == RoleAssistant && len(m.ToolCalls) > 0:
		var blocks []map[string]any
		if m.Content != "" {
			blocks = append(blocks, map[string]any{"type": "text", "text": m.Content})
		}
		for _, tc := range m.ToolCalls {
			input := tc.Arguments
			if len(input) == 0 {
				input = json.RawMessage("{}")
			}
			blocks = append(blocks, map[string]any{
				"type":  "tool_use",
				"id":    tc.ID,
				"name":  tc.Name,
				"input": input,
			})
		}
		raw, _ := json.Marshal(blocks)
		return anthropicMsg{Role: "assistant", Content: raw}
	default:
		return anthropicMsg{Role: string(m.Role), Content: anthropicTextContent(m.Content)}
	}
}

func (c *anthropicClient) newRequest(ctx context.Context, body anthropicReq) (*http.Request, error) {
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("aichat: marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, anthropicURL, bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", c.apiKey)
	req.Header.Set("anthropic-version", anthropicVersion)
	return req, nil
}

func (c *anthropicClient) StreamChat(ctx context.Context, msgs []Message, opts Options) (<-chan Chunk, error) {
	req, err := c.newRequest(ctx, c.buildBody(msgs, opts, true))
	if err != nil {
		return nil, err
	}
	return doStream(ctx, req, parseAnthropicLine)
}

// anthropicToolSpecs maps generic tool specs into Messages API tool declarations.
func anthropicToolSpecs(tools []ToolSpec) []anthropicTool {
	out := make([]anthropicTool, 0, len(tools))
	for _, t := range tools {
		schema := t.Schema
		if len(schema) == 0 {
			schema = json.RawMessage(`{"type":"object"}`)
		}
		out = append(out, anthropicTool{Name: t.Name, Description: t.Description, InputSchema: schema})
	}
	return out
}

// anthropicResp is the subset of a non-streaming Messages response we read.
type anthropicResp struct {
	Content []struct {
		Type  string          `json:"type"`
		Text  string          `json:"text"`
		ID    string          `json:"id"`
		Name  string          `json:"name"`
		Input json.RawMessage `json:"input"`
	} `json:"content"`
}

func (c *anthropicClient) ChatWithTools(ctx context.Context, msgs []Message, opts Options, tools []ToolSpec) (*Turn, error) {
	body := c.buildBody(msgs, opts, false)
	body.Tools = anthropicToolSpecs(tools)
	req, err := c.newRequest(ctx, body)
	if err != nil {
		return nil, err
	}
	var resp anthropicResp
	if err := doJSON(req, &resp); err != nil {
		return nil, err
	}
	turn := &Turn{}
	for _, blk := range resp.Content {
		switch blk.Type {
		case "text":
			turn.Text += blk.Text
		case "tool_use":
			turn.ToolCalls = append(turn.ToolCalls, ToolCall{ID: blk.ID, Name: blk.Name, Arguments: blk.Input})
		}
	}
	return turn, nil
}

func (c *anthropicClient) Verify(ctx context.Context) error {
	body := c.buildBody([]Message{{Role: RoleUser, Content: "ping"}}, Options{MaxTokens: 1, Temperature: -1}, false)
	req, err := c.newRequest(ctx, body)
	if err != nil {
		return err
	}
	return doVerify(req)
}

// anthropicEvent is the subset of streamed event JSON we read. Only
// content_block_delta carries assistant text; message_stop ends the stream.
type anthropicEvent struct {
	Type  string `json:"type"`
	Delta struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"delta"`
}

func parseAnthropicLine(data string) (string, bool, error) {
	var ev anthropicEvent
	if err := json.Unmarshal([]byte(data), &ev); err != nil {
		return "", false, nil // ignore non-JSON keepalives
	}
	switch ev.Type {
	case "content_block_delta":
		return ev.Delta.Text, false, nil
	case "message_stop":
		return "", true, nil
	default:
		return "", false, nil
	}
}

func defaultStr(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
