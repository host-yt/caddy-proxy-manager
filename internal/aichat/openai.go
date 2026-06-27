package aichat

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

const (
	openaiURL          = "https://api.openai.com/v1/chat/completions"
	openaiDefaultModel = "gpt-4o-mini"

	openrouterURL          = "https://openrouter.ai/api/v1/chat/completions"
	openrouterDefaultModel = "openai/gpt-4o-mini"
)

// openaiClient talks to the OpenAI chat/completions API (stream=true).
type openaiClient struct{ apiKey string }

func (c *openaiClient) Provider() string { return "openai" }

// openrouterClient is OpenAI-compatible; same wire shape, different base URL.
type openrouterClient struct{ apiKey string }

func (c *openrouterClient) Provider() string { return "openrouter" }

// oaiReq is the chat/completions request shape shared by OpenAI + OpenRouter.
type oaiReq struct {
	Model       string    `json:"model"`
	Messages    []oaiMsg  `json:"messages"`
	Tools       []oaiTool `json:"tools,omitempty"`
	MaxTokens   int       `json:"max_tokens,omitempty"`
	Stream      bool      `json:"stream"`
	Temperature *float64  `json:"temperature,omitempty"`
}

type oaiMsg struct {
	Role string `json:"role"`
	// Content is a pointer so an assistant tool-call turn can omit it (null).
	Content    *string       `json:"content,omitempty"`
	ToolCalls  []oaiToolCall `json:"tool_calls,omitempty"`
	ToolCallID string        `json:"tool_call_id,omitempty"`
}

// oaiTool declares a callable function tool. Parameters is the JSON-schema object.
type oaiTool struct {
	Type     string      `json:"type"`
	Function oaiToolFunc `json:"function"`
}

type oaiToolFunc struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Parameters  json.RawMessage `json:"parameters,omitempty"`
}

// oaiToolCall is one tool call in an assistant message (request + response side).
type oaiToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

func buildOAIBody(model string, msgs []Message, opts Options, stream bool) oaiReq {
	body := oaiReq{
		Model:     defaultStr(opts.Model, model),
		MaxTokens: maxToks(opts),
		Stream:    stream,
	}
	if opts.Temperature >= 0 {
		t := opts.Temperature
		body.Temperature = &t
	}
	for _, m := range msgs {
		body.Messages = append(body.Messages, oaiMessage(m))
	}
	return body
}

// oaiMessage encodes one Message into the chat/completions shape, including the
// tool round-trip (assistant tool_calls and role:tool results).
func oaiMessage(m Message) oaiMsg {
	switch {
	case m.Role == RoleTool:
		content := m.Content
		return oaiMsg{Role: "tool", ToolCallID: m.ToolCallID, Content: &content}
	case m.Role == RoleAssistant && len(m.ToolCalls) > 0:
		out := oaiMsg{Role: "assistant"}
		if m.Content != "" {
			content := m.Content
			out.Content = &content
		}
		for _, tc := range m.ToolCalls {
			var call oaiToolCall
			call.ID = tc.ID
			call.Type = "function"
			call.Function.Name = tc.Name
			call.Function.Arguments = string(tc.Arguments)
			out.ToolCalls = append(out.ToolCalls, call)
		}
		return out
	default:
		content := m.Content
		return oaiMsg{Role: string(m.Role), Content: &content}
	}
}

// oaiToolSpecs maps generic tool specs into chat/completions function tools.
func oaiToolSpecs(tools []ToolSpec) []oaiTool {
	out := make([]oaiTool, 0, len(tools))
	for _, t := range tools {
		schema := t.Schema
		if len(schema) == 0 {
			schema = json.RawMessage(`{"type":"object"}`)
		}
		out = append(out, oaiTool{Type: "function", Function: oaiToolFunc{
			Name: t.Name, Description: t.Description, Parameters: schema,
		}})
	}
	return out
}

// oaiChatResp is the subset of a non-streaming chat/completions response we read.
type oaiChatResp struct {
	Choices []struct {
		Message struct {
			Content   string        `json:"content"`
			ToolCalls []oaiToolCall `json:"tool_calls"`
		} `json:"message"`
	} `json:"choices"`
}

// chatWithToolsOAI runs the shared OpenAI-compatible tool completion.
func chatWithToolsOAI(ctx context.Context, url, apiKey, model string, msgs []Message, opts Options, tools []ToolSpec, extra map[string]string) (*Turn, error) {
	body := buildOAIBody(model, msgs, opts, false)
	body.Tools = oaiToolSpecs(tools)
	req, err := newOAIRequest(ctx, url, apiKey, body, extra)
	if err != nil {
		return nil, err
	}
	var resp oaiChatResp
	if err := doJSON(req, &resp); err != nil {
		return nil, err
	}
	turn := &Turn{}
	if len(resp.Choices) > 0 {
		msg := resp.Choices[0].Message
		turn.Text = msg.Content
		for _, tc := range msg.ToolCalls {
			turn.ToolCalls = append(turn.ToolCalls, ToolCall{
				ID: tc.ID, Name: tc.Function.Name, Arguments: json.RawMessage(tc.Function.Arguments),
			})
		}
	}
	return turn, nil
}

func newOAIRequest(ctx context.Context, url, apiKey string, body oaiReq, extra map[string]string) (*http.Request, error) {
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("aichat: marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)
	for k, v := range extra {
		req.Header.Set(k, v)
	}
	return req, nil
}

func (c *openaiClient) StreamChat(ctx context.Context, msgs []Message, opts Options) (<-chan Chunk, error) {
	req, err := newOAIRequest(ctx, openaiURL, c.apiKey, buildOAIBody(openaiDefaultModel, msgs, opts, true), nil)
	if err != nil {
		return nil, err
	}
	return doStream(ctx, req, parseOAILine)
}

func (c *openaiClient) ChatWithTools(ctx context.Context, msgs []Message, opts Options, tools []ToolSpec) (*Turn, error) {
	return chatWithToolsOAI(ctx, openaiURL, c.apiKey, openaiDefaultModel, msgs, opts, tools, nil)
}

func (c *openaiClient) Verify(ctx context.Context) error {
	body := buildOAIBody(openaiDefaultModel, []Message{{Role: RoleUser, Content: "ping"}}, Options{MaxTokens: 1, Temperature: -1}, false)
	req, err := newOAIRequest(ctx, openaiURL, c.apiKey, body, nil)
	if err != nil {
		return err
	}
	return doVerify(req)
}

// openrouterHeaders are optional attribution headers OpenRouter recommends.
var openrouterHeaders = map[string]string{
	"HTTP-Referer": "https://github.com/host-yt/caddy-proxy-manager",
	"X-Title":      "Hostyt Proxy Gateway",
}

func (c *openrouterClient) StreamChat(ctx context.Context, msgs []Message, opts Options) (<-chan Chunk, error) {
	req, err := newOAIRequest(ctx, openrouterURL, c.apiKey, buildOAIBody(openrouterDefaultModel, msgs, opts, true), openrouterHeaders)
	if err != nil {
		return nil, err
	}
	return doStream(ctx, req, parseOAILine)
}

func (c *openrouterClient) ChatWithTools(ctx context.Context, msgs []Message, opts Options, tools []ToolSpec) (*Turn, error) {
	return chatWithToolsOAI(ctx, openrouterURL, c.apiKey, openrouterDefaultModel, msgs, opts, tools, openrouterHeaders)
}

func (c *openrouterClient) Verify(ctx context.Context) error {
	body := buildOAIBody(openrouterDefaultModel, []Message{{Role: RoleUser, Content: "ping"}}, Options{MaxTokens: 1, Temperature: -1}, false)
	req, err := newOAIRequest(ctx, openrouterURL, c.apiKey, body, openrouterHeaders)
	if err != nil {
		return err
	}
	return doVerify(req)
}

// oaiStreamChunk is the subset of a streamed chunk we read.
type oaiStreamChunk struct {
	Choices []struct {
		Delta struct {
			Content string `json:"content"`
		} `json:"delta"`
		FinishReason *string `json:"finish_reason"`
	} `json:"choices"`
}

func parseOAILine(data string) (string, bool, error) {
	var ch oaiStreamChunk
	if err := json.Unmarshal([]byte(data), &ch); err != nil {
		return "", false, nil
	}
	if len(ch.Choices) == 0 {
		return "", false, nil
	}
	choice := ch.Choices[0]
	done := choice.FinishReason != nil && *choice.FinishReason != ""
	return choice.Delta.Content, done, nil
}
