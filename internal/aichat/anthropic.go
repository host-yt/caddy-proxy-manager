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
// not a message role.
type anthropicReq struct {
	Model       string         `json:"model"`
	MaxTokens   int            `json:"max_tokens"`
	System      string         `json:"system,omitempty"`
	Messages    []anthropicMsg `json:"messages"`
	Stream      bool           `json:"stream,omitempty"`
	Temperature *float64       `json:"temperature,omitempty"`
}

type anthropicMsg struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// buildReq splits the system prompt out and maps roles. Consecutive same-role
// turns are left as-is; the API tolerates them.
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
		body.Messages = append(body.Messages, anthropicMsg{Role: string(m.Role), Content: m.Content})
	}
	return body
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
