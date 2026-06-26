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
	Model       string   `json:"model"`
	Messages    []oaiMsg `json:"messages"`
	MaxTokens   int      `json:"max_tokens,omitempty"`
	Stream      bool     `json:"stream"`
	Temperature *float64 `json:"temperature,omitempty"`
}

type oaiMsg struct {
	Role    string `json:"role"`
	Content string `json:"content"`
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
		body.Messages = append(body.Messages, oaiMsg{Role: string(m.Role), Content: m.Content})
	}
	return body
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
