package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

const anthropicDefaultModel = "claude-sonnet-4-6"
const anthropicDefaultMaxTokens = 4096
const anthropicEndpoint = "https://api.anthropic.com/v1/messages"
const anthropicVersion = "2023-06-01"

type anthropicProvider struct {
	apiKey string
	client *http.Client
	log    *slog.Logger
}

func newAnthropic(apiKey string, log *slog.Logger) *anthropicProvider {
	return &anthropicProvider{
		apiKey: apiKey,
		client: &http.Client{Timeout: 30 * time.Second},
		log:    log,
	}
}

func (p *anthropicProvider) Name() string { return "anthropic" }

func (p *anthropicProvider) Models() []string {
	return []string{"claude-sonnet-4-6", "claude-haiku-4-5-20251001", "claude-opus-4-8"}
}

type anthropicMsg struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type anthropicRequest struct {
	Model     string         `json:"model"`
	MaxTokens int            `json:"max_tokens"`
	System    string         `json:"system,omitempty"`
	Messages  []anthropicMsg `json:"messages"`
}

type anthropicResponse struct {
	Content []struct {
		Text string `json:"text"`
	} `json:"content"`
	Model string `json:"model"`
	Usage struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func (p *anthropicProvider) Chat(ctx context.Context, messages []Message, opts ChatOptions) (*Response, error) {
	if p.apiKey == "" {
		return nil, ErrNoAPIKey
	}

	model := opts.Model
	if model == "" {
		model = anthropicDefaultModel
	}
	maxTokens := opts.MaxTokens
	if maxTokens == 0 {
		maxTokens = anthropicDefaultMaxTokens
	}

	var system string
	var msgs []anthropicMsg
	for _, m := range messages {
		if m.Role == RoleSystem {
			system = m.Content
			continue
		}
		msgs = append(msgs, anthropicMsg{Role: string(m.Role), Content: m.Content})
	}

	reqBody := anthropicRequest{
		Model:     model,
		MaxTokens: maxTokens,
		System:    system,
		Messages:  msgs,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("ai/anthropic: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, anthropicEndpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("ai/anthropic: %w", err)
	}
	req.Header.Set("x-api-key", p.apiKey)
	req.Header.Set("anthropic-version", anthropicVersion)
	req.Header.Set("content-type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ai/anthropic: %w", err)
	}
	defer resp.Body.Close()

	var ar anthropicResponse
	if err := decodeProviderResponse(resp.Body, &ar); err != nil {
		return nil, fmt.Errorf("ai/anthropic: decode: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		msg := "unexpected error"
		if ar.Error != nil {
			msg = ar.Error.Message
		}
		return nil, fmt.Errorf("ai/anthropic: %s", msg)
	}

	if len(ar.Content) == 0 {
		return nil, fmt.Errorf("ai/anthropic: empty content in response")
	}

	return &Response{
		Content:      ar.Content[0].Text,
		Model:        ar.Model,
		InputTokens:  ar.Usage.InputTokens,
		OutputTokens: ar.Usage.OutputTokens,
	}, nil
}
