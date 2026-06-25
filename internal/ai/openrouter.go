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

const openrouterDefaultModel = "anthropic/claude-sonnet-4-6"
const openrouterEndpoint = "https://openrouter.ai/api/v1/chat/completions"
const openrouterReferer = "https://hostyt.com"

type openrouterProvider struct {
	apiKey string
	client *http.Client
	log    *slog.Logger
}

func newOpenRouter(apiKey string, log *slog.Logger) *openrouterProvider {
	return &openrouterProvider{
		apiKey: apiKey,
		client: &http.Client{Timeout: 30 * time.Second},
		log:    log,
	}
}

func (p *openrouterProvider) Name() string { return "openrouter" }

func (p *openrouterProvider) Models() []string {
	return []string{
		"anthropic/claude-sonnet-4-6",
		"openai/gpt-4o",
		"google/gemini-2.0-flash",
		"meta-llama/llama-3.3-70b-instruct",
	}
}

func (p *openrouterProvider) Chat(ctx context.Context, messages []Message, opts ChatOptions) (*Response, error) {
	if p.apiKey == "" {
		return nil, ErrNoAPIKey
	}

	model := opts.Model
	if model == "" {
		model = openrouterDefaultModel
	}
	maxTokens := opts.MaxTokens
	if maxTokens == 0 {
		maxTokens = openaiDefaultMaxTokens
	}

	msgs := make([]openaiMessage, 0, len(messages))
	for _, m := range messages {
		msgs = append(msgs, openaiMessage{Role: string(m.Role), Content: m.Content})
	}

	reqBody := openaiRequest{
		Model:       model,
		MaxTokens:   maxTokens,
		Temperature: opts.Temperature,
		Messages:    msgs,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("ai/openrouter: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, openrouterEndpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("ai/openrouter: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+p.apiKey)
	req.Header.Set("content-type", "application/json")
	req.Header.Set("HTTP-Referer", openrouterReferer)

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ai/openrouter: %w", err)
	}
	defer resp.Body.Close()

	var or openaiResponse
	if err := decodeProviderResponse(resp.Body, &or); err != nil {
		return nil, fmt.Errorf("ai/openrouter: decode: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		msg := "unexpected error"
		if or.Error != nil {
			msg = or.Error.Message
		}
		return nil, fmt.Errorf("ai/openrouter: %s", msg)
	}

	if len(or.Choices) == 0 {
		return nil, fmt.Errorf("ai/openrouter: empty choices in response")
	}

	return &Response{
		Content:      or.Choices[0].Message.Content,
		Model:        or.Model,
		InputTokens:  or.Usage.PromptTokens,
		OutputTokens: or.Usage.CompletionTokens,
	}, nil
}
