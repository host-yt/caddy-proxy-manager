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

const openaiDefaultModel = "gpt-4o"
const openaiDefaultMaxTokens = 4096
const openaiEndpoint = "https://api.openai.com/v1/chat/completions"

type openaiProvider struct {
	apiKey string
	client *http.Client
	log    *slog.Logger
}

func newOpenAI(apiKey string, log *slog.Logger) *openaiProvider {
	return &openaiProvider{
		apiKey: apiKey,
		client: &http.Client{Timeout: 30 * time.Second},
		log:    log,
	}
}

func (p *openaiProvider) Name() string { return "openai" }

func (p *openaiProvider) Models() []string {
	return []string{"gpt-4o", "gpt-4o-mini", "gpt-4-turbo"}
}

type openaiMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openaiRequest struct {
	Model       string          `json:"model"`
	MaxTokens   int             `json:"max_tokens"`
	Temperature float64         `json:"temperature"`
	Messages    []openaiMessage `json:"messages"`
}

type openaiResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
	Model string `json:"model"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	} `json:"usage"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func (p *openaiProvider) Chat(ctx context.Context, messages []Message, opts ChatOptions) (*Response, error) {
	if p.apiKey == "" {
		return nil, ErrNoAPIKey
	}

	model := opts.Model
	if model == "" {
		model = openaiDefaultModel
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
		return nil, fmt.Errorf("ai/openai: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, openaiEndpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("ai/openai: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+p.apiKey)
	req.Header.Set("content-type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ai/openai: %w", err)
	}
	defer resp.Body.Close()

	var or openaiResponse
	if err := decodeProviderResponse(resp.Body, &or); err != nil {
		return nil, fmt.Errorf("ai/openai: decode: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		msg := "unexpected error"
		if or.Error != nil {
			msg = or.Error.Message
		}
		return nil, fmt.Errorf("ai/openai: %s", msg)
	}

	if len(or.Choices) == 0 {
		return nil, fmt.Errorf("ai/openai: empty choices in response")
	}

	return &Response{
		Content:      or.Choices[0].Message.Content,
		Model:        or.Model,
		InputTokens:  or.Usage.PromptTokens,
		OutputTokens: or.Usage.CompletionTokens,
	}, nil
}
