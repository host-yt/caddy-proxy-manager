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

const geminiDefaultModel = "gemini-2.0-flash"
const geminiDefaultMaxTokens = 4096
const geminiEndpointFmt = "https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent?key=%s"

type geminiProvider struct {
	apiKey string
	client *http.Client
	log    *slog.Logger
}

func newGemini(apiKey string, log *slog.Logger) *geminiProvider {
	return &geminiProvider{
		apiKey: apiKey,
		client: &http.Client{Timeout: 30 * time.Second},
		log:    log,
	}
}

func (p *geminiProvider) Name() string { return "gemini" }

func (p *geminiProvider) Models() []string {
	return []string{"gemini-2.0-flash", "gemini-1.5-pro"}
}

type geminiPart struct {
	Text string `json:"text"`
}

type geminiContent struct {
	Role  string       `json:"role"`
	Parts []geminiPart `json:"parts"`
}

type geminiGenerationConfig struct {
	MaxOutputTokens int     `json:"maxOutputTokens"`
	Temperature     float64 `json:"temperature"`
}

type geminiRequest struct {
	Contents         []geminiContent        `json:"contents"`
	GenerationConfig geminiGenerationConfig `json:"generationConfig"`
}

type geminiResponse struct {
	Candidates []struct {
		Content struct {
			Parts []struct {
				Text string `json:"text"`
			} `json:"parts"`
		} `json:"content"`
	} `json:"candidates"`
	UsageMetadata struct {
		PromptTokenCount     int `json:"promptTokenCount"`
		CandidatesTokenCount int `json:"candidatesTokenCount"`
	} `json:"usageMetadata"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func (p *geminiProvider) Chat(ctx context.Context, messages []Message, opts ChatOptions) (*Response, error) {
	if p.apiKey == "" {
		return nil, ErrNoAPIKey
	}

	model := opts.Model
	if model == "" {
		model = geminiDefaultModel
	}
	maxTokens := opts.MaxTokens
	if maxTokens == 0 {
		maxTokens = geminiDefaultMaxTokens
	}

	var contents []geminiContent
	for _, m := range messages {
		switch m.Role {
		case RoleSystem:
			// Gemini has no system role; prepend as a user turn before first user message.
			contents = append([]geminiContent{{
				Role:  "user",
				Parts: []geminiPart{{Text: m.Content}},
			}}, contents...)
		case RoleAssistant:
			contents = append(contents, geminiContent{
				Role:  "model",
				Parts: []geminiPart{{Text: m.Content}},
			})
		default:
			contents = append(contents, geminiContent{
				Role:  "user",
				Parts: []geminiPart{{Text: m.Content}},
			})
		}
	}

	reqBody := geminiRequest{
		Contents: contents,
		GenerationConfig: geminiGenerationConfig{
			MaxOutputTokens: maxTokens,
			Temperature:     opts.Temperature,
		},
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("ai/gemini: %w", err)
	}

	endpoint := fmt.Sprintf(geminiEndpointFmt, model, p.apiKey)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("ai/gemini: %w", err)
	}
	req.Header.Set("content-type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ai/gemini: %w", err)
	}
	defer resp.Body.Close()

	var gr geminiResponse
	if err := decodeProviderResponse(resp.Body, &gr); err != nil {
		return nil, fmt.Errorf("ai/gemini: decode: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		msg := "unexpected error"
		if gr.Error != nil {
			msg = gr.Error.Message
		}
		return nil, fmt.Errorf("ai/gemini: %s", msg)
	}

	if len(gr.Candidates) == 0 || len(gr.Candidates[0].Content.Parts) == 0 {
		return nil, fmt.Errorf("ai/gemini: empty candidates in response")
	}

	return &Response{
		Content:      gr.Candidates[0].Content.Parts[0].Text,
		Model:        model,
		InputTokens:  gr.UsageMetadata.PromptTokenCount,
		OutputTokens: gr.UsageMetadata.CandidatesTokenCount,
	}, nil
}
