package aichat

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

const (
	geminiBase         = "https://generativelanguage.googleapis.com/v1beta/models/"
	geminiDefaultModel = "gemini-1.5-flash"
)

// geminiClient talks to the Gemini generateContent API. Streaming uses
// :streamGenerateContent?alt=sse which yields OpenAI-style data: lines.
type geminiClient struct{ apiKey string }

func (c *geminiClient) Provider() string { return "gemini" }

type geminiReq struct {
	Contents          []geminiContent `json:"contents"`
	SystemInstruction *geminiContent  `json:"systemInstruction,omitempty"`
	GenerationConfig  geminiGenConfig `json:"generationConfig"`
}

type geminiContent struct {
	Role  string       `json:"role,omitempty"`
	Parts []geminiPart `json:"parts"`
}

type geminiPart struct {
	Text string `json:"text"`
}

type geminiGenConfig struct {
	MaxOutputTokens int      `json:"maxOutputTokens,omitempty"`
	Temperature     *float64 `json:"temperature,omitempty"`
}

func (c *geminiClient) buildBody(msgs []Message, opts Options) geminiReq {
	body := geminiReq{GenerationConfig: geminiGenConfig{MaxOutputTokens: maxToks(opts)}}
	if opts.Temperature >= 0 {
		t := opts.Temperature
		body.GenerationConfig.Temperature = &t
	}
	for _, m := range msgs {
		if m.Role == RoleSystem {
			if body.SystemInstruction == nil {
				body.SystemInstruction = &geminiContent{}
			}
			body.SystemInstruction.Parts = append(body.SystemInstruction.Parts, geminiPart{Text: m.Content})
			continue
		}
		role := "user"
		if m.Role == RoleAssistant {
			role = "model" // Gemini calls the assistant role "model"
		}
		body.Contents = append(body.Contents, geminiContent{Role: role, Parts: []geminiPart{{Text: m.Content}}})
	}
	return body
}

// endpoint builds the model URL. The API key goes in the ?key= query param;
// it is never logged by this package.
func (c *geminiClient) endpoint(model, method, extraQuery string) string {
	u := geminiBase + url.PathEscape(model) + ":" + method + "?key=" + url.QueryEscape(c.apiKey)
	if extraQuery != "" {
		u += "&" + extraQuery
	}
	return u
}

func (c *geminiClient) newRequest(ctx context.Context, urlStr string, body geminiReq) (*http.Request, error) {
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("aichat: marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, urlStr, bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return req, nil
}

func (c *geminiClient) StreamChat(ctx context.Context, msgs []Message, opts Options) (<-chan Chunk, error) {
	model := defaultStr(opts.Model, geminiDefaultModel)
	req, err := c.newRequest(ctx, c.endpoint(model, "streamGenerateContent", "alt=sse"), c.buildBody(msgs, opts))
	if err != nil {
		return nil, err
	}
	return doStream(ctx, req, parseGeminiLine)
}

// ChatWithTools is not implemented for Gemini: its function-calling wire shape
// (functionCall/functionResponse parts, no stable call IDs) does not map cleanly
// onto the shared ToolCall round-trip, so callers fall back to plain streaming.
func (c *geminiClient) ChatWithTools(ctx context.Context, msgs []Message, opts Options, tools []ToolSpec) (*Turn, error) {
	return nil, ErrToolsUnsupported
}

func (c *geminiClient) Verify(ctx context.Context) error {
	model := defaultStr("", geminiDefaultModel)
	body := c.buildBody([]Message{{Role: RoleUser, Content: "ping"}}, Options{MaxTokens: 1, Temperature: -1})
	req, err := c.newRequest(ctx, c.endpoint(model, "generateContent", ""), body)
	if err != nil {
		return err
	}
	return doVerify(req)
}

// geminiStreamChunk is the subset of a streamed response we read.
type geminiStreamChunk struct {
	Candidates []struct {
		Content struct {
			Parts []geminiPart `json:"parts"`
		} `json:"content"`
		FinishReason string `json:"finishReason"`
	} `json:"candidates"`
}

func parseGeminiLine(data string) (string, bool, error) {
	var ch geminiStreamChunk
	if err := json.Unmarshal([]byte(data), &ch); err != nil {
		return "", false, nil
	}
	if len(ch.Candidates) == 0 {
		return "", false, nil
	}
	cand := ch.Candidates[0]
	var text string
	for _, p := range cand.Content.Parts {
		text += p.Text
	}
	return text, cand.FinishReason != "", nil
}
