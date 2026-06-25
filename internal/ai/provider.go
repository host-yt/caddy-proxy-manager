package ai

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
)

type Role string

const (
	RoleUser      Role = "user"
	RoleAssistant Role = "assistant"
	RoleSystem    Role = "system"
)

type Message struct {
	Role    Role
	Content string
}

type ChatOptions struct {
	Model       string
	MaxTokens   int
	Temperature float64
}

type Response struct {
	Content      string
	Model        string
	InputTokens  int
	OutputTokens int
}

type Provider interface {
	Chat(ctx context.Context, messages []Message, opts ChatOptions) (*Response, error)
	Models() []string
	Name() string
}

// ErrNoAPIKey is returned when the provider's API key is not configured.
var ErrNoAPIKey = errors.New("ai: API key not configured")

const maxProviderResponseBytes = 4 << 20

func decodeProviderResponse(r io.Reader, v any) error {
	return json.NewDecoder(io.LimitReader(r, maxProviderResponseBytes)).Decode(v)
}

// Build returns the named provider using decrypted keys from the settings map.
// providerName: "anthropic", "openai", "gemini", "openrouter"
// keys map: "anthropic_key", "openai_key", "gemini_key", "openrouter_key" (already decrypted)
func Build(providerName string, keys map[string]string, logger *slog.Logger) (Provider, error) {
	switch providerName {
	case "anthropic":
		return newAnthropic(keys["anthropic_key"], logger), nil
	case "openai":
		return newOpenAI(keys["openai_key"], logger), nil
	case "gemini":
		return newGemini(keys["gemini_key"], logger), nil
	case "openrouter":
		return newOpenRouter(keys["openrouter_key"], logger), nil
	default:
		return nil, fmt.Errorf("ai: unknown provider %q", providerName)
	}
}
