// Package aichat is a provider-agnostic streaming chat client over net/http.
// It targets the 4 providers seeded in the settings table (anthropic, openai,
// gemini, openrouter) without pulling in any vendor SDK. Phase 2 (chat handler
// + SSE) pumps the chunk channel into the browser.
package aichat

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

// Role is a chat message role. Mirrors the OpenAI/Anthropic vocabulary.
type Role string

const (
	RoleSystem    Role = "system"
	RoleUser      Role = "user"
	RoleAssistant Role = "assistant"
	// RoleTool carries a tool execution result back to the model. The matching
	// ToolCallID ties it to the assistant turn that requested the call.
	RoleTool Role = "tool"
)

// Message is one turn in a conversation. For the tool round-trip an assistant
// message may carry ToolCalls (the model asking to run tools) and a tool-result
// message uses RoleTool with ToolCallID + Content.
type Message struct {
	Role    Role
	Content string
	// ToolCalls is set on an assistant message that requested tool execution.
	ToolCalls []ToolCall
	// ToolCallID links a RoleTool result back to the originating ToolCall.
	ToolCallID string
}

// ToolSpec describes a tool the model may call. Schema is the JSON-schema for
// the tool's parameters (a JSON object schema).
type ToolSpec struct {
	Name        string
	Description string
	Schema      json.RawMessage
}

// ToolCall is one tool invocation the model requested. Arguments is the raw JSON
// object the model produced for the tool's parameters.
type ToolCall struct {
	ID        string
	Name      string
	Arguments json.RawMessage
}

// Turn is the result of one non-streaming ChatWithTools round. When len(ToolCalls)
// > 0 the model wants tools run; otherwise Text holds the final answer.
type Turn struct {
	Text      string
	ToolCalls []ToolCall
}

// Options tunes a single StreamChat call. Zero values fall back to per-adapter
// defaults so callers can pass an empty Options.
type Options struct {
	// Model overrides the provider default model id when non-empty.
	Model string
	// MaxTokens caps the response length. <=0 uses the adapter default.
	MaxTokens int
	// Temperature is passed through when >=0; negative means "omit / provider default".
	Temperature float64
}

// Chunk is one streamed piece of assistant text. Done marks the final sentinel
// (Text empty). Err, when non-nil, is a terminal stream error.
type Chunk struct {
	Text string
	Done bool
	Err  error
}

// Client is a provider-agnostic streaming chat client. Implementations issue a
// single streaming request per StreamChat call.
type Client interface {
	// StreamChat sends messages and returns a receive-only channel of text
	// chunks. The channel is always closed when the stream ends; a terminal
	// error arrives as a final Chunk with Err set (then the channel closes).
	// Cancel via ctx. Provider is the lowercase provider id (e.g. "anthropic").
	StreamChat(ctx context.Context, msgs []Message, opts Options) (<-chan Chunk, error)
	// ChatWithTools runs one non-streaming completion with tool-calling enabled.
	// It returns a Turn: either ToolCalls the model wants executed, or final
	// Text. The caller drives the tool loop (execute, append RoleTool results,
	// call again). Providers without tool support return ErrToolsUnsupported so
	// the caller can fall back to plain StreamChat.
	ChatWithTools(ctx context.Context, msgs []Message, opts Options, tools []ToolSpec) (*Turn, error)
	// Verify performs a minimal 1-token, non-streaming call to confirm the key
	// works. Returns nil on success; never leaks the key in the error.
	Verify(ctx context.Context) error
	// Provider returns the lowercase provider id this client talks to.
	Provider() string
}

// Sentinel errors. Phase 2 should branch on these with errors.Is.
var (
	// ErrNotConfigured means no default provider is selected or its key is empty.
	ErrNotConfigured = errors.New("aichat: no AI provider configured")
	// ErrUnknownProvider means the configured provider id is not supported.
	ErrUnknownProvider = errors.New("aichat: unknown AI provider")
	// ErrToolsUnsupported means this provider/adapter has no tool-calling path;
	// the caller should fall back to plain StreamChat.
	ErrToolsUnsupported = errors.New("aichat: tools unsupported for this provider")
)

// NotConfiguredError wraps ErrNotConfigured with the offending provider id so
// the UI can say which provider needs a key. errors.Is(err, ErrNotConfigured)
// still matches.
type NotConfiguredError struct {
	Provider string // may be empty when no default_provider is set at all
	Reason   string // short human reason (e.g. "key empty")
}

func (e *NotConfiguredError) Error() string {
	if e.Provider == "" {
		return "aichat: no AI provider configured"
	}
	return "aichat: provider " + e.Provider + " not configured: " + e.Reason
}

func (e *NotConfiguredError) Unwrap() error { return ErrNotConfigured }

// httpClient is shared by all adapters. Per-call deadlines come from ctx, so we
// only set a generous overall ceiling here as a backstop for hung connections.
var httpClient = &http.Client{Timeout: 5 * time.Minute}

// supportedProviders is the canonical set the factory + UI accept.
var supportedProviders = []string{"anthropic", "openai", "gemini", "openrouter"}

// SupportedProviders returns the provider ids this package can build clients for.
func SupportedProviders() []string {
	out := make([]string, len(supportedProviders))
	copy(out, supportedProviders)
	return out
}
