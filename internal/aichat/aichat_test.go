package aichat

import (
	"errors"
	"testing"
)

func TestNotConfiguredErrorIs(t *testing.T) {
	err := &NotConfiguredError{Provider: "openai", Reason: "key empty"}
	if !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("expected errors.Is ErrNotConfigured to match")
	}
	if err.Error() == "" {
		t.Fatalf("error message should be non-empty")
	}
}

func TestNewClientUnknownProvider(t *testing.T) {
	if _, err := newClient("bogus", "k", ""); !errors.Is(err, ErrUnknownProvider) {
		t.Fatalf("want ErrUnknownProvider, got %v", err)
	}
}

func TestNewClientAll(t *testing.T) {
	for _, p := range SupportedProviders() {
		c, err := newClient(p, "test-key", "")
		if err != nil {
			t.Fatalf("newClient(%s) error: %v", p, err)
		}
		if c.Provider() != p {
			t.Fatalf("Provider() = %s, want %s", c.Provider(), p)
		}
		if c.Model() == "" {
			t.Fatalf("Model() empty for %s; want adapter default", p)
		}
	}
	// Configured model overrides the adapter default.
	for _, p := range SupportedProviders() {
		c, err := newClient(p, "test-key", "custom-model-x")
		if err != nil {
			t.Fatalf("newClient(%s, model) error: %v", p, err)
		}
		if c.Model() != "custom-model-x" {
			t.Fatalf("Model() = %s, want custom-model-x", c.Model())
		}
	}
}

func TestParseAnthropicLine(t *testing.T) {
	txt, done, err := parseAnthropicLine(`{"type":"content_block_delta","delta":{"type":"text_delta","text":"hi"}}`)
	if err != nil || txt != "hi" || done {
		t.Fatalf("delta parse: %q done=%v err=%v", txt, done, err)
	}
	_, done, _ = parseAnthropicLine(`{"type":"message_stop"}`)
	if !done {
		t.Fatalf("message_stop should mark done")
	}
}

func TestParseOAILine(t *testing.T) {
	txt, done, err := parseOAILine(`{"choices":[{"delta":{"content":"yo"}}]}`)
	if err != nil || txt != "yo" || done {
		t.Fatalf("oai parse: %q done=%v err=%v", txt, done, err)
	}
	_, done, _ = parseOAILine(`{"choices":[{"delta":{},"finish_reason":"stop"}]}`)
	if !done {
		t.Fatalf("finish_reason should mark done")
	}
}

func TestParseGeminiLine(t *testing.T) {
	txt, done, err := parseGeminiLine(`{"candidates":[{"content":{"parts":[{"text":"ok"}]}}]}`)
	if err != nil || txt != "ok" || done {
		t.Fatalf("gemini parse: %q done=%v err=%v", txt, done, err)
	}
	_, done, _ = parseGeminiLine(`{"candidates":[{"content":{"parts":[]},"finishReason":"STOP"}]}`)
	if !done {
		t.Fatalf("finishReason should mark done")
	}
}
