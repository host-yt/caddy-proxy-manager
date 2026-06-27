package aichat

import (
	"context"
	"strings"
	"testing"
)

// TestAnthropicListModels parses data[].id from GET /v1/models and sorts.
func TestAnthropicListModels(t *testing.T) {
	ct := withTransport(t, `{"data":[{"id":"claude-3-7-sonnet"},{"id":"claude-3-5-haiku"}]}`)
	c := &anthropicClient{apiKey: "k"}
	got, err := c.ListModels(context.Background())
	if err != nil {
		t.Fatalf("ListModels: %v", err)
	}
	want := []string{"claude-3-5-haiku", "claude-3-7-sonnet"}
	if !equalIDs(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	// Must hit the models endpoint with the version header (no key leak in URL).
	if !strings.Contains(ct.url, "/v1/models") {
		t.Fatalf("url = %s", ct.url)
	}
	if ct.header.Get("anthropic-version") == "" || ct.header.Get("x-api-key") != "k" {
		t.Fatalf("missing auth headers: %v", ct.header)
	}
}

// TestOpenAIListModels filters to chat-ish ids and drops noise families.
func TestOpenAIListModels(t *testing.T) {
	ct := withTransport(t, `{"data":[{"id":"gpt-4o"},{"id":"o3-mini"},{"id":"text-embedding-3-small"},{"id":"whisper-1"},{"id":"dall-e-3"}]}`)
	c := &openaiClient{apiKey: "k"}
	got, err := c.ListModels(context.Background())
	if err != nil {
		t.Fatalf("ListModels: %v", err)
	}
	want := []string{"gpt-4o", "o3-mini"}
	if !equalIDs(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	if ct.header.Get("Authorization") != "Bearer k" {
		t.Fatalf("missing bearer auth: %v", ct.header)
	}
}

// TestOpenRouterListModels is permissive: keeps all data[].id.
func TestOpenRouterListModels(t *testing.T) {
	withTransport(t, `{"data":[{"id":"openai/gpt-4o"},{"id":"anthropic/claude-3.5-sonnet"}]}`)
	c := &openrouterClient{apiKey: "k"}
	got, err := c.ListModels(context.Background())
	if err != nil {
		t.Fatalf("ListModels: %v", err)
	}
	want := []string{"anthropic/claude-3.5-sonnet", "openai/gpt-4o"}
	if !equalIDs(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

// TestGeminiListModels strips the models/ prefix and requires generateContent.
func TestGeminiListModels(t *testing.T) {
	ct := withTransport(t, `{"models":[
		{"name":"models/gemini-1.5-pro","supportedGenerationMethods":["generateContent"]},
		{"name":"models/gemini-1.5-flash","supportedGenerationMethods":["generateContent","countTokens"]},
		{"name":"models/embedding-001","supportedGenerationMethods":["embedContent"]}
	]}`)
	c := &geminiClient{apiKey: "k"}
	got, err := c.ListModels(context.Background())
	if err != nil {
		t.Fatalf("ListModels: %v", err)
	}
	want := []string{"gemini-1.5-flash", "gemini-1.5-pro"}
	if !equalIDs(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	// Key travels in the query param, not a header.
	if !strings.Contains(ct.url, "key=k") {
		t.Fatalf("url = %s", ct.url)
	}
}

func TestSortCapModelsDedup(t *testing.T) {
	got := sortCapModels([]string{"b", "a", "b", "", " c "})
	want := []string{"a", "b", "c"}
	if !equalIDs(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func equalIDs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
