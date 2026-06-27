// Package aitools is a read-only tool registry the AI assistant can call to
// answer questions about live HPG state. Every tool is a parameterized,
// LIMIT-bounded SELECT over existing tables and returns compact JSON. Tools
// NEVER expose secret columns (password/key/token/private-key material) - see
// the per-query column lists, which only carry non-sensitive operational fields.
package aitools

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/host-yt/caddy-proxy-manager/internal/aichat"
)

// maxResultBytes caps a single tool's serialized output so a tool result cannot
// blow up the model prompt (and provider cost) regardless of row LIMITs.
const maxResultBytes = 16 * 1024

// ErrUnknownTool is returned by Call for a name not in the registry.
var ErrUnknownTool = errors.New("aitools: unknown tool")

// Tool is one read-only capability the model may invoke.
type Tool struct {
	Name        string
	Description string
	Schema      json.RawMessage // JSON-schema for the tool's params
	Exec        func(ctx context.Context, args json.RawMessage) (string, error)
}

// Registry holds the available tools over a single DB handle.
type Registry struct {
	db    *sql.DB
	tools map[string]Tool
	order []string // stable Specs() order
}

// New builds the registry. A nil db yields a registry whose tools return a
// clear "database unavailable" result rather than panicking.
func New(db *sql.DB) *Registry {
	r := &Registry{db: db, tools: map[string]Tool{}}
	for _, t := range r.builtins() {
		r.tools[t.Name] = t
		r.order = append(r.order, t.Name)
	}
	return r
}

// Specs returns the tool declarations to hand to the AI client, in stable order.
func (r *Registry) Specs() []aichat.ToolSpec {
	out := make([]aichat.ToolSpec, 0, len(r.order))
	for _, name := range r.order {
		t := r.tools[name]
		out = append(out, aichat.ToolSpec{Name: t.Name, Description: t.Description, Schema: t.Schema})
	}
	return out
}

// Call executes a tool by name. Unknown names return ErrUnknownTool. The result
// is truncated to maxResultBytes as a final backstop.
func (r *Registry) Call(ctx context.Context, name string, args json.RawMessage) (string, error) {
	t, ok := r.tools[name]
	if !ok {
		return "", fmt.Errorf("%w: %q", ErrUnknownTool, name)
	}
	if r.db == nil {
		return `{"error":"database unavailable"}`, nil
	}
	out, err := t.Exec(ctx, args)
	if err != nil {
		return "", err
	}
	if len(out) > maxResultBytes {
		out = out[:maxResultBytes] + `... [truncated]`
	}
	return out, nil
}

// emptyObjectSchema is the schema for tools that take no parameters.
var emptyObjectSchema = json.RawMessage(`{"type":"object","properties":{},"additionalProperties":false}`)

// clampLimit bounds a caller-supplied limit to a safe range.
func clampLimit(n, def, max int) int {
	if n <= 0 {
		return def
	}
	if n > max {
		return max
	}
	return n
}

// toJSON marshals v compactly; marshal failures surface as a structured error
// string rather than leaking the underlying value.
func toJSON(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("aitools: marshal result: %w", err)
	}
	return string(b), nil
}
