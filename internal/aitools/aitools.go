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

// ErrToolNotInScope is returned by CallScoped when a caller's scope does not
// include the requested tool. Defense in depth: even if the model is somehow
// offered an out-of-scope tool name, executing it is refused server-side.
var ErrToolNotInScope = errors.New("aitools: tool not allowed for caller scope")

// Scope is the per-caller visibility boundary applied to every tool. AllClients
// (super_admin / unscoped admin) sees the full infra tool set; otherwise the
// caller only sees client-relevant tools filtered to ClientIDs. An empty
// ClientIDs with AllClients=false means "no rows" - never "all".
type Scope struct {
	AllClients bool
	ClientIDs  []int64
}

// allClientsScope is the implicit scope for the legacy Specs()/Call() path.
var allClientsScope = Scope{AllClients: true}

// Tool is one read-only capability the model may invoke. clientRelevant marks a
// tool safe to offer to a scoped (client / scoped-admin) caller; infra tools
// (list_nodes, node_health, global list_clients) are NOT clientRelevant and are
// only offered when scope.AllClients is true. scopedExec runs the tool with a
// scope's client-id filter applied SERVER-SIDE; tools without a scopedExec are
// admin-only and CallScoped refuses them for a non-AllClients scope.
type Tool struct {
	Name           string
	Description    string
	Schema         json.RawMessage // JSON-schema for the tool's params
	Exec           func(ctx context.Context, args json.RawMessage) (string, error)
	clientRelevant bool
	scopedExec     func(ctx context.Context, scope Scope, args json.RawMessage) (string, error)
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

// Specs returns the full (AllClients) tool declarations - the admin path.
func (r *Registry) Specs() []aichat.ToolSpec {
	return r.SpecsFor(allClientsScope)
}

// SpecsFor returns the tool declarations visible to a given scope. AllClients
// gets every tool; a scoped caller (client / scoped admin) gets ONLY the
// client-relevant tools so infra and other-tenant tools are never even offered.
func (r *Registry) SpecsFor(scope Scope) []aichat.ToolSpec {
	out := make([]aichat.ToolSpec, 0, len(r.order))
	for _, name := range r.order {
		t := r.tools[name]
		if !scope.AllClients && !t.clientRelevant {
			continue
		}
		out = append(out, aichat.ToolSpec{Name: t.Name, Description: t.Description, Schema: t.Schema})
	}
	return out
}

// Call executes a tool with the full (AllClients) scope - the admin path.
func (r *Registry) Call(ctx context.Context, name string, args json.RawMessage) (string, error) {
	return r.CallScoped(ctx, allClientsScope, name, args)
}

// CallScoped executes a tool by name applying the caller's scope SERVER-SIDE.
// It refuses any tool not in SpecsFor(scope) (defense in depth) and, for a
// non-AllClients scope, runs the tool's scopedExec so the client-id WHERE
// filter is enforced from the scope - never from model-supplied args. The
// result is truncated to maxResultBytes as a final backstop.
func (r *Registry) CallScoped(ctx context.Context, scope Scope, name string, args json.RawMessage) (string, error) {
	t, ok := r.tools[name]
	if !ok {
		return "", fmt.Errorf("%w: %q", ErrUnknownTool, name)
	}
	if !scope.AllClients && !t.clientRelevant {
		return "", fmt.Errorf("%w: %q", ErrToolNotInScope, name)
	}
	if r.db == nil {
		return `{"error":"database unavailable"}`, nil
	}
	var (
		out string
		err error
	)
	if scope.AllClients {
		out, err = t.Exec(ctx, args)
	} else {
		// scopedExec must exist for any clientRelevant tool; its absence is a
		// programming error, so refuse rather than silently run the unscoped path.
		if t.scopedExec == nil {
			return "", fmt.Errorf("%w: %q", ErrToolNotInScope, name)
		}
		out, err = t.scopedExec(ctx, scope, args)
	}
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
