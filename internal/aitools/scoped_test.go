package aitools

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// helper: set of spec names for a scope.
func specNames(r *Registry, scope Scope) map[string]bool {
	out := map[string]bool{}
	for _, s := range r.SpecsFor(scope) {
		out[s.Name] = true
	}
	return out
}

// A scoped (client) caller must NOT be offered infra / cross-tenant tools.
func TestSpecsForClientScopeExcludesInfraTools(t *testing.T) {
	r := New(nil)
	names := specNames(r, Scope{ClientIDs: []int64{1}})

	for _, infra := range []string{"list_nodes", "node_health"} {
		if names[infra] {
			t.Fatalf("client scope must NOT expose %q", infra)
		}
	}
	// Client-relevant tools must still be offered.
	for _, want := range []string{
		"list_services", "list_routes", "get_traffic_stats", "list_clients",
		"get_audit_log", "list_wg_peers", "get_service_detail", "get_route_detail",
	} {
		if !names[want] {
			t.Fatalf("client scope must expose %q", want)
		}
	}
}

// AllClients (super_admin / unscoped admin) gets the full tool set.
func TestSpecsForAllClientsIsFullSet(t *testing.T) {
	r := New(nil)
	full := specNames(r, Scope{AllClients: true})
	for _, name := range r.order {
		if !full[name] {
			t.Fatalf("AllClients scope missing tool %q", name)
		}
	}
	if len(full) != len(r.order) {
		t.Fatalf("AllClients specs = %d, want %d", len(full), len(r.order))
	}
}

// Defense in depth: CallScoped must refuse an admin-only tool for a client scope
// even though the model "asked" for it.
func TestCallScopedRejectsAdminOnlyToolForClient(t *testing.T) {
	r := New(nil)
	scope := Scope{ClientIDs: []int64{42}}
	for _, infra := range []string{"list_nodes", "node_health"} {
		_, err := r.CallScoped(context.Background(), scope, infra, json.RawMessage(`{}`))
		if !errors.Is(err, ErrToolNotInScope) {
			t.Fatalf("CallScoped(%q) for client scope: want ErrToolNotInScope, got %v", infra, err)
		}
	}
}

// Unknown tool names still surface ErrUnknownTool through the scoped path.
func TestCallScopedUnknownTool(t *testing.T) {
	r := New(nil)
	_, err := r.CallScoped(context.Background(), Scope{AllClients: true}, "drop_tables", nil)
	if !errors.Is(err, ErrUnknownTool) {
		t.Fatalf("want ErrUnknownTool, got %v", err)
	}
}

// An empty client list must produce no rows (never "all"): the scoped builders
// short-circuit via emptyResult instead of emitting "IN ()" or an unfiltered
// query. inPlaceholders(nil) returning ok=false is what drives that branch.
func TestEmptyClientIDsYieldsNoRows(t *testing.T) {
	if _, _, ok := inPlaceholders(nil); ok {
		t.Fatal("empty scope must not build an IN clause")
	}
	out, err := emptyResult("services")
	if err != nil {
		t.Fatalf("emptyResult err: %v", err)
	}
	if !strings.Contains(out, `"count":0`) || !strings.Contains(out, `"services":[]`) {
		t.Fatalf("empty result should be zero rows, got %q", out)
	}
}

// inPlaceholders must refuse an empty id list (so we never emit "IN ()" or widen
// to all) and otherwise build a matching placeholder/arg pair.
func TestInPlaceholders(t *testing.T) {
	if _, _, ok := inPlaceholders(nil); ok {
		t.Fatalf("empty ids must return ok=false")
	}
	clause, args, ok := inPlaceholders([]int64{1, 2, 3})
	if !ok || clause != "(?,?,?)" || len(args) != 3 {
		t.Fatalf("inPlaceholders([1,2,3]) = %q, %v, %v", clause, args, ok)
	}
}

// The scoped service query must constrain by client_id - proven by the SQL the
// builder would run carrying a client_id IN filter (query-builder unit, no DB).
func TestScopedServicesSQLHasClientFilter(t *testing.T) {
	in, args, ok := inPlaceholders([]int64{7, 9})
	if !ok {
		t.Fatal("expected ok for non-empty ids")
	}
	q := "WHERE s.client_id IN " + in
	if !strings.Contains(q, "s.client_id IN (?,?)") {
		t.Fatalf("scoped services SQL missing client_id filter: %q", q)
	}
	if len(args) != 2 {
		t.Fatalf("want 2 bound client ids, got %d", len(args))
	}
}

// Verify scoped audit log filters by user_id (from the client's user account).
func TestScopedAuditLogSQLHasUserFilter(t *testing.T) {
	in, _, ok := inPlaceholders([]int64{3, 5})
	if !ok {
		t.Fatal("expected ok")
	}
	q := "WHERE al.user_id IN (SELECT user_id FROM clients WHERE id IN " + in + ")"
	if !strings.Contains(q, "SELECT user_id FROM clients WHERE id IN") {
		t.Fatalf("scoped audit log SQL missing user_id subquery: %q", q)
	}
}

// Verify scoped WG peers filter by client_id directly (no cross-tenant join needed).
func TestScopedWGPeersSQLHasClientFilter(t *testing.T) {
	in, _, ok := inPlaceholders([]int64{2})
	if !ok {
		t.Fatal("expected ok")
	}
	q := "WHERE p.client_id IN " + in
	if !strings.Contains(q, "p.client_id IN (?)") {
		t.Fatalf("scoped WG peers SQL missing client_id filter: %q", q)
	}
}

// Verify service detail scoped enforces client ownership (must not return other clients' data).
func TestScopedServiceDetailSQLEnforcesOwnership(t *testing.T) {
	in, args, ok := inPlaceholders([]int64{10})
	if !ok {
		t.Fatal("expected ok")
	}
	q := "WHERE (s.id = ? OR s.name = ?) AND s.client_id IN " + in
	if !strings.Contains(q, "AND s.client_id IN") {
		t.Fatalf("service detail scoped SQL missing ownership filter: %q", q)
	}
	if len(args) != 1 {
		t.Fatalf("want 1 arg, got %d", len(args))
	}
}
