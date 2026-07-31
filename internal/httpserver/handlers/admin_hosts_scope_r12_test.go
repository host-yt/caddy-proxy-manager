package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"testing"

	"github.com/host-yt/caddy-proxy-manager/internal/auth"
	"github.com/host-yt/caddy-proxy-manager/internal/caddyapi"
)

// hostsScopeDB extends the limited-admin fixture with the route/service/node
// rows the host guards read.
func hostsScopeDB(t *testing.T) *sql.DB {
	t.Helper()
	db := openLimitedAdminDB(t)
	for _, s := range []string{
		`CREATE TABLE services (id INTEGER PRIMARY KEY, client_id INTEGER, plan_id INTEGER, node_group_id INTEGER)`,
		`CREATE TABLE caddy_nodes (id INTEGER PRIMARY KEY, name TEXT, node_group_id INTEGER,
		   approved_at TEXT, is_enabled INTEGER DEFAULT 1)`,
		`CREATE TABLE routes (id INTEGER PRIMARY KEY, service_id INTEGER, caddy_node_id INTEGER,
		   domain TEXT, path_prefix TEXT, aliases TEXT, aliases_verified TEXT,
		   status TEXT DEFAULT 'active',
		   custom_config TEXT, domain_verified INTEGER DEFAULT 0, verify_token TEXT,
		   ssl_enabled INTEGER DEFAULT 1, updated_at TEXT)`,
		// Client 70 (reseller 7, the restricted admin's tenant) and client 90 (reseller 9).
		`INSERT INTO services (id, client_id, plan_id, node_group_id) VALUES (1, 70, 7, 1), (2, 90, 9, 2)`,
		`INSERT INTO caddy_nodes (id, name, node_group_id, approved_at, is_enabled)
		   VALUES (1, 'own', 1, '2026-01-01', 1), (2, 'foreign', 2, '2026-01-01', 1),
		          (3, 'pending', 1, NULL, 1), (4, 'disabled', 1, '2026-01-01', 0)`,
		`INSERT INTO routes (id, service_id, caddy_node_id, domain, path_prefix, status, domain_verified)
		   VALUES (10, 1, 1, 'owned.example', '', 'active', 1)`,
		`INSERT INTO routes (id, service_id, caddy_node_id, domain, path_prefix, status, domain_verified)
		   VALUES (11, 2, 2, 'victim.example', '', 'active', 1)`,
	} {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("exec %q: %v", s, err)
		}
	}
	return db
}

// FINDING 1 (r12): a route owner must not be able to smuggle a Caddy handler
// that proxies into the node's unauthenticated local admin API on :2019.
func TestSanitizeCustomConfigRejectsCaddyAdminProxy(t *testing.T) {
	bad := []string{
		// The exploit: reverse_proxy straight at the local admin endpoint.
		`[{"handler":"reverse_proxy","upstreams":[{"dial":"127.0.0.1:2019"}],
		   "headers":{"request":{"set":{"Host":["localhost:2019"]}}}}]`,
		// Same capability hidden one level down.
		`[{"handler":"subroute","routes":[{"handle":[{"handler":"reverse_proxy",
		   "upstreams":[{"dial":"127.0.0.1:2019"}]}]}]}]`,
		// Nested inside an allow-listed handler.
		`[{"handler":"headers","response":{"handle":[{"handler":"reverse_proxy"}]}}]`,
		// Other denied capabilities: auth, filesystem, execution, routing.
		`[{"handler":"authentication","providers":{}}]`,
		`[{"handler":"file_server","root":"/"}]`,
		`[{"handler":"exec","command":"/bin/sh"}]`,
		`[{"handler":"map","source":"{http.request.host}"}]`,
		// Allow-listed handler, denied property (filesystem reach).
		`[{"handler":"templates","file_root":"/etc"}]`,
		// vars must stay scalar - an object could carry a chain.
		`[{"handler":"vars","x":{"handler":"reverse_proxy"}}]`,
		// Missing handler name.
		`[{"upstreams":[{"dial":"127.0.0.1:2019"}]}]`,
	}
	for _, raw := range bad {
		if out, err := sanitizeCustomConfig(raw); err == nil {
			t.Errorf("accepted forbidden custom config %s -> %s", raw, out)
		}
	}

	good := []string{
		`[{"handler":"headers","response":{"set":{"X-Foo":["bar"]}}}]`,
		`[{"handler":"encode","encodings":{"gzip":{}},"prefer":["gzip"]}]`,
		`[{"handler":"rewrite","strip_path_prefix":"/api"}]`,
		`[{"handler":"vars","tier":"gold"}]`,
		`[{"handler":"request_body","max_size":1024}]`,
	}
	for _, raw := range good {
		if _, err := sanitizeCustomConfig(raw); err != nil {
			t.Errorf("rejected benign custom config %s: %v", raw, err)
		}
	}
}

// FINDING 1 (r12): even a syntactically valid chain is platform-admin only -
// a scoped admin owning the route may not change it, and what survives the
// guard can never emit an upstream pointing at the Caddy admin API.
func TestCustomConfigScopeEndToEnd(t *testing.T) {
	db := hostsScopeDB(t)
	h := limitedAdminHandlers(db)
	ctx := context.Background()

	exploit := `[{"handler":"reverse_proxy","upstreams":[{"dial":"127.0.0.1:2019"}]}]`
	benign := `[{"handler":"headers","response":{"set":{"X-Foo":["bar"]}}}]`

	for _, sess := range []*auth.Session{restrictedSess, resellerSess} {
		if _, err := h.resolveCustomConfig(ctx, sess, 10, benign); err == nil {
			t.Errorf("scoped admin (user %d) was allowed to set custom handlers", sess.UserID)
		}
	}
	// Platform admin keeps the capability.
	if got, err := h.resolveCustomConfig(ctx, platformSess, 10, benign); err != nil || got == "" {
		t.Errorf("platform admin custom config = (%q,%v), want a stored chain", got, err)
	}
	// Unchanged submissions from a scoped admin pass through untouched.
	if got, err := h.resolveCustomConfig(ctx, restrictedSess, 10, ""); err != nil || got != "" {
		t.Errorf("no-op edit = (%q,%v), want ('',nil)", got, err)
	}

	// End-to-end: the exploit never survives validation, so it never reaches
	// the emitted Caddy config.
	if _, err := sanitizeCustomConfig(exploit); err == nil {
		t.Fatal("exploit chain passed sanitisation")
	}
	if _, err := h.resolveCustomConfig(ctx, restrictedSess, 10, exploit); err == nil {
		t.Fatal("restricted admin stored the exploit chain")
	}
	// A legacy chain the allow-list now rejects must not lock a scoped admin out
	// of unrelated edits, but it is quarantined rather than carried forward
	// (r13 FINDING 2: the old passthrough kept the payload executable).
	if _, err := db.Exec(`UPDATE routes SET custom_config=? WHERE id=10`, exploit); err != nil {
		t.Fatalf("seed legacy: %v", err)
	}
	if got, err := h.resolveCustomConfig(ctx, restrictedSess, 10, exploit); err != nil || got != "" {
		t.Errorf("unchanged legacy chain = (%q,%v), want quarantine ('',nil)", got, err)
	}
	if _, err := db.Exec(`UPDATE routes SET custom_config=NULL WHERE id=10`); err != nil {
		t.Fatalf("clear legacy: %v", err)
	}
	var stored sql.NullString
	if err := db.QueryRow(`SELECT custom_config FROM routes WHERE id=10`).Scan(&stored); err != nil {
		t.Fatalf("read back: %v", err)
	}
	built, _ := json.Marshal(caddyapi.BuildRoute(caddyapi.Route{
		Hosts: []string{"owned.example"}, UpstreamIP: "10.0.0.5", UpstreamPort: 80,
		CustomHandlers: stored.String,
	}))
	for _, needle := range []string{"2019", "reverse_proxy\",\"upstreams\":[{\"dial\":\"127.0.0.1"} {
		if strings.Contains(string(built), needle) {
			t.Errorf("emitted config reaches the Caddy admin API: %s", built)
		}
	}
}

// FINDING 2 (r12): every non-platform caller must re-prove DNS ownership after
// a matcher change - inheriting domain_verified is the takeover.
func TestVerificationResetRequired(t *testing.T) {
	h := limitedAdminHandlers(hostsScopeDB(t))
	ctx := context.Background()

	for _, sess := range []*auth.Session{restrictedSess, resellerSess} {
		if !h.verificationResetRequired(ctx, sess, true) {
			t.Errorf("user %d kept domain_verified across a matcher change", sess.UserID)
		}
		if h.verificationResetRequired(ctx, sess, false) {
			t.Errorf("user %d reset verification without a matcher change", sess.UserID)
		}
	}
	if h.verificationResetRequired(ctx, platformSess, true) {
		t.Error("platform admin must stay trusted (routes.Create lands theirs verified)")
	}
	if !h.verificationResetRequired(ctx, nil, true) {
		t.Error("no session must fail closed")
	}
}

// FINDING 3 (r12): a scoped admin may only move an owned route inside the node
// group its service is placed in; anything else is another tenant's iron.
func TestMoveRouteToNodeBoundary(t *testing.T) {
	db := hostsScopeDB(t)
	h := limitedAdminHandlers(db)
	ctx := context.Background()

	// Foreign group, unapproved and disabled nodes are all refused.
	for _, dest := range []int64{2, 3, 4, 999} {
		if _, err := h.moveRouteToNode(ctx, restrictedSess, 10, dest); err == nil {
			t.Errorf("restricted admin moved route onto node %d", dest)
		}
	}
	for _, dest := range []int64{2, 3, 4} {
		if _, err := h.moveRouteToNode(ctx, resellerSess, 10, dest); err == nil {
			t.Errorf("reseller admin moved route onto node %d", dest)
		}
	}
	var node int64
	if err := db.QueryRow(`SELECT caddy_node_id FROM routes WHERE id=10`).Scan(&node); err != nil {
		t.Fatalf("read node: %v", err)
	}
	if node != 1 {
		t.Fatalf("route moved despite refusal: node=%d", node)
	}
	// Platform admin may still place across groups.
	if old, err := h.moveRouteToNode(ctx, platformSess, 10, 2); err != nil || old != 1 {
		t.Fatalf("platform move = (%d,%v), want (1,nil)", old, err)
	}
	if err := db.QueryRow(`SELECT caddy_node_id FROM routes WHERE id=10`).Scan(&node); err != nil || node != 2 {
		t.Fatalf("platform move not persisted: node=%d err=%v", node, err)
	}
}

// FINDING 2 (r12): a hostname already served by another tenant must be
// refused, whatever path the mover picks.
func TestDomainCollisionCrossTenant(t *testing.T) {
	db := hostsScopeDB(t)
	ctx := context.Background()

	clash, err := domainCollision(ctx, db, "victim.example", 10)
	if err != nil {
		t.Fatalf("collision check: %v", err)
	}
	if !clash {
		t.Error("stealing another tenant's hostname was allowed")
	}
	// Alias of a foreign route counts too.
	if _, err := db.Exec(`UPDATE routes SET aliases='alias.example' WHERE id=11`); err != nil {
		t.Fatalf("set alias: %v", err)
	}
	if clash, err = domainCollision(ctx, db, "alias.example", 10); err != nil || !clash {
		t.Errorf("alias collision = (%v,%v), want (true,nil)", clash, err)
	}
	// Same tenant keeps path-splitting on its own hostname.
	if _, err := db.Exec(
		`INSERT INTO routes (id, service_id, caddy_node_id, domain, path_prefix, status)
		 VALUES (12, 1, 1, 'shared.example', '/a', 'active')`); err != nil {
		t.Fatalf("insert sibling: %v", err)
	}
	if clash, err = domainCollision(ctx, db, "shared.example", 10); err != nil || clash {
		t.Errorf("same-tenant split = (%v,%v), want (false,nil)", clash, err)
	}
	// Free hostname passes.
	if clash, err = domainCollision(ctx, db, "fresh.example", 10); err != nil || clash {
		t.Errorf("free hostname = (%v,%v), want (false,nil)", clash, err)
	}
}
