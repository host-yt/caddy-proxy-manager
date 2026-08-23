package handlers

import (
	"context"
	"database/sql"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	_ "modernc.org/sqlite"

	"github.com/host-yt/caddy-proxy-manager/internal/security"
)

// openRBACTestDB builds the tables the RBAC check reads: one route on node 1
// with a /admin/* rule requiring the "admin" role, and one active cert holding
// that role.
func openRBACTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	stmts := []string{
		`CREATE TABLE routes (id INTEGER PRIMARY KEY, caddy_node_id INTEGER, mtls_ca_id INTEGER)`,
		`CREATE TABLE route_node_assignments (route_id INTEGER, node_id INTEGER)`,
		`CREATE TABLE mtls_roles (id INTEGER PRIMARY KEY, name TEXT)`,
		`CREATE TABLE mtls_path_rules (id INTEGER PRIMARY KEY, route_id INTEGER, path_pattern TEXT, required_role_id INTEGER)`,
		`CREATE TABLE mtls_issued_certs (id INTEGER PRIMARY KEY, ca_id INTEGER, subject TEXT, status TEXT)`,
		`CREATE TABLE mtls_cert_roles (cert_id INTEGER, role_id INTEGER)`,
		`INSERT INTO routes (id, caddy_node_id, mtls_ca_id) VALUES (7, 1, 3)`,
		`INSERT INTO mtls_roles (id, name) VALUES (1, 'admin')`,
		`INSERT INTO mtls_path_rules (id, route_id, path_pattern, required_role_id) VALUES (1, 7, '/admin/*', 1)`,
		`INSERT INTO mtls_issued_certs (id, ca_id, subject, status) VALUES (5, 3, 'CN=ops', 'active')`,
		`INSERT INTO mtls_cert_roles (cert_id, role_id) VALUES (5, 1)`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("schema %q: %v", s, err)
		}
	}
	return db
}

func rbacRequest(t *testing.T, h *AdminHandlers, routeID string, headers map[string]string) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/internal/mtls-rbac/"+routeID, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("route_id", routeID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rec := httptest.NewRecorder()
	h.MTLSRBACCheck(rec, req)
	return rec.Code
}

// TestMTLSRBACCheck_RequiresNodeToken is the MTLS-01 regression: reaching the
// endpoint from inside the mesh is no longer enough - a caller must present the
// (node, route) token the panel wrote into that node's Caddy config.
func TestMTLSRBACCheck_RequiresNodeToken(t *testing.T) {
	db := openRBACTestDB(t)
	key := []byte("0123456789abcdef0123456789abcdef")
	h := &AdminHandlers{DB: func() *sql.DB { return db }, Logger: slog.Default(), MTLSRBACKey: key}

	good := security.MTLSRBACToken(key, 1, 7)
	cases := []struct {
		name    string
		route   string
		headers map[string]string
		want    int
	}{
		{
			name:  "valid token and role",
			route: "7",
			headers: map[string]string{
				"X-Mtls-Subject":             "CN=ops",
				"X-Forwarded-Uri":            "/admin/panel",
				security.MTLSRBACHeaderNode:  "1",
				security.MTLSRBACHeaderToken: good,
				"X-Forwarded-Method":         "GET",
			},
			want: http.StatusOK,
		},
		{
			name:    "no token at all",
			route:   "7",
			headers: map[string]string{"X-Mtls-Subject": "CN=ops", "X-Forwarded-Uri": "/admin/panel"},
			want:    http.StatusForbidden,
		},
		{
			name:  "token minted for another route",
			route: "7",
			headers: map[string]string{
				"X-Mtls-Subject":             "CN=ops",
				"X-Forwarded-Uri":            "/admin/panel",
				security.MTLSRBACHeaderNode:  "1",
				security.MTLSRBACHeaderToken: security.MTLSRBACToken(key, 1, 8),
			},
			want: http.StatusForbidden,
		},
		{
			name:  "token from a node that does not serve the route",
			route: "7",
			headers: map[string]string{
				"X-Mtls-Subject":             "CN=ops",
				"X-Forwarded-Uri":            "/admin/panel",
				security.MTLSRBACHeaderNode:  "2",
				security.MTLSRBACHeaderToken: security.MTLSRBACToken(key, 2, 7),
			},
			want: http.StatusForbidden,
		},
		{
			name:  "valid token but subject lacks the role",
			route: "7",
			headers: map[string]string{
				"X-Mtls-Subject":             "CN=intern",
				"X-Forwarded-Uri":            "/admin/panel",
				security.MTLSRBACHeaderNode:  "1",
				security.MTLSRBACHeaderToken: good,
			},
			want: http.StatusForbidden,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := rbacRequest(t, h, c.route, c.headers); got != c.want {
				t.Errorf("status = %d, want %d", got, c.want)
			}
		})
	}
}

// TestMTLSRBACCheck_FanoutPeerAccepted proves an active-active peer that serves
// the route via route_node_assignments can still run checks.
func TestMTLSRBACCheck_FanoutPeerAccepted(t *testing.T) {
	db := openRBACTestDB(t)
	if _, err := db.Exec(`INSERT INTO route_node_assignments (route_id, node_id) VALUES (7, 2)`); err != nil {
		t.Fatalf("assign: %v", err)
	}
	key := []byte("0123456789abcdef0123456789abcdef")
	h := &AdminHandlers{DB: func() *sql.DB { return db }, Logger: slog.Default(), MTLSRBACKey: key}
	code := rbacRequest(t, h, "7", map[string]string{
		"X-Mtls-Subject":             "CN=ops",
		"X-Forwarded-Uri":            "/admin/panel",
		security.MTLSRBACHeaderNode:  "2",
		security.MTLSRBACHeaderToken: security.MTLSRBACToken(key, 2, 7),
	})
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
}

// TestMTLSRBACCheck_AllowUnsignedEscapeHatch keeps the documented upgrade-window
// behaviour working (and only that).
func TestMTLSRBACCheck_AllowUnsignedEscapeHatch(t *testing.T) {
	db := openRBACTestDB(t)
	h := &AdminHandlers{
		DB: func() *sql.DB { return db }, Logger: slog.Default(),
		MTLSRBACKey: []byte("0123456789abcdef0123456789abcdef"), MTLSRBACAllowUnsigned: true,
	}
	code := rbacRequest(t, h, "7", map[string]string{
		"X-Mtls-Subject":  "CN=ops",
		"X-Forwarded-Uri": "/admin/panel",
	})
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200 with MTLS_RBAC_ALLOW_UNSIGNED", code)
	}
}
