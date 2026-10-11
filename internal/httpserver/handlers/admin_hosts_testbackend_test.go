package handlers

import (
	"context"
	"database/sql"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/host-yt/caddy-proxy-manager/internal/auth"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
)

// HostsTestBackend must apply the full infra deny set (not just loopback /
// link-local), so a backend pointed at a managed node is refused before dialing.
func TestHostsTestBackendRefusesInfraTargets(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	for _, s := range []string{
		`CREATE TABLE services (id INTEGER PRIMARY KEY, backend_ip TEXT)`,
		`CREATE TABLE routes (id INTEGER PRIMARY KEY, service_id INTEGER, backend_ip_override TEXT, upstream_port INTEGER)`,
		`CREATE TABLE caddy_nodes (public_ip TEXT, wg_ip TEXT, api_url TEXT, public_hostname TEXT, tunnel_subnet TEXT)`,
		"CREATE TABLE settings (`key` TEXT, value TEXT)",
		`INSERT INTO caddy_nodes (public_ip) VALUES ('203.0.113.5')`,
		`INSERT INTO services (id, backend_ip) VALUES (1, '203.0.113.5'), (2, '127.0.0.1')`,
		`INSERT INTO routes (id, service_id, upstream_port) VALUES (10, 1, 80), (20, 2, 80)`,
	} {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("exec %q: %v", s, err)
		}
	}
	h := &AdminHandlers{DB: func() *sql.DB { return db }, Logger: slog.Default()}
	super := &auth.Session{UserID: 1, Role: "super_admin"}
	for _, id := range []string{"10", "20"} {
		req := httptest.NewRequest(http.MethodPost, "/admin/hosts/"+id+"/test-backend", nil)
		req = req.WithContext(middleware.ContextWithSession(req.Context(), super))
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", id)
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
		rr := httptest.NewRecorder()
		h.HostsTestBackend(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Errorf("route %s: want 403, got %d %s", id, rr.Code, rr.Body.String())
		}
	}
}
