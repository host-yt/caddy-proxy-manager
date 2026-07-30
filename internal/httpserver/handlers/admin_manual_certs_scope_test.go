package handlers

import (
	"context"
	"database/sql"
	"log/slog"
	"testing"

	"github.com/host-yt/caddy-proxy-manager/internal/adminscope"
	"github.com/host-yt/caddy-proxy-manager/internal/auth"
	_ "modernc.org/sqlite"
)

// openManualCertScopeDB builds the schema scopeCheckRoute (via CanAccessRoute)
// reads: admin_client_scope -> services.client_id -> routes.service_id.
func openManualCertScopeDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	for _, s := range []string{
		`CREATE TABLE users (id INTEGER PRIMARY KEY, reseller_id INTEGER, is_restricted INTEGER DEFAULT 0, role TEXT DEFAULT 'admin')`,
		`CREATE TABLE admin_client_scope (admin_user_id INTEGER, client_id INTEGER)`,
		`CREATE TABLE clients (id INTEGER PRIMARY KEY)`,
		`CREATE TABLE services (id INTEGER PRIMARY KEY, client_id INTEGER)`,
		`CREATE TABLE routes (id INTEGER PRIMARY KEY, service_id INTEGER)`,
		// admin 20 is restricted, scoped to client 1 only.
		`INSERT INTO users (id, is_restricted) VALUES (20, 1)`,
		`INSERT INTO admin_client_scope (admin_user_id, client_id) VALUES (20, 1)`,
		`INSERT INTO clients (id) VALUES (1), (2)`,
		// service 1 -> client 1 (in scope); service 2 -> client 2 (out of scope).
		`INSERT INTO services (id, client_id) VALUES (1, 1), (2, 2)`,
		// route 11 -> service 1 (in scope); route 22 -> service 2 (out of scope).
		`INSERT INTO routes (id, service_id) VALUES (11, 1), (22, 2)`,
	} {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("exec %q: %v", s, err)
		}
	}
	return db
}

// Manual certs push cert material + backend routing to serving nodes; every
// ManualCerts* handler must gate on the linked route's scope.
func TestManualCertRouteAllowed(t *testing.T) {
	db := openManualCertScopeDB(t)
	scoped := &AdminHandlers{DB: func() *sql.DB { return db }, AdminScope: adminscope.New(func() *sql.DB { return db }), Logger: slog.Default()}
	noScope := &AdminHandlers{DB: func() *sql.DB { return db }, AdminScope: nil, Logger: slog.Default()}
	ctx := context.Background()

	cases := []struct {
		name    string
		h       *AdminHandlers
		sess    *auth.Session
		routeID int64
		want    bool
	}{
		{"super_admin any route", scoped, &auth.Session{UserID: 1, Role: "super_admin"}, 22, true},
		{"super_admin unlinked cert", scoped, &auth.Session{UserID: 1, Role: "super_admin"}, 0, true},
		{"scoped admin in-scope route", scoped, &auth.Session{UserID: 20, Role: "admin"}, 11, true},
		{"scoped admin out-of-scope route", scoped, &auth.Session{UserID: 20, Role: "admin"}, 22, false},
		{"scoped admin unlinked cert denied", scoped, &auth.Session{UserID: 20, Role: "admin"}, 0, false},
		{"AdminScope nil non-super_admin denied", noScope, &auth.Session{UserID: 20, Role: "admin"}, 11, false},
		{"nil session denied", scoped, nil, 11, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.h.manualCertRouteAllowed(ctx, c.sess, c.routeID); got != c.want {
				t.Errorf("manualCertRouteAllowed(route=%d) = %v, want %v", c.routeID, got, c.want)
			}
		})
	}
}
