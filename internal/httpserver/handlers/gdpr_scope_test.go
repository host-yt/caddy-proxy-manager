package handlers

import (
	"context"
	"database/sql"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/host-yt/caddy-proxy-manager/internal/adminscope"
	"github.com/host-yt/caddy-proxy-manager/internal/auth"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
	_ "modernc.org/sqlite"
)

// openGDPRScopeDB builds the minimal schema gdprExportAllowed reads.
func openGDPRScopeDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	for _, s := range []string{
		`CREATE TABLE users (id INTEGER PRIMARY KEY, reseller_id INTEGER, is_restricted INTEGER DEFAULT 0, role TEXT DEFAULT 'admin')`,
		`CREATE TABLE admin_client_scope (admin_user_id INTEGER, client_id INTEGER)`,
		`CREATE TABLE clients (id INTEGER PRIMARY KEY, user_id INTEGER)`,
		// admin user 10 is restricted, scoped to client 100.
		`INSERT INTO users (id, is_restricted) VALUES (10, 1)`,
		`INSERT INTO admin_client_scope (admin_user_id, client_id) VALUES (10, 100)`,
		// target user 1 belongs to client 100 (in scope); target user 2 to client 200 (out of scope).
		`INSERT INTO clients (id, user_id) VALUES (100, 1), (200, 2)`,
	} {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("exec %q: %v", s, err)
		}
	}
	return db
}

// GDPRExport can leak identity/OAuth/audit data cross-tenant; a scoped admin
// must only export a target whose client resolves into their scope.
func TestGDPRExportAllowed(t *testing.T) {
	db := openGDPRScopeDB(t)
	scoped := &AdminHandlers{DB: func() *sql.DB { return db }, AdminScope: adminscope.New(func() *sql.DB { return db }), Logger: slog.Default()}
	noScope := &AdminHandlers{DB: func() *sql.DB { return db }, AdminScope: nil, Logger: slog.Default()}
	ctx := context.Background()

	cases := []struct {
		name   string
		h      *AdminHandlers
		sess   *auth.Session
		target int64
		want   bool
	}{
		{"super_admin any target", scoped, &auth.Session{UserID: 1, Role: "super_admin"}, 2, true},
		{"scoped admin in-scope target", scoped, &auth.Session{UserID: 10, Role: "admin"}, 1, true},
		{"scoped admin out-of-scope target", scoped, &auth.Session{UserID: 10, Role: "admin"}, 2, false},
		{"scoped admin unresolvable target", scoped, &auth.Session{UserID: 10, Role: "admin"}, 999, false},
		{"AdminScope nil, non-super_admin denied", noScope, &auth.Session{UserID: 10, Role: "admin"}, 1, false},
		{"nil session denied", scoped, nil, 1, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.h.gdprExportAllowed(ctx, c.sess, c.target); got != c.want {
				t.Errorf("gdprExportAllowed(%v, target=%d) = %v, want %v", c.sess, c.target, got, c.want)
			}
		})
	}
}

// GDPRDelete is destructive and cross-tenant: only super_admin may call it,
// regardless of whether AdminScope is wired.
func TestGDPRDeleteScope(t *testing.T) {
	cases := []struct {
		name       string
		sess       *auth.Session
		adminScope *adminscope.Service
		wantForbid bool
	}{
		{"super_admin allowed", &auth.Session{UserID: 1, Role: "super_admin"}, &adminscope.Service{}, false},
		{"scoped admin denied", &auth.Session{UserID: 10, Role: "admin"}, &adminscope.Service{}, true},
		{"AdminScope nil non-super_admin denied", &auth.Session{UserID: 10, Role: "admin"}, nil, true},
		{"nil session denied", nil, &adminscope.Service{}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := &AdminHandlers{AdminScope: c.adminScope, DB: func() *sql.DB { return nil }}
			req := httptest.NewRequest(http.MethodPost, "/admin/users/1/gdpr-delete", nil)
			if c.sess != nil {
				req = req.WithContext(middleware.ContextWithSession(req.Context(), c.sess))
			}
			rr := httptest.NewRecorder()
			h.GDPRDelete(rr, req)
			if c.wantForbid && rr.Code != http.StatusForbidden {
				t.Errorf("want 403, got %d", rr.Code)
			}
			if !c.wantForbid && rr.Code == http.StatusForbidden {
				t.Errorf("super_admin must not be scope-denied, got 403")
			}
		})
	}
}
