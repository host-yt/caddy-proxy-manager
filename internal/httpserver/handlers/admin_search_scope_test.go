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

// openSearchScopeDB builds the schema searchScope's ScopeFilter call reads.
func openSearchScopeDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	for _, s := range []string{
		`CREATE TABLE users (id INTEGER PRIMARY KEY, reseller_id INTEGER, is_restricted INTEGER DEFAULT 0, role TEXT DEFAULT 'admin')`,
		`CREATE TABLE admin_client_scope (admin_user_id INTEGER, client_id INTEGER)`,
		`INSERT INTO users (id, is_restricted) VALUES (30, 1)`,
		`INSERT INTO admin_client_scope (admin_user_id, client_id) VALUES (30, 5), (30, 6)`,
	} {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("exec %q: %v", s, err)
		}
	}
	return db
}

// AdminSearch spans multiple tenants' domains/backends/nodes; searchScope
// must resolve to a client filter for scoped admins and hide global-infra
// rows (nodes/webhooks/alerts/plans/api_keys) from them entirely.
func TestAdminSearchScope(t *testing.T) {
	db := openSearchScopeDB(t)
	scoped := &AdminHandlers{DB: func() *sql.DB { return db }, AdminScope: adminscope.New(func() *sql.DB { return db }), Logger: slog.Default()}
	noScope := &AdminHandlers{DB: func() *sql.DB { return db }, AdminScope: nil, Logger: slog.Default()}
	ctx := context.Background()

	t.Run("super_admin unfiltered", func(t *testing.T) {
		allowed, isScoped := scoped.searchScope(ctx, &auth.Session{UserID: 1, Role: "super_admin"})
		if isScoped || allowed != nil {
			t.Errorf("super_admin should be unfiltered, got scoped=%v allowed=%v", isScoped, allowed)
		}
	})

	t.Run("scoped admin filtered to own clients", func(t *testing.T) {
		allowed, isScoped := scoped.searchScope(ctx, &auth.Session{UserID: 30, Role: "admin"})
		if !isScoped || !allowed[5] || !allowed[6] || allowed[7] {
			t.Errorf("scoped admin should be limited to {5,6}, got scoped=%v allowed=%v", isScoped, allowed)
		}
	})

	t.Run("AdminScope nil non-super_admin denied", func(t *testing.T) {
		allowed, isScoped := noScope.searchScope(ctx, &auth.Session{UserID: 30, Role: "admin"})
		if !isScoped || len(allowed) != 0 {
			t.Errorf("nil AdminScope should fail closed (empty), got scoped=%v allowed=%v", isScoped, allowed)
		}
	})

	t.Run("nil session denied", func(t *testing.T) {
		allowed, isScoped := scoped.searchScope(ctx, nil)
		if !isScoped || len(allowed) != 0 {
			t.Errorf("nil session should fail closed (empty), got scoped=%v allowed=%v", isScoped, allowed)
		}
	})
}
