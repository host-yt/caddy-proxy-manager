package handlers

import (
	"context"
	"database/sql"
	"testing"

	"github.com/host-yt/caddy-proxy-manager/internal/adminscope"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
	_ "modernc.org/sqlite"
)

// openAPIScopeDB builds the schema adminscope.ScopeFilter reads: users with
// reseller_id, clients with reseller_id, and admin_client_scope.
func openAPIScopeDB(t *testing.T) func() *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	for _, s := range []string{
		`CREATE TABLE users (id INTEGER PRIMARY KEY, reseller_id INTEGER, is_restricted INTEGER DEFAULT 0)`,
		`CREATE TABLE clients (id INTEGER PRIMARY KEY, reseller_id INTEGER)`,
		`CREATE TABLE admin_client_scope (admin_user_id INTEGER, client_id INTEGER)`,
		`CREATE TABLE resellers (id INTEGER PRIMARY KEY, status TEXT)`,
		`INSERT INTO resellers (id, status) VALUES (7, 'active'), (9, 'active')`,
		// user 1 = reseller-admin (reseller 7); user 3 = bare admin.
		`INSERT INTO users (id, reseller_id) VALUES (1, 7), (3, NULL)`,
		`INSERT INTO clients (id, reseller_id) VALUES (100, 7), (101, 7), (200, 9), (300, NULL)`,
	} {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("exec %q: %v", s, err)
		}
	}
	return func() *sql.DB { return db }
}

func TestAPIScopeResellerAdmin(t *testing.T) {
	dbf := openAPIScopeDB(t)
	h := &APIHandlers{DB: dbf, AdminScope: adminscope.New(dbf)}
	ctx := context.Background()

	// Reseller-admin (user 1) is scoped to reseller 7's clients only.
	ids, all, err := h.apiScope(ctx, &middleware.APICaller{UserID: 1, Role: "admin"})
	if err != nil || all {
		t.Fatalf("reseller-admin should be scoped: all=%v err=%v", all, err)
	}
	got := map[int64]bool{}
	for _, id := range ids {
		got[id] = true
	}
	if !got[100] || !got[101] || got[200] || got[300] {
		t.Fatalf("wrong reseller scope: %v", ids)
	}
	if !h.apiAllowClient(ctx, &middleware.APICaller{UserID: 1, Role: "admin"}, 100) {
		t.Fatal("owned client 100 must be allowed")
	}
	if h.apiAllowClient(ctx, &middleware.APICaller{UserID: 1, Role: "admin"}, 200) {
		t.Fatal("foreign client 200 must be denied")
	}
}

func TestAPIScopeBareAdminAndSuper(t *testing.T) {
	dbf := openAPIScopeDB(t)
	h := &APIHandlers{DB: dbf, AdminScope: adminscope.New(dbf)}
	ctx := context.Background()

	// Bare admin (user 3, no reseller, no scope rows) is unrestricted.
	if _, all, err := h.apiScope(ctx, &middleware.APICaller{UserID: 3, Role: "admin"}); err != nil || !all {
		t.Fatalf("bare admin should be unrestricted: all=%v err=%v", all, err)
	}
	// super_admin bypasses scope resolution entirely.
	if _, all, err := h.apiScope(ctx, &middleware.APICaller{UserID: 1, Role: "super_admin"}); err != nil || !all {
		t.Fatalf("super_admin should be unrestricted: all=%v err=%v", all, err)
	}
	// Any client allowed for an unrestricted caller.
	if !h.apiAllowClient(ctx, &middleware.APICaller{UserID: 3, Role: "admin"}, 200) {
		t.Fatal("bare admin must reach any client")
	}
}
