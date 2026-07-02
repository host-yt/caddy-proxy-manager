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

// openPlanScopeDB builds the schema planScope/planManageable/planAccessible read.
func openPlanScopeDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	for _, s := range []string{
		`CREATE TABLE users (id INTEGER PRIMARY KEY, reseller_id INTEGER, is_restricted INTEGER DEFAULT 0, role TEXT DEFAULT 'admin')`,
		`CREATE TABLE admin_client_scope (admin_user_id INTEGER, client_id INTEGER)`,
		`CREATE TABLE plans (id INTEGER PRIMARY KEY, reseller_id INTEGER)`,
		`INSERT INTO users (id, reseller_id) VALUES (3, NULL)`, // bare platform admin
		`INSERT INTO plans (id, reseller_id) VALUES (1, NULL), (7, 7), (9, 9)`,
	} {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("exec %q: %v", s, err)
		}
	}
	return db
}

func TestPlanScopeResellerAdmin(t *testing.T) {
	db := openPlanScopeDB(t)
	h := &AdminHandlers{
		DB:         func() *sql.DB { return db },
		AdminScope: adminscope.New(func() *sql.DB { return db }),
		Logger:     slog.Default(),
	}
	ctx := context.Background()
	reseller := &auth.Session{UserID: 1, Role: "admin", ResellerID: 7}

	if rid, all, ok := h.planScope(ctx, reseller); !ok || all || rid != 7 {
		t.Fatalf("reseller planScope = (%d,%v,%v)", rid, all, ok)
	}
	// Manage only own reseller plan (7); not global (1) nor foreign (9).
	if !h.planManageable(ctx, reseller, 7) {
		t.Error("must manage own reseller plan 7")
	}
	if h.planManageable(ctx, reseller, 1) {
		t.Error("must NOT manage global plan 1")
	}
	if h.planManageable(ctx, reseller, 9) {
		t.Error("must NOT manage foreign reseller plan 9")
	}
	// Accessible for service creation: global (1) + own (7), not foreign (9).
	if !h.planAccessible(ctx, reseller, 1) || !h.planAccessible(ctx, reseller, 7) {
		t.Error("global and own plans must be accessible")
	}
	if h.planAccessible(ctx, reseller, 9) {
		t.Error("foreign reseller plan must not be accessible")
	}
}

func TestPlanScopePlatformAdmin(t *testing.T) {
	db := openPlanScopeDB(t)
	h := &AdminHandlers{
		DB:         func() *sql.DB { return db },
		AdminScope: adminscope.New(func() *sql.DB { return db }),
		Logger:     slog.Default(),
	}
	ctx := context.Background()
	bare := &auth.Session{UserID: 3, Role: "admin"} // no reseller, no scope rows

	if rid, all, ok := h.planScope(ctx, bare); !ok || !all || rid != 0 {
		t.Fatalf("bare admin planScope = (%d,%v,%v), want (0,true,true)", rid, all, ok)
	}
	// Platform admin manages every plan incl. global and any reseller's.
	for _, id := range []int64{1, 7, 9} {
		if !h.planManageable(ctx, bare, id) {
			t.Errorf("platform admin must manage plan %d", id)
		}
	}
}
