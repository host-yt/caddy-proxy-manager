package adminscope

import (
	"context"
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"
)

// openResellerDB builds a hermetic schema covering ScopeFilter's reseller path:
// users.reseller_id + clients.reseller_id, plus admin_client_scope so we can
// prove ownership takes precedence over manual assignment.
func openResellerDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	stmts := []string{
		`CREATE TABLE users (id INTEGER PRIMARY KEY, reseller_id INTEGER)`,
		`CREATE TABLE clients (id INTEGER PRIMARY KEY, reseller_id INTEGER)`,
		`CREATE TABLE admin_client_scope (admin_user_id INTEGER, client_id INTEGER)`,
		// user 1 = reseller-admin of reseller 7; user 2 = plain scoped admin.
		`INSERT INTO users (id, reseller_id) VALUES (1, 7), (2, NULL)`,
		// reseller 7 owns clients 100,101; client 200 belongs to another reseller;
		// client 300 is platform-direct (reseller_id NULL).
		`INSERT INTO clients (id, reseller_id) VALUES (100, 7), (101, 7), (200, 9), (300, NULL)`,
		// A stray manual assignment to a foreign client must NOT widen the
		// reseller-admin's ownership-derived scope.
		`INSERT INTO admin_client_scope (admin_user_id, client_id) VALUES (1, 200), (2, 300)`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("exec %q: %v", s, err)
		}
	}
	return db
}

// TestScopeFilterResellerAdmin: a reseller-admin's scope is exactly its
// reseller's owned clients, never "all", and never widened by a manual
// admin_client_scope row pointing at a foreign client.
func TestScopeFilterResellerAdmin(t *testing.T) {
	db := openResellerDB(t)
	svc := New(func() *sql.DB { return db })
	ctx := context.Background()

	ids, all, err := svc.ScopeFilter(ctx, 1)
	if err != nil {
		t.Fatalf("ScopeFilter(reseller-admin): %v", err)
	}
	if all {
		t.Fatal("reseller-admin must never get all=true (platform-wide visibility)")
	}
	if got := idSet(ids); len(got) != 2 || !got[100] || !got[101] {
		t.Fatalf("reseller-admin scope = %v, want exactly {100,101}", ids)
	}
	if idSet(ids)[200] {
		t.Fatal("cross-reseller leak: manual assignment to client 200 widened the scope")
	}
}

// TestScopeFilterPlainAdminUnchanged: a non-reseller admin still resolves via
// admin_client_scope (reseller_id NULL preserves the old behavior).
func TestScopeFilterPlainAdminUnchanged(t *testing.T) {
	db := openResellerDB(t)
	svc := New(func() *sql.DB { return db })
	ctx := context.Background()

	ids, all, err := svc.ScopeFilter(ctx, 2)
	if err != nil {
		t.Fatalf("ScopeFilter(plain admin): %v", err)
	}
	if all {
		t.Fatal("plain scoped admin must not get all=true")
	}
	if got := idSet(ids); len(got) != 1 || !got[300] {
		t.Fatalf("plain admin scope = %v, want {300} from admin_client_scope", ids)
	}
}

// TestScopeFilterSuperAdmin: id 0 remains the unfiltered super_admin path.
func TestScopeFilterSuperAdmin(t *testing.T) {
	db := openResellerDB(t)
	svc := New(func() *sql.DB { return db })
	_, all, err := svc.ScopeFilter(context.Background(), 0)
	if err != nil {
		t.Fatalf("ScopeFilter(super_admin): %v", err)
	}
	if !all {
		t.Fatal("super_admin (id=0) must get all=true")
	}
}

func idSet(ids []int64) map[int64]bool {
	m := make(map[int64]bool, len(ids))
	for _, id := range ids {
		m[id] = true
	}
	return m
}
