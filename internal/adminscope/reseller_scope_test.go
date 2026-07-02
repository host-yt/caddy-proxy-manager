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
		// user 1 = reseller-admin (reseller 7); user 2 = client-scoped admin
		// (has admin_client_scope rows); user 3 = bare/unrestricted admin.
		`INSERT INTO users (id, reseller_id) VALUES (1, 7), (2, NULL), (3, NULL)`,
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

// TestScopeFilterBareAdmin: an admin with no reseller and no admin_client_scope
// rows is unrestricted (all=true) - restriction is opt-in.
func TestScopeFilterBareAdmin(t *testing.T) {
	db := openResellerDB(t)
	svc := New(func() *sql.DB { return db })
	ctx := context.Background()

	_, all, err := svc.ScopeFilter(ctx, 3)
	if err != nil {
		t.Fatalf("ScopeFilter(bare admin): %v", err)
	}
	if !all {
		t.Fatal("bare admin (no reseller, no scope rows) must be unrestricted (all=true)")
	}
	// And per-resource checks allow anything for a bare admin.
	ok, err := svc.CanAccessClient(ctx, 3, 200) // client of another reseller
	if err != nil {
		t.Fatalf("CanAccessClient(bare): %v", err)
	}
	if !ok {
		t.Fatal("bare admin must access any client")
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

// TestCanAccessResellerOwnership: a reseller-admin reaches resources under its
// reseller's clients and is denied cross-reseller ones, without any
// admin_client_scope rows.
func TestCanAccessResellerOwnership(t *testing.T) {
	db := openResellerDB(t)
	// Resources: service+route+peer under client 100 (reseller 7) and client 200
	// (reseller 9).
	for _, s := range []string{
		`CREATE TABLE services (id INTEGER PRIMARY KEY, client_id INTEGER)`,
		`CREATE TABLE routes (id INTEGER PRIMARY KEY, service_id INTEGER)`,
		`CREATE TABLE customer_wg_peer (id INTEGER PRIMARY KEY, client_id INTEGER)`,
		`INSERT INTO services (id, client_id) VALUES (10, 100), (20, 200)`,
		`INSERT INTO routes (id, service_id) VALUES (1000, 10), (2000, 20)`,
		`INSERT INTO customer_wg_peer (id, client_id) VALUES (500, 100), (600, 200)`,
	} {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("exec %q: %v", s, err)
		}
	}
	svc := New(func() *sql.DB { return db })
	ctx := context.Background()
	const resellerAdmin = int64(1) // reseller 7

	checks := []struct {
		name string
		fn   func() (bool, error)
		want bool
	}{
		{"own client", func() (bool, error) { return svc.CanAccessClient(ctx, resellerAdmin, 100) }, true},
		{"foreign client", func() (bool, error) { return svc.CanAccessClient(ctx, resellerAdmin, 200) }, false},
		{"own route", func() (bool, error) { return svc.CanAccessRoute(ctx, resellerAdmin, 1000) }, true},
		{"foreign route", func() (bool, error) { return svc.CanAccessRoute(ctx, resellerAdmin, 2000) }, false},
		{"own peer", func() (bool, error) { return svc.CanAccessPeer(ctx, resellerAdmin, 500) }, true},
		{"foreign peer", func() (bool, error) { return svc.CanAccessPeer(ctx, resellerAdmin, 600) }, false},
	}
	for _, c := range checks {
		got, err := c.fn()
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got != c.want {
			t.Fatalf("%s = %v, want %v", c.name, got, c.want)
		}
	}
}

func idSet(ids []int64) map[int64]bool {
	m := make(map[int64]bool, len(ids))
	for _, id := range ids {
		m[id] = true
	}
	return m
}
