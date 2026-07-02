package adminscope

import (
	"context"
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"
)

// openTestDB builds a hermetic in-memory schema covering only what
// CanAccessClient/CanAccessRoute query - no MySQL/Redis needed.
func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	stmts := []string{
		`CREATE TABLE admin_client_scope (admin_user_id INTEGER, client_id INTEGER)`,
		`CREATE TABLE services (id INTEGER PRIMARY KEY, client_id INTEGER)`,
		`CREATE TABLE routes (id INTEGER PRIMARY KEY, service_id INTEGER)`,
		// admin 1 is scoped to client 100 only; client 200 belongs to a different tenant.
		`INSERT INTO admin_client_scope (admin_user_id, client_id) VALUES (1, 100)`,
		`INSERT INTO services (id, client_id) VALUES (10, 100), (20, 200)`,
		`INSERT INTO routes (id, service_id) VALUES (1000, 10), (2000, 20)`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("exec %q: %v", s, err)
		}
	}
	return db
}

// TestClientCannotAccessOtherTenantResource is a BOLA/IDOR regression: a
// scoped admin assigned to client 100 must be denied client 200's client
// record and route, even though both exist and only the tenant differs.
func TestClientCannotAccessOtherTenantResource(t *testing.T) {
	db := openTestDB(t)
	svc := New(func() *sql.DB { return db })
	ctx := context.Background()

	const scopedAdmin = int64(1)

	okOwn, err := svc.CanAccessClient(ctx, scopedAdmin, 100)
	if err != nil {
		t.Fatalf("CanAccessClient(own): %v", err)
	}
	if !okOwn {
		t.Fatal("scoped admin must access its own assigned client")
	}

	okOther, err := svc.CanAccessClient(ctx, scopedAdmin, 200)
	if err != nil {
		t.Fatalf("CanAccessClient(other): %v", err)
	}
	if okOther {
		t.Fatal("IDOR: scoped admin accessed a client outside its scope")
	}

	okOwnRoute, err := svc.CanAccessRoute(ctx, scopedAdmin, 1000)
	if err != nil {
		t.Fatalf("CanAccessRoute(own): %v", err)
	}
	if !okOwnRoute {
		t.Fatal("scoped admin must access a route under its own client")
	}

	okOtherRoute, err := svc.CanAccessRoute(ctx, scopedAdmin, 2000)
	if err != nil {
		t.Fatalf("CanAccessRoute(other): %v", err)
	}
	if okOtherRoute {
		t.Fatal("IDOR: scoped admin accessed a route belonging to another tenant")
	}
}
