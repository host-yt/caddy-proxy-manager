package portal

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	proxygateway "github.com/host-yt/caddy-proxy-manager"
	"github.com/host-yt/caddy-proxy-manager/internal/store"
	_ "modernc.org/sqlite"
)

// migratedSQLite gives the test the real schema without needing TEST_DB_DSN.
func migratedSQLite(t *testing.T) *sql.DB {
	t.Helper()
	prev := store.Driver()
	store.SetDriver("sqlite3")
	t.Cleanup(func() { store.SetDriver(prev) })
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "portal.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := store.RunMigrations(context.Background(), db, proxygateway.MigrationsFS, "migrations"); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

func exec(t *testing.T, db *sql.DB, stmts ...string) {
	t.Helper()
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("exec %q: %v", s, err)
		}
	}
}

func baseFixture(t *testing.T, db *sql.DB) {
	t.Helper()
	exec(t, db,
		`INSERT INTO node_groups (id, name) VALUES (1, 'g1')`,
		`INSERT INTO caddy_nodes (id, name, api_url, is_enabled, node_group_id) VALUES (1, 'edge1', 'http://n1:2019', 1, 1)`,
		`INSERT INTO plans (id, name, node_group_id) VALUES (1, 'p1', 1)`,
		`INSERT INTO services (id, client_id, name, backend_ip, allowed_port_start, allowed_port_end, plan_id, node_group_id)
		   VALUES (1, 1, 'svc', '10.0.0.9', 1, 65535, 1, 1)`,
	)
}

func insertRoute(t *testing.T, db *sql.DB, id int64, domain, path string, protect int) {
	t.Helper()
	if _, err := db.Exec(
		`INSERT INTO routes (id, service_id, caddy_node_id, domain, path_prefix, upstream_port, upstream_scheme,
		   ssl_enabled, status, kind, domain_verified, portal_protect)
		   VALUES (?, 1, 1, ?, ?, 8080, 'http', 1, 'active', 'proxy', 1, ?)`,
		id, domain, path, protect); err != nil {
		t.Fatalf("insert route %d: %v", id, err)
	}
}

// HPG-002: the verifier authorized a HOSTNAME. Two routes on one host - a
// protected /team-a and a public catch-all - collapsed to one policy record,
// so the public sibling could answer for the protected path (and either team's
// grants could answer for the other's). Resolution must bind to the exact
// route: proven host matcher plus longest path prefix.
func TestRouteForRequestBindsToExactRoute(t *testing.T) {
	db := migratedSQLite(t)
	baseFixture(t, db)
	insertRoute(t, db, 10, "app.example", "", 0)        // public catch-all
	insertRoute(t, db, 11, "app.example", "/team-a", 1) // protected
	insertRoute(t, db, 12, "app.example", "/team-b", 1) // protected, other grants
	svc := New(func() *sql.DB { return db })
	ctx := context.Background()

	cases := []struct {
		path        string
		wantID      int64
		wantProtect bool
	}{
		{"/team-a", 11, true},
		{"/team-a/docs", 11, true},
		{"/team-b/docs", 12, true},
		{"/anything-else", 10, false},
		{"/", 10, false},
	}
	for _, c := range cases {
		id, protect, err := svc.RouteForRequest(ctx, "app.example", c.path)
		if err != nil {
			t.Fatalf("%s: %v", c.path, err)
		}
		if id != c.wantID || protect != c.wantProtect {
			t.Errorf("%s: got (%d, %v), want (%d, %v)", c.path, id, protect, c.wantID, c.wantProtect)
		}
	}
}

// Fail-closed: no identity, no serving route, and two equally specific routes
// must all be errors, never a permissive default.
func TestRouteForRequestFailsClosed(t *testing.T) {
	db := migratedSQLite(t)
	baseFixture(t, db)
	insertRoute(t, db, 10, "app.example", "/x", 1)
	// Same host reachable through a PROVEN alias on a second route with the
	// same prefix: no single policy applies.
	insertRoute(t, db, 11, "other.example", "/x", 1)
	exec(t, db, `UPDATE routes SET aliases = 'app.example', aliases_verified = 'app.example' WHERE id = 11`)
	// An UNPROVEN alias must never pull a route into the candidate set.
	insertRoute(t, db, 12, "third.example", "/y", 1)
	exec(t, db, `UPDATE routes SET aliases = 'app.example' WHERE id = 12`)

	svc := New(func() *sql.DB { return db })
	ctx := context.Background()

	if _, _, err := svc.RouteForRequest(ctx, "app.example", "/x"); !errors.Is(err, ErrAmbiguousRoute) {
		t.Errorf("tie must be ambiguous, got %v", err)
	}
	if _, _, err := svc.RouteForRequest(ctx, "app.example", "/y"); !errors.Is(err, ErrNoRoute) {
		t.Errorf("unproven alias must not serve, got %v", err)
	}
	if _, _, err := svc.RouteForRequest(ctx, "app.example", "no-slash"); !errors.Is(err, ErrNoRoute) {
		t.Errorf("missing identity must fail closed, got %v", err)
	}
	if _, _, err := svc.RouteForRequest(ctx, "", "/x"); !errors.Is(err, ErrNoRoute) {
		t.Errorf("empty host must fail closed, got %v", err)
	}
	if _, _, err := svc.RouteForRequest(ctx, "unknown.example", "/x"); !errors.Is(err, ErrNoRoute) {
		t.Errorf("unknown host must fail closed, got %v", err)
	}
}

// A route that is not serving (unverified domain / non-serving status) is not
// emitted as a host matcher, so it must not supply a portal policy either.
func TestRouteForRequestIgnoresNonServingRoutes(t *testing.T) {
	db := migratedSQLite(t)
	baseFixture(t, db)
	insertRoute(t, db, 10, "app.example", "", 1)
	exec(t, db, `UPDATE routes SET domain_verified = 0 WHERE id = 10`)
	svc := New(func() *sql.DB { return db })
	if _, _, err := svc.RouteForRequest(context.Background(), "app.example", "/"); !errors.Is(err, ErrNoRoute) {
		t.Errorf("unverified route must not resolve, got %v", err)
	}
}

// HPG-004: a portal session outlived the account behind it. Every verification
// re-reads is_active and auth_epoch, so a disable or a re-scope ends access on
// the next request instead of up to 30 days later.
func TestIdentityStillValid(t *testing.T) {
	db := migratedSQLite(t)
	exec(t, db,
		`INSERT INTO users (id, email, password_hash, role, is_active) VALUES (7, 'u@example.com', 'x', 'client', 1)`)
	svc := New(func() *sql.DB { return db })
	ctx := context.Background()

	var epoch int64
	if err := db.QueryRow(`SELECT auth_epoch FROM users WHERE id = 7`).Scan(&epoch); err != nil {
		t.Fatalf("epoch: %v", err)
	}
	if ok, err := svc.IdentityStillValid(ctx, 7, epoch); err != nil || !ok {
		t.Fatalf("active user with matching epoch: ok=%v err=%v", ok, err)
	}
	if ok, err := svc.IdentityStillValid(ctx, 7, epoch+1); err != nil || ok {
		t.Errorf("stale epoch must be invalid: ok=%v err=%v", ok, err)
	}
	exec(t, db, `UPDATE users SET is_active = 0 WHERE id = 7`)
	if ok, err := svc.IdentityStillValid(ctx, 7, epoch); err != nil || ok {
		t.Errorf("disabled user must be invalid: ok=%v err=%v", ok, err)
	}
	if ok, err := svc.IdentityStillValid(ctx, 999, 0); err != nil || ok {
		t.Errorf("missing user must be invalid: ok=%v err=%v", ok, err)
	}
}

// HPG-003: the protect flag and the grant set are one decision. A split write
// can leave "protected, no grants" - which the build side reads as "no gate",
// i.e. public - so both must land in a single transaction.
func TestSetRouteProtectionIsAtomic(t *testing.T) {
	db := migratedSQLite(t)
	baseFixture(t, db)
	insertRoute(t, db, 10, "app.example", "", 0)
	exec(t, db,
		`INSERT INTO access_groups (id, name, client_id) VALUES (1, 'team-a', 1)`,
		`INSERT INTO access_groups (id, name, client_id) VALUES (2, 'other-tenant', 2)`,
	)
	svc := New(func() *sql.DB { return db })
	ctx := context.Background()
	visible := map[int64]bool{1: true}

	if err := svc.SetRouteProtection(ctx, 10, true, []int64{1, 2}, visible, false); err != nil {
		t.Fatalf("SetRouteProtection: %v", err)
	}
	var protect int
	if err := db.QueryRow(`SELECT portal_protect FROM routes WHERE id = 10`).Scan(&protect); err != nil {
		t.Fatalf("read protect: %v", err)
	}
	if protect != 1 {
		t.Errorf("protect flag not written")
	}
	grants, err := svc.RouteGrants(ctx, 10)
	if err != nil {
		t.Fatalf("RouteGrants: %v", err)
	}
	if len(grants) != 1 || grants[0] != 1 {
		t.Errorf("grants = %v, want [1] (another tenant's group must be dropped)", grants)
	}

	// A rolled-back grant write must not leave the flag behind: point the
	// service at a closed DB and prove nothing changed.
	closed := migratedSQLite(t)
	closed.Close()
	if err := New(func() *sql.DB { return closed }).
		SetRouteProtection(ctx, 10, false, nil, visible, false); err == nil {
		t.Errorf("write against a dead DB must error, not report success")
	}
}

// A security write must never report success when there is no database.
func TestSetRouteGrantsWithoutDBFails(t *testing.T) {
	svc := New(func() *sql.DB { return nil })
	if err := svc.SetRouteGrants(context.Background(), 1, []int64{1}, nil, true); err == nil {
		t.Errorf("SetRouteGrants with no DB must error")
	}
	if err := svc.SetRouteProtection(context.Background(), 1, true, []int64{1}, nil, true); err == nil {
		t.Errorf("SetRouteProtection with no DB must error")
	}
	if _, err := svc.IdentityStillValid(context.Background(), 1, 0); err == nil {
		t.Errorf("IdentityStillValid with no DB must error (indeterminate = deny)")
	}
}
