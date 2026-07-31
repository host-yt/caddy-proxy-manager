package routes

import (
	"context"
	"database/sql"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	proxygateway "github.com/host-yt/caddy-proxy-manager"
	"github.com/host-yt/caddy-proxy-manager/internal/store"
	_ "modernc.org/sqlite"
)

// FINDING 1 (r14): migration 00138 drops the 00136 backfill, so the panel has
// to know which aliases are still owed a proof - that is what drives the
// automatic re-check and the operator report.
func TestUnprovenHosts(t *testing.T) {
	cases := []struct {
		name, aliases, verified, want string
	}{
		{"nothing proven", "a.example,b.example", "", "a.example,b.example"},
		{"partially proven", "a.example,b.example", "a.example", "b.example"},
		{"all proven", "a.example,b.example", "b.example,a.example", ""},
		{"proof for a removed alias", "a.example", "a.example,gone.example", ""},
		{"whitespace and case", "A.Example , b.example", "a.example", "b.example"},
	}
	for _, tc := range cases {
		if got := strings.Join(unprovenHosts(tc.aliases, tc.verified), ","); got != tc.want {
			t.Errorf("%s: unprovenHosts = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// migratedSQLite gives the test the real schema without needing TEST_DB_DSN.
func migratedSQLite(t *testing.T) *sql.DB {
	t.Helper()
	prev := store.Driver()
	store.SetDriver("sqlite3")
	t.Cleanup(func() { store.SetDriver(prev) })
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "r14.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := store.RunMigrations(context.Background(), db, proxygateway.MigrationsFS, "migrations"); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

// FINDING 2 (r14): bulk retry_ssl could park an unverified route in a serving
// status. The emission query must refuse it regardless of how it got there,
// so an unowned hostname never lands in a Caddy host matcher.
func TestBuildRoutesSkipsUnverifiedDomain(t *testing.T) {
	db := migratedSQLite(t)
	ctx := context.Background()
	for _, s := range []string{
		`INSERT INTO node_groups (id, name) VALUES (1, 'g1')`,
		`INSERT INTO caddy_nodes (id, name, api_url, is_enabled, node_group_id) VALUES (1, 'edge1', 'http://n1:2019', 1, 1)`,
		`INSERT INTO plans (id, name, node_group_id) VALUES (1, 'p1', 1)`,
		`INSERT INTO services (id, client_id, name, backend_ip, allowed_port_start, allowed_port_end, plan_id, node_group_id)
		   VALUES (1, 1, 'svc', '10.0.0.9', 1, 65535, 1, 1)`,
		`INSERT INTO routes (id, service_id, caddy_node_id, domain, upstream_port, upstream_scheme,
		   ssl_enabled, status, kind, domain_verified)
		   VALUES (10, 1, 1, 'owned.example', 8080, 'http', 1, 'pending_ssl', 'proxy', 1)`,
		`INSERT INTO routes (id, service_id, caddy_node_id, domain, upstream_port, upstream_scheme,
		   ssl_enabled, status, kind, domain_verified)
		   VALUES (11, 1, 1, 'victim.example', 8080, 'http', 1, 'pending_ssl', 'proxy', 0)`,
	} {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("exec %q: %v", s, err)
		}
	}
	svc := &Service{DB: db, Logger: slog.Default()}
	_, ids, err := svc.buildRoutesForNode(ctx, 1)
	if err != nil {
		t.Fatalf("buildRoutesForNode: %v", err)
	}
	got := map[int64]bool{}
	for _, id := range ids {
		got[id] = true
	}
	if !got[10] {
		t.Error("verified route was dropped from the node config")
	}
	if got[11] {
		t.Error("unverified route reached the Caddy host matcher")
	}
}
