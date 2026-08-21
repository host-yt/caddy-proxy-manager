package proxygateway_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	proxygateway "github.com/host-yt/caddy-proxy-manager"
	"github.com/host-yt/caddy-proxy-manager/internal/store"
)

// TestMigrationsApplyOnSQLite runs the whole migration set through the real
// runner on a real SQLite file - the same path the install wizard takes when
// db_driver=sqlite. Unit-testing single transform rules missed migration
// 00018 shipping a bare NOW(), which aborted every SQLite install with
// "no such function: NOW".
func TestMigrationsApplyOnSQLite(t *testing.T) {
	prev := store.Driver()
	store.SetDriver("sqlite3")
	t.Cleanup(func() { store.SetDriver(prev) })

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	dsn := filepath.Join(t.TempDir(), "hpg.db")
	db, err := store.Open(ctx, "sqlite3", dsn, 10*time.Second)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()

	if err := store.RunMigrations(ctx, db, proxygateway.MigrationsFS, "migrations"); err != nil {
		t.Fatalf("migrations failed on sqlite: %v", err)
	}

	// Spot-check that real schema landed, not just an empty goose ledger.
	for _, table := range []string{"routes", "users", "caddy_nodes", "node_groups", "settings"} {
		var name string
		if err := db.QueryRowContext(ctx,
			"SELECT name FROM sqlite_master WHERE type='table' AND name=?", table).Scan(&name); err != nil {
			t.Fatalf("table %q missing after migrate: %v", table, err)
		}
	}
}

// TestMigrationsUpgradeFromPreviousRelease exercises the path a real upgrade
// takes and a from-empty apply never does: an existing schema at the previous
// migration, then the newest one applied on top of live data.
//
// A migration that only works against a freshly created table - a column added
// with a NOT NULL and no default, an index over data that already violates it -
// passes the from-empty test and fails on the first real deployment.
func TestMigrationsUpgradeFromPreviousRelease(t *testing.T) {
	prev := store.Driver()
	store.SetDriver("sqlite3")
	t.Cleanup(func() { store.SetDriver(prev) })

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	latest, err := store.LatestMigrationVersion(proxygateway.MigrationsFS, "migrations")
	if err != nil {
		t.Fatalf("latest migration version: %v", err)
	}

	dsn := filepath.Join(t.TempDir(), "hpg.db")
	db, err := store.Open(ctx, "sqlite3", dsn, 10*time.Second)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()

	// Stand up the schema as of the previous release.
	if err := store.MigrateUpTo(ctx, db, proxygateway.MigrationsFS, "migrations", latest-1); err != nil {
		t.Fatalf("migrate to N-1 (%d): %v", latest-1, err)
	}

	// Put a row in the table upgrades most often touch, so the newest
	// migration runs against data rather than an empty table.
	if _, err := db.ExecContext(ctx,
		`INSERT INTO node_groups (id, name, mode) VALUES (1, 'default', 'single')`); err != nil {
		t.Fatalf("seed node_groups: %v", err)
	}
	if _, err := db.ExecContext(ctx,
		`INSERT INTO caddy_nodes (id, name, api_url, node_group_id) VALUES (1, 'edge1', 'http://10.0.0.2:2019', 1)`); err != nil {
		t.Fatalf("seed caddy_nodes: %v", err)
	}

	// Now the upgrade itself.
	if err := store.RunMigrations(ctx, db, proxygateway.MigrationsFS, "migrations"); err != nil {
		t.Fatalf("upgrade N-1 -> N failed: %v", err)
	}

	var applied int64
	if err := db.QueryRowContext(ctx,
		"SELECT MAX(version_id) FROM goose_db_version WHERE is_applied = 1").Scan(&applied); err != nil {
		t.Fatalf("read goose version: %v", err)
	}
	if applied != latest {
		t.Fatalf("applied version = %d, want %d", applied, latest)
	}
	// The seeded row must have survived the upgrade.
	var name string
	if err := db.QueryRowContext(ctx, "SELECT name FROM caddy_nodes WHERE id = 1").Scan(&name); err != nil {
		t.Fatalf("seeded node lost in upgrade: %v", err)
	}
	if name != "edge1" {
		t.Fatalf("node name = %q after upgrade, want edge1", name)
	}
}
