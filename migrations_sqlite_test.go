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
