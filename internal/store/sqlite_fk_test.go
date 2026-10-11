package store_test

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	proxygateway "github.com/host-yt/caddy-proxy-manager"
	"github.com/host-yt/caddy-proxy-manager/internal/store"
)

// #93: FKs are enforced on SQLite pools, the full chain migrates with them on,
// and orphans left by older installs are resolved per their ON DELETE action.
func TestSQLiteForeignKeysEnforced(t *testing.T) {
	prev := store.Driver()
	defer store.SetDriver(prev)
	ctx := context.Background()
	db, err := store.Open(ctx, "sqlite3", "file:"+filepath.Join(t.TempDir(), "fk.db"), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := store.RunMigrations(ctx, db, proxygateway.MigrationsFS, "migrations"); err != nil {
		t.Fatalf("migrate with FKs on: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO recovery_codes (user_id, code_hash) VALUES (999, 'x')`); err == nil {
		t.Fatal("orphan insert accepted: foreign keys not enforced")
	}

	// Simulate a pre-fix install: orphans written with enforcement off.
	mustExec(t, db, `PRAGMA foreign_keys=OFF`)
	mustExec(t, db, `INSERT INTO recovery_codes (user_id, code_hash) VALUES (999, 'x')`)
	mustExec(t, db, `INSERT INTO webhook_endpoints (name, url, events, created_by) VALUES ('w', 'https://x', 'e', 999)`)
	mustExec(t, db, `PRAGMA foreign_keys=ON`)

	if err := store.RunMigrations(ctx, db, proxygateway.MigrationsFS, "migrations"); err != nil {
		t.Fatalf("re-run migrations: %v", err)
	}
	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM recovery_codes`).Scan(&n)
	if n != 0 {
		t.Fatalf("CASCADE orphan not deleted: %d rows", n)
	}
	var createdBy sql.NullInt64
	if err := db.QueryRow(`SELECT created_by FROM webhook_endpoints`).Scan(&createdBy); err != nil || createdBy.Valid {
		t.Fatalf("SET NULL orphan not nulled: %v %v", createdBy, err)
	}
	var on int
	_ = db.QueryRow(`PRAGMA foreign_keys`).Scan(&on)
	if on != 1 {
		t.Fatal("foreign_keys not restored after migrations")
	}
}

func mustExec(t *testing.T, db *sql.DB, q string) {
	t.Helper()
	if _, err := db.Exec(q); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
}
