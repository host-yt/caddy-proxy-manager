// Package sqlitetest hands tests a fully migrated SQLite file without paying
// for the whole migration chain per test.
package sqlitetest

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"sync"
	"testing"

	proxygateway "github.com/host-yt/caddy-proxy-manager"
	"github.com/host-yt/caddy-proxy-manager/internal/store"
	_ "modernc.org/sqlite"
)

var (
	once sync.Once
	tmpl []byte
	err0 error
)

// MigratedCopy returns the path of a private copy of a schema migrated once per
// test binary. Migrating per test pushed CI past the 10 min -race timeout.
func MigratedCopy(t testing.TB, name string) string {
	t.Helper()
	once.Do(func() { tmpl, err0 = build() })
	if err0 != nil {
		t.Fatalf("migrate sqlite template: %v", err0)
	}
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, tmpl, 0o600); err != nil {
		t.Fatalf("copy sqlite template: %v", err)
	}
	return path
}

func build() ([]byte, error) {
	prev := store.Driver()
	store.SetDriver("sqlite3")
	defer store.SetDriver(prev)
	dir, err := os.MkdirTemp("", "hpg-sqlite-tmpl")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "tmpl.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	err = store.RunMigrations(context.Background(), db, proxygateway.MigrationsFS, "migrations")
	// Close before reading so nothing is left in a journal.
	if cerr := db.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return nil, err
	}
	return os.ReadFile(path)
}
