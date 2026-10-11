package handlers

import (
	"context"
	"database/sql"
	"testing"

	"github.com/host-yt/caddy-proxy-manager/internal/store"
	_ "modernc.org/sqlite"
)

// A failing write must roll back the whole schedule, not leave it half-saved.
func TestSaveBackupScheduleAtomic(t *testing.T) {
	prev := store.Driver()
	store.SetDriver("sqlite3")
	t.Cleanup(func() { store.SetDriver(prev) })
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	for _, s := range []string{
		`CREATE TABLE settings ("key" TEXT PRIMARY KEY, value TEXT, is_encrypted INTEGER)`,
		`CREATE TRIGGER fail_enc BEFORE INSERT ON settings WHEN NEW."key"='backup.encrypt' BEGIN SELECT RAISE(ABORT, 'boom'); END`,
	} {
		if _, err := db.Exec(s); err != nil {
			t.Fatal(err)
		}
	}
	ctx := context.Background()
	if err := saveBackupSchedule(ctx, db, "24", "7", "1"); err == nil {
		t.Fatal("want error from failing encrypt write")
	}
	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM settings`).Scan(&n)
	if n != 0 {
		t.Fatalf("partial write persisted: %d rows", n)
	}
	if _, err := db.Exec(`DROP TRIGGER fail_enc`); err != nil {
		t.Fatal(err)
	}
	if err := saveBackupSchedule(ctx, db, "24", "7", "1"); err != nil {
		t.Fatal(err)
	}
	_ = db.QueryRow(`SELECT COUNT(*) FROM settings`).Scan(&n)
	if n != 3 {
		t.Fatalf("rows = %d, want 3", n)
	}
}
