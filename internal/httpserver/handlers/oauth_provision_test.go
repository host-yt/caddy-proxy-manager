package handlers

import (
	"context"
	"database/sql"
	"testing"

	"github.com/host-yt/caddy-proxy-manager/internal/store"
	_ "modernc.org/sqlite"
)

func provisionTestDB(t *testing.T, withClients bool) *sql.DB {
	t.Helper()
	prev := store.Driver()
	store.SetDriver("sqlite3")
	t.Cleanup(func() { store.SetDriver(prev) })
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1) // one :memory: database across the tx
	t.Cleanup(func() { db.Close() })
	stmts := []string{
		`CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT UNIQUE, password_hash TEXT, password_set INTEGER,
			role TEXT, full_name TEXT, is_active INTEGER, email_verified INTEGER)`,
		`CREATE TABLE oauth_identities (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, provider TEXT NOT NULL,
			subject TEXT NOT NULL, email TEXT, issuer TEXT NOT NULL DEFAULT '', UNIQUE (provider, issuer, subject))`,
	}
	if withClients {
		stmts = append(stmts, `CREATE TABLE clients (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL UNIQUE, display_name TEXT)`)
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

func countRows(t *testing.T, db *sql.DB, q string) int {
	t.Helper()
	var n int
	if err := db.QueryRow(q).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// An auto-provisioned client must get its tenant row with the user, or nothing.
func TestProvisionSSOUserCreatesClientRecord(t *testing.T) {
	db := provisionTestDB(t, true)
	uid, err := provisionSSOUser(context.Background(), db, "c@example.com", "client", "C", true, "github", "s1", "c@example.com", "github")
	if err != nil {
		t.Fatal(err)
	}
	if n := countRows(t, db, "SELECT COUNT(*) FROM clients WHERE user_id = "+itoa64(uid)); n != 1 {
		t.Fatalf("clients rows = %d, want 1", n)
	}
	if n := countRows(t, db, "SELECT COUNT(*) FROM oauth_identities WHERE user_id = "+itoa64(uid)); n != 1 {
		t.Fatalf("identity rows = %d, want 1", n)
	}

	// support gets no client row.
	uid2, err := provisionSSOUser(context.Background(), db, "s@example.com", "support", "S", true, "github", "s2", "s@example.com", "github")
	if err != nil {
		t.Fatal(err)
	}
	if n := countRows(t, db, "SELECT COUNT(*) FROM clients WHERE user_id = "+itoa64(uid2)); n != 0 {
		t.Fatalf("support clients rows = %d, want 0", n)
	}
}

func TestProvisionSSOUserRollsBackOnClientFailure(t *testing.T) {
	db := provisionTestDB(t, false) // clients insert fails
	if _, err := provisionSSOUser(context.Background(), db, "c@example.com", "client", "C", true, "github", "s1", "c@example.com", "github"); err == nil {
		t.Fatal("want error when the client row cannot be created")
	}
	if n := countRows(t, db, "SELECT COUNT(*) FROM users"); n != 0 {
		t.Fatalf("orphan users rows = %d, want 0", n)
	}
	if n := countRows(t, db, "SELECT COUNT(*) FROM oauth_identities"); n != 0 {
		t.Fatalf("orphan identity rows = %d, want 0", n)
	}
}
