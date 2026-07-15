package handlers

import (
	"database/sql"
	"testing"

	"github.com/host-yt/caddy-proxy-manager/internal/store"
	_ "modernc.org/sqlite"
)

// The OIDC callback links a login to an oauth_identities row via an upsert
// whose two dialect arms are hand-written (see resolveOrCreateOAuthIdentity).
// The panel's SSRF guard blocks a local OIDC issuer, so the full browser flow
// can't run against dex on a private docker IP - but the engine-specific bit is
// this query, and it can be exercised directly. Runs the exact sqlite arm and
// asserts insert-then-conflict behaves: same user re-links idempotently, a
// different user does not steal the email.
func TestOAuthIdentityUpsertSQLite(t *testing.T) {
	prev := store.Driver()
	store.SetDriver("sqlite3")
	t.Cleanup(func() { store.SetDriver(prev) })

	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// Mirror of migration 00084 (sqlite spelling), enough for the upsert.
	if _, err := db.Exec(`CREATE TABLE oauth_identities (
		id INTEGER PRIMARY KEY,
		user_id INTEGER NOT NULL,
		provider TEXT NOT NULL,
		subject TEXT NOT NULL,
		email TEXT,
		issuer TEXT NOT NULL DEFAULT '',
		linked_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
		UNIQUE (provider, issuer, subject)
	)`); err != nil {
		t.Fatal(err)
	}

	// The exact sqlite arm from oauth_identity.go.
	const q = `INSERT INTO oauth_identities (user_id, provider, subject, email, issuer) VALUES (?, ?, ?, NULLIF(?, ''), ?) ON CONFLICT(provider, issuer, subject) DO UPDATE SET email=CASE WHEN user_id=excluded.user_id THEN COALESCE(excluded.email, email) ELSE email END`

	// First link: user 10.
	if _, err := db.Exec(q, 10, "oidc", "subj-1", "u10@example.com", "http://dex:5556"); err != nil {
		t.Fatalf("initial insert: %v", err)
	}
	// Same identity, same user, newer email -> email updates, no dup row.
	if _, err := db.Exec(q, 10, "oidc", "subj-1", "u10-new@example.com", "http://dex:5556"); err != nil {
		t.Fatalf("idempotent relink: %v", err)
	}
	// A DIFFERENT user hitting the same subject must not overwrite the owner's
	// email (account-takeover guard the CASE expression encodes).
	if _, err := db.Exec(q, 99, "oidc", "subj-1", "attacker@evil.com", "http://dex:5556"); err != nil {
		t.Fatalf("cross-user upsert: %v", err)
	}

	var rows int
	db.QueryRow(`SELECT COUNT(*) FROM oauth_identities`).Scan(&rows)
	if rows != 1 {
		t.Fatalf("row count = %d, want 1 (upsert, not insert)", rows)
	}
	var owner int
	var email string
	db.QueryRow(`SELECT user_id, email FROM oauth_identities WHERE subject='subj-1'`).Scan(&owner, &email)
	if owner != 10 {
		t.Errorf("owner = %d, want 10 (a different user must not seize the identity)", owner)
	}
	if email != "u10-new@example.com" {
		t.Errorf("email = %q, want u10-new@example.com (own relink updates, attacker does not)", email)
	}

	// NULLIF('' ...): an empty email must store NULL, not "".
	if _, err := db.Exec(q, 11, "oidc", "subj-2", "", "http://dex:5556"); err != nil {
		t.Fatal(err)
	}
	var e sql.NullString
	db.QueryRow(`SELECT email FROM oauth_identities WHERE subject='subj-2'`).Scan(&e)
	if e.Valid {
		t.Errorf("empty email stored as %q, want NULL", e.String)
	}
}
