package auth

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

// Minimal schema: only the columns VerifyAPIKey touches. A real MySQL is not
// needed to prove the epoch/activation gate.
const apiKeyTestSchema = `
CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  role TEXT NOT NULL DEFAULT 'client',
  is_active INTEGER NOT NULL DEFAULT 1,
  auth_epoch INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE api_keys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  name TEXT NOT NULL,
  key_prefix TEXT NOT NULL UNIQUE,
  key_hash TEXT NOT NULL,
  key_hmac TEXT,
  scopes TEXT NOT NULL DEFAULT '',
  last_used_at TIMESTAMP NULL,
  last_used_ip TEXT NOT NULL DEFAULT '',
  use_count INTEGER NOT NULL DEFAULT 0,
  revoked_at TIMESTAMP NULL,
  expires_at TIMESTAMP NULL,
  auth_epoch INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMP NULL
);
`

func newAPIKeyTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec(apiKeyTestSchema); err != nil {
		t.Fatalf("schema: %v", err)
	}
	return db
}

// newTestKey seeds a user at the given epoch and issues a key for it.
func newTestKey(t *testing.T, db *sql.DB, role string, epoch int64) (token string, userID int64) {
	t.Helper()
	ctx := context.Background()
	res, err := db.ExecContext(ctx, "INSERT INTO users (role, is_active, auth_epoch) VALUES (?, 1, ?)", role, epoch)
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}
	userID, _ = res.LastInsertId()
	token, _, _, err = CreateAPIKey(ctx, db, userID, "test", "admin:read")
	if err != nil {
		t.Fatalf("create key: %v", err)
	}
	return token, userID
}

func TestVerifyAPIKeyHealthyKeyWorks(t *testing.T) {
	defer SetHMACKey(nil)
	SetHMACKey([]byte("test-key-do-not-use"))
	db := newAPIKeyTestDB(t)
	token, userID := newTestKey(t, db, "admin", 7)

	uid, _, role, scopes, err := VerifyAPIKey(context.Background(), db, token, "")
	if err != nil {
		t.Fatalf("healthy key denied: %v", err)
	}
	if uid != userID || role != "admin" || scopes != "admin:read" {
		t.Fatalf("unexpected principal: uid=%d role=%q scopes=%q", uid, role, scopes)
	}
}

func TestVerifyAPIKeyDeniedWhenUserDeactivated(t *testing.T) {
	defer SetHMACKey(nil)
	SetHMACKey([]byte("test-key-do-not-use"))
	db := newAPIKeyTestDB(t)
	token, userID := newTestKey(t, db, "admin", 0)

	if _, err := db.Exec("UPDATE users SET is_active = 0 WHERE id = ?", userID); err != nil {
		t.Fatalf("deactivate: %v", err)
	}
	if _, _, _, _, err := VerifyAPIKey(context.Background(), db, token, ""); !errors.Is(err, ErrAPIKeyInvalid) {
		t.Fatalf("deactivated owner: want ErrAPIKeyInvalid, got %v", err)
	}
}

func TestVerifyAPIKeyDeniedAfterEpochBump(t *testing.T) {
	defer SetHMACKey(nil)
	SetHMACKey([]byte("test-key-do-not-use"))
	db := newAPIKeyTestDB(t)
	token, userID := newTestKey(t, db, "admin", 3)

	if _, _, _, _, err := VerifyAPIKey(context.Background(), db, token, ""); err != nil {
		t.Fatalf("key should work before the bump: %v", err)
	}
	// What a role change / reseller suspend does inside its transaction.
	if _, err := db.Exec("UPDATE users SET role = 'client', auth_epoch = auth_epoch + 1 WHERE id = ?", userID); err != nil {
		t.Fatalf("bump: %v", err)
	}
	if _, _, _, _, err := VerifyAPIKey(context.Background(), db, token, ""); !errors.Is(err, ErrAPIKeyInvalid) {
		t.Fatalf("after epoch bump: want ErrAPIKeyInvalid, got %v", err)
	}
}

func TestVerifyAPIKeyDeniedWhenUserDeleted(t *testing.T) {
	defer SetHMACKey(nil)
	SetHMACKey([]byte("test-key-do-not-use"))
	db := newAPIKeyTestDB(t)
	token, userID := newTestKey(t, db, "admin", 0)

	if _, err := db.Exec("DELETE FROM users WHERE id = ?", userID); err != nil {
		t.Fatalf("delete user: %v", err)
	}
	if _, _, _, _, err := VerifyAPIKey(context.Background(), db, token, ""); !errors.Is(err, ErrAPIKeyInvalid) {
		t.Fatalf("deleted owner: want ErrAPIKeyInvalid, got %v", err)
	}
}

// An unreadable database must surface as an error (the caller denies), never as
// a silent pass.
func TestVerifyAPIKeyDBErrorDenies(t *testing.T) {
	defer SetHMACKey(nil)
	SetHMACKey([]byte("test-key-do-not-use"))
	db := newAPIKeyTestDB(t)
	token, _ := newTestKey(t, db, "admin", 0)

	db.Close()
	uid, _, role, _, err := VerifyAPIKey(context.Background(), db, token, "")
	if err == nil {
		t.Fatal("closed db: want error, got nil")
	}
	if uid != 0 || role != "" {
		t.Fatalf("closed db leaked a principal: uid=%d role=%q", uid, role)
	}
}

// A key issued while the owner's epoch was already non-zero must carry that
// epoch, not 0.
func TestCreateAPIKeyStampsCurrentEpoch(t *testing.T) {
	defer SetHMACKey(nil)
	SetHMACKey([]byte("test-key-do-not-use"))
	db := newAPIKeyTestDB(t)
	_, userID := newTestKey(t, db, "admin", 9)

	var stamped int64
	if err := db.QueryRow("SELECT auth_epoch FROM api_keys WHERE user_id = ?", userID).Scan(&stamped); err != nil {
		t.Fatalf("read stamp: %v", err)
	}
	if stamped != 9 {
		t.Fatalf("stamped epoch = %d, want 9", stamped)
	}
}
