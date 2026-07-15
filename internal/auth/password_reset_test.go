package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

// openTestDB opens a real DB via TEST_DB_DSN or skips. ConsumeResetToken
// relies on MySQL-specific NOW()/FOR UPDATE, so this can't run against
// sqlite - same TEST_DB_DSN convention as internal/wafevents and friends.
func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("TEST_DB_DSN")
	if dsn == "" {
		t.Skip("TEST_DB_DSN not set - skipping DB-backed test")
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		t.Skipf("DB not reachable: %v", err)
	}
	return db
}

// insertResetTestUser creates a throwaway user row to satisfy the
// password_resets.user_id foreign key, and returns a cleanup func.
func insertResetTestUser(t *testing.T, db *sql.DB) (int64, func()) {
	t.Helper()
	ctx := context.Background()
	email := fmt.Sprintf("resettest_%d@example.com", time.Now().UnixNano())
	res, err := db.ExecContext(ctx,
		`INSERT INTO users (email, password_hash, role) VALUES (?, 'x', 'client')`, email)
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}
	uid, _ := res.LastInsertId()
	return uid, func() {
		_, _ = db.ExecContext(ctx, "DELETE FROM password_resets WHERE user_id = ?", uid)
		_, _ = db.ExecContext(ctx, "DELETE FROM users WHERE id = ?", uid)
	}
}

// TestPasswordResetTokenSingleUseAndExpiry proves two invariants: a reset
// token can be consumed exactly once (replay must fail), and an expired
// token is rejected even though it was never consumed.
func TestPasswordResetTokenSingleUseAndExpiry(t *testing.T) {
	db := openTestDB(t)
	defer db.Close()
	ctx := context.Background()

	userID, cleanup := insertResetTestUser(t, db)
	defer cleanup()

	plain, err := CreateResetToken(ctx, db, userID, "203.0.113.1")
	if err != nil {
		t.Fatalf("CreateResetToken: %v", err)
	}

	// First consume must succeed and return the owning user.
	gotUser, err := ConsumeResetToken(ctx, db, plain)
	if err != nil {
		t.Fatalf("first ConsumeResetToken: %v", err)
	}
	if gotUser != userID {
		t.Fatalf("consumed token resolved to user %d, want %d", gotUser, userID)
	}

	// Replay of the same plaintext token must fail - single-use enforcement.
	if _, err := ConsumeResetToken(ctx, db, plain); !errors.Is(err, ErrResetTokenInvalid) {
		t.Fatalf("replayed token: got err=%v, want ErrResetTokenInvalid", err)
	}

	// A freshly issued but already-expired token must also be rejected.
	expiredPlain, err := CreateResetToken(ctx, db, userID, "203.0.113.1")
	if err != nil {
		t.Fatalf("CreateResetToken(expired): %v", err)
	}
	if _, err := db.ExecContext(ctx,
		"UPDATE password_resets SET expires_at = ? WHERE user_id = ? AND used_at IS NULL",
		time.Now().UTC().Add(-time.Minute), userID,
	); err != nil {
		t.Fatalf("force-expire token: %v", err)
	}
	if _, err := ConsumeResetToken(ctx, db, expiredPlain); !errors.Is(err, ErrResetTokenInvalid) {
		t.Fatalf("expired token: got err=%v, want ErrResetTokenInvalid", err)
	}
}

// TestResetTokenSurvivesNonUTCServerTimezone pins the fix for tokens that were
// born expired: CreateResetToken used to store a Go-side UTC expiry while
// ConsumeResetToken compared it against the DB's local NOW(). On a server ahead
// of UTC that made every reset link dead on arrival (a 30-minute token on a
// CEST server expired 90 minutes before it was issued). The session timezone is
// forced ahead of UTC here so a regression fails regardless of the host's clock.
func TestResetTokenSurvivesNonUTCServerTimezone(t *testing.T) {
	db := openTestDB(t)
	defer db.Close()
	ctx := context.Background()

	if _, err := db.ExecContext(ctx, "SET SESSION time_zone = '+05:00'"); err != nil {
		t.Skipf("cannot set session time_zone: %v", err)
	}

	userID, cleanup := insertResetTestUser(t, db)
	defer cleanup()

	plain, err := CreateResetToken(ctx, db, userID, "203.0.113.9")
	if err != nil {
		t.Fatalf("CreateResetToken: %v", err)
	}
	gotUser, err := ConsumeResetToken(ctx, db, plain)
	if err != nil {
		t.Fatalf("token issued on a UTC+5 server was not consumable: %v", err)
	}
	if gotUser != userID {
		t.Fatalf("consumed token resolved to user %d, want %d", gotUser, userID)
	}
}
