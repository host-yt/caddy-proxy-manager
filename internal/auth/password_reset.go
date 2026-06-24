package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// ResetTokenTTL is how long a password reset link stays valid.
const ResetTokenTTL = 30 * time.Minute

var ErrResetTokenInvalid = errors.New("reset token invalid or expired")

// CreateResetToken issues a one-time reset token for userID. Returns the
// plaintext token (only shown in the email) and stores its sha256 hash.
func CreateResetToken(ctx context.Context, db *sql.DB, userID int64, ip string) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	plain := base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(plain))
	hashHex := hex.EncodeToString(sum[:])
	expires := time.Now().UTC().Add(ResetTokenTTL)
	var ipVal sql.NullString
	if ip != "" {
		ipVal = sql.NullString{String: ip, Valid: true}
	}
	if _, err := db.ExecContext(ctx,
		"INSERT INTO password_resets (user_id, token_hash, expires_at, ip) VALUES (?, ?, ?, ?)",
		userID, hashHex, expires, ipVal,
	); err != nil {
		return "", fmt.Errorf("insert reset: %w", err)
	}
	return plain, nil
}

// ConsumeResetToken verifies the token, marks it used, and returns the user_id.
func ConsumeResetToken(ctx context.Context, db *sql.DB, plain string) (int64, error) {
	sum := sha256.Sum256([]byte(plain))
	hashHex := hex.EncodeToString(sum[:])
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback() //nolint:errcheck

	var id int64
	var userID int64
	// FOR UPDATE row-locks the token so two concurrent requests with the same
	// token can't both pass the SELECT before either UPDATE commits (strict
	// single-use).
	err = tx.QueryRowContext(ctx,
		`SELECT id, user_id FROM password_resets
		 WHERE token_hash = ? AND used_at IS NULL AND expires_at > NOW() LIMIT 1 FOR UPDATE`,
		hashHex,
	).Scan(&id, &userID)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrResetTokenInvalid
	}
	if err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE password_resets SET used_at = NOW() WHERE id = ?", id); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return userID, nil
}
