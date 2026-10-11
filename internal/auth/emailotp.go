package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// Email OTP shares SMS OTP code generation + hashing primitives — only the
// transport differs. Redis ticket TTL mirrors SMS for UX consistency.
const EmailOTPTTLSeconds = 600 // 10 min (email delivery latency tolerant)

// GenerateEmailOTP returns a zero-padded 6-digit code (reuses SMS impl).
func GenerateEmailOTP() (string, error) { return GenerateSMSOTP() }

// EmailOTPHash reuses the SMS OTP SHA-256 hash.
func EmailOTPHash(code string) string { return SMSOTPHash(code) }

// StoreEmailOTP stashes a SHA-256 hash in Redis; returns an opaque ticket.
func StoreEmailOTP(ctx context.Context, rdb *redis.Client, userID int64, code string) (string, error) {
	raw := make([]byte, 18)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	ticket := base64.RawURLEncoding.EncodeToString(raw)
	key := fmt.Sprintf("hpg:emailotp:%s", ticket)
	val := fmt.Sprintf("%d:%s", userID, EmailOTPHash(code))
	return ticket, rdb.Set(ctx, key, val, EmailOTPTTLSeconds*time.Second).Err()
}

// VerifyEmailOTP verifies the code, deletes the ticket on success, returns userID.
func VerifyEmailOTP(ctx context.Context, rdb *redis.Client, ticket, code string) (int64, error) {
	return verifyOTP(ctx, rdb, "emailotp", ticket, code)
}
