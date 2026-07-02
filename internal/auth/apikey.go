package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// API key format: hpg_<8charprefix>_<32bytebase64>
//
// Verification path is on every authenticated REST request, so it must be
// cheap. We use HMAC-SHA256 keyed with APP_SECRET (the same value HKDF-fed
// into installstate.Manager); ~microseconds per verify vs ~150 ms for
// Argon2id. Bearer tokens already carry ≥192 bits of entropy, so HMAC's
// preimage resistance is the only property we need.
//
// Legacy rows that have only the Argon2id hash (`key_hash`) still verify via
// the slow path and are auto-rehashed to `key_hmac` on first use.

var ErrAPIKeyInvalid = errors.New("api key invalid")

// HMACKey is the runtime key used by HMAC-SHA256 verification. Set by
// main.go from APP_SECRET. Empty disables HMAC fast-path (legacy Argon2id
// only).
var HMACKey []byte

// SetHMACKey wires the verification key. Safe to call once at startup.
func SetHMACKey(k []byte) { HMACKey = k }

func hmacHex(secret string) string {
	if len(HMACKey) == 0 {
		return ""
	}
	mac := hmac.New(sha256.New, HMACKey)
	mac.Write([]byte(secret))
	return hex.EncodeToString(mac.Sum(nil))
}

// CreateAPIKey issues a new key for userID with the supplied name + scopes.
// Returns the plaintext key (shown ONCE to the user) and DB id.
func CreateAPIKey(ctx context.Context, db *sql.DB, userID int64, name, scopes string) (plain string, id int64, prefix string, err error) {
	prefixBytes := make([]byte, 6)
	if _, err := rand.Read(prefixBytes); err != nil {
		return "", 0, "", err
	}
	prefix = base64.RawURLEncoding.EncodeToString(prefixBytes)[:8]

	secretBytes := make([]byte, 32)
	if _, err := rand.Read(secretBytes); err != nil {
		return "", 0, "", err
	}
	secret := base64.RawURLEncoding.EncodeToString(secretBytes)
	plain = fmt.Sprintf("hpg_%s_%s", prefix, secret)

	// Argon2id for back-compat (legacy verify path).
	hash, err := HashPassword(secret)
	if err != nil {
		return "", 0, "", err
	}
	mac := hmacHex(secret)

	// Retry on UNIQUE-prefix collision (migration 00008 added the constraint).
	// 48-bit prefix means collisions are vanishingly rare in practice, but
	// the loop makes correctness obvious to a reader.
	var res sql.Result
	for attempt := 0; attempt < 5; attempt++ {
		res, err = db.ExecContext(ctx,
			"INSERT INTO api_keys (user_id, name, key_prefix, key_hash, key_hmac, scopes) VALUES (?, ?, ?, ?, ?, ?)",
			userID, name, prefix, hash, nullableStr(mac), scopes)
		if err == nil {
			break
		}
		if !strings.Contains(err.Error(), "Duplicate") {
			return "", 0, "", err
		}
		// Regenerate prefix + plain on collision.
		_, _ = rand.Read(prefixBytes)
		prefix = base64.RawURLEncoding.EncodeToString(prefixBytes)[:8]
		plain = fmt.Sprintf("hpg_%s_%s", prefix, secret)
	}
	if err != nil {
		return "", 0, "", err
	}
	id, _ = res.LastInsertId()
	return plain, id, prefix, nil
}

// VerifyAPIKey parses, looks up, and verifies a bearer token.
// clientIP is recorded in last_used_ip; pass "" to leave it unchanged.
// On success returns the owning user id, role, and the key's comma-separated
// scopes (empty string = unscoped / full access, for keys issued before scope
// enforcement existed).
func VerifyAPIKey(ctx context.Context, db *sql.DB, token, clientIP string) (userID int64, role, scopes string, err error) {
	token = strings.TrimSpace(token)
	if !strings.HasPrefix(token, "hpg_") {
		return 0, "", "", ErrAPIKeyInvalid
	}
	parts := strings.SplitN(strings.TrimPrefix(token, "hpg_"), "_", 2)
	if len(parts) != 2 || len(parts[0]) != 8 || parts[1] == "" {
		return 0, "", "", ErrAPIKeyInvalid
	}
	prefix, secret := parts[0], parts[1]

	var (
		id, uid  int64
		hash     string
		hmacCol  sql.NullString
		scopeCol sql.NullString
		revoked  sql.NullTime
		expires  sql.NullTime
	)
	err = db.QueryRowContext(ctx,
		`SELECT id, user_id, key_hash, key_hmac, scopes, revoked_at, expires_at FROM api_keys WHERE key_prefix = ? LIMIT 1`,
		prefix,
	).Scan(&id, &uid, &hash, &hmacCol, &scopeCol, &revoked, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, "", "", ErrAPIKeyInvalid
	}
	if err != nil {
		return 0, "", "", err
	}
	if revoked.Valid {
		return 0, "", "", ErrAPIKeyInvalid
	}
	if expires.Valid && time.Now().UTC().After(expires.Time) {
		return 0, "", "", ErrAPIKeyInvalid
	}
	scopes = scopeCol.String

	// Fast path: constant-time HMAC compare.
	if hmacCol.Valid && hmacCol.String != "" && len(HMACKey) > 0 {
		want, derr := hex.DecodeString(hmacCol.String)
		got, gerr := hex.DecodeString(hmacHex(secret))
		if derr == nil && gerr == nil && subtle.ConstantTimeCompare(want, got) == 1 {
			finalizeAPIKey(ctx, db, id, uid, secret, hmacCol.String, clientIP)
			role, err = lookupRole(ctx, db, uid)
			return uid, role, scopes, err
		}
		// HMAC present + mismatch → still try Argon2id below in case the
		// stored HMAC was written with a different key (post-rotation).
	}

	// Legacy slow path: Argon2id from key_hash. On success, write key_hmac
	// so the next call uses the fast path.
	if err := VerifyPassword(hash, secret); err != nil {
		return 0, "", "", ErrAPIKeyInvalid
	}
	finalizeAPIKey(ctx, db, id, uid, secret, "", clientIP)
	role, err = lookupRole(ctx, db, uid)
	return uid, role, scopes, err
}

func finalizeAPIKey(ctx context.Context, db *sql.DB, id, uid int64, secret, existingHMAC, clientIP string) {
	if clientIP != "" {
		_, _ = db.ExecContext(ctx,
			"UPDATE api_keys SET last_used_at=NOW(), last_used_ip=?, use_count=use_count+1 WHERE id=?", clientIP, id)
	} else {
		_, _ = db.ExecContext(ctx, "UPDATE api_keys SET last_used_at=NOW(), use_count=use_count+1 WHERE id=?", id)
	}
	if len(HMACKey) == 0 {
		return
	}
	mac := hmacHex(secret)
	if mac == existingHMAC {
		return
	}
	_, _ = db.ExecContext(ctx, "UPDATE api_keys SET key_hmac = ? WHERE id = ?", mac, id)
}

func lookupRole(ctx context.Context, db *sql.DB, uid int64) (string, error) {
	var role string
	err := db.QueryRowContext(ctx, "SELECT role FROM users WHERE id = ?", uid).Scan(&role)
	return role, err
}

func nullableStr(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}
