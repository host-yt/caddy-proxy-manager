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
		// Stamp the owner's current epoch in the same statement: a privilege
		// change racing the insert must not mint a key that outlives it.
		res, err = db.ExecContext(ctx,
			"INSERT INTO api_keys (user_id, name, key_prefix, key_hash, key_hmac, scopes, auth_epoch) VALUES (?, ?, ?, ?, ?, ?, (SELECT auth_epoch FROM users WHERE id = ?))",
			userID, name, prefix, hash, nullableStr(mac), scopes, userID)
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
func VerifyAPIKey(ctx context.Context, db *sql.DB, token, clientIP string) (userID, keyID int64, role, scopes string, err error) {
	token = strings.TrimSpace(token)
	if !strings.HasPrefix(token, "hpg_") {
		return 0, 0, "", "", ErrAPIKeyInvalid
	}
	// Parse positionally: "hpg_" + 8-char prefix + "_" + secret. Splitting on
	// "_" instead was wrong, because the prefix is base64url and roughly one
	// key in eight contains a "_" - those keys parsed into a short prefix and
	// were rejected forever, at issue time, with no way to tell them from a
	// bad token. The rate-limit middleware already reads token[4:12].
	rest := strings.TrimPrefix(token, "hpg_")
	if len(rest) < 10 || rest[8] != '_' {
		return 0, 0, "", "", ErrAPIKeyInvalid
	}
	prefix, secret := rest[:8], rest[9:]
	if secret == "" {
		return 0, 0, "", "", ErrAPIKeyInvalid
	}

	var (
		id, uid   int64
		hash      string
		hmacCol   sql.NullString
		scopeCol  sql.NullString
		revoked   sql.NullTime
		expires   sql.NullTime
		keyEpoch  int64
		userEpoch int64
		active    bool
	)
	// One joined read carries the owner's live state too: role, activation and
	// authorization epoch, so no request pays a second round trip. The INNER
	// JOIN also makes a deleted owner a no-rows denial.
	err = db.QueryRowContext(ctx,
		`SELECT k.id, k.user_id, k.key_hash, k.key_hmac, k.scopes, k.revoked_at, k.expires_at, k.auth_epoch,
		        u.role, u.is_active, u.auth_epoch
		   FROM api_keys k JOIN users u ON u.id = k.user_id
		  WHERE k.key_prefix = ? LIMIT 1`,
		prefix,
	).Scan(&id, &uid, &hash, &hmacCol, &scopeCol, &revoked, &expires, &keyEpoch, &role, &active, &userEpoch)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, 0, "", "", ErrAPIKeyInvalid
	}
	if err != nil {
		// Indeterminate, never permissive: the caller denies on any error.
		return 0, 0, "", "", err
	}
	if revoked.Valid {
		return 0, 0, "", "", ErrAPIKeyInvalid
	}
	if expires.Valid && time.Now().UTC().After(expires.Time) {
		return 0, 0, "", "", ErrAPIKeyInvalid
	}
	// The key is a snapshot of the owner's privileges at issue time; any epoch
	// bump (role, scope, activation, reseller, password, delete) retires it.
	if !active || keyEpoch != userEpoch {
		return 0, 0, "", "", ErrAPIKeyInvalid
	}
	scopes = scopeCol.String

	// Fast path: constant-time HMAC compare.
	if hmacCol.Valid && hmacCol.String != "" && len(HMACKey) > 0 {
		want, derr := hex.DecodeString(hmacCol.String)
		got, gerr := hex.DecodeString(hmacHex(secret))
		if derr == nil && gerr == nil && subtle.ConstantTimeCompare(want, got) == 1 {
			finalizeAPIKey(ctx, db, id, uid, secret, hmacCol.String, clientIP)
			return uid, id, role, scopes, nil
		}
		// HMAC present + mismatch → still try Argon2id below in case the
		// stored HMAC was written with a different key (post-rotation).
	}

	// Legacy slow path: Argon2id from key_hash. On success, write key_hmac
	// so the next call uses the fast path.
	if err := VerifyPassword(hash, secret); err != nil {
		return 0, 0, "", "", ErrAPIKeyInvalid
	}
	finalizeAPIKey(ctx, db, id, uid, secret, "", clientIP)
	return uid, id, role, scopes, nil
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

func nullableStr(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}
