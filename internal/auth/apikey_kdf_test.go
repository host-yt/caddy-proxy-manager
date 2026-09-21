package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"
)

// cheapArgonHash encodes an Argon2id hash with the lowest parameters
// VerifyPassword accepts, so a test can exercise the compat path without
// paying 64 MiB and 150 ms per attempt.
func cheapArgonHash(t *testing.T, secret string) string {
	t.Helper()
	salt := []byte("0123456789abcdef")
	h := argon2.IDKey([]byte(secret), salt, 1, minArgonMemory, 1, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, minArgonMemory, 1, 1,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(h))
}

func secretOf(t *testing.T, token string) string {
	t.Helper()
	rest := strings.TrimPrefix(token, "hpg_")
	return rest[9:]
}

// HPG-017: a stored HMAC is the verdict. The old code fell through to Argon2id
// on every HMAC miss, which both accepted a secret the authoritative HMAC
// rejects and let anyone holding a known prefix force unbounded KDF work.
func TestVerifyAPIKeyStoredHMACIsAuthoritative(t *testing.T) {
	defer SetHMACKey(nil)
	SetHMACKey([]byte("test-key-do-not-use"))
	db := newAPIKeyTestDB(t)
	token, _ := newTestKey(t, db, "admin", 0)

	// key_hash now matches a DIFFERENT secret than key_hmac does. Only the
	// Argon2 fallback could ever accept it.
	const attacker = "wrong-secret-entirely"
	if _, err := db.Exec("UPDATE api_keys SET key_hash = ?", cheapArgonHash(t, attacker)); err != nil {
		t.Fatalf("seed hash: %v", err)
	}
	prefix := strings.TrimPrefix(token, "hpg_")[:8]
	bad := "hpg_" + prefix + "_" + attacker

	if _, _, _, _, err := VerifyAPIKey(context.Background(), db, bad, ""); !errors.Is(err, ErrAPIKeyInvalid) {
		t.Fatalf("secret rejected by key_hmac was accepted via the Argon2 fallback: err=%v", err)
	}
	// The real secret still verifies.
	if _, _, _, _, err := VerifyAPIKey(context.Background(), db, token, ""); err != nil {
		t.Fatalf("valid key denied: %v", err)
	}
}

// HPG-017: the compat path (no usable HMAC on the row) is the only way left to
// reach Argon2 pre-auth, so it gets a budget of its own. Past it the answer is
// a throttle, not another 64 MiB of uncancellable work.
func TestVerifyAPIKeyLegacyKDFIsBudgeted(t *testing.T) {
	defer SetHMACKey(nil)
	SetHMACKey([]byte("test-key-do-not-use"))
	legacyKDF = newKDFBudget(legacyKDFConcurrency) // fresh window for this test
	defer func() { legacyKDF = newKDFBudget(legacyKDFConcurrency) }()

	db := newAPIKeyTestDB(t)
	token, _ := newTestKey(t, db, "admin", 0)
	secret := secretOf(t, token)
	// Legacy row: Argon2id only, exactly what a pre-HMAC key or a post
	// rotate-secret row looks like.
	if _, err := db.Exec("UPDATE api_keys SET key_hmac = NULL, key_hash = ?", cheapArgonHash(t, secret)); err != nil {
		t.Fatalf("seed legacy row: %v", err)
	}
	prefix := strings.TrimPrefix(token, "hpg_")[:8]
	bad := "hpg_" + prefix + "_not-the-secret"

	for i := 0; i < legacyKDFPerPrefix; i++ {
		if _, _, _, _, err := VerifyAPIKey(context.Background(), db, bad, ""); !errors.Is(err, ErrAPIKeyInvalid) {
			t.Fatalf("attempt %d: want ErrAPIKeyInvalid, got %v", i, err)
		}
	}
	if _, _, _, _, err := VerifyAPIKey(context.Background(), db, bad, ""); !errors.Is(err, ErrAPIKeyThrottled) {
		t.Fatalf("over-budget attempt still ran the KDF: err=%v", err)
	}
}

// A legacy key that is actually valid must keep working - and get upgraded to
// the HMAC fast path so it never pays the KDF again.
func TestVerifyAPIKeyLegacyValidKeyStillWorks(t *testing.T) {
	defer SetHMACKey(nil)
	SetHMACKey([]byte("test-key-do-not-use"))
	legacyKDF = newKDFBudget(legacyKDFConcurrency)
	defer func() { legacyKDF = newKDFBudget(legacyKDFConcurrency) }()

	db := newAPIKeyTestDB(t)
	token, userID := newTestKey(t, db, "admin", 0)
	if _, err := db.Exec("UPDATE api_keys SET key_hmac = NULL, key_hash = ?", cheapArgonHash(t, secretOf(t, token))); err != nil {
		t.Fatalf("seed legacy row: %v", err)
	}
	uid, _, _, _, err := VerifyAPIKey(context.Background(), db, token, "")
	if err != nil || uid != userID {
		t.Fatalf("legacy key denied: uid=%d err=%v", uid, err)
	}
	var mac any
	if err := db.QueryRow("SELECT key_hmac FROM api_keys WHERE user_id = ?", userID).Scan(&mac); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if mac == nil {
		t.Fatal("legacy key was not upgraded to the HMAC fast path")
	}
}
