package auth

import (
	"testing"
)

// TestHMACFastPath exercises the constant-time HMAC compare used by the
// VerifyAPIKey fast path. We don't need a real DB to test the hashing — it's
// a pure function of secret + key.
func TestHMACFastPath(t *testing.T) {
	defer SetHMACKey(nil)
	SetHMACKey([]byte("test-key-do-not-use"))
	a := hmacHex("secret-1")
	b := hmacHex("secret-1")
	c := hmacHex("secret-2")
	if a == "" {
		t.Fatal("empty mac with key set")
	}
	if a != b {
		t.Fatal("same secret produced different macs")
	}
	if a == c {
		t.Fatal("different secrets collided")
	}
}

func TestHMACDisabledWithoutKey(t *testing.T) {
	SetHMACKey(nil)
	if got := hmacHex("anything"); got != "" {
		t.Fatalf("expected empty mac with no key, got %q", got)
	}
}
