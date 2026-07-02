package handlers

import (
	"context"
	"testing"
)

// TestLoginRateLimitLockout covers the login brute-force lockout at the two
// points it's hermetically testable without a live Redis:
//  1. the fail-open contract (h.RDB == nil must never lock out or panic -
//     a Redis outage must not brick every login), and
//  2. the per-(email,IP) key derivation used as the actual lock trigger,
//     which must stay scoped per-IP (see loginFailIPLimit comment: a
//     per-email-only lock lets an attacker DoS a known admin address).
func TestLoginRateLimitLockout(t *testing.T) {
	h := &AuthHandlers{} // RDB is nil: simulates Redis unavailable
	ctx := context.Background()

	if h.locked(ctx, "admin@example.com", "203.0.113.1") {
		t.Fatal("fail-open: locked() must return false when Redis is unavailable")
	}

	// Must not panic across the full attempt cycle with no Redis backing.
	for i := 0; i < loginFailIPLimit+5; i++ {
		h.recordFail(ctx, "admin@example.com", "203.0.113.1")
	}
	if h.locked(ctx, "admin@example.com", "203.0.113.1") {
		t.Fatal("fail-open: repeated recordFail without Redis must not lock the account")
	}
	if got := h.emailFailCount(ctx, "admin@example.com"); got != 0 {
		t.Fatalf("emailFailCount without Redis = %d, want 0", got)
	}
	h.clearFails(ctx, "admin@example.com", "203.0.113.1") // must not panic
}

// TestLoginFailKeysScopedPerIP guards the key derivation itself: the hard
// lock bucket must be keyed per (email, IP), never per email alone, or a
// known admin email becomes a single-IP-free DoS vector (see P1-D-7).
func TestLoginFailKeysScopedPerIP(t *testing.T) {
	h := &AuthHandlers{}
	const email = "victim@example.com"

	keyA := h.failKeyEmailIP(email, "203.0.113.1")
	keyB := h.failKeyEmailIP(email, "198.51.100.7")
	if keyA == keyB {
		t.Fatalf("failKeyEmailIP must differ per source IP, got same key %q for both", keyA)
	}
	if keyA == h.failKeyEmail(email) {
		t.Fatal("per-(email,IP) key must not collide with the per-email-only key")
	}
}
