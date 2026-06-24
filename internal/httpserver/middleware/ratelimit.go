package middleware

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/hostyt/proxy-gateway/internal/security"
)

// RateLimitConfig caps requests per source IP per minute. When RDB is
// nil the middleware is a no-op (test/dev environments without Redis).
type RateLimitConfig struct {
	RDB         *redis.Client
	PerIPPerMin int    // requests allowed per source IP per minute
	KeyPrefix   string // Redis key namespace, e.g. "hpg:rl:public"
	// SkipFn returns true to bypass the limit for a given request
	// (e.g. authenticated admin sessions, internal health checks).
	SkipFn func(*http.Request) bool
}

// RateLimit returns a middleware that 429s any source IP exceeding the
// configured threshold within a rolling 60s window. Implementation:
// Redis INCR + EXPIRE on hpg:rl:<prefix>:<ip>, fail-open if Redis is
// down (we don't want to take the whole panel down on a Redis blip).
func RateLimit(cfg RateLimitConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if cfg.RDB == nil || cfg.PerIPPerMin <= 0 {
				next.ServeHTTP(w, r)
				return
			}
			if cfg.SkipFn != nil && cfg.SkipFn(r) {
				next.ServeHTTP(w, r)
				return
			}
			ip := security.ClientIP(r)
			key := cfg.KeyPrefix + ":" + ip
			ctx, cancel := context.WithTimeout(r.Context(), 200*time.Millisecond)
			defer cancel()
			n, err := cfg.RDB.Incr(ctx, key).Result()
			if err != nil {
				// Fail-open: a Redis blip should not 429 every request.
				next.ServeHTTP(w, r)
				return
			}
			if n == 1 {
				_ = cfg.RDB.Expire(ctx, key, time.Minute).Err()
			}
			if int(n) > cfg.PerIPPerMin {
				w.Header().Set("Retry-After", "60")
				http.Error(w, "rate limited", http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// UnauthPostLimit is a convenience wrapper for the common pattern of
// rate-limiting only non-authenticated POSTs (login, password reset,
// public form submissions). Authenticated sessions are skipped via the
// admin session cookie check.
func UnauthPostLimit(rdb *redis.Client, perMin int) func(http.Handler) http.Handler {
	return RateLimit(RateLimitConfig{
		RDB:         rdb,
		PerIPPerMin: perMin,
		KeyPrefix:   "hpg:rl:unauth-post",
		SkipFn: func(r *http.Request) bool {
			if r.Method != http.MethodPost {
				return true
			}
			// Skip passkey login challenge generation: it's a benign
			// stateless op (returns a fresh assertion request) and has
			// no credential-leak surface, so it doesn't need the same
			// throttle as /auth/login. Without this a single user can
			// burn the global budget by retrying passkey login a few
			// times in a row.
			if r.URL.Path == "/auth/passkey/login/begin" {
				return true
			}
			// Skip when an admin/client session cookie is present (any
			// cookie name starting with "hpg_session"). Wrong-skip is
			// safe: authed users hit their own per-handler rate limits.
			// Also skip mid-2FA POSTs (hpg_2fa_pending cookie): the
			// per-ticket OTP attempt cap already bounds those - without
			// this, a NAT'd source can 429 the user out of /auth/2fa
			// after a couple of wrong codes + page reloads.
			for _, c := range r.Cookies() {
				if strings.HasPrefix(c.Name, "hpg_session") {
					return true
				}
				if c.Name == "hpg_2fa_pending" && c.Value != "" {
					return true
				}
			}
			return false
		},
	})
}
