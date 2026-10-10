package middleware

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
)

// RequireAdmin2FA redirects admin/super_admin users who have no 2FA method
// enrolled to a setup interstitial. It bypasses itself on enrollment + logout
// routes (no redirect loop) and during impersonation. graceHours > 0 gives an
// existing admin a break-glass window after enforcement first applies to them,
// so flipping the policy on doesn't instantly lock anyone out. enabled
// returning an error means the policy is unknown: the request gets a 503 and
// no grace window is started.
func RequireAdmin2FA(db func() *sql.DB, rdb *redis.Client, enabled func() (bool, error), graceHours int) func(http.Handler) http.Handler {
	bypass := []string{"/admin/2fa", "/admin/passkeys", "/auth/logout"}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if enabled == nil {
				next.ServeHTTP(w, r)
				return
			}
			sess := SessionFromContext(r.Context())
			if sess == nil || sess.ImpersonatorUserID > 0 ||
				(sess.Role != "admin" && sess.Role != "super_admin" && sess.Role != "reseller") {
				next.ServeHTTP(w, r)
				return
			}
			p := r.URL.Path
			for _, pfx := range bypass {
				if p == pfx || strings.HasPrefix(p, pfx+"/") {
					next.ServeHTTP(w, r)
					return
				}
			}
			on, err := enabled()
			if err != nil {
				http.Error(w, "2FA policy unavailable, retry shortly", http.StatusServiceUnavailable)
				return
			}
			if !on {
				next.ServeHTTP(w, r)
				return
			}
			if admin2FAEnrolled(r.Context(), db(), rdb, sess.UserID) {
				next.ServeHTTP(w, r)
				return
			}
			if graceHours > 0 && within2FAGrace(r.Context(), rdb, sess.UserID, graceHours) {
				next.ServeHTTP(w, r)
				return
			}
			if rdb != nil {
				_ = rdb.Set(r.Context(), fmt.Sprintf("hpg:2fa:setup_next:%d", sess.UserID), r.URL.RequestURI(), 10*time.Minute).Err()
			}
			http.Redirect(w, r, "/admin/2fa/required", http.StatusSeeOther)
		})
	}
}

// admin2FALastOn remembers the last successfully read runtime policy so a
// transient DB error keeps enforcing once 2FA has been seen enabled.
var admin2FALastOn atomic.Bool

// Admin2FAPolicy turns the result of reading security.require_admin_2fa into
// a decision. sql.ErrNoRows is the only "off" default; any other error fails
// closed: enforce if the policy was last seen on, else report it as unknown.
func Admin2FAPolicy(on bool, err error) (bool, error) {
	switch {
	case err == nil:
		admin2FALastOn.Store(on)
		return on, nil
	case errors.Is(err, sql.ErrNoRows):
		admin2FALastOn.Store(false)
		return false, nil
	case admin2FALastOn.Load():
		return true, nil
	default:
		return false, fmt.Errorf("reading 2FA policy: %w", err)
	}
}

// admin2FAEnrolled reports whether the user has any 2FA method active. Result
// is Redis-cached for 60s so admin page loads don't each hit the DB.
func admin2FAEnrolled(ctx context.Context, db *sql.DB, rdb *redis.Client, userID int64) bool {
	key := fmt.Sprintf("hpg:2fa:enrolled:%d", userID)
	if rdb != nil {
		if v, err := rdb.Get(ctx, key).Result(); err == nil {
			return v == "1"
		}
	}
	if db == nil {
		return false
	}
	var totp, sms, email bool
	var passkeys int
	_ = db.QueryRowContext(ctx, `
		SELECT totp_enabled, sms_otp_enabled, email_otp_enabled,
		       (SELECT COUNT(*) FROM webauthn_credentials WHERE user_id = u.id)
		FROM users u WHERE u.id = ?`, userID).Scan(&totp, &sms, &email, &passkeys)
	enrolled := totp || sms || email || passkeys > 0
	if rdb != nil {
		v := "0"
		if enrolled {
			v = "1"
		}
		_ = rdb.Set(ctx, key, v, 60*time.Second).Err()
	}
	return enrolled
}

// within2FAGrace returns true while the user is inside their break-glass
// window. The deadline is created once (SET NX, no TTL) and kept after it
// passes, so an unenrolled admin never gets a second window. Any Redis error
// denies grace.
// ponytail: Redis eviction of the key would re-grant once; move the deadline
// to a users column if the instance runs an evicting maxmemory-policy.
func within2FAGrace(ctx context.Context, rdb *redis.Client, userID int64, graceHours int) bool {
	if rdb == nil {
		return false
	}
	key := fmt.Sprintf("hpg:2fa:grace_until:%d", userID)
	v, err := rdb.Get(ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		deadline := strconv.FormatInt(time.Now().Add(time.Duration(graceHours)*time.Hour).Unix(), 10)
		created, serr := rdb.SetNX(ctx, key, deadline, 0).Result()
		if serr != nil {
			return false
		}
		if created {
			return true
		}
		v, err = rdb.Get(ctx, key).Result() // lost the race: use the winner's deadline
	}
	if err != nil {
		return false
	}
	// Strip the 60-day TTL older releases set, so the key can't expire and re-grant.
	_ = rdb.Persist(ctx, key).Err()
	deadline, perr := strconv.ParseInt(v, 10, 64)
	return perr == nil && time.Now().Unix() < deadline
}

// InvalidateAdmin2FACache drops the enrollment cache after a 2FA method is
// added or removed so the middleware re-reads the DB on the next request.
func InvalidateAdmin2FACache(ctx context.Context, rdb *redis.Client, userID int64) {
	if rdb == nil {
		return
	}
	_ = rdb.Del(ctx, fmt.Sprintf("hpg:2fa:enrolled:%d", userID)).Err()
}
