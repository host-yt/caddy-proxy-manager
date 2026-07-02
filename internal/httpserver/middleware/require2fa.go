package middleware

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// graceTTL keeps a per-user grace deadline long enough that it can't silently
// reset and re-grant a fresh window on each restart.
const graceTTL = 60 * 24 * time.Hour

// RequireAdmin2FA redirects admin/super_admin users who have no 2FA method
// enrolled to a setup interstitial. It bypasses itself on enrollment + logout
// routes (no redirect loop) and during impersonation. graceHours > 0 gives an
// existing admin a break-glass window after enforcement first applies to them,
// so flipping the policy on doesn't instantly lock anyone out.
func RequireAdmin2FA(db func() *sql.DB, rdb *redis.Client, enabled func() bool, graceHours int) func(http.Handler) http.Handler {
	bypass := []string{"/admin/2fa", "/admin/passkeys", "/auth/logout"}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if enabled == nil || !enabled() {
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
// window. The deadline is fixed on first encounter (persisted) so it cannot
// reset on restart and keep granting access forever.
func within2FAGrace(ctx context.Context, rdb *redis.Client, userID int64, graceHours int) bool {
	if rdb == nil {
		return false
	}
	key := fmt.Sprintf("hpg:2fa:grace_until:%d", userID)
	if v, err := rdb.Get(ctx, key).Result(); err == nil {
		deadline, perr := strconv.ParseInt(v, 10, 64)
		return perr == nil && time.Now().Unix() < deadline
	}
	// First encounter under enforcement: open the window once.
	deadline := time.Now().Add(time.Duration(graceHours) * time.Hour).Unix()
	_ = rdb.Set(ctx, key, strconv.FormatInt(deadline, 10), graceTTL).Err()
	return true
}

// InvalidateAdmin2FACache drops the enrollment cache after a 2FA method is
// added or removed so the middleware re-reads the DB on the next request.
func InvalidateAdmin2FACache(ctx context.Context, rdb *redis.Client, userID int64) {
	if rdb == nil {
		return
	}
	_ = rdb.Del(ctx, fmt.Sprintf("hpg:2fa:enrolled:%d", userID)).Err()
}
