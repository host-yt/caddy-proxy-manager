package middleware

import (
	"context"
	"database/sql"
	"net/http"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// APIQuota enforces a per-key requests-per-minute cap via Redis INCR. Reads
// the per-key value from api_keys.rate_limit_rpm (NULL = no cap). Sits
// AFTER APIKeyAuth so CallerFromContext is populated.
//
// Implementation: bucket key `hpg:apikey:rl:<user_id>:<yyyymmddhhmm>` with
// 70s expiry. Atomic incr; reject when > cap. The cap value is cached in
// Redis for 5 minutes per user to avoid a DB hit on every request.
func APIQuota(rdb *redis.Client, db func() *sql.DB) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if rdb == nil {
				next.ServeHTTP(w, r)
				return
			}
			c := CallerFromContext(r.Context())
			if c == nil {
				next.ServeHTTP(w, r)
				return
			}
			ctx, cancel := context.WithTimeout(r.Context(), 200*time.Millisecond)
			defer cancel()
			cap_, err := lookupQuota(ctx, rdb, db, c.UserID)
			if err != nil || cap_ <= 0 {
				next.ServeHTTP(w, r)
				return
			}
			now := time.Now().UTC()
			bucket := "hpg:apikey:rl:" + strconv.FormatInt(c.UserID, 10) + ":" + now.Format("200601021504")
			n, err := rdb.Incr(ctx, bucket).Result()
			if err == nil {
				if n == 1 {
					_ = rdb.Expire(ctx, bucket, 70*time.Second).Err()
				}
				if int(n) > cap_ {
					w.Header().Set("Retry-After", "60")
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusTooManyRequests)
					_, _ = w.Write([]byte(`{"error":"rate_limit_exceeded","cap_rpm":` + strconv.Itoa(cap_) + `}`))
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

func lookupQuota(ctx context.Context, rdb *redis.Client, db func() *sql.DB, userID int64) (int, error) {
	key := "hpg:apikey:cap:" + strconv.FormatInt(userID, 10)
	if v, err := rdb.Get(ctx, key).Result(); err == nil {
		n, _ := strconv.Atoi(v)
		return n, nil
	}
	d := db()
	if d == nil {
		return 0, nil
	}
	var maxRPM int
	row := d.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(rate_limit_rpm), 0) FROM api_keys
		 WHERE user_id = ? AND revoked_at IS NULL`, userID)
	if err := row.Scan(&maxRPM); err != nil {
		return 0, err
	}
	_ = rdb.Set(ctx, key, strconv.Itoa(maxRPM), 5*time.Minute).Err()
	return maxRPM, nil
}
