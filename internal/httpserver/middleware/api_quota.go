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
// Implementation: bucket key `hpg:apikey:rl:<key_id>:<yyyymmddhhmm>` with
// 70s expiry. Atomic incr; reject when > cap. The cap value is cached in
// Redis for 5 minutes per key to avoid a DB hit on every request. Bucket and
// cap are keyed on the API key ID (not the user) so one key's high limit does
// not raise the limit for the user's other keys.
func APIQuota(rdb *redis.Client, db func() *sql.DB) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if rdb == nil {
				next.ServeHTTP(w, r)
				return
			}
			c := CallerFromContext(r.Context())
			if c == nil || c.KeyID == 0 {
				next.ServeHTTP(w, r)
				return
			}
			ctx, cancel := context.WithTimeout(r.Context(), 200*time.Millisecond)
			defer cancel()
			cap_, err := lookupQuota(ctx, rdb, db, c.KeyID)
			if err != nil || cap_ <= 0 {
				next.ServeHTTP(w, r)
				return
			}
			now := time.Now().UTC()
			bucket := "hpg:apikey:rl:" + strconv.FormatInt(c.KeyID, 10) + ":" + now.Format("200601021504")
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

func lookupQuota(ctx context.Context, rdb *redis.Client, db func() *sql.DB, keyID int64) (int, error) {
	key := "hpg:apikey:cap:" + strconv.FormatInt(keyID, 10)
	if v, err := rdb.Get(ctx, key).Result(); err == nil {
		n, _ := strconv.Atoi(v)
		return n, nil
	}
	d := db()
	if d == nil {
		return 0, nil
	}
	var rpm int
	row := d.QueryRowContext(ctx,
		`SELECT COALESCE(rate_limit_rpm, 0) FROM api_keys
		 WHERE id = ? AND revoked_at IS NULL`, keyID)
	if err := row.Scan(&rpm); err != nil {
		return 0, err
	}
	_ = rdb.Set(ctx, key, strconv.Itoa(rpm), 5*time.Minute).Err()
	return rpm, nil
}
