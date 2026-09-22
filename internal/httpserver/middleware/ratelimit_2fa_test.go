package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// testRedis connects to HPG_TEST_REDIS_ADDR (e.g. 127.0.0.1:6379) and skips
// when it is unset; the limiter's behaviour is only observable with Redis.
func testRedis(t *testing.T) *redis.Client {
	t.Helper()
	addr := os.Getenv("HPG_TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("HPG_TEST_REDIS_ADDR not set")
	}
	rdb := redis.NewClient(&redis.Options{Addr: addr})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := rdb.Ping(ctx).Err(); err != nil {
		t.Skipf("redis unavailable: %v", err)
	}
	t.Cleanup(func() { _ = rdb.Close() })
	return rdb
}

// A client-supplied hpg_2fa_pending cookie used to switch the unauthenticated
// POST limiter off for every path. Only a live ticket, on the 2FA endpoints,
// may be exempt now.
func TestUnauthPostLimitIgnoresForgedPending2FACookie(t *testing.T) {
	rdb := testRedis(t)
	ctx := context.Background()
	live := "live-ticket-" + time.Now().Format("150405.000000000")
	if err := rdb.Set(ctx, pending2FAKeyPrefix+live, "{}", time.Minute).Err(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rdb.Del(ctx, pending2FAKeyPrefix+live) })

	h := UnauthPostLimit(rdb, 2)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	post := func(path, cookie, ip string) int {
		req := httptest.NewRequest(http.MethodPost, path, nil)
		req.RemoteAddr = ip + ":1234"
		if cookie != "" {
			req.AddCookie(&http.Cookie{Name: "hpg_2fa_pending", Value: cookie})
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	cases := []struct {
		name, path, cookie string
		limited            bool
	}{
		{"forged cookie on /auth/forgot", "/auth/forgot", "x", true},
		{"live ticket off the 2FA paths", "/auth/forgot", live, true},
		{"forged cookie on /auth/2fa", "/auth/2fa", "x", true},
		{"live ticket on /auth/2fa/send", "/auth/2fa/send", live, false},
	}
	for i, c := range cases {
		ip := "192.0.2." + string(rune('1'+i))
		t.Cleanup(func() { rdb.Del(ctx, "hpg:rl:unauth-post:"+ip) })
		last := 0
		for n := 0; n < 4; n++ {
			last = post(c.path, c.cookie, ip)
		}
		if got := last == http.StatusTooManyRequests; got != c.limited {
			t.Errorf("%s: limited=%v, want %v (last status %d)", c.name, got, c.limited, last)
		}
	}
}
