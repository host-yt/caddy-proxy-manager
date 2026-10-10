package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/host-yt/caddy-proxy-manager/internal/auth"
)

// A valid session must not lift the limit on public auth routes (#57), while
// logged-in POSTs elsewhere stay unthrottled.
func TestUnauthPostLimitSessionBypassScope(t *testing.T) {
	rdb := testRedis(t)
	ctx := context.Background()
	h := UnauthPostLimit(rdb, 2)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	cases := []struct {
		name, path string
		limited    bool
	}{
		{"session on /auth/forgot", "/auth/forgot", true},
		{"session on /auth/register", "/auth/register", true},
		{"session on /hpg-portal/login", "/hpg-portal/login", true},
		{"session on admin POST", "/admin/hosts", false},
	}
	for i, c := range cases {
		ip := "198.51.100." + string(rune('1'+i))
		t.Cleanup(func() { rdb.Del(ctx, "hpg:rl:unauth-post:"+ip) })
		last := 0
		for n := 0; n < 4; n++ {
			req := httptest.NewRequest(http.MethodPost, c.path, nil)
			req.RemoteAddr = ip + ":1234"
			req = req.WithContext(context.WithValue(req.Context(), sessionCtxKey, &auth.Session{UserID: 1}))
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			last = rec.Code
		}
		if got := last == http.StatusTooManyRequests; got != c.limited {
			t.Errorf("%s: limited=%v, want %v (last status %d)", c.name, got, c.limited, last)
		}
	}
}
