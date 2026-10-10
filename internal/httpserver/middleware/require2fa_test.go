package middleware

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/host-yt/caddy-proxy-manager/internal/auth"
)

func TestAdmin2FAPolicyFailsClosed(t *testing.T) {
	dbErr := errors.New("i/o timeout")
	t.Cleanup(func() { admin2FALastOn.Store(false) })

	admin2FALastOn.Store(false)
	if on, err := Admin2FAPolicy(false, sql.ErrNoRows); on || err != nil {
		t.Fatalf("missing row: got %v,%v want false,nil", on, err)
	}
	// Never seen on: an error is "unknown", not "off".
	if _, err := Admin2FAPolicy(false, dbErr); err == nil {
		t.Fatal("db error with no prior policy must return an error")
	}
	if on, err := Admin2FAPolicy(true, nil); !on || err != nil {
		t.Fatalf("row=1: got %v,%v want true,nil", on, err)
	}
	// Seen on: a transient error keeps enforcing.
	if on, err := Admin2FAPolicy(false, dbErr); !on || err != nil {
		t.Fatalf("db error after on: got %v,%v want true,nil", on, err)
	}
	if on, _ := Admin2FAPolicy(false, nil); on {
		t.Fatal("row=0 must turn enforcement off")
	}
}

func adminReq(userID int64) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/admin/", nil)
	return r.WithContext(context.WithValue(r.Context(), sessionCtxKey, &auth.Session{UserID: userID, Role: "admin"}))
}

func TestRequireAdmin2FAPolicyErrorIs503(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	h := RequireAdmin2FA(func() *sql.DB { return nil }, nil,
		func() (bool, error) { return false, errors.New("db down") }, 24)(ok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, adminReq(1))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("got %d, want 503", rec.Code)
	}
}

// An unknown policy must not start (and so burn) the one-time grace window.
func TestRequireAdmin2FAPolicyErrorKeepsGrace(t *testing.T) {
	rdb := testRedis(t)
	ctx := context.Background()
	const uid = 990055
	key := fmt.Sprintf("hpg:2fa:grace_until:%d", uid)
	rdb.Del(ctx, key, fmt.Sprintf("hpg:2fa:enrolled:%d", uid))
	t.Cleanup(func() { rdb.Del(ctx, key, fmt.Sprintf("hpg:2fa:enrolled:%d", uid)) })

	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	h := RequireAdmin2FA(func() *sql.DB { return nil }, rdb,
		func() (bool, error) { return false, errors.New("db down") }, 24)(ok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, adminReq(uid))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("got %d, want 503", rec.Code)
	}
	if n, _ := rdb.Exists(ctx, key).Result(); n != 0 {
		t.Fatal("grace window started while policy was unknown")
	}
}
