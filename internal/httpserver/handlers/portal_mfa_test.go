package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/host-yt/caddy-proxy-manager/internal/auth"
	"github.com/host-yt/caddy-proxy-manager/internal/domain/portal"
)

func portalTestRedis(t *testing.T) *redis.Client {
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

func portalPost(path string, form url.Values, cookies ...*http.Cookie) *http.Request {
	form.Set("csrf_token", "tok")
	r := httptest.NewRequest(http.MethodPost, "https://app.example"+path, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: portalCSRFCookie, Value: "tok"})
	for _, c := range cookies {
		r.AddCookie(c)
	}
	return r
}

func cookieNamed(rec *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == name && c.Value != "" {
			return c
		}
	}
	return nil
}

// an SMS-only (or email-only) user used to get a portal
// session from the password alone. The session must wait for the second factor.
func TestPortalLoginRequiresSMSFactor(t *testing.T) {
	rdb := portalTestRedis(t)
	db := portalVerifyDB(t)
	hash, err := auth.HashPassword("correct horse")
	if err != nil {
		t.Fatal(err)
	}
	res, err := db.Exec(`INSERT INTO users (email, password_hash, role, full_name, is_active, sms_otp_enabled, phone_e164)
		VALUES ('sms@example.com', ?, 'client', 'S', 1, 1, '+48500000000')`, hash)
	if err != nil {
		t.Fatal(err)
	}
	uid, _ := res.LastInsertId()
	ctx := context.Background()
	_ = rdb.Del(ctx, "hpg:2fa:fail:"+itoa64(uid)).Err()

	dbf := func() *sql.DB { return db }
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := &PortalHandlers{
		DB: dbf, RDB: rdb, Logger: logger, Portal: portal.New(dbf),
		Auth: &AuthHandlers{DB: dbf, RDB: rdb, Logger: logger},
	}

	rec := httptest.NewRecorder()
	h.LoginSubmit(rec, portalPost("/hpg-portal/login", url.Values{"email": {"sms@example.com"}, "password": {"correct horse"}, "back": {"/"}}))
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/hpg-portal/2fa" {
		t.Fatalf("login: status %d location %q, want 303 to /hpg-portal/2fa", rec.Code, rec.Header().Get("Location"))
	}
	if cookieNamed(rec, portalCookie) != nil {
		t.Fatal("password alone minted a portal session")
	}
	challenge := cookieNamed(rec, portal2FACookie)
	if challenge == nil {
		t.Fatal("no 2FA challenge cookie")
	}

	page := httptest.NewRequest(http.MethodGet, "https://app.example/hpg-portal/2fa", nil)
	page.AddCookie(challenge)
	rec = httptest.NewRecorder()
	h.Portal2FAPage(rec, page)
	if body := rec.Body.String(); !strings.Contains(body, "Send code by SMS") || strings.Contains(body, "Use authenticator app") {
		t.Fatalf("2FA page must offer only the enrolled SMS factor:\n%s", body)
	}

	// A factor the user did not enrol, or an SMS code never sent, must not pass.
	for _, f := range []url.Values{
		{"method": {"totp"}, "code": {"123456"}},
		{"method": {"sms"}, "code": {"123456"}},
	} {
		rec = httptest.NewRecorder()
		h.Portal2FASubmit(rec, portalPost("/hpg-portal/2fa", f, challenge))
		if cookieNamed(rec, portalCookie) != nil {
			t.Fatalf("%v minted a portal session", f)
		}
	}

	// A code sent for this challenge completes it.
	ticket, err := auth.StoreSMSOTP(ctx, rdb, uid, "654321")
	if err != nil {
		t.Fatal(err)
	}
	_, st := h.loadPortal2FA(ctx, portalPost("/", url.Values{}, challenge))
	if st == nil {
		t.Fatal("challenge gone after two failed attempts")
	}
	st.OTPMethod, st.OTPTicket = "sms", ticket
	b, _ := json.Marshal(st)
	if err := rdb.Set(ctx, portal2FARedisPfx+challenge.Value, b, redis.KeepTTL).Err(); err != nil {
		t.Fatal(err)
	}
	rec = httptest.NewRecorder()
	h.Portal2FASubmit(rec, portalPost("/hpg-portal/2fa", url.Values{"method": {"sms"}, "code": {"654-321"}}, challenge))
	if cookieNamed(rec, portalCookie) == nil {
		t.Fatalf("valid SMS code did not mint a session: status %d body %s", rec.Code, rec.Body.String())
	}
}
