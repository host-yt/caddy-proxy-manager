package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestSessionCookieFlags guards the session cookie's transport security
// attributes: HttpOnly blocks JS exfiltration (XSS), Secure blocks plaintext
// transmission, SameSite blocks cross-site request forgery via auto-attach.
func TestSessionCookieFlags(t *testing.T) {
	m := NewSessionManager(nil, "hpg_session", true, "strict", time.Hour)

	if !m.CookieSecure() {
		t.Fatal("session manager configured secure=true but CookieSecure() reports false")
	}
	if m.sameSite != http.SameSiteStrictMode {
		t.Fatalf("sameSite = %v, want SameSiteStrictMode", m.sameSite)
	}

	// Destroy() with no cookie on the request never touches rdb (nil-safe
	// here), so this exercises the exact cookie literal written on logout.
	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	rr := httptest.NewRecorder()
	m.Destroy(context.Background(), rr, req)

	cookies := rr.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie written, got %d", len(cookies))
	}
	c := cookies[0]
	if !c.HttpOnly {
		t.Error("session cookie missing HttpOnly")
	}
	if !c.Secure {
		t.Error("session cookie missing Secure")
	}
	if c.SameSite != http.SameSiteStrictMode {
		t.Errorf("session cookie SameSite = %v, want SameSiteStrictMode", c.SameSite)
	}
}

// TestSessionCookieSameSiteMapping locks the string->http.SameSite mapping
// used by config (session_cookie_same_site) so a typo silently downgrades to Lax.
func TestSessionCookieSameSiteMapping(t *testing.T) {
	cases := []struct {
		in   string
		want http.SameSite
	}{
		{"strict", http.SameSiteStrictMode},
		{"none", http.SameSiteNoneMode},
		{"lax", http.SameSiteLaxMode},
		{"", http.SameSiteLaxMode},
		{"garbage", http.SameSiteLaxMode},
	}
	for _, tc := range cases {
		m := NewSessionManager(nil, "hpg_session", true, tc.in, time.Hour)
		if m.sameSite != tc.want {
			t.Errorf("sameSite(%q) = %v, want %v", tc.in, m.sameSite, tc.want)
		}
	}
}
