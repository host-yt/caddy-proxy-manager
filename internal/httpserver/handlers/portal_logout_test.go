package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// TestPortalLogoutConfirm_GETNoSideEffects is the regression for HPG-SEC-007:
// a GET to /hpg-portal/logout must only render a confirmation, never touch
// Redis or clear the session cookie itself.
func TestPortalLogoutConfirm_GETNoSideEffects(t *testing.T) {
	h := &PortalHandlers{}
	req := httptest.NewRequest(http.MethodGet, "https://tenant.example.com/hpg-portal/logout", nil)
	rec := httptest.NewRecorder()

	h.LogoutConfirm(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `method="POST"`) || !strings.Contains(body, `action="/hpg-portal/logout"`) {
		t.Errorf("confirmation page must POST to /hpg-portal/logout\nbody: %s", body)
	}
	if !strings.Contains(body, `name="csrf_token"`) {
		t.Errorf("confirmation page must carry a csrf_token field\nbody: %s", body)
	}
	// The confirm page must not itself clear the portal session cookie.
	for _, c := range rec.Result().Cookies() {
		if c.Name == portalCookie {
			t.Errorf("GET must not touch the portal session cookie, got %+v", c)
		}
	}
}

// TestPortalLogout_GETIsRejected proves the state-changing handler itself
// requires POST + a valid CSRF token - a bare GET (as the old route wiring
// allowed) must not destroy the session.
func TestPortalLogout_GETIsRejected(t *testing.T) {
	h := &PortalHandlers{}
	req := httptest.NewRequest(http.MethodGet, "https://tenant.example.com/hpg-portal/logout", nil)
	rec := httptest.NewRecorder()

	// Logout() itself has no method check (routing enforces POST); calling
	// it directly with no csrf_token/cookie proves the CSRF gate, not routing.
	h.Logout(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (falls back to the confirmation page)", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Sign out") {
		t.Errorf("missing-CSRF logout must fall back to the confirmation page, got: %s", body)
	}
}

// TestPortalLogout_CSRFMismatchRejected: a forged POST with no matching
// double-submit cookie must not destroy the session or redirect.
func TestPortalLogout_CSRFMismatchRejected(t *testing.T) {
	h := &PortalHandlers{}
	form := url.Values{"csrf_token": {"attacker-guess"}}
	req := httptest.NewRequest(http.MethodPost, "https://tenant.example.com/hpg-portal/logout", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// No portalCSRFCookie set - double-submit has nothing to match against.
	rec := httptest.NewRecorder()

	h.Logout(rec, req)

	if rec.Code == http.StatusSeeOther {
		t.Fatalf("forged POST without a matching CSRF cookie must not redirect (would-be logout), got %d", rec.Code)
	}
}

// TestPortalLogout_ValidCSRFSucceeds: a same-origin POST carrying the
// double-submit cookie + matching form token clears the session and
// redirects to login - the legitimate flow must keep working.
func TestPortalLogout_ValidCSRFSucceeds(t *testing.T) {
	h := &PortalHandlers{}
	const tok = "real-token-value"
	form := url.Values{"csrf_token": {tok}}
	req := httptest.NewRequest(http.MethodPost, "https://tenant.example.com/hpg-portal/logout", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: portalCSRFCookie, Value: tok})
	// No portalCookie set, so Logout skips the RDB.Del call entirely (RDB is
	// nil here) - this isolates the CSRF-gate behavior from Redis.
	rec := httptest.NewRecorder()

	h.Logout(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303 redirect to login", rec.Code)
	}
}
