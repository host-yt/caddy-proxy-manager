package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/host-yt/caddy-proxy-manager/internal/auth"
)

// review 13: CSRF must reject a cookie-authed POST that lacks / mismatches the
// session token, and accept a matching one.
func TestCSRFRejectsMissingToken(t *testing.T) {
	var reached bool
	h := VerifyCSRF(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))
	sess := &auth.Session{UserID: 1, CSRFToken: "good-token"}

	cases := []struct {
		name       string
		header     string
		wantStatus int
		wantReach  bool
	}{
		{"missing token", "", http.StatusForbidden, false},
		{"wrong token", "bad-token", http.StatusForbidden, false},
		{"correct token", "good-token", http.StatusOK, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reached = false
			req := httptest.NewRequest(http.MethodPost, "/admin/hosts", strings.NewReader(""))
			req = req.WithContext(ContextWithSession(req.Context(), sess))
			if tc.header != "" {
				req.Header.Set("X-CSRF-Token", tc.header)
			}
			rw := httptest.NewRecorder()
			h.ServeHTTP(rw, req)
			if rw.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rw.Code, tc.wantStatus)
			}
			if reached != tc.wantReach {
				t.Fatalf("handler reached = %v, want %v", reached, tc.wantReach)
			}
		})
	}
}

// A GET is a safe method and must pass CSRF untouched even without a token.
func TestCSRFAllowsSafeMethod(t *testing.T) {
	h := VerifyCSRF(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	sess := &auth.Session{UserID: 1, CSRFToken: "good-token"}
	req := httptest.NewRequest(http.MethodGet, "/admin/hosts", nil)
	req = req.WithContext(ContextWithSession(req.Context(), sess))
	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, req)
	if rw.Code != http.StatusOK {
		t.Fatalf("GET status = %d, want 200", rw.Code)
	}
}

// TestCSRFExemptPathsAndNoSession covers the documented pre-session/bearer-
// auth bypasses: a missing/wrong token must still 403 on a normal admin POST,
// but must NOT block the exempt prefixes (install wizard, /api/*, login) or
// any request that carries no session at all.
func TestCSRFExemptPathsAndNoSession(t *testing.T) {
	sess := &auth.Session{UserID: 1, CSRFToken: "good-token"}

	cases := []struct {
		name     string
		target   string
		withSess bool
	}{
		{"install wizard POST exempt", "/install/step1", true},
		{"api POST exempt (bearer auth)", "/api/v1/hosts", true},
		{"login POST exempt (no session yet)", "/auth/login", true},
		{"forgot-password POST exempt", "/auth/forgot", true},
		{"reset-password POST exempt", "/auth/reset/abc123", true},
		{"no session at all bypasses", "/admin/hosts", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			h := VerifyCSRF(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				w.WriteHeader(http.StatusOK)
			}))
			req := httptest.NewRequest(http.MethodPost, tc.target, strings.NewReader(""))
			if tc.withSess {
				req = req.WithContext(ContextWithSession(req.Context(), sess))
			}
			// Deliberately no X-CSRF-Token: these paths must pass without one.
			rw := httptest.NewRecorder()
			h.ServeHTTP(rw, req)
			if !called || rw.Code != http.StatusOK {
				t.Fatalf("%s: status = %d, called = %v, want 200/true (exempt path must bypass CSRF)", tc.target, rw.Code, called)
			}
		})
	}

	// Sanity: the same admin path with a session and no token still 403s,
	// proving the exemptions above are path-specific, not a global bypass.
	called := false
	h := VerifyCSRF(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodPost, "/admin/hosts/new", strings.NewReader(""))
	req = req.WithContext(ContextWithSession(req.Context(), sess))
	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, req)
	if rw.Code != http.StatusForbidden || called {
		t.Fatalf("non-exempt admin POST without token: status = %d, called = %v, want 403/false", rw.Code, called)
	}
}
