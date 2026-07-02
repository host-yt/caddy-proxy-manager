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
