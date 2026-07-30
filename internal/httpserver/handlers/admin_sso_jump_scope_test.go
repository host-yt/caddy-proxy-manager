package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/host-yt/caddy-proxy-manager/internal/auth"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
)

// The SSO-jump shared secret mints sessions for any email, so only a
// super_admin may save or rotate it - never a restricted/reseller admin.
func TestSSOJumpSettings_NonSuperAdminRejected(t *testing.T) {
	h := &AdminHandlers{}

	sessions := map[string]*auth.Session{
		"plain admin":      {UserID: 7, Role: "admin"},
		"restricted admin": {UserID: 8, Role: "admin", Restricted: true},
		"reseller admin":   {UserID: 9, Role: "admin", ResellerID: 3},
		"client":           {UserID: 10, Role: "client"},
		"no session":       nil,
	}
	for name, sess := range sessions {
		for _, op := range []string{"save", "rotate"} {
			req := httptest.NewRequest(http.MethodPost, "/admin/settings/sso-jump", nil)
			if sess != nil {
				req = req.WithContext(middleware.ContextWithSession(req.Context(), sess))
			}
			rr := httptest.NewRecorder()
			if op == "save" {
				h.SettingsSSOJumpSave(rr, req)
			} else {
				h.SettingsSSOJumpRotate(rr, req)
			}
			if rr.Code != http.StatusForbidden {
				t.Errorf("%s/%s: want 403, got %d", name, op, rr.Code)
			}
		}
	}
}

// An impersonating super_admin session must not reach the secret either.
func TestSSOJumpSettings_ImpersonationRejected(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/admin/settings/sso-jump/rotate", nil)
	req = req.WithContext(middleware.ContextWithSession(req.Context(),
		&auth.Session{UserID: 5, Role: "super_admin", ImpersonatorUserID: 1}))
	rr := httptest.NewRecorder()
	if !ssoJumpDenied(rr, req) || rr.Code != http.StatusForbidden {
		t.Errorf("impersonating session must be denied, got %d", rr.Code)
	}
}
