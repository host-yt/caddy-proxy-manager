package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/host-yt/caddy-proxy-manager/internal/adminscope"
	"github.com/host-yt/caddy-proxy-manager/internal/auth"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
)

// mTLS CAs are operator-global trust anchors: a scoped admin (non-super_admin
// with AdminScope wired) must be rejected from managing them.
func TestMTLS_ScopedAdminRejected(t *testing.T) {
	h := &AdminHandlers{AdminScope: &adminscope.Service{}}
	sess := &auth.Session{UserID: 7, Role: "admin"} // not super_admin

	for _, name := range []string{"list", "create", "delete", "issue", "revoke", "bundle", "crl"} {
		req := httptest.NewRequest(http.MethodGet, "/admin/mtls", nil)
		req = req.WithContext(middleware.ContextWithSession(req.Context(), sess))
		rr := httptest.NewRecorder()
		switch name {
		case "list":
			h.MTLSList(rr, req)
		case "create":
			h.MTLSCreateCA(rr, req)
		case "delete":
			h.MTLSDeleteCA(rr, req)
		case "issue":
			h.MTLSIssue(rr, req)
		case "revoke":
			h.MTLSRevoke(rr, req)
		case "bundle":
			h.MTLSCABundle(rr, req)
		case "crl":
			h.MTLSCRL(rr, req)
		}
		if rr.Code != http.StatusForbidden {
			t.Errorf("%s: want 403 for scoped admin, got %d", name, rr.Code)
		}
	}
}

// super_admin passes the scope guard (handlers then fail later on nil deps,
// which is fine - we only assert they are NOT 403'd by the scope check).
func TestMTLS_SuperAdminNotScopeBlocked(t *testing.T) {
	h := &AdminHandlers{AdminScope: &adminscope.Service{}}
	sess := &auth.Session{UserID: 1, Role: "super_admin"}
	req := httptest.NewRequest(http.MethodGet, "/admin/mtls", nil)
	req = req.WithContext(middleware.ContextWithSession(req.Context(), sess))
	if h.mtlsScopeDenied(httptest.NewRecorder(), req) {
		t.Error("super_admin must not be scope-denied")
	}
}
