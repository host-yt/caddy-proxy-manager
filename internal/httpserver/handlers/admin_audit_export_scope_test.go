package handlers

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/host-yt/caddy-proxy-manager/internal/adminscope"
	"github.com/host-yt/caddy-proxy-manager/internal/auth"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
)

// AuditExport streams up to 50k platform-wide rows (actor IP/UA): super_admin
// only, regardless of AdminScope wiring.
func TestAuditExportScope(t *testing.T) {
	cases := []struct {
		name       string
		sess       *auth.Session
		adminScope *adminscope.Service
		wantForbid bool
	}{
		{"super_admin allowed", &auth.Session{UserID: 1, Role: "super_admin"}, &adminscope.Service{}, false},
		{"scoped admin denied", &auth.Session{UserID: 10, Role: "admin"}, &adminscope.Service{}, true},
		{"AdminScope nil non-super_admin denied", &auth.Session{UserID: 10, Role: "admin"}, nil, true},
		{"nil session denied", nil, &adminscope.Service{}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := &AdminHandlers{AdminScope: c.adminScope, DB: func() *sql.DB { return nil }}
			req := httptest.NewRequest(http.MethodGet, "/admin/audit/export", nil)
			if c.sess != nil {
				req = req.WithContext(middleware.ContextWithSession(req.Context(), c.sess))
			}
			rr := httptest.NewRecorder()
			h.AuditExport(rr, req)
			if c.wantForbid && rr.Code != http.StatusForbidden {
				t.Errorf("want 403, got %d", rr.Code)
			}
			if !c.wantForbid && rr.Code == http.StatusForbidden {
				t.Errorf("super_admin must not be scope-denied, got 403")
			}
		})
	}
}
