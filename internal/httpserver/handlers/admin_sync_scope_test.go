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

// Instance sync (SlaveAdd/Delete/Sync) is global infrastructure and can be
// used as an SSRF pivot: super_admin only, regardless of AdminScope wiring.
func TestSyncSlaveScope(t *testing.T) {
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
		for _, action := range []string{"add", "delete", "sync"} {
			t.Run(c.name+"/"+action, func(t *testing.T) {
				h := &AdminHandlers{AdminScope: c.adminScope, DB: func() *sql.DB { return nil }}
				var req *http.Request
				switch action {
				case "add":
					req = httptest.NewRequest(http.MethodPost, "/admin/settings/instances", nil)
				case "delete":
					req = httptest.NewRequest(http.MethodPost, "/admin/settings/instances/1/delete", nil)
				case "sync":
					req = httptest.NewRequest(http.MethodPost, "/admin/settings/instances/1/sync", nil)
				}
				if c.sess != nil {
					req = req.WithContext(middleware.ContextWithSession(req.Context(), c.sess))
				}
				rr := httptest.NewRecorder()
				switch action {
				case "add":
					h.SlaveAdd(rr, req)
				case "delete":
					h.SlaveDelete(rr, req)
				case "sync":
					h.SlaveSync(rr, req)
				}
				if c.wantForbid && rr.Code != http.StatusForbidden {
					t.Errorf("%s: want 403, got %d", action, rr.Code)
				}
				if !c.wantForbid && rr.Code == http.StatusForbidden {
					t.Errorf("%s: super_admin must not be scope-denied, got 403", action)
				}
			})
		}
	}
}
