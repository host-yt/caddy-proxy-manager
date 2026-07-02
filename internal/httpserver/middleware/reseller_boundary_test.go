package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/host-yt/caddy-proxy-manager/internal/auth"
)

// TestResellerAdminBoundary: a reseller-admin (ResellerID != 0) is confined to
// the allow-list; global-infra paths 403. A platform admin (ResellerID == 0)
// and an anonymous request pass through untouched.
func TestResellerAdminBoundary(t *testing.T) {
	allowed := []string{"/admin", "/admin/map", "/admin/ai/chat*", "/admin/2fa*"}

	cases := []struct {
		name       string
		resellerID int64
		method     string
		path       string
		noSession  bool
		wantStatus int
	}{
		{"reseller-admin dashboard ok", 7, "GET", "/admin", false, http.StatusOK},
		{"reseller-admin scoped map ok", 7, "GET", "/admin/map", false, http.StatusOK},
		{"reseller-admin ai chat prefix ok", 7, "GET", "/admin/ai/chat/sessions", false, http.StatusOK},
		{"reseller-admin 2fa prefix ok", 7, "POST", "/admin/2fa/confirm", false, http.StatusOK},
		{"reseller-admin nodes blocked", 7, "GET", "/admin/nodes", false, http.StatusForbidden},
		{"reseller-admin settings write blocked", 7, "POST", "/admin/settings/ai", false, http.StatusForbidden},
		{"reseller-admin clients blocked", 7, "GET", "/admin/clients", false, http.StatusForbidden},
		{"platform admin nodes ok", 0, "GET", "/admin/nodes", false, http.StatusOK},
		{"platform admin settings ok", 0, "POST", "/admin/settings/ai", false, http.StatusOK},
		{"no session passes", 0, "GET", "/admin/nodes", true, http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var reached bool
			h := ResellerAdminBoundary(allowed)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				reached = true
				w.WriteHeader(http.StatusOK)
			}))
			req := httptest.NewRequest(tc.method, tc.path, nil)
			if !tc.noSession {
				req = req.WithContext(ContextWithSession(req.Context(),
					&auth.Session{UserID: 1, Role: "admin", ResellerID: tc.resellerID}))
			}
			rw := httptest.NewRecorder()
			h.ServeHTTP(rw, req)
			if rw.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rw.Code, tc.wantStatus)
			}
			if wantReach := tc.wantStatus == http.StatusOK; reached != wantReach {
				t.Fatalf("handler reached = %v, want %v", reached, wantReach)
			}
		})
	}
}
