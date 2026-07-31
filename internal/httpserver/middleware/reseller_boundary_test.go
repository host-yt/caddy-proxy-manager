package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/host-yt/caddy-proxy-manager/internal/auth"
)

// TestResellerAdminBoundary: every limited admin (ResellerID != 0 or
// Restricted) is confined to the allow-list; global-infra paths 403. A full
// platform admin and an anonymous request pass through untouched.
func TestResellerAdminBoundary(t *testing.T) {
	allowed := []string{"/admin", "/admin/map", "/admin/ai/chat*", "/admin/2fa*"}

	cases := []struct {
		name       string
		resellerID int64
		restricted bool
		method     string
		path       string
		noSession  bool
		wantStatus int
	}{
		{"reseller-admin dashboard ok", 7, false, "GET", "/admin", false, http.StatusOK},
		{"reseller-admin scoped map ok", 7, false, "GET", "/admin/map", false, http.StatusOK},
		{"reseller-admin ai chat prefix ok", 7, false, "GET", "/admin/ai/chat/sessions", false, http.StatusOK},
		{"reseller-admin 2fa prefix ok", 7, false, "POST", "/admin/2fa/confirm", false, http.StatusOK},
		{"reseller-admin nodes blocked", 7, false, "GET", "/admin/nodes", false, http.StatusForbidden},
		{"reseller-admin settings write blocked", 7, false, "POST", "/admin/settings/ai", false, http.StatusForbidden},
		{"reseller-admin clients blocked", 7, false, "GET", "/admin/clients", false, http.StatusForbidden},
		// Restricted admin: reseller_id==0 but users.is_restricted=1.
		{"restricted admin dashboard ok", 0, true, "GET", "/admin", false, http.StatusOK},
		{"restricted admin map ok", 0, true, "GET", "/admin/map", false, http.StatusOK},
		{"restricted admin nodes blocked", 0, true, "GET", "/admin/nodes", false, http.StatusForbidden},
		{"restricted admin sso-jump rotate blocked", 0, true, "POST", "/admin/settings/sso-jump/rotate", false, http.StatusForbidden},
		{"platform admin nodes ok", 0, false, "GET", "/admin/nodes", false, http.StatusOK},
		{"platform admin settings ok", 0, false, "POST", "/admin/settings/ai", false, http.StatusOK},
		{"no session passes", 0, false, "GET", "/admin/nodes", true, http.StatusOK},
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
					&auth.Session{UserID: 1, Role: "admin", ResellerID: tc.resellerID, Restricted: tc.restricted}))
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

// An orphaned reseller (its reseller row deleted, reseller_id nulled) must stay
// confined: role alone can never widen into a platform admin.
func TestOrphanedResellerStaysConfined(t *testing.T) {
	h := ResellerAdminBoundary([]string{"/admin", "/admin/hosts*"})(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))

	for _, tc := range []struct {
		path string
		want int
	}{
		{"/admin/nodes", http.StatusForbidden},
		{"/admin/settings", http.StatusForbidden},
		{"/admin/hosts", http.StatusOK},
	} {
		req := httptest.NewRequest(http.MethodGet, tc.path, nil)
		req = req.WithContext(ContextWithSession(req.Context(),
			&auth.Session{UserID: 1, Role: "reseller", ResellerID: 0, Restricted: false}))
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != tc.want {
			t.Errorf("%s: got %d want %d", tc.path, rr.Code, tc.want)
		}
	}
}
