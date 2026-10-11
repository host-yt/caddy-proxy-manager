package handlers

import (
	"log/slog"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/host-yt/caddy-proxy-manager/internal/auth"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
)

// Global (client_id<=0) access groups are super_admin-only, even for an
// admin whose scope resolves to all clients.
func TestAccessGroupsCreateGlobalSuperAdminOnly(t *testing.T) {
	h := &AdminHandlers{Logger: slog.Default()} // unwired scope: platform admin resolves to all
	for _, cid := range []string{"0", "-1"} {
		form := url.Values{"name": {"g"}, "client_id": {cid}}
		r := httptest.NewRequest("POST", "/admin/access-groups", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r = r.WithContext(middleware.ContextWithSession(r.Context(), &auth.Session{UserID: 2, Role: "admin"}))
		w := httptest.NewRecorder()
		h.AccessGroupsCreate(w, r) // nil Portal: reaching CreateGroup would panic
		if loc := w.Header().Get("Location"); !strings.Contains(loc, "err=") {
			t.Fatalf("client_id=%s: want error redirect, got %q", cid, loc)
		}
	}
}
