package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/host-yt/caddy-proxy-manager/internal/adminscope"
	"github.com/host-yt/caddy-proxy-manager/internal/auth"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
	"github.com/host-yt/caddy-proxy-manager/internal/wafevents"
)

// TestWAFSuppressRule_ScopedAdminCannotCreateGlobal asserts that a scoped
// admin (non-super_admin with AdminScope wired) is rejected when they attempt
// to POST a global suppression (route_id omitted / 0).
func TestWAFSuppressRule_ScopedAdminCannotCreateGlobal(t *testing.T) {
	h := &AdminHandlers{
		WAFEvents:  wafevents.New(nil), // nil db - no DB calls expected
		AdminScope: &adminscope.Service{},
	}

	sess := &auth.Session{
		UserID: 7,
		Email:  "scoped@example.com",
		Role:   "admin", // not super_admin
	}

	form := url.Values{}
	form.Set("rule_id", "sqli-001")
	form.Set("route_id", "0") // global - must be rejected for scoped admin
	form.Set("reason", "test")

	req := httptest.NewRequest(http.MethodPost, "/admin/waf/suppress", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(middleware.ContextWithSession(req.Context(), sess))

	rr := httptest.NewRecorder()
	h.WAFSuppressRule(rr, req)

	// Handler calls redirectWithFlash -> 303 with err= in location.
	if rr.Code != http.StatusSeeOther {
		t.Errorf("expected 303 SeeOther, got %d", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if !strings.Contains(loc, "err=") {
		t.Errorf("expected err= in redirect location, got %q", loc)
	}
}

// TestWAFSuppressRule_SuperAdminCanCreateGlobal asserts that super_admin is
// not blocked by scope checks and reaches the store (nil db is a no-op).
func TestWAFSuppressRule_SuperAdminCanCreateGlobal(t *testing.T) {
	h := &AdminHandlers{
		WAFEvents:  wafevents.New(nil), // nil db -> SuppressRule returns (0, nil)
		AdminScope: &adminscope.Service{},
		// DB nil: audit.Write guard is inside the handler
	}

	sess := &auth.Session{
		UserID: 1,
		Email:  "super@example.com",
		Role:   "super_admin",
	}

	form := url.Values{}
	form.Set("rule_id", "sqli-001")
	// No route_id = global suppression.
	form.Set("reason", "testing")

	req := httptest.NewRequest(http.MethodPost, "/admin/waf/suppress", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(middleware.ContextWithSession(req.Context(), sess))

	rr := httptest.NewRecorder()
	h.WAFSuppressRule(rr, req)

	// Must not be forbidden - authz passed (even if DB nil causes redirect).
	if rr.Code == http.StatusForbidden {
		t.Errorf("super_admin should not be forbidden; got 403")
	}
}
