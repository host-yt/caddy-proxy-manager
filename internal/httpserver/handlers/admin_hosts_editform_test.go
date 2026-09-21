package handlers

import (
	"context"
	"database/sql"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/host-yt/caddy-proxy-manager/internal/auth"
	"github.com/host-yt/caddy-proxy-manager/internal/domain/routes"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
	"github.com/host-yt/caddy-proxy-manager/internal/view"
)

// editFormHandlers builds an AdminHandlers wired for full HTTP round-trips
// (unlike postHostEdit's callers, these tests need real template rendering).
func editFormHandlers(t *testing.T, db *sql.DB) *AdminHandlers {
	t.Helper()
	tpls, err := view.LoadAdminTemplates()
	if err != nil {
		t.Fatalf("load admin templates: %v", err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	bg, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	cancel() // cancelled background context: no real Caddy push in tests
	return &AdminHandlers{
		DB:        func() *sql.DB { return db },
		Logger:    logger,
		Templates: tpls,
		Routes:    &routes.Service{DB: db, Logger: logger, BgCtx: bg},
	}
}

func postHostEditRec(h *AdminHandlers, form url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/admin/hosts/7/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "7")
	ctx := context.WithValue(req.Context(), chi.RouteCtxKey, rctx)
	ctx = middleware.ContextWithSession(ctx, &auth.Session{UserID: 1, Role: "super_admin"})
	rec := httptest.NewRecorder()
	h.HostsUpdate(rec, req.WithContext(ctx))
	return rec
}

func getHostEditRec(h *AdminHandlers) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/admin/hosts/7/edit", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "7")
	ctx := context.WithValue(req.Context(), chi.RouteCtxKey, rctx)
	ctx = middleware.ContextWithSession(ctx, &auth.Session{UserID: 1, Role: "super_admin"})
	rec := httptest.NewRecorder()
	h.HostsEdit(rec, req.WithContext(ctx))
	return rec
}

// HPG-022: a route absent from CompileResults (never compiled since upgrade)
// must render as "unchecked", never fall back to the "published" (ok) pill.
func TestHostsList_CompileBadgeUnknownNeverShowsOK(t *testing.T) {
	db := mtlsTLSEditDB(t) // route 7, last_compile_status left NULL by the fixture
	h := editFormHandlers(t, db)

	req := httptest.NewRequest(http.MethodGet, "/admin/hosts", nil)
	ctx := middleware.ContextWithSession(req.Context(), &auth.Session{UserID: 1, Role: "super_admin"})
	rec := httptest.NewRecorder()
	h.HostsList(rec, req.WithContext(ctx))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "unchecked") {
		t.Error("route missing from CompileResults must show the unchecked pill")
	}
	if strings.Contains(body, ">published<") {
		t.Error("a never-compiled route must never render the ok/published pill")
	}

	// Now record a real compile outcome and confirm it DOES surface.
	if _, err := db.Exec(`UPDATE routes SET last_compile_status='quarantined', last_compile_reason='no grants', last_compile_at=CURRENT_TIMESTAMP WHERE id=7`); err != nil {
		t.Fatal(err)
	}
	rec2 := httptest.NewRecorder()
	h.HostsList(rec2, req.WithContext(ctx))
	if body2 := rec2.Body.String(); !strings.Contains(body2, "quarantined") {
		t.Error("a recorded compile outcome must surface as its own badge")
	}
}

// portal_public_paths must save on POST and come back on the next GET -
// operators upgrading from the old implicit bypass need this to round-trip.
func TestHostsUpdate_PortalPublicPathsRoundTrips(t *testing.T) {
	db := mtlsTLSEditDB(t)
	h := editFormHandlers(t, db)

	form := baseEditForm()
	form.Set("portal_public_paths", "/assets/*, *.js")
	rec := postHostEditRec(h, form)
	if loc := rec.Header().Get("Location"); strings.Contains(loc, "err=") {
		t.Fatalf("save rejected: %s (body %s)", loc, rec.Body.String())
	}

	var stored string
	if err := db.QueryRow("SELECT COALESCE(portal_public_paths,'') FROM routes WHERE id = 7").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	// sanitizePathList prefixes bare globs with "/", same as the sibling sso_paths field.
	if stored != "/assets/*,/*.js" {
		t.Errorf("portal_public_paths stored = %q, want /assets/*,/*.js", stored)
	}

	getRec := getHostEditRec(h)
	if getRec.Code != http.StatusOK {
		t.Fatalf("GET edit status = %d", getRec.Code)
	}
	if body := getRec.Body.String(); !strings.Contains(body, "/assets/*") || !strings.Contains(body, "*.js") {
		t.Error("edit form did not reload the saved portal_public_paths value")
	}
}

// HPG-023: a validation failure must return 422 (never a 303 that would
// replay the POST on refresh) and echo back what the operator just typed,
// not the value still sitting in the DB.
func TestHostsUpdate_ValidationErrorKeepsSubmittedValues(t *testing.T) {
	db := mtlsTLSEditDB(t)
	h := editFormHandlers(t, db)

	form := baseEditForm()
	form.Set("domain", "") // triggers the "domain required" field error
	form.Set("path_prefix", "/keep-me-xyz")
	rec := postHostEditRec(h, form)

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422; body %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "/keep-me-xyz") {
		t.Error("re-rendered form lost a field the operator typed alongside the bad one")
	}
	if strings.Contains(body, "locked.example") {
		t.Error("re-rendered form fell back to the stored domain instead of the (empty) submitted one")
	}
	if !strings.Contains(body, "domain required") {
		t.Error("field-scoped error message missing from the re-rendered form")
	}

	// Nothing must have been written.
	var storedPrefix string
	if err := db.QueryRow("SELECT COALESCE(path_prefix,'') FROM routes WHERE id = 7").Scan(&storedPrefix); err != nil {
		t.Fatal(err)
	}
	if storedPrefix == "/keep-me-xyz" {
		t.Error("a rejected submission must not be persisted")
	}
}
