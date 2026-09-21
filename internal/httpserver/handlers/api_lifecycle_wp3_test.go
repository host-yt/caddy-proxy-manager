package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/host-yt/caddy-proxy-manager/internal/domain/routes"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"

	_ "modernc.org/sqlite"
)

// HPG-008: the API update path used to write any port the caller asked for.
// Owning the record is not permission to move it outside the service's
// allocation (10000-20000 in the seeded fixture).
func TestAPIRouteUpdate_RejectsPortOutsideServiceRange(t *testing.T) {
	db := mtlsTLSEditDB(t)

	rec := patchRoute7(t, db, `{"upstream_port":9000}`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
	}
	var port int
	if err := db.QueryRow("SELECT upstream_port FROM routes WHERE id = 7").Scan(&port); err != nil {
		t.Fatal(err)
	}
	if port != 10001 {
		t.Errorf("port = %d, want the row left untouched at 10001", port)
	}
}

// HPG-019: a PATCH that writes nothing new to an existing, authorized route is
// a success, not a 404. (The 404 itself only reproduces on MySQL, whose default
// affected-rows semantics report 0 for a no-op write; the distinction the fix
// makes - missing / security conflict / nothing changed - is asserted here.)
func TestAPIRouteUpdate_NoopIsSuccess(t *testing.T) {
	db := mtlsTLSEditDB(t)

	rec := patchRoute7(t, db, `{"upstream_port":10001}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["updated"] != false {
		t.Errorf("updated = %v, want false for a no-op", body["updated"])
	}
}

// A missing route still has to be a 404, so the no-op success above cannot be
// mistaken for "any id is fine".
func TestAPIRouteUpdate_MissingRouteIs404(t *testing.T) {
	db := mtlsTLSEditDB(t)
	h := &APIHandlers{
		DB: func() *sql.DB { return db }, Logger: discardLoggerWP3(),
		Routes: &routes.Service{DB: db, Logger: discardLoggerWP3()},
	}
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/routes/4242", strings.NewReader(`{"upstream_port":10002}`))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "4242")
	ctx := context.WithValue(req.Context(), chi.RouteCtxKey, rctx)
	ctx = middleware.ContextWithAPICaller(ctx, &middleware.APICaller{UserID: 1, Role: "super_admin"})
	rec := httptest.NewRecorder()
	h.RouteUpdate(rec, req.WithContext(ctx))
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404; body %s", rec.Code, rec.Body.String())
	}
}

// HPG-007: FOSSBilling suspend used to call Routes.Delete per route, which
// physically deleted the rows - an unsuspend had nothing left to restore.
func TestFOSSBillingSuspend_KeepsRouteDefinitions(t *testing.T) {
	db := mtlsTLSEditDB(t)
	h := &FOSSBillingHandlers{
		DB:     func() *sql.DB { return db },
		Routes: &routes.Service{DB: db, Logger: discardLoggerWP3(), BgCtx: cancelledCtxWP3()},
	}
	req := httptest.NewRequest(http.MethodPost, "/api/fossbilling/services/1/suspend", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "1")
	ctx := context.WithValue(req.Context(), chi.RouteCtxKey, rctx)
	ctx = middleware.ContextWithAPICaller(ctx, &middleware.APICaller{UserID: 1, Role: "super_admin"})
	rec := httptest.NewRecorder()
	h.SuspendService(rec, req.WithContext(ctx))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}

	var status, reason, svcStatus string
	if err := db.QueryRow(
		`SELECT r.status, COALESCE(r.disabled_reason,''), s.status
		   FROM routes r JOIN services s ON s.id = r.service_id WHERE r.id = 7`,
	).Scan(&status, &reason, &svcStatus); err != nil {
		t.Fatalf("route row is gone after suspend: %v", err)
	}
	if status != "disabled" || reason != "service_suspended" || svcStatus != "suspended" {
		t.Errorf("route=%s/%s service=%s, want disabled/service_suspended/suspended", status, reason, svcStatus)
	}
}

// HPG-001 write side: Caddy expands placeholders in a static_response body, so
// a tenant-supplied error page naming {file.*} must be refused at save time.
func TestHostsUpdate_RejectsPlaceholderInErrorHTML(t *testing.T) {
	db := mtlsTLSEditDB(t)
	form := baseEditForm()
	form.Set("ssl", "1")
	form.Set("error_override", "1")
	form.Set("error_html", "<h1>down</h1>{file./etc/ssl/private/node.key}")
	loc := postHostEdit(t, db, form)
	if !strings.Contains(loc, "err=") || !strings.Contains(loc, "placeholder") {
		t.Fatalf("Location = %q, want a placeholder rejection", loc)
	}
	var stored string
	if err := db.QueryRow("SELECT COALESCE(error_html,'') FROM routes WHERE id = 7").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != "" {
		t.Errorf("error_html was stored despite the rejection: %q", stored)
	}
}

// The same screen on the redirect target: it lands in a Location header the
// replacer expands.
func TestHostsUpdate_RejectsPlaceholderInRedirectURL(t *testing.T) {
	db := mtlsTLSEditDB(t)
	form := url.Values{
		"domain":        {"locked.example"},
		"kind":          {"redirect"},
		"redirect_url":  {"https://evil.example/{env.APP_SECRET}"},
		"redirect_code": {"308"},
		"ssl":           {"1"},
	}
	loc := postHostEdit(t, db, form)
	if !strings.Contains(loc, "err=") || !strings.Contains(loc, "placeholder") {
		t.Fatalf("Location = %q, want a placeholder rejection", loc)
	}
	var kind string
	if err := db.QueryRow("SELECT kind FROM routes WHERE id = 7").Scan(&kind); err != nil {
		t.Fatal(err)
	}
	if kind != "proxy" {
		t.Errorf("kind = %q, want the save rejected before any write", kind)
	}
}

// HPG-008 on the panel form: the edit page bypassed the same port allocation.
func TestHostsUpdate_RejectsPortOutsideServiceRange(t *testing.T) {
	db := mtlsTLSEditDB(t)
	form := baseEditForm()
	form.Set("port", "9000")
	loc := postHostEdit(t, db, form)
	if !strings.Contains(loc, "err=") {
		t.Fatalf("Location = %q, want a rejection", loc)
	}
	var port int
	if err := db.QueryRow("SELECT upstream_port FROM routes WHERE id = 7").Scan(&port); err != nil {
		t.Fatal(err)
	}
	if port != 10001 {
		t.Errorf("port = %d, want 10001 (write refused)", port)
	}
}

func discardLoggerWP3() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// cancelledCtxWP3 keeps post-commit pushes from dialling the fake node.
func cancelledCtxWP3() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

// listRoutes drives GET /api/v1/routes with the given query string.
func listRoutes(t *testing.T, db *sql.DB, query string) *httptest.ResponseRecorder {
	t.Helper()
	h := &APIHandlers{DB: func() *sql.DB { return db }, Logger: discardLoggerWP3()}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/routes"+query, nil)
	ctx := middleware.ContextWithAPICaller(req.Context(), &middleware.APICaller{UserID: 1, Role: "super_admin"})
	rec := httptest.NewRecorder()
	h.RoutesList(rec, req.WithContext(ctx))
	return rec
}

// HPG-020: a row that cannot be read used to be skipped, so a failed read
// reached the integration as a normal, shorter list - and missing resources
// look deleted.
func TestAPIRoutesList_ReadFailureIsNotAShortList(t *testing.T) {
	db := mtlsTLSEditDB(t)
	if _, err := db.Exec(
		`INSERT INTO routes (id, service_id, caddy_node_id, domain, upstream_port, upstream_scheme, kind,
		   ssl_enabled, status, domain_verified, created_at)
		 VALUES (8, 1, 1, 'broken.example', 10002, 'http', 'proxy', 1, 'active', 1, 'not-a-timestamp')`); err != nil {
		t.Fatal(err)
	}
	rec := listRoutes(t, db, "")
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500; body %s", rec.Code, rec.Body.String())
	}
}

// Pagination is opt-in: no ?limit keeps the single complete array, ?limit pages
// with a stable keyset cursor.
func TestAPIRoutesList_OptInPagination(t *testing.T) {
	db := mtlsTLSEditDB(t)
	if _, err := db.Exec(
		`INSERT INTO routes (id, service_id, caddy_node_id, domain, upstream_port, upstream_scheme, kind,
		   ssl_enabled, status, domain_verified)
		 VALUES (8, 1, 1, 'second.example', 10002, 'http', 'proxy', 1, 'active', 1)`); err != nil {
		t.Fatal(err)
	}
	decode := func(rec *httptest.ResponseRecorder) map[string]any {
		t.Helper()
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d; body %s", rec.Code, rec.Body.String())
		}
		var body map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		return body
	}
	full := decode(listRoutes(t, db, ""))
	if n := len(full["routes"].([]any)); n != 2 {
		t.Errorf("unpaginated list = %d routes, want both", n)
	}
	if _, ok := full["next_cursor"]; ok {
		t.Error("unpaginated list must not carry a cursor")
	}
	page := decode(listRoutes(t, db, "?limit=1"))
	if n := len(page["routes"].([]any)); n != 1 {
		t.Fatalf("page = %d routes, want 1", n)
	}
	cur, ok := page["next_cursor"].(string)
	if !ok {
		t.Fatal("first page has no next_cursor")
	}
	next := decode(listRoutes(t, db, "?limit=1&cursor="+cur))
	if n := len(next["routes"].([]any)); n != 1 {
		t.Errorf("second page = %d routes, want 1", n)
	}
	if rec := listRoutes(t, db, "?limit=99999"); rec.Code != http.StatusBadRequest {
		t.Errorf("oversized limit = %d, want 400", rec.Code)
	}
}
