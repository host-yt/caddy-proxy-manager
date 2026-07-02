package handlers

import (
	"bytes"
	"context"
	"database/sql"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/host-yt/caddy-proxy-manager/internal/adminscope"
	"github.com/host-yt/caddy-proxy-manager/internal/auth"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
	"github.com/host-yt/caddy-proxy-manager/internal/view"

	_ "modernc.org/sqlite"
)

// TestClientTwofaEnrollNoHiddenSecret verifies that the client TOTP enrollment
// template does NOT embed the TOTP secret in a hidden form field.
// The secret must only be shown once for manual entry; the confirm step reads
// it from the server-side DB stash, not from the POST body.
func TestClientTwofaEnrollNoHiddenSecret(t *testing.T) {
	tpls, err := view.LoadAppTemplates()
	if err != nil {
		t.Fatalf("load app templates: %v", err)
	}

	const sentinel = "SECRETVALUE123456789"
	var buf bytes.Buffer
	err = tpls.Render(&buf, "twofa", clientTwofaData{
		baseAppData: baseAppData{
			CSRF:     "csrf",
			CSPNonce: "nonce",
		},
		Enrolling: true,
		Secret:    sentinel,
		QRBase64:  "AAAA",
	})
	if err != nil {
		t.Fatalf("render twofa: %v", err)
	}
	html := buf.String()

	// Secret should appear exactly once (the visible display for manual entry).
	count := strings.Count(html, sentinel)
	if count == 0 {
		t.Fatal("secret not shown at all - QR display is broken")
	}

	// It MUST NOT appear inside a hidden input or any form field.
	if strings.Contains(html, `type="hidden" name="secret"`) {
		t.Fatal("hidden form field 'secret' found - secret must not round-trip through the browser")
	}
	if strings.Contains(html, `name="secret" value=`) {
		t.Fatal("'secret' value attribute in form - secret must not round-trip through the browser")
	}
}

// scopedAdminSchemaDB builds a hermetic in-memory scope DB: adminUserID=1 is
// assigned client 100 (route 1000) only; client 200 (route 2000) is another
// tenant. Mirrors the fixture in internal/adminscope/service_test.go.
func scopedAdminSchemaDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	stmts := []string{
		`CREATE TABLE admin_client_scope (admin_user_id INTEGER, client_id INTEGER)`,
		`CREATE TABLE services (id INTEGER PRIMARY KEY, client_id INTEGER)`,
		`CREATE TABLE routes (id INTEGER PRIMARY KEY, service_id INTEGER)`,
		`INSERT INTO admin_client_scope (admin_user_id, client_id) VALUES (1, 100)`,
		`INSERT INTO services (id, client_id) VALUES (10, 100), (20, 200)`,
		`INSERT INTO routes (id, service_id) VALUES (1000, 10), (2000, 20)`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("exec %q: %v", s, err)
		}
	}
	return db
}

// TestClientCannotAccessOtherTenantResource is an IDOR/BOLA regression at the
// handler-glue layer: scopeCheckRoute/scopeCheckClient (called from
// admin_host_logs.go and admin_tunnels.go before touching a route/client)
// must deny a scoped admin reaching another tenant's route or client.
func TestClientCannotAccessOtherTenantResource(t *testing.T) {
	db := scopedAdminSchemaDB(t)
	h := &AdminHandlers{
		AdminScope: adminscope.New(func() *sql.DB { return db }),
		Logger:     slog.Default(),
	}
	ctx := context.Background()
	scoped := &auth.Session{UserID: 1, Role: "admin"} // scoped to client 100 only

	if !h.scopeCheckRoute(ctx, scoped, 1000) {
		t.Error("scoped admin must access a route under its own client")
	}
	if h.scopeCheckRoute(ctx, scoped, 2000) {
		t.Error("IDOR: scoped admin reached a route belonging to another tenant")
	}
	if !h.scopeCheckClient(ctx, scoped, 100) {
		t.Error("scoped admin must access its own assigned client")
	}
	if h.scopeCheckClient(ctx, scoped, 200) {
		t.Error("IDOR: scoped admin reached a client outside its scope")
	}

	// super_admin bypasses scoping entirely regardless of assignment rows.
	super := &auth.Session{UserID: 99, Role: "super_admin"}
	if !h.scopeCheckRoute(ctx, super, 2000) {
		t.Error("super_admin must not be scope-blocked")
	}
	if !h.scopeCheckClient(ctx, super, 200) {
		t.Error("super_admin must not be scope-blocked")
	}
}

// TestUsersReset2FARequiresSuperAdmin verifies that a non-super_admin session
// cannot reset another user's 2FA. This would allow privilege escalation via
// disabling MFA on a super_admin account.
func TestUsersReset2FARequiresSuperAdmin(t *testing.T) {
	h := &AdminHandlers{}
	for _, role := range []string{"admin", "support", "client", ""} {
		req := httptest.NewRequest(http.MethodPost, "/admin/users/1/reset-2fa", nil)
		sess := &auth.Session{UserID: 99, Role: role}
		req = req.WithContext(middleware.ContextWithSession(req.Context(), sess))
		rr := httptest.NewRecorder()
		h.UsersReset2FA(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Errorf("role %q: expected 403 Forbidden, got %d", role, rr.Code)
		}
	}
}

// TestAdminTwofaEnrollNoHiddenSecret verifies that the admin TOTP enrollment
// template likewise does NOT embed the secret in any hidden form field.
// The admin path already uses Redis; this guards against regressions.
func TestAdminTwofaEnrollNoHiddenSecret(t *testing.T) {
	tpls, err := view.LoadAdminTemplates()
	if err != nil {
		t.Fatalf("load admin templates: %v", err)
	}

	const sentinel = "SECRETVALUE123456789"
	var buf bytes.Buffer
	err = tpls.Render(&buf, "twofa", twofaData{
		baseAdminData: baseAdminData{
			Role:     "admin",
			CSRF:     "csrf",
			CSPNonce: "nonce",
		},
		Enrolling: true,
		Secret:    sentinel,
		QRBase64:  "AAAA",
	})
	if err != nil {
		t.Fatalf("render admin twofa: %v", err)
	}
	html := buf.String()

	if strings.Contains(html, `type="hidden" name="secret"`) {
		t.Fatal("hidden form field 'secret' found in admin template")
	}
	if strings.Contains(html, `name="secret" value=`) {
		t.Fatal("'secret' value attribute found in admin template form")
	}
}

// TestNoSQLAntiPatterns guards against known bad SQL patterns in handler files.
// UNIX_TIMESTAMP(NOW() ... ) compared against a DATETIME column always passes
// because MySQL coerces DATETIME to YYYYMMDDHHMMSS (a 14-digit integer) which
// always exceeds any unix timestamp; the WHERE clause becomes a no-op.
// Also guards against action='block' (node-agent stores 'blocked', not 'block').
func TestNoSQLAntiPatterns(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		src, err := os.ReadFile(filepath.Join(".", e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		lower := strings.ToLower(string(src))
		// Remove line comments so doc examples don't trip the check.
		var clean strings.Builder
		for _, line := range strings.Split(lower, "\n") {
			if i := strings.Index(line, "//"); i >= 0 {
				line = line[:i]
			}
			clean.WriteString(line)
			clean.WriteString("\n")
		}
		code := clean.String()
		if strings.Contains(code, "unix_timestamp(now()") && strings.Contains(code, "interval") {
			if strings.Contains(code, ">= unix_timestamp(now()") || strings.Contains(code, "> unix_timestamp(now()") {
				t.Errorf("%s: DATETIME compared to UNIX_TIMESTAMP(NOW()) always passes - use NOW() - INTERVAL directly", e.Name())
			}
		}
		// WAF action values: node-agent writes 'blocked'/'detected'; 'block'/'detect' never match.
		if strings.Contains(code, "waf_events") {
			if strings.Contains(code, "action='block'") || strings.Contains(code, `action = 'block'`) {
				t.Errorf("%s: WAF action='block' never matches - node-agent stores 'blocked'", e.Name())
			}
			// waf_events.ts is indexed; waf_events.created_at skips the index.
			if strings.Contains(code, "we.created_at") || strings.Contains(code, "waf_events.created_at") {
				t.Errorf("%s: filter waf_events by we.ts (indexed), not we.created_at", e.Name())
			}
		}
		// plans column is websocket_enabled; p.websocket=N in SQL (without _enabled) does not exist.
		if strings.Contains(code, "p.websocket=") || strings.Contains(code, "p.websocket =") {
			if !strings.Contains(code, "p.websocket_enabled") {
				t.Errorf("%s: plans column is websocket_enabled, not websocket", e.Name())
			}
		}
	}
}
