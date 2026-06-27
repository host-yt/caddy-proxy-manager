package handlers

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/host-yt/caddy-proxy-manager/internal/auth"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
	"github.com/host-yt/caddy-proxy-manager/internal/view"
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
		}
	}
}
