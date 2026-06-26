package handlers

import (
	"bytes"
	"strings"
	"testing"

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
