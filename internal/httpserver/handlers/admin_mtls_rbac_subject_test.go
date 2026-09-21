package handlers

import (
	"crypto/x509/pkix"
	"database/sql"
	"log/slog"
	"net/http"
	"testing"

	"github.com/host-yt/caddy-proxy-manager/internal/security"
)

// Path RBAC denied every request, legitimate ones included: issuance stores the
// operator-typed common name, Caddy sends the rendered DN, and the two were
// compared directly. The existing suite missed it because its fixture seeds a
// subject ("CN=ops") that the issue path cannot produce.
func TestMTLSRBACCheck_MatchesIssuedBareCommonName(t *testing.T) {
	db := openRBACTestDB(t)
	// Overwrite the fixture row with what mtls.Issue actually writes.
	if _, err := db.Exec(`UPDATE mtls_issued_certs SET subject = 'device-42' WHERE id = 5`); err != nil {
		t.Fatalf("seed: %v", err)
	}
	key := []byte("0123456789abcdef0123456789abcdef")
	h := &AdminHandlers{DB: func() *sql.DB { return db }, Logger: slog.Default(), MTLSRBACKey: key}

	// Exactly what Caddy's {http.request.tls.client.subject} renders for it.
	dn := pkix.Name{CommonName: "device-42"}.String()
	if dn == "device-42" {
		t.Fatalf("expected a DN distinct from the stored name, got %q", dn)
	}

	got := rbacRequest(t, h, "7", map[string]string{
		"X-Mtls-Subject":             dn,
		"X-Forwarded-Uri":            "/admin/panel",
		"X-Forwarded-Method":         "GET",
		security.MTLSRBACHeaderNode:  "1",
		security.MTLSRBACHeaderToken: security.MTLSRBACToken(key, 1, 7),
	})
	if got != http.StatusOK {
		t.Errorf("status = %d, want %d - a valid cert holder is being denied", got, http.StatusOK)
	}
}

// The normalization must not become a way in: a DN whose common name holds no
// issued cert still fails.
func TestMTLSRBACCheck_UnknownCommonNameStillDenied(t *testing.T) {
	db := openRBACTestDB(t)
	if _, err := db.Exec(`UPDATE mtls_issued_certs SET subject = 'device-42' WHERE id = 5`); err != nil {
		t.Fatalf("seed: %v", err)
	}
	key := []byte("0123456789abcdef0123456789abcdef")
	h := &AdminHandlers{DB: func() *sql.DB { return db }, Logger: slog.Default(), MTLSRBACKey: key}

	got := rbacRequest(t, h, "7", map[string]string{
		"X-Mtls-Subject":             pkix.Name{CommonName: "attacker"}.String(),
		"X-Forwarded-Uri":            "/admin/panel",
		"X-Forwarded-Method":         "GET",
		security.MTLSRBACHeaderNode:  "1",
		security.MTLSRBACHeaderToken: security.MTLSRBACToken(key, 1, 7),
	})
	if got != http.StatusForbidden {
		t.Errorf("status = %d, want %d", got, http.StatusForbidden)
	}
}
