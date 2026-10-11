package handlers

import (
	"database/sql"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/host-yt/caddy-proxy-manager/internal/security"
)

// RBAC must resolve the exact presented leaf: a second cert with the same
// subject, a revoked or expired row, or a forged fingerprint gets no roles.
func TestMTLSRBACCheck_ExactLeafOnly(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	req := func(db *sql.DB, certPEM string, tweak func(map[string]string)) int {
		h := &AdminHandlers{DB: func() *sql.DB { return db }, Logger: slog.Default(), MTLSRBACKey: key}
		hdr := withLeaf(certPEM, map[string]string{
			"X-Forwarded-Uri":            "/admin/panel",
			security.MTLSRBACHeaderNode:  "1",
			security.MTLSRBACHeaderToken: security.MTLSRBACToken(key, 1, 7),
		})
		if tweak != nil {
			tweak(hdr)
		}
		return rbacRequest(t, h, "7", hdr)
	}

	t.Run("same subject, no role", func(t *testing.T) {
		db := openRBACTestDB(t)
		twin := mustLeafPEM(6, "ops", time.Now().Add(time.Hour))
		insertRBACCert(t, db, 6, "ops", "active", twin)
		if got := req(db, twin, nil); got != http.StatusForbidden {
			t.Errorf("twin status = %d, want 403", got)
		}
	})
	t.Run("revoked leaf keeps no role", func(t *testing.T) {
		db := openRBACTestDB(t)
		if _, err := db.Exec(`UPDATE mtls_issued_certs SET status = 'revoked' WHERE id = 5`); err != nil {
			t.Fatal(err)
		}
		if got := req(db, rbacOpsPEM, nil); got != http.StatusForbidden {
			t.Errorf("revoked status = %d, want 403", got)
		}
	})
	t.Run("expired leaf", func(t *testing.T) {
		db := openRBACTestDB(t)
		old := mustLeafPEM(8, "old", time.Now().Add(-time.Hour))
		insertRBACCert(t, db, 8, "old", "active", old)
		if _, err := db.Exec(`INSERT INTO mtls_cert_roles (cert_id, role_id) VALUES (8, 1)`); err != nil {
			t.Fatal(err)
		}
		if got := req(db, old, nil); got != http.StatusForbidden {
			t.Errorf("expired status = %d, want 403", got)
		}
	})
	t.Run("forged fingerprint", func(t *testing.T) {
		db := openRBACTestDB(t)
		got := req(db, rbacOpsPEM, func(h map[string]string) { h["X-Mtls-Fingerprint"] = "ab" })
		if got != http.StatusForbidden {
			t.Errorf("forged status = %d, want 403", got)
		}
	})
	t.Run("legit leaf", func(t *testing.T) {
		db := openRBACTestDB(t)
		if got := req(db, rbacOpsPEM, nil); got != http.StatusOK {
			t.Errorf("legit status = %d, want 200", got)
		}
	})
}
