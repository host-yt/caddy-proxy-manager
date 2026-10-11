package handlers

import (
	"context"
	"database/sql"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/host-yt/caddy-proxy-manager/internal/auth"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
	_ "modernc.org/sqlite"
)

// openGDPRDeleteDB builds the schema GDPRDelete touches, minus skip.
func openGDPRDeleteDB(t *testing.T, skip string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	tables := map[string]string{
		"users": `CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT, role TEXT, password_hash TEXT,
			password_set INTEGER, full_name TEXT, totp_secret TEXT, totp_secret_enc TEXT, totp_enabled INTEGER,
			is_active INTEGER, auth_epoch INTEGER DEFAULT 0)`,
		"data_deletions":  `CREATE TABLE data_deletions (user_id INTEGER, email TEXT, requested_by INTEGER, completed_at TEXT)`,
		"api_keys":        `CREATE TABLE api_keys (user_id INTEGER)`,
		"recovery_codes":  `CREATE TABLE recovery_codes (user_id INTEGER)`,
		"password_resets": `CREATE TABLE password_resets (user_id INTEGER)`,
		"audit_log":       `CREATE TABLE audit_log (user_id INTEGER, ip TEXT, user_agent TEXT)`,
	}
	for name, ddl := range tables {
		if name == skip {
			continue
		}
		if _, err := db.Exec(ddl); err != nil {
			t.Fatalf("exec %q: %v", ddl, err)
		}
	}
	if _, err := db.Exec(`INSERT INTO users (id, email, role, is_active) VALUES (5, 'a@b.c', 'client', 1)`); err != nil {
		t.Fatal(err)
	}
	return db
}

func runGDPRDelete(t *testing.T, db *sql.DB) int {
	t.Helper()
	h := &AdminHandlers{DB: func() *sql.DB { return db }, Logger: slog.Default()}
	req := httptest.NewRequest(http.MethodPost, "/admin/users/5/gdpr-delete", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "5")
	ctx := context.WithValue(req.Context(), chi.RouteCtxKey, rctx)
	ctx = middleware.ContextWithSession(ctx, &auth.Session{UserID: 1, Role: "super_admin"})
	rr := httptest.NewRecorder()
	h.GDPRDelete(rr, req.WithContext(ctx))
	return rr.Code
}

// A failing cleanup statement must abort the whole erasure, not commit a partial one.
func TestGDPRDeleteRollsBackOnCleanupFailure(t *testing.T) {
	db := openGDPRDeleteDB(t, "password_resets")
	if code := runGDPRDelete(t, db); code != http.StatusInternalServerError {
		t.Fatalf("want 500, got %d", code)
	}
	var email string
	var n int
	_ = db.QueryRow(`SELECT email FROM users WHERE id = 5`).Scan(&email)
	_ = db.QueryRow(`SELECT COUNT(*) FROM data_deletions`).Scan(&n)
	if email != "a@b.c" || n != 0 {
		t.Fatalf("partial erasure committed: email=%q deletions=%d", email, n)
	}
}

func TestGDPRDeleteSucceeds(t *testing.T) {
	db := openGDPRDeleteDB(t, "")
	if code := runGDPRDelete(t, db); code != http.StatusSeeOther && code != http.StatusFound {
		t.Fatalf("want redirect, got %d", code)
	}
	var email string
	_ = db.QueryRow(`SELECT email FROM users WHERE id = 5`).Scan(&email)
	if email != "deleted-user-5@hpg.invalid" {
		t.Fatalf("email not masked: %q", email)
	}
}
