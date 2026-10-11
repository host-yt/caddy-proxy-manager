package handlers

import (
	"context"
	"database/sql"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/host-yt/caddy-proxy-manager/internal/mail"
)

// A failed "Send test email" must not overwrite the live SMTP settings.
func TestSettingsSMTPTestDoesNotPersist(t *testing.T) {
	db := openTestDBHandlers(t)
	defer db.Close()
	ctx := context.Background()

	var prev sql.NullString
	_ = db.QueryRowContext(ctx, "SELECT value FROM settings WHERE `key` = 'smtp.host'").Scan(&prev)
	h := &AdminHandlers{DB: func() *sql.DB { return db }, Logger: slog.Default(),
		Mailer: &mail.Mailer{DB: db, Logger: slog.Default()}}
	if err := h.saveSettings(ctx, db, map[string]string{"smtp.host": "live.example.test"}, false); err != nil {
		t.Fatalf("seed: %v", err)
	}
	t.Cleanup(func() {
		if prev.Valid {
			_ = h.saveSettings(ctx, db, map[string]string{"smtp.host": prev.String}, false)
		} else {
			_, _ = db.ExecContext(ctx, "DELETE FROM settings WHERE `key` = 'smtp.host'")
		}
	})

	form := url.Values{"action": {"test"}, "host": {"127.0.0.1"}, "port": {"1"},
		"encryption": {"none"}, "from_email": {"ops@example.test"}}
	req := httptest.NewRequest(http.MethodPost, "/admin/settings/smtp", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.SettingsSMTP(rec, req)
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "Test+failed") && !strings.Contains(loc, "Test%20failed") {
		t.Fatalf("expected failed test redirect, got %q", loc)
	}

	var host string
	if err := db.QueryRowContext(ctx, "SELECT value FROM settings WHERE `key` = 'smtp.host'").Scan(&host); err != nil {
		t.Fatalf("select: %v", err)
	}
	if host != "live.example.test" {
		t.Fatalf("test send overwrote smtp.host: %q", host)
	}
}
