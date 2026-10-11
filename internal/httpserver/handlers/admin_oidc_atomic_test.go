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

	"github.com/host-yt/caddy-proxy-manager/internal/auth"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
)

func readSetting(t *testing.T, db *sql.DB, key string) sql.NullString {
	t.Helper()
	var v sql.NullString
	_ = db.QueryRowContext(context.Background(), "SELECT value FROM settings WHERE `key` = ?", key).Scan(&v)
	return v
}

func restoreSetting(db *sql.DB, key string, prev sql.NullString) {
	ctx := context.Background()
	if prev.Valid {
		_ = saveSettingsTx(ctx, db, map[string]string{key: prev.String}, nil)
	} else {
		_, _ = db.ExecContext(ctx, "DELETE FROM settings WHERE `key` = ?", key)
	}
}

// A failing row must roll back the whole batch.
func TestSaveSettingsTxRollsBack(t *testing.T) {
	db := openTestDBHandlers(t)
	defer db.Close()
	prev := readSetting(t, db, "oidc.scopes")
	t.Cleanup(func() { restoreSetting(db, "oidc.scopes", prev) })
	_ = saveSettingsTx(context.Background(), db, map[string]string{"oidc.scopes": "before"}, nil)

	err := saveSettingsTx(context.Background(), db,
		map[string]string{"oidc.scopes": "after"},
		map[string]string{strings.Repeat("k", 200): "too long key"})
	if err == nil {
		t.Fatal("expected error for oversized key")
	}
	if got := readSetting(t, db, "oidc.scopes"); got.String != "before" {
		t.Fatalf("partial commit: oidc.scopes = %q", got.String)
	}
}

// An unencryptable client secret must leave every OIDC row untouched.
func TestSettingsOIDCSecretFailureWritesNothing(t *testing.T) {
	db := openTestDBHandlers(t)
	defer db.Close()
	prev := readSetting(t, db, "oidc.client_id")
	t.Cleanup(func() { restoreSetting(db, "oidc.client_id", prev) })
	_ = saveSettingsTx(context.Background(), db, map[string]string{"oidc.client_id": "old-id"}, nil)

	h := &AdminHandlers{DB: func() *sql.DB { return db }, Logger: slog.Default()} // State nil => encrypt fails
	form := url.Values{"client_id": {"new-id"}, "client_secret": {"s3cret"}, "default_role": {"client"}}
	req := httptest.NewRequest(http.MethodPost, "/admin/settings/oidc", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(middleware.ContextWithSession(req.Context(), &auth.Session{UserID: 1, Role: "super_admin"}))
	h.SettingsOIDC(httptest.NewRecorder(), req)

	if got := readSetting(t, db, "oidc.client_id"); got.String != "old-id" {
		t.Fatalf("client_id written despite secret failure: %q", got.String)
	}
}
