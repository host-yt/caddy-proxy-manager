package handlers

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/pquerna/otp/totp"

	"github.com/host-yt/caddy-proxy-manager/internal/auth"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
	"github.com/host-yt/caddy-proxy-manager/internal/view"
)

// openTestDBHandlers opens a real DB via TEST_DB_DSN or skips.
func openTestDBHandlers(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("TEST_DB_DSN")
	if dsn == "" {
		t.Skip("TEST_DB_DSN not set - skipping DB-backed test")
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		t.Skipf("DB not reachable: %v", err)
	}
	return db
}

// insertPendingTOTPUser creates a client user with a TOTP enrollment stash and
// returns its id plus a cleanup func. stashSecret is stored raw (State is nil
// in these tests, so the confirm path reads it without decryption).
func insertPendingTOTPUser(t *testing.T, db *sql.DB, stashSecret string) (int64, func()) {
	t.Helper()
	ctx := context.Background()
	email := fmt.Sprintf("twofatest_%d@example.com", time.Now().UnixNano())
	res, err := db.ExecContext(ctx,
		`INSERT INTO users (email, password_hash, role, totp_enabled,
		   totp_pending_secret, totp_pending_exp, totp_pending_attempts)
		 VALUES (?, 'x', 'client', 0, ?, ?, 0)`,
		email, stashSecret, time.Now().Add(10*time.Minute))
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}
	uid, _ := res.LastInsertId()
	cleanup := func() {
		_, _ = db.ExecContext(ctx, "DELETE FROM recovery_codes WHERE user_id = ?", uid)
		_, _ = db.ExecContext(ctx, "DELETE FROM users WHERE id = ?", uid)
	}
	return uid, cleanup
}

func newTOTPConfirmHandler(t *testing.T, db *sql.DB) *ClientHandlers {
	t.Helper()
	tpls, err := view.LoadAppTemplates()
	if err != nil {
		t.Fatalf("load app templates: %v", err)
	}
	return &ClientHandlers{
		DB:        func() *sql.DB { return db },
		Templates: tpls,
		Logger:    slog.Default(),
		State:     nil, // raw stash, no encryption
	}
}

func postConfirm(h *ClientHandlers, uid int64, formSecret, code string) {
	form := url.Values{"secret": {formSecret}, "code": {code}}
	r := httptest.NewRequest(http.MethodPost, "/app/2fa/confirm", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = r.WithContext(middleware.ContextWithSession(r.Context(),
		&auth.Session{UserID: uid, Role: "client", Email: "u@example.com"}))
	h.TwoFAConfirm(httptest.NewRecorder(), r)
}

// TestTwoFAConfirmUsesStashNotForm proves the confirm step validates the code
// against the server-side DB stash, never against a `secret` from the POST body.
// Catches reintroduction of r.FormValue("secret").
func TestTwoFAConfirmUsesStashNotForm(t *testing.T) {
	db := openTestDBHandlers(t)
	defer db.Close()
	ctx := context.Background()
	h := newTOTPConfirmHandler(t, db)

	_, stashSecret, _, err := auth.GenerateTOTP("HPG", "stash")
	if err != nil {
		t.Fatalf("gen stash secret: %v", err)
	}

	t.Run("valid stash code with garbage form secret enables 2FA", func(t *testing.T) {
		uid, cleanup := insertPendingTOTPUser(t, db, stashSecret)
		defer cleanup()
		code, err := totp.GenerateCode(stashSecret, time.Now())
		if err != nil {
			t.Fatalf("gen code: %v", err)
		}
		postConfirm(h, uid, "GARBAGEFORMSECRET", code)

		var enabled bool
		var pending sql.NullString
		if err := db.QueryRowContext(ctx,
			"SELECT totp_enabled, totp_pending_secret FROM users WHERE id = ?", uid,
		).Scan(&enabled, &pending); err != nil {
			t.Fatalf("read user: %v", err)
		}
		if !enabled {
			t.Error("2FA not enabled - confirm rejected a valid stash code")
		}
		if pending.Valid && pending.String != "" {
			t.Error("stash not consumed after success")
		}
	})

	t.Run("code valid only for form secret is rejected", func(t *testing.T) {
		uid, cleanup := insertPendingTOTPUser(t, db, stashSecret)
		defer cleanup()
		_, formSecret, _, err := auth.GenerateTOTP("HPG", "form")
		if err != nil {
			t.Fatalf("gen form secret: %v", err)
		}
		code, err := totp.GenerateCode(formSecret, time.Now())
		if err != nil {
			t.Fatalf("gen code: %v", err)
		}
		postConfirm(h, uid, formSecret, code)

		var enabled bool
		var attempts int
		if err := db.QueryRowContext(ctx,
			"SELECT totp_enabled, totp_pending_attempts FROM users WHERE id = ?", uid,
		).Scan(&enabled, &attempts); err != nil {
			t.Fatalf("read user: %v", err)
		}
		if enabled {
			t.Error("2FA enabled with a code valid only for the form secret - handler trusted the form body")
		}
		if attempts != 1 {
			t.Errorf("attempts = %d, want 1 (one failed guess against the stash)", attempts)
		}
	})
}

// TestTwoFAConfirmAttemptCap proves the enrollment stash is cleared after 5
// failed confirm attempts so guesses against the window are bounded.
func TestTwoFAConfirmAttemptCap(t *testing.T) {
	db := openTestDBHandlers(t)
	defer db.Close()
	ctx := context.Background()
	h := newTOTPConfirmHandler(t, db)

	_, stashSecret, _, err := auth.GenerateTOTP("HPG", "cap")
	if err != nil {
		t.Fatalf("gen secret: %v", err)
	}
	uid, cleanup := insertPendingTOTPUser(t, db, stashSecret)
	defer cleanup()

	// A code guaranteed wrong for the current window: flip a digit of the valid one.
	valid, err := totp.GenerateCode(stashSecret, time.Now())
	if err != nil {
		t.Fatalf("gen code: %v", err)
	}
	wrong := []byte(valid)
	wrong[0] = '0' + byte((int(wrong[0]-'0')+1)%10)

	for i := 0; i < 5; i++ {
		postConfirm(h, uid, "", string(wrong))
	}

	var enabled bool
	var pending sql.NullString
	if err := db.QueryRowContext(ctx,
		"SELECT totp_enabled, totp_pending_secret FROM users WHERE id = ?", uid,
	).Scan(&enabled, &pending); err != nil {
		t.Fatalf("read user: %v", err)
	}
	if enabled {
		t.Error("2FA enabled after only wrong codes")
	}
	if pending.Valid && pending.String != "" {
		t.Error("stash not cleared after 5 failed attempts - guesses are not bounded")
	}
}
