package handlers

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/host-yt/caddy-proxy-manager/internal/audit"
	"github.com/host-yt/caddy-proxy-manager/internal/auth"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
	"github.com/host-yt/caddy-proxy-manager/internal/security"
	"github.com/host-yt/caddy-proxy-manager/internal/store"
)

// emailRegexp validates the basic shape of an email address.
var emailRegexp = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

// registerRateMu guards registerRateMap.
var registerRateMu sync.Mutex

// registerRateMap tracks last registration attempt time per IP.
// Simple in-memory 1-per-minute-per-IP gate; resets on restart.
var registerRateMap = map[string]time.Time{}

type registerViewData struct {
	Error    string
	Flash    string
	CSPNonce string
	Lang     string
	Brand    Branding
}

func (h *AuthHandlers) stampRegister(r *http.Request, d registerViewData) registerViewData {
	d.CSPNonce, d.Lang = authBase(r)
	if db := h.DB(); db != nil {
		d.Brand = LoadBranding(r.Context(), db)
	}
	return d
}

func (h *AuthHandlers) renderRegister(w http.ResponseWriter, status int, data registerViewData) {
	var buf bytes.Buffer
	if err := h.Templates.Render(&buf, "register.html.tmpl", data); err != nil {
		h.Logger.Error("render register", "err", err)
		http.Error(w, "render failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

// selfRegEnabled reads the toggle from the settings table.
func selfRegEnabled(ctx context.Context, db *sql.DB) bool {
	var v string
	_ = db.QueryRowContext(ctx,
		"SELECT value FROM settings WHERE `key` = 'auth.allow_self_registration' LIMIT 1",
	).Scan(&v)
	return v == "1"
}

// RegisterPage serves GET /auth/register.
// Redirects to login when the toggle is off.
func (h *AuthHandlers) RegisterPage(w http.ResponseWriter, r *http.Request) {
	db := h.DB()
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	if db == nil || !selfRegEnabled(ctx, db) {
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}
	nonce, lang := authBase(r)
	h.renderRegister(w, http.StatusOK, h.stampRegister(r, registerViewData{CSPNonce: nonce, Lang: lang}))
}

// RegisterSubmit handles POST /auth/register.
func (h *AuthHandlers) RegisterSubmit(w http.ResponseWriter, r *http.Request) {
	db := h.DB()
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	if db == nil || !selfRegEnabled(ctx, db) {
		http.Error(w, "Registration is disabled.", http.StatusForbidden)
		return
	}

	_ = r.ParseForm()
	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	password := r.FormValue("password")
	confirm := r.FormValue("confirm_password")

	renderErr := func(msg string) {
		h.renderRegister(w, http.StatusBadRequest, h.stampRegister(r, registerViewData{Error: msg}))
	}

	// Validate fields.
	if email == "" || password == "" || confirm == "" {
		renderErr("All fields are required.")
		return
	}
	if !emailRegexp.MatchString(email) {
		renderErr("Invalid email address.")
		return
	}
	// AUTH-04: align with the reset flow (>=12), which is the stronger bar.
	if len(password) < 12 {
		renderErr("Password must be at least 12 characters.")
		return
	}
	if password != confirm {
		renderErr("Passwords do not match.")
		return
	}

	// Per-IP rate limit: 1 registration attempt per minute.
	ip := security.ClientIP(r)
	if ip != "" {
		registerRateMu.Lock()
		last, ok := registerRateMap[ip]
		now := time.Now()
		if ok && now.Sub(last) < time.Minute {
			registerRateMu.Unlock()
			renderErr("Too many registration attempts. Try again in a minute.")
			return
		}
		registerRateMap[ip] = now
		registerRateMu.Unlock()
	}

	// Check email uniqueness.
	var existing int64
	_ = db.QueryRowContext(ctx, "SELECT id FROM users WHERE email = ? LIMIT 1", email).Scan(&existing)
	if existing != 0 {
		renderErr("An account with that email already exists.")
		return
	}

	// Hash password using the project-standard Argon2id hasher.
	hash, err := auth.HashPassword(password)
	if err != nil {
		h.Logger.Error("register hash password", "err", err)
		h.renderRegister(w, http.StatusInternalServerError, h.stampRegister(r, registerViewData{Error: "Server error."}))
		return
	}

	// AUTH-02: self-registered accounts are attacker-chosen and unproven. Insert
	// email_verified=0 + is_active=0 so they cannot log in and cannot be adopted
	// by an OAuth/OIDC-by-email path until the double opt-in link is followed.
	// Existing users were backfilled to email_verified=1 and are unaffected.
	res, err := db.ExecContext(ctx,
		"INSERT INTO users (email, password_hash, role, is_active, full_name, email_verified) VALUES (?, ?, 'client', 0, ?, 0)",
		email, hash, email,
	)
	if err != nil {
		h.Logger.Error("register insert user", "err", err)
		h.renderRegister(w, http.StatusInternalServerError, h.stampRegister(r, registerViewData{Error: "Server error."}))
		return
	}
	userID, _ := res.LastInsertId()

	// Insert corresponding client row.
	if _, err := db.ExecContext(ctx,
		"INSERT INTO clients (user_id, display_name) VALUES (?, ?)",
		userID, email,
	); err != nil {
		h.Logger.Error("register insert client", "err", err)
		// User row exists - don't fail visibly; client row can be fixed via admin.
	}

	// Record intended default plan in audit; service creation requires
	// backend_ip + node_group_id which self-registration cannot supply.
	var defaultPlanID string
	_ = db.QueryRowContext(ctx,
		"SELECT value FROM settings WHERE `key` = 'auth.default_plan_id' LIMIT 1",
	).Scan(&defaultPlanID)

	sess := middleware.SessionFromContext(r.Context())
	actor := "self"
	if sess != nil {
		actor = sess.Email
	}
	uid := userID
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: &uid,
		Action: "auth.register", Entity: "user", EntityID: email,
		Meta: map[string]any{"ip": ip, "actor": actor, "default_plan_id": defaultPlanID},
	})

	// Double opt-in: mint a one-time verify token and email the link. The
	// account stays email_verified=0/is_active=0 until the link is followed.
	if token, terr := createEmailVerifyToken(ctx, db, userID); terr == nil && h.Mailer != nil {
		verifyURL := strings.TrimRight(h.AppURL, "/") + "/auth/verify?token=" + token
		if serr := h.Mailer.Send(ctx, email, "Verify your Hostyt Proxy email", "notice", map[string]any{
			"Subject": "Verify your email",
			"Body":    "Confirm your email to activate your account:\n\n" + verifyURL + "\n\nThis link expires in 30 minutes.",
		}); serr != nil {
			h.Logger.Warn("register verify email send", "err", serr, "user_id", userID)
		}
	} else if terr != nil {
		h.Logger.Error("register verify token", "err", terr, "user_id", userID)
	}

	http.Redirect(w, r, "/auth/login?flash=Check+your+email+to+verify+your+account+before+signing+in", http.StatusSeeOther)
}

// emailVerifyTokenTTL matches the password-reset link lifetime.
const emailVerifyTokenTTL = 30 * time.Minute

// createEmailVerifyToken issues a one-time email-verification token. Stores
// only the sha256 hash (mirrors password_resets); returns the plaintext token.
func createEmailVerifyToken(ctx context.Context, db *sql.DB, userID int64) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	plain := base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(plain))
	hashHex := hex.EncodeToString(sum[:])
	// DB-side expiry: the consume path compares against NOW(), so a Go-side UTC
	// timestamp expires the token on issue wherever the DB runs ahead of UTC.
	if _, err := db.ExecContext(ctx,
		"INSERT INTO email_verifications (user_id, token_hash, expires_at) VALUES (?, ?, "+
			store.DateAddSecondsParam()+")",
		userID, hashHex, int(emailVerifyTokenTTL/time.Second),
	); err != nil {
		return "", err
	}
	return plain, nil
}

// VerifyEmail handles GET /auth/verify?token=... - consumes a one-time token
// and flips the user's email_verified=1 + is_active=1 so they can sign in.
// Route wiring (GET /auth/verify -> this handler) lives in server.go, which is
// outside this task's editable set; add it there to complete the flow.
func (h *AuthHandlers) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimSpace(r.URL.Query().Get("token"))
	if token == "" {
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	db := h.DB()
	if db == nil {
		http.Redirect(w, r, "/auth/login?flash=Server+unavailable", http.StatusSeeOther)
		return
	}
	sum := sha256.Sum256([]byte(token))
	hashHex := hex.EncodeToString(sum[:])

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		http.Redirect(w, r, "/auth/login?flash=Server+error", http.StatusSeeOther)
		return
	}
	defer tx.Rollback() //nolint:errcheck

	var id, userID int64
	// FOR UPDATE row-locks the token so concurrent hits can't both pass.
	err = tx.QueryRowContext(ctx,
		`SELECT id, user_id FROM email_verifications
		 WHERE token_hash = ? AND used_at IS NULL AND expires_at > NOW() LIMIT 1`+store.ForUpdate(),
		hashHex,
	).Scan(&id, &userID)
	if err != nil {
		http.Redirect(w, r, "/auth/login?flash=Verification+link+invalid+or+expired", http.StatusSeeOther)
		return
	}
	if _, err := tx.ExecContext(ctx, "UPDATE email_verifications SET used_at = NOW() WHERE id = ?", id); err != nil {
		http.Redirect(w, r, "/auth/login?flash=Server+error", http.StatusSeeOther)
		return
	}
	if _, err := tx.ExecContext(ctx, "UPDATE users SET email_verified = 1, is_active = 1 WHERE id = ?", userID); err != nil {
		http.Redirect(w, r, "/auth/login?flash=Server+error", http.StatusSeeOther)
		return
	}
	if err := tx.Commit(); err != nil {
		http.Redirect(w, r, "/auth/login?flash=Server+error", http.StatusSeeOther)
		return
	}
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: &userID, Action: "auth.email_verified", Entity: "user", EntityID: fmt.Sprintf("%d", userID),
	})
	http.Redirect(w, r, "/auth/login?flash=Email+verified+-+you+can+now+sign+in", http.StatusSeeOther)
}
