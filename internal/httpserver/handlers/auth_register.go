package handlers

import (
	"bytes"
	"context"
	"database/sql"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/host-yt/caddy-proxy-manager/internal/audit"
	"github.com/host-yt/caddy-proxy-manager/internal/auth"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
	"github.com/host-yt/caddy-proxy-manager/internal/security"
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
	if len(password) < 10 {
		renderErr("Password must be at least 10 characters.")
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

	// Insert user row.
	res, err := db.ExecContext(ctx,
		"INSERT INTO users (email, password_hash, role, is_active, full_name) VALUES (?, ?, 'client', 1, ?)",
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

	http.Redirect(w, r, "/auth/login?flash=Account+created+-+you+can+now+log+in", http.StatusSeeOther)
}
