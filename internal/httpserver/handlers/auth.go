package handlers

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"

	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	xnorm "golang.org/x/text/unicode/norm"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/host-yt/caddy-proxy-manager/internal/audit"
	"github.com/host-yt/caddy-proxy-manager/internal/auth"
	"github.com/host-yt/caddy-proxy-manager/internal/captcha"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
	"github.com/host-yt/caddy-proxy-manager/internal/i18n"
	"github.com/host-yt/caddy-proxy-manager/internal/installstate"
	"github.com/host-yt/caddy-proxy-manager/internal/mail"
	"github.com/host-yt/caddy-proxy-manager/internal/oauth2x"
	"github.com/host-yt/caddy-proxy-manager/internal/obs"
	hpgoidc "github.com/host-yt/caddy-proxy-manager/internal/oidc"
	"github.com/host-yt/caddy-proxy-manager/internal/security"
	"github.com/host-yt/caddy-proxy-manager/internal/sms"
	"github.com/host-yt/caddy-proxy-manager/internal/view"
)

// Brute-force lockout window. Per-(email,IP) bucket caps in this window;
// see locked/recordFail below for the rule.
const (
	loginFailWindow = 15 * time.Minute
	pending2FATTL   = 5 * time.Minute
	// trustDeviceTTL: how long a "remember this device" cookie skips 2FA
	// on the same browser. 30 days is a common balance.
	trustDeviceTTL = 30 * 24 * time.Hour
	trustCookie    = "hpg_2fa_trust"
)

// AuthHandlers groups password-login + reset + 2FA challenge handlers.
type AuthHandlers struct {
	DB        func() *sql.DB
	Sessions  *auth.Manager
	Templates *view.AuthTemplates
	Logger    *slog.Logger
	RDB       *redis.Client
	Mailer    *mail.Mailer
	Captcha   *captcha.Verifier
	OIDC      *hpgoidc.Service
	// OAuth2X drives the social-login providers (GitHub, Google) that run
	// alongside OIDC. nil disables their start/callback routes.
	OAuth2X *oauth2x.Service
	SMS     *sms.Sender
	// PasskeyEnabled controls the "Sign in with passkey" button visibility
	// on /auth/login. Wired from main.go when the WebAuthn service is
	// available (App.URL valid).
	PasskeyEnabled bool
	AppURL         string
	// Metrics (nil-safe) - emits login/OTP/session counters.
	Metrics *obs.Metrics
	// State is the installstate manager used for AES-GCM encryption of
	// TOTP secrets at rest. When non-nil, login/verify paths prefer the
	// encrypted `users.totp_secret_enc` column; the legacy plaintext
	// `users.totp_secret` column is auto-migrated on first successful
	// verify.
	State *installstate.Manager
}

// readTOTPSecret returns the plaintext TOTP secret for a user, preferring
// the encrypted column. Returns ("", false) when no secret is provisioned.
func readTOTPSecret(ctx context.Context, db *sql.DB, st *installstate.Manager, userID int64) (string, bool, bool) {
	// last bool: needs migration (read from legacy column).
	var enc sql.NullString
	var plain sql.NullString
	if err := db.QueryRowContext(ctx,
		"SELECT totp_secret_enc, totp_secret FROM users WHERE id = ?", userID,
	).Scan(&enc, &plain); err != nil {
		return "", false, false
	}
	if enc.Valid && enc.String != "" && st != nil {
		pt, err := st.Decrypt(enc.String)
		if err == nil {
			return pt, true, false
		}
	}
	if plain.Valid && plain.String != "" {
		return plain.String, true, true
	}
	return "", false, false
}

// upgradeTOTPSecret re-encrypts a legacy plaintext TOTP secret into the new
// column and clears the old one. Idempotent.
func upgradeTOTPSecret(ctx context.Context, db *sql.DB, st *installstate.Manager, userID int64, plain string) {
	if st == nil {
		return
	}
	enc, err := st.Encrypt(plain)
	if err != nil {
		return
	}
	_, _ = db.ExecContext(ctx,
		"UPDATE users SET totp_secret_enc = ?, totp_secret = NULL WHERE id = ?", enc, userID)
}

// writeTOTPSecret stores a TOTP secret encrypted at rest. Returns error
// when the State manager is missing (caller must require it before
// enabling 2FA in such a setup).
func writeTOTPSecret(ctx context.Context, db *sql.DB, st *installstate.Manager, userID int64, plain string) error {
	if st == nil {
		// Fall back to plaintext column only when no manager is wired
		// (degraded mode; should never happen in production).
		_, err := db.ExecContext(ctx,
			"UPDATE users SET totp_secret = ?, totp_secret_enc = NULL, totp_enabled = 1 WHERE id = ?",
			plain, userID)
		return err
	}
	enc, err := st.Encrypt(plain)
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx,
		"UPDATE users SET totp_secret_enc = ?, totp_secret = NULL, totp_enabled = 1 WHERE id = ?",
		enc, userID)
	return err
}

// clearTOTPSecret nulls both old + new columns.
func clearTOTPSecret(ctx context.Context, db *sql.DB, userID int64) error {
	_, err := db.ExecContext(ctx,
		"UPDATE users SET totp_secret = NULL, totp_secret_enc = NULL, totp_enabled = 0 WHERE id = ?",
		userID)
	return err
}

// ---- Login -------------------------------------------------------------

type loginViewData struct {
	Email                 string
	Error                 string
	Flash                 string
	CaptchaEnabled        bool
	CaptchaProvider       string // "turnstile" | "hcaptcha" | "recaptcha"
	CaptchaSiteKey        string
	OIDCEnabled           bool
	OIDCProviderName      string
	GitHubEnabled         bool
	GoogleEnabled         bool
	PasswordLoginDisabled bool
	PasskeyEnabled        bool
	CSPNonce              string
	Lang                  string
	Brand                 Branding
}

// authBase / stamp* populate the CSP nonce + selected language onto each
// auth view payload. Auth templates render outside the admin/app layout
// so they need their own base bits per render.
func authBase(r *http.Request) (string, string) {
	return middleware.CSPNonce(r.Context()), i18n.LangFromRequest(r)
}

func (h *AuthHandlers) stampLogin(r *http.Request, d loginViewData) loginViewData {
	d.CSPNonce, d.Lang = authBase(r)
	if db := h.DB(); db != nil {
		d.Brand = LoadBranding(r.Context(), db)
	}
	return d
}
func (h *AuthHandlers) stampTOTP(r *http.Request, d totpViewData) totpViewData {
	d.CSPNonce, d.Lang = authBase(r)
	if db := h.DB(); db != nil {
		d.Brand = LoadBranding(r.Context(), db)
	}
	return d
}
func (h *AuthHandlers) stampForgot(r *http.Request, d forgotViewData) forgotViewData {
	d.CSPNonce, d.Lang = authBase(r)
	if db := h.DB(); db != nil {
		d.Brand = LoadBranding(r.Context(), db)
	}
	return d
}
func (h *AuthHandlers) stampReset(r *http.Request, d resetViewData) resetViewData {
	d.CSPNonce, d.Lang = authBase(r)
	if db := h.DB(); db != nil {
		d.Brand = LoadBranding(r.Context(), db)
	}
	return d
}

func (h *AuthHandlers) renderLogin(w http.ResponseWriter, status int, data loginViewData) {
	_ = data.CSPNonce
	if h.Captcha != nil && h.Captcha.Enabled() {
		data.CaptchaEnabled = true
	}
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	if h.OIDC != nil {
		if cfg, err := h.OIDC.CurrentConfigForUI(ctx); err == nil && cfg.Enabled && cfg.ClientID != "" && cfg.Issuer != "" {
			data.OIDCEnabled = true
			data.OIDCProviderName = cfg.ProviderName
			if data.OIDCProviderName == "" {
				data.OIDCProviderName = "SSO"
			}
		}
	}
	// Check SSO-only mode - load from DB directly (no cache needed here).
	if db := h.DB(); db != nil {
		var v string
		_ = db.QueryRowContext(ctx,
			"SELECT value FROM settings WHERE `key` = 'oidc.password_login_disabled' LIMIT 1",
		).Scan(&v)
		data.PasswordLoginDisabled = v == "1"
	}
	// Social-login button visibility - nil-safe, never errors.
	if h.OAuth2X != nil {
		data.GitHubEnabled = h.OAuth2X.Enabled(ctx, "github")
		data.GoogleEnabled = h.OAuth2X.Enabled(ctx, "google")
	}
	data.PasskeyEnabled = h.PasskeyEnabled
	if h.Captcha != nil && h.Captcha.Enabled() {
		data.CaptchaSiteKey = h.Captcha.SiteKey()
		data.CaptchaProvider = h.Captcha.Provider()
	}
	var buf bytes.Buffer
	if err := h.Templates.Render(&buf, "login.html.tmpl", data); err != nil {
		h.Logger.Error("render login", "err", err)
		http.Error(w, "render failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

func (h *AuthHandlers) LoginPage(w http.ResponseWriter, r *http.Request) {
	nonce, lang := authBase(r)
	h.renderLogin(w, http.StatusOK, h.stampLogin(r, loginViewData{Flash: r.URL.Query().Get("flash"), CSPNonce: nonce, Lang: lang}))
}

func (h *AuthHandlers) LoginSubmit(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	password := r.FormValue("password")
	// Each widget posts its own token field name; read whichever is present.
	captchaToken := firstNonEmpty(
		r.FormValue("cf-turnstile-response"),
		r.FormValue("h-captcha-response"),
		r.FormValue("g-recaptcha-response"),
	)
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()

	if email == "" || password == "" {
		nonce, lang := authBase(r)
		h.renderLogin(w, http.StatusBadRequest, h.stampLogin(r, loginViewData{Email: email, Error: "Email and password are required.", CSPNonce: nonce, Lang: lang}))
		return
	}

	ip := security.ClientIP(r)
	if h.locked(ctx, email, ip) {
		h.renderLogin(w, http.StatusTooManyRequests, h.stampLogin(r, loginViewData{Email: email, Error: "Too many failed attempts. Try again in a few minutes."}))
		return
	}

	// WEB-03: once an email is under a cross-IP horizontal scan (per-email fail
	// count over threshold), force captcha for THAT email regardless of source
	// IP - never a hard block (avoids the known-email DoS). If captcha isn't
	// configured, fall back to a modest delay so the scan can't run at full rate.
	emailOverThreshold := h.emailFailCount(ctx, email) >= loginFailMaxEmail
	captchaOn := h.Captcha != nil && h.Captcha.Enabled()
	if captchaOn || emailOverThreshold {
		if captchaOn {
			if err := h.Captcha.Verify(ctx, captchaToken, clientIPFromReq(r)); err != nil {
				h.renderLogin(w, http.StatusBadRequest, h.stampLogin(r, loginViewData{Email: email, Error: "Captcha verification failed."}))
				return
			}
		} else if emailOverThreshold {
			// No captcha plumbing available - slow the attacker down instead.
			time.Sleep(2 * time.Second)
		}
	}

	db := h.DB()
	if db == nil {
		h.renderLogin(w, http.StatusServiceUnavailable, h.stampLogin(r, loginViewData{Email: email, Error: "Database not configured."}))
		return
	}

	// SSO-only mode: block password login for non-admins when flag is set.
	var pwdDisabled string
	_ = db.QueryRowContext(ctx,
		"SELECT value FROM settings WHERE `key` = 'oidc.password_login_disabled' LIMIT 1",
	).Scan(&pwdDisabled)

	var (
		userID          int64
		hash            string
		role            string
		isActive        bool
		totpEnabled     bool
		smsOTPEnabled   bool
		emailOTPEnabled bool
	)
	err := db.QueryRowContext(ctx,
		"SELECT id, password_hash, role, is_active, totp_enabled, sms_otp_enabled, email_otp_enabled FROM users WHERE email = ? LIMIT 1",
		email,
	).Scan(&userID, &hash, &role, &isActive, &totpEnabled, &smsOTPEnabled, &emailOTPEnabled)
	if errors.Is(err, sql.ErrNoRows) {
		// Equalize timing: a real account spends ~150ms in Argon2 verify, an
		// unknown email would return in microseconds and leak account existence.
		// Burn the same work against a fixed decoy hash before responding.
		_ = auth.VerifyPassword(decoyPasswordHash(), password)
		h.recordFail(ctx, email, ip)
		audit.Write(ctx, db, h.Logger, r, audit.Entry{
			Action: "login.fail", Entity: "auth", EntityID: maskEmail(email),
			Meta: map[string]any{"reason": "unknown_email"},
		})
		h.Metrics.LoginEvent("fail", "password", "none")
		h.renderLogin(w, http.StatusUnauthorized, h.stampLogin(r, loginViewData{Email: email, Error: "Invalid email or password."}))
		return
	}
	if err != nil {
		h.Logger.Error("login query", "err", err)
		h.renderLogin(w, http.StatusInternalServerError, h.stampLogin(r, loginViewData{Email: email, Error: "Server error."}))
		return
	}
	if !isActive {
		audit.Write(ctx, db, h.Logger, r, audit.Entry{
			UserID: &userID, Action: "login.fail", Entity: "auth", EntityID: email,
			Meta: map[string]any{"reason": "disabled"},
		})
		h.Metrics.LoginEvent("fail", "password", "none")
		h.renderLogin(w, http.StatusForbidden, h.stampLogin(r, loginViewData{Email: email, Error: "Account is disabled."}))
		return
	}

	// SSO-only mode: superadmins (role="admin") bypass the block as failsafe.
	if pwdDisabled == "1" && role != "admin" {
		audit.Write(ctx, db, h.Logger, r, audit.Entry{
			UserID: &userID, Action: "login.fail", Entity: "auth", EntityID: email,
			Meta: map[string]any{"reason": "password_login_disabled"},
		})
		h.renderLogin(w, http.StatusForbidden, h.stampLogin(r, loginViewData{
			Email: email, Error: "Password login disabled - use SSO.",
		}))
		return
	}

	if err := auth.VerifyPassword(hash, password); err != nil {
		h.recordFail(ctx, email, ip)
		audit.Write(ctx, db, h.Logger, r, audit.Entry{
			UserID: &userID, Action: "login.fail", Entity: "auth", EntityID: email,
			Meta: map[string]any{"reason": "bad_password"},
		})
		h.Metrics.LoginEvent("fail", "password", "none")
		h.renderLogin(w, http.StatusUnauthorized, h.stampLogin(r, loginViewData{Email: email, Error: "Invalid email or password."}))
		return
	}
	h.clearFails(ctx, email, ip)

	var clientID int64
	if role == "client" {
		_ = db.QueryRowContext(ctx, "SELECT id FROM clients WHERE user_id = ?", userID).Scan(&clientID)
	}

	// "Remember this device" cookie skips 2FA for trustDeviceTTL.
	// Bound to userID via AES-GCM seal (APP_SECRET-derived).
	if (totpEnabled || smsOTPEnabled || emailOTPEnabled) && h.State != nil {
		if c, cerr := r.Cookie(trustCookie); cerr == nil && h.verifyTrustToken(c.Value, userID) {
			audit.Write(ctx, db, h.Logger, r, audit.Entry{
				UserID: &userID, Action: "2fa.skip.trusted_device", Entity: "auth", EntityID: email,
			})
			h.finalizeLogin(ctx, w, r, userID, email, role, clientID, "password", "trusted")
			return
		}
	}

	// Any 2FA enrolled → unified picker at /auth/2fa.
	if totpEnabled || smsOTPEnabled || emailOTPEnabled {
		ticket, err := h.issuePending2FA(ctx, userID, email, role, clientID)
		if err != nil {
			h.Logger.Error("pending 2fa issue", "err", err)
			h.renderLogin(w, http.StatusInternalServerError, h.stampLogin(r, loginViewData{Email: email, Error: "Server error."}))
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name: "hpg_2fa_pending", Value: ticket, Path: "/", HttpOnly: true,
			Secure: h.Sessions.CookieSecure(), SameSite: http.SameSiteLaxMode,
			Expires: time.Now().Add(pending2FATTL),
		})
		http.Redirect(w, r, "/auth/2fa", http.StatusSeeOther)
		return
	}

	h.finalizeLogin(ctx, w, r, userID, email, role, clientID, "password", "none")
}

// finalizeLogin completes a login and writes a login.success audit record.
// `via` is the entry path ("password", "oidc"). `mfa` is the second-factor
// used ("none", "totp", "recovery", "sms", "email"); SSO logins report "none"
// with via="oidc" so the dashboard can distinguish them.
// resellerScopeUnknown: non-zero poison so a lookup failure fails CLOSED
// (boundary denies, ScopeFilter matches no clients), never platform-admin.
const resellerScopeUnknown = int64(-1)

// lookupResellerID returns the user's reseller (0 = none). Fail-closed: a DB
// error yields resellerScopeUnknown; only a clean NULL/no-row maps to 0.
func lookupResellerID(ctx context.Context, db *sql.DB, userID int64) int64 {
	if db == nil {
		return resellerScopeUnknown
	}
	var rid sql.NullInt64
	err := db.QueryRowContext(ctx, "SELECT reseller_id FROM users WHERE id = ?", userID).Scan(&rid)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0
		}
		return resellerScopeUnknown // fail-closed on a real DB error
	}
	if rid.Valid {
		return rid.Int64
	}
	return 0
}

func (h *AuthHandlers) finalizeLogin(ctx context.Context, w http.ResponseWriter, r *http.Request,
	userID int64, email, role string, clientID int64, via, mfa string) {
	if _, err := h.Sessions.Create(ctx, w, userID, email, role, clientID, lookupResellerID(ctx, h.DB(), userID)); err != nil {
		h.Logger.Error("session create", "err", err)
		h.renderLogin(w, http.StatusInternalServerError, h.stampLogin(r, loginViewData{Email: email, Error: "Could not create session."}))
		return
	}
	db := h.DB()
	_, _ = db.ExecContext(ctx, "UPDATE users SET last_login_at = NOW() WHERE id = ?", userID)
	action := "login.success"
	if via == "sso" {
		action = "sso_jump.success"
	}
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: &userID, Action: action, Entity: "auth", EntityID: email,
		Meta: map[string]any{"role": role, "via": via, "mfa": mfa},
	})
	h.Metrics.LoginEvent("success", via, mfa)
	h.Metrics.SessionEvent("create")
	dest := "/admin"
	if role == "client" {
		dest = "/app"
	}
	http.Redirect(w, r, dest, http.StatusSeeOther)
}

// ---- 2FA challenge ------------------------------------------------------

type totpViewData struct {
	Error       string
	CSPNonce    string
	Lang        string
	Brand       Branding
	HasTOTP     bool
	HasSMS      bool
	HasEmail    bool
	HasRecovery bool
	// DefaultMethod: which tab is pre-selected. App → email → sms order,
	// falling through whichever the user has actually enrolled.
	DefaultMethod string
}

// twoFAOptions reports which second-factor methods the given user has
// available + the default-pick following the app→email→sms preference.
func (h *AuthHandlers) twoFAOptions(ctx context.Context, userID int64) (hasTOTP, hasSMS, hasEmail, hasRecovery bool, defaultMethod string) {
	db := h.DB()
	if db == nil {
		return
	}
	_ = db.QueryRowContext(ctx,
		"SELECT totp_enabled, sms_otp_enabled, email_otp_enabled FROM users WHERE id = ?",
		userID,
	).Scan(&hasTOTP, &hasSMS, &hasEmail)
	var n int
	_ = db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM recovery_codes WHERE user_id = ? AND used_at IS NULL",
		userID,
	).Scan(&n)
	hasRecovery = n > 0
	switch {
	case hasTOTP:
		defaultMethod = "totp"
	case hasEmail:
		defaultMethod = "email"
	case hasSMS:
		defaultMethod = "sms"
	case hasRecovery:
		defaultMethod = "recovery"
	}
	return
}

// renderTOTP is callable with an old (w, status, data) signature; the
// older call sites are kept literal but the helper now stamps CSPNonce +
// Lang from the http.Request via the wrapping httpReq() context the
// middleware put on the chain. When the request isn't available we leave
// the fields empty (will be blocked by CSP - that's the contract).
func (h *AuthHandlers) renderTOTP(w http.ResponseWriter, status int, d totpViewData) {
	var buf bytes.Buffer
	if err := h.Templates.Render(&buf, "totp_challenge.html.tmpl", d); err != nil {
		h.Logger.Error("render totp", "err", err)
		http.Error(w, "render failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

func (h *AuthHandlers) TOTPChallenge(w http.ResponseWriter, r *http.Request) {
	pend, ok := h.readPending2FA(r)
	if !ok {
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	d := totpViewData{}
	d.HasTOTP, d.HasSMS, d.HasEmail, d.HasRecovery, d.DefaultMethod = h.twoFAOptions(ctx, pend.UserID)
	h.renderTOTP(w, http.StatusOK, h.stampTOTP(r, d))
}

// renderTOTPRetry re-renders the picker with an error, preserving the
// user's enrolled-method list so they can pick another factor.
func (h *AuthHandlers) renderTOTPRetry(w http.ResponseWriter, r *http.Request, status int, msg string) {
	pend, ok := h.readPending2FA(r)
	if !ok {
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}
	d := totpViewData{Error: msg}
	d.HasTOTP, d.HasSMS, d.HasEmail, d.HasRecovery, d.DefaultMethod = h.twoFAOptions(r.Context(), pend.UserID)
	h.renderTOTP(w, status, h.stampTOTP(r, d))
}

// TOTPVerify validates whichever second-factor the user picked on the
// /auth/2fa page (totp | recovery | sms | email). totp also accepts a
// recovery code in the same field as a graceful-degradation path.
func (h *AuthHandlers) TOTPVerify(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	method := strings.TrimSpace(r.FormValue("method"))
	code := strings.TrimSpace(r.FormValue("code"))
	trustDev := r.FormValue("trust_device") == "on"

	pend, ok := h.readPending2FA(r)
	if !ok {
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	db := h.DB()
	ticket := pending2FATicket(r)

	// Per-user 2FA hard lock, independent of the ticket. A fresh ticket mints
	// on every password login, so ticket-only caps let an attacker who knows
	// the password loop forever; this counter does not reset on new tickets.
	if h.twoFALocked(ctx, pend.UserID) {
		audit.Write(ctx, db, h.Logger, r, audit.Entry{
			UserID: &pend.UserID, Action: "2fa.locked", Entity: "auth", EntityID: pend.Email,
		})
		h.consumePending2FA(r)
		http.Redirect(w, r, "/auth/login?flash=Too+many+failed+codes", http.StatusSeeOther)
		return
	}

	success := false
	mfaTag := method
	if mfaTag == "" {
		method = "totp"
		mfaTag = "totp"
	}

	switch method {
	case "totp":
		secret, ok, needsMigrate := readTOTPSecret(ctx, db, h.State, pend.UserID)
		if !ok {
			h.renderTOTPRetry(w, r, http.StatusInternalServerError, "Server error.")
			return
		}
		// Reject a valid code whose 30s counter was already consumed (replay);
		// treat it exactly like an invalid code.
		if err := auth.ValidateTOTP(secret, code); err == nil && h.markTOTPConsumed(ctx, pend.UserID, code) {
			success = true
			if needsMigrate {
				upgradeTOTPSecret(ctx, db, h.State, pend.UserID, secret)
			}
		} else if h.tryRecoveryCode(ctx, db, pend.UserID, code) {
			success = true
			mfaTag = "recovery"
		}
	case "recovery":
		if h.tryRecoveryCode(ctx, db, pend.UserID, code) {
			success = true
		}
	case "sms":
		otpCookie, err := r.Cookie("hpg_smsotp")
		if err != nil || otpCookie.Value == "" {
			h.renderTOTPRetry(w, r, http.StatusBadRequest, "Send a code first.")
			return
		}
		cleaned := strings.ReplaceAll(code, "-", "")
		if uid, verr := auth.VerifySMSOTP(ctx, h.RDB, otpCookie.Value, cleaned); verr == nil && uid == pend.UserID {
			success = true
			http.SetCookie(w, &http.Cookie{Name: "hpg_smsotp", Value: "", Path: "/", MaxAge: -1})
		}
	case "email":
		otpCookie, err := r.Cookie("hpg_emailotp")
		if err != nil || otpCookie.Value == "" {
			h.renderTOTPRetry(w, r, http.StatusBadRequest, "Send a code first.")
			return
		}
		if uid, verr := auth.VerifyEmailOTP(ctx, h.RDB, otpCookie.Value, code); verr == nil && uid == pend.UserID {
			success = true
			http.SetCookie(w, &http.Cookie{Name: "hpg_emailotp", Value: "", Path: "/", MaxAge: -1})
		}
	default:
		h.renderTOTPRetry(w, r, http.StatusBadRequest, "Unknown method.")
		return
	}

	if !success {
		// Per-user counter (survives ticket rotation) + per-ticket cap both bump.
		h.record2FAFail(ctx, pend.UserID)
		audit.Write(ctx, db, h.Logger, r, audit.Entry{
			UserID: &pend.UserID, Action: "2fa.fail", Entity: "auth", EntityID: pend.Email,
			Meta: map[string]any{"method": mfaTag},
		})
		h.Metrics.OTPAttempt(mfaTag, "fail")
		if h.burnAttempt(ctx, ticket) || h.twoFALocked(ctx, pend.UserID) {
			h.consumePending2FA(r)
			http.SetCookie(w, &http.Cookie{Name: "hpg_smsotp", Value: "", Path: "/", MaxAge: -1})
			http.SetCookie(w, &http.Cookie{Name: "hpg_emailotp", Value: "", Path: "/", MaxAge: -1})
			http.Redirect(w, r, "/auth/login?flash=Too+many+failed+codes", http.StatusSeeOther)
			return
		}
		h.renderTOTPRetry(w, r, http.StatusUnauthorized, "Invalid code.")
		return
	}

	h.clearAttempts(ctx, ticket)
	h.clear2FAFails(ctx, pend.UserID) // reset per-user counter only on success
	h.consumePending2FA(r)
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: &pend.UserID, Action: "2fa.success", Entity: "auth", EntityID: pend.Email,
		Meta: map[string]any{"method": mfaTag},
	})
	h.Metrics.OTPAttempt(mfaTag, "success")
	if trustDev {
		h.issueTrustCookie(w, pend.UserID)
	}
	h.finalizeLogin(ctx, w, r, pend.UserID, pend.Email, pend.Role, pend.ClientID, pendViaOrPassword(pend), mfaTag)
}

// TwoFASend dispatches an OTP code for the picker page. POST form field
// `method`=sms|email. Returns 204 on success, 4xx/5xx with text body on
// failure. Requires pending 2FA cookie (no session yet).
func (h *AuthHandlers) TwoFASend(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	method := strings.TrimSpace(r.FormValue("method"))
	pend, ok := h.readPending2FA(r)
	if !ok {
		http.Error(w, "session expired", http.StatusUnauthorized)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	db := h.DB()
	if db == nil {
		http.Error(w, "db unavailable", http.StatusServiceUnavailable)
		return
	}

	switch method {
	case "sms":
		var phone sql.NullString
		_ = db.QueryRowContext(ctx, "SELECT phone_e164 FROM users WHERE id = ?", pend.UserID).Scan(&phone)
		if !phone.Valid || phone.String == "" {
			http.Error(w, "no phone on file", http.StatusBadRequest)
			return
		}
		if h.SMS == nil {
			http.Error(w, "sms not configured", http.StatusServiceUnavailable)
			return
		}
		if active, retry := h.checkResendCooldown(ctx, pend.UserID, "sms"); active {
			w.Header().Set("Retry-After", strconv.Itoa(retry))
			http.Error(w, fmt.Sprintf("wait %ds before resending", retry), http.StatusTooManyRequests)
			return
		}
		sentN, over := h.checkDailyCap(ctx, pend.UserID, "sms")
		if over {
			http.Error(w, fmt.Sprintf("daily SMS limit (%d) reached", otpDailyCap), http.StatusTooManyRequests)
			return
		}
		code, err := auth.GenerateSMSOTP()
		if err != nil {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		otpTicket, err := auth.StoreSMSOTP(ctx, h.RDB, pend.UserID, code)
		if err != nil {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		body := fmt.Sprintf("Code #%d: %s", sentN, formatSMSCode(code))
		if err := h.SMS.Send(ctx, phone.String, body); err != nil {
			h.Logger.Warn("sms send", "err", err)
			http.Error(w, "sms provider: "+firstLine(err.Error()), http.StatusBadGateway)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name: "hpg_smsotp", Value: otpTicket, Path: "/", HttpOnly: true,
			Secure: h.Sessions.CookieSecure(), SameSite: http.SameSiteLaxMode,
			Expires: time.Now().Add(auth.SMSOTPTTLSeconds * time.Second),
		})
		w.Header().Set("X-Resend-After", strconv.Itoa(int(otpResendCooldown.Seconds())))
		w.WriteHeader(http.StatusNoContent)

	case "email":
		if h.Mailer == nil {
			http.Error(w, "mailer not configured", http.StatusServiceUnavailable)
			return
		}
		if active, retry := h.checkResendCooldown(ctx, pend.UserID, "email"); active {
			w.Header().Set("Retry-After", strconv.Itoa(retry))
			http.Error(w, fmt.Sprintf("wait %ds before resending", retry), http.StatusTooManyRequests)
			return
		}
		if _, over := h.checkDailyCap(ctx, pend.UserID, "email"); over {
			http.Error(w, fmt.Sprintf("daily email limit (%d) reached", otpDailyCap), http.StatusTooManyRequests)
			return
		}
		var fullName sql.NullString
		_ = db.QueryRowContext(ctx, "SELECT full_name FROM users WHERE id = ?", pend.UserID).Scan(&fullName)
		code, err := auth.GenerateEmailOTP()
		if err != nil {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		otpTicket, err := auth.StoreEmailOTP(ctx, h.RDB, pend.UserID, code)
		if err != nil {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		name := ""
		if fullName.Valid {
			name = fullName.String
		}
		if err := sendOTPEmail(ctx, h.Mailer, db, r, pend.Email, name, code,
			"Sign-in verification code",
			"Someone (hopefully you) is signing in to your account.",
			int(auth.EmailOTPTTLSeconds/60)); err != nil {
			h.Logger.Warn("email send", "err", err)
			http.Error(w, "smtp: "+firstLine(err.Error()), http.StatusBadGateway)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name: "hpg_emailotp", Value: otpTicket, Path: "/", HttpOnly: true,
			Secure: h.Sessions.CookieSecure(), SameSite: http.SameSiteLaxMode,
			Expires: time.Now().Add(auth.EmailOTPTTLSeconds * time.Second),
		})
		w.Header().Set("X-Resend-After", strconv.Itoa(int(otpResendCooldown.Seconds())))
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "unknown method", http.StatusBadRequest)
	}
}

// pendViaOrPassword returns the recorded via, defaulting to "password" for
// records created before the field was added.
func pendViaOrPassword(p pending2FA) string {
	if p.Via == "" {
		return "password"
	}
	return p.Via
}

// otpMaxAttempts caps how many wrong codes a single OTP ticket / pending2FA
// challenge tolerates before we burn the ticket and force a fresh login.
// Without this, an attacker who has a stolen password only has to brute-
// force a 6-digit code (1e6 combos) - well within reach of the per-IP
// rate limit when XFF was blindly trusted.
const otpMaxAttempts = 5

// otpResendCooldown enforces a server-side delay between resends so a
// stolen pending2FA cookie can't burn the daily SMS budget instantly.
const otpResendCooldown = 60 * time.Second

// otpDailyCap stops the same user from flooding their own phone/inbox
// (or our SMS bill) across multiple sessions in 24h.
const otpDailyCap = 10

// checkResendCooldown returns (true, remainingSeconds) when the user must
// wait before resending via this method. Uses Redis NX-set with 60s TTL.
// Fails open on Redis errors - better a duplicate SMS than a locked-out
// user.
func (h *AuthHandlers) checkResendCooldown(ctx context.Context, userID int64, method string) (bool, int) {
	if h.RDB == nil {
		return false, 0
	}
	key := fmt.Sprintf("hpg:2fa:cooldown:%d:%s", userID, method)
	ok, err := h.RDB.SetNX(ctx, key, "1", otpResendCooldown).Result()
	if err != nil {
		return false, 0
	}
	if ok {
		return false, 0
	}
	ttl, _ := h.RDB.TTL(ctx, key).Result()
	if ttl < 0 {
		return true, int(otpResendCooldown.Seconds())
	}
	return true, int(ttl.Seconds())
}

// checkDailyCap increments the per-(user,method,day) sent counter and
// returns the new value + over-budget flag. Fails open on Redis errors
// (returns 0, false) so a Redis blip doesn't lock the user out.
func (h *AuthHandlers) checkDailyCap(ctx context.Context, userID int64, method string) (int64, bool) {
	if h.RDB == nil {
		return 0, false
	}
	day := time.Now().UTC().Format("20060102")
	key := fmt.Sprintf("hpg:2fa:sent:%d:%s:%s", userID, method, day)
	n, err := h.RDB.Incr(ctx, key).Result()
	if err != nil {
		return 0, false
	}
	if n == 1 {
		_ = h.RDB.Expire(ctx, key, 26*time.Hour).Err()
	}
	return n, n > otpDailyCap
}

// formatSMSCode renders a 6-digit OTP as "123-456" for SMS body
// readability. The hyphen is cosmetic; verify path strips it.
func formatSMSCode(code string) string {
	if len(code) != 6 {
		return code
	}
	return code[:3] + "-" + code[3:]
}

// burnAttempt records a failed OTP attempt for the given ticket. Returns
// true when the cap has been reached; callers then delete the ticket +
// force the user back to /auth/login. Best-effort: Redis errors fall open
// so a Redis outage doesn't lock everyone out of TOTP forever.
func (h *AuthHandlers) burnAttempt(ctx context.Context, key string) bool {
	if h.RDB == nil {
		return false
	}
	n, err := h.RDB.Incr(ctx, "hpg:otp:attempts:"+key).Result()
	if err != nil {
		return false
	}
	if n == 1 {
		_ = h.RDB.Expire(ctx, "hpg:otp:attempts:"+key, pending2FATTL).Err()
	}
	return n >= otpMaxAttempts
}

// clearAttempts drops the per-ticket attempt counter on success.
func (h *AuthHandlers) clearAttempts(ctx context.Context, key string) {
	if h.RDB == nil {
		return
	}
	_ = h.RDB.Del(ctx, "hpg:otp:attempts:"+key).Err()
}

// pending2FATicket pulls the raw cookie value used as the attempt key.
// Falls back to a synthetic value if absent.
func pending2FATicket(r *http.Request) string {
	if c, err := r.Cookie("hpg_2fa_pending"); err == nil {
		return c.Value
	}
	return "anon"
}

// decoyPasswordHash returns a fixed valid Argon2id encoded hash, computed
// once, used to equalize login timing for unknown emails so the verify cost
// can't be used as an account-enumeration oracle.
var (
	decoyHashOnce  sync.Once
	decoyHashValue string
)

func decoyPasswordHash() string {
	decoyHashOnce.Do(func() {
		// Random password we never reveal; only the ~150ms verify cost matters.
		buf := make([]byte, 32)
		_, _ = rand.Read(buf)
		if hpw, err := auth.HashPassword(base64.StdEncoding.EncodeToString(buf)); err == nil {
			decoyHashValue = hpw
		}
	})
	return decoyHashValue
}

func (h *AuthHandlers) tryRecoveryCode(ctx context.Context, db *sql.DB, userID int64, code string) bool {
	rows, err := db.QueryContext(ctx,
		"SELECT id, code_hash FROM recovery_codes WHERE user_id = ? AND used_at IS NULL", userID)
	if err != nil {
		return false
	}
	// Collect all hashes first, then CLOSE the rows (release the pool conn)
	// before running Argon2. Otherwise the DB connection is pinned for up to
	// 8 x ~150ms while we verify, multiplying conn-hold time under concurrent
	// logins and starving the pool.
	type rc struct {
		id   int64
		hash string
	}
	var codes []rc
	for rows.Next() {
		var c rc
		if err := rows.Scan(&c.id, &c.hash); err == nil {
			codes = append(codes, c)
		}
	}
	rows.Close()

	trimmed := strings.TrimSpace(code)
	for _, c := range codes {
		if err := auth.VerifyPassword(c.hash, trimmed); err == nil {
			_, _ = db.ExecContext(ctx, "UPDATE recovery_codes SET used_at = NOW() WHERE id = ?", c.id)
			return true
		}
	}
	return false
}

// ---- Logout -------------------------------------------------------------

func (h *AuthHandlers) Logout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if db := h.DB(); db != nil {
		if sess, _ := h.Sessions.Load(ctx, r); sess != nil {
			uid := sess.UserID
			audit.Write(ctx, db, h.Logger, r, audit.Entry{
				UserID: &uid, Action: "logout", Entity: "auth", EntityID: sess.Email,
			})
		}
	}
	h.Sessions.Destroy(ctx, w, r)
	http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
}

// EndImpersonation drops the impersonation session and re-issues a
// normal admin session for ImpersonatorUserID. Safe to call when no
// impersonation is active - just redirects back to /admin.
func (h *AuthHandlers) EndImpersonation(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sess, _ := h.Sessions.Load(ctx, r)
	if sess == nil || !sess.IsImpersonating() {
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	var (
		adminEmail string
		adminRole  string
		adminAct   bool
	)
	if err := db.QueryRowContext(ctx,
		"SELECT email, role, is_active FROM users WHERE id = ?", sess.ImpersonatorUserID,
	).Scan(&adminEmail, &adminRole, &adminAct); err != nil || !adminAct {
		h.Sessions.Destroy(ctx, w, r)
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}
	h.Sessions.Destroy(ctx, w, r)
	if _, err := h.Sessions.Create(ctx, w, sess.ImpersonatorUserID, adminEmail, adminRole, 0, lookupResellerID(ctx, db, sess.ImpersonatorUserID)); err != nil {
		h.Logger.Error("end impersonation: create admin session", "err", err)
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: &sess.ImpersonatorUserID, Action: "admin.impersonate.end", Entity: "user",
		EntityID: fmt.Sprintf("%d", sess.UserID),
		Meta:     map[string]any{"impersonated_email": sess.Email},
	})
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

// ---- Forgot / Reset -----------------------------------------------------

type forgotViewData struct {
	Email    string
	Flash    string
	Error    string
	CSPNonce string
	Lang     string
	Brand    Branding
}

func (h *AuthHandlers) renderForgot(w http.ResponseWriter, status int, d forgotViewData) {
	var buf bytes.Buffer
	if err := h.Templates.Render(&buf, "forgot.html.tmpl", d); err != nil {
		http.Error(w, "render failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

func (h *AuthHandlers) ForgotPage(w http.ResponseWriter, r *http.Request) {
	h.renderForgot(w, http.StatusOK, h.stampForgot(r, forgotViewData{}))
}

func (h *AuthHandlers) ForgotSubmit(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	if email == "" {
		h.renderForgot(w, http.StatusBadRequest, h.stampForgot(r, forgotViewData{Error: "Email required."}))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	db := h.DB()
	if db == nil {
		h.renderForgot(w, http.StatusServiceUnavailable, h.stampForgot(r, forgotViewData{Email: email, Error: "Server unavailable."}))
		return
	}
	var (
		userID   int64
		fullName sql.NullString
		isActive bool
	)
	err := db.QueryRowContext(ctx, "SELECT id, full_name, is_active FROM users WHERE email = ?", email).
		Scan(&userID, &fullName, &isActive)
	flash := "If that email exists, a reset link is on its way."
	if err == nil && isActive {
		token, terr := auth.CreateResetToken(ctx, db, userID, clientIPFromReq(r))
		if terr == nil && h.Mailer != nil {
			resetURL := strings.TrimRight(h.AppURL, "/") + "/auth/reset?token=" + token
			name := "there"
			if fullName.Valid && fullName.String != "" {
				name = fullName.String
			}
			if sendErr := h.Mailer.Send(ctx, email, "Reset your Hostyt Proxy password", "password_reset", map[string]any{
				"Name": name, "AppName": "Hostyt Proxy", "ResetURL": resetURL, "ExpiresMin": int(auth.ResetTokenTTL.Minutes()),
			}); sendErr != nil {
				h.Logger.Warn("password reset email send", "err", sendErr, "user_id", userID)
			}
			audit.Write(ctx, db, h.Logger, r, audit.Entry{
				UserID: &userID, Action: "password_reset.requested", Entity: "auth", EntityID: email,
			})
		}
	}
	h.renderForgot(w, http.StatusOK, h.stampForgot(r, forgotViewData{Flash: flash}))
}

type resetViewData struct {
	Token    string
	Error    string
	CSPNonce string
	Lang     string
	Brand    Branding
}

func (h *AuthHandlers) renderReset(w http.ResponseWriter, status int, d resetViewData) {
	var buf bytes.Buffer
	if err := h.Templates.Render(&buf, "reset.html.tmpl", d); err != nil {
		http.Error(w, "render failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

func (h *AuthHandlers) ResetPage(w http.ResponseWriter, r *http.Request) {
	tok := r.URL.Query().Get("token")
	if tok == "" {
		http.Redirect(w, r, "/auth/forgot", http.StatusSeeOther)
		return
	}
	h.renderReset(w, http.StatusOK, h.stampReset(r, resetViewData{Token: tok}))
}

func (h *AuthHandlers) ResetSubmit(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	token := strings.TrimSpace(r.FormValue("token"))
	password := r.FormValue("password")
	confirm := r.FormValue("password_confirm")
	if token == "" || password == "" || confirm == "" {
		h.renderReset(w, http.StatusBadRequest, h.stampReset(r, resetViewData{Token: token, Error: "All fields required."}))
		return
	}
	if password != confirm {
		h.renderReset(w, http.StatusBadRequest, h.stampReset(r, resetViewData{Token: token, Error: "Passwords dont match."}))
		return
	}
	if len(password) < 12 {
		h.renderReset(w, http.StatusBadRequest, h.stampReset(r, resetViewData{Token: token, Error: "Min 12 characters."}))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	db := h.DB()
	userID, err := auth.ConsumeResetToken(ctx, db, token)
	if err != nil {
		h.renderReset(w, http.StatusBadRequest, h.stampReset(r, resetViewData{Token: token, Error: "Reset link invalid or expired."}))
		return
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		h.renderReset(w, http.StatusInternalServerError, h.stampReset(r, resetViewData{Token: token, Error: "Server error."}))
		return
	}
	// password_set=1 marks this as a real usable password (not an OIDC dummy hash).
	if _, err := db.ExecContext(ctx, "UPDATE users SET password_hash = ?, password_set = 1 WHERE id = ?", hash, userID); err != nil {
		h.renderReset(w, http.StatusInternalServerError, h.stampReset(r, resetViewData{Token: token, Error: "Server error."}))
		return
	}
	// Invalidate every existing session for this user - a successful reset
	// must kick out anyone who already had the account open (including the
	// attacker scenario the codex review flagged).
	killed, _ := h.Sessions.DestroyAllForUser(ctx, userID)
	// Revoke all API keys for the user; a stolen key survives a password
	// reset otherwise, defeating the whole purpose of the reset.
	keysRes, _ := db.ExecContext(ctx,
		`UPDATE api_keys SET revoked_at = NOW() WHERE user_id = ? AND revoked_at IS NULL`, userID)
	var revokedKeys int64
	if keysRes != nil {
		revokedKeys, _ = keysRes.RowsAffected()
	}
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: &userID, Action: "password_reset.completed", Entity: "auth", EntityID: fmt.Sprintf("%d", userID),
		Meta: map[string]any{"sessions_killed": killed, "api_keys_revoked": revokedKeys},
	})
	http.Redirect(w, r, "/auth/login?flash=Password+updated.+Please+sign+in.", http.StatusSeeOther)
}

// ---- Brute-force lockout (Redis-backed) --------------------------------
//
// Two independent buckets:
//   - per-email   bucket (slow): protects an account from horizontal scans.
//   - per-(email,IP) bucket (fast): the actual lock-out trigger. This is
//     what 429s a single attacker; the per-email count grows but does not
//     lock the legitimate user from a different network.
//
// Why both: the v1 code locked per-email only, which let any attacker who
// knew an admin's email DoS them off the panel. The audit (P1-D-7) flagged
// this. The fix is to gate on per-(email,IP) AND, only when an unusually
// high per-email count appears, require a captcha - never a hard block.

const (
	loginFailIPLimit  = 10 // hard lock after 10 fails from one IP for an email
	loginFailMaxEmail = 50 // soft threshold: force captcha cross-IP for the email
)

// twoFAFailLimit hard-locks a user's 2FA challenge after this many failed
// codes across ALL tickets, closing the "fresh-ticket-per-login" amplification
// where an attacker with the password loops login -> 5 guesses -> repeat.
// Matches the spirit of loginFailIPLimit (per-IP password cap).
const twoFAFailLimit = 10

func (h *AuthHandlers) failKeyEmail(email string) string { return "hpg:login:fail:email:" + email }
func (h *AuthHandlers) failKeyEmailIP(email, ip string) string {
	return "hpg:login:fail:" + ip + ":" + email
}

// twoFAFailKey is the per-user 2FA failure counter, independent of any ticket.
func (h *AuthHandlers) twoFAFailKey(userID int64) string {
	return fmt.Sprintf("hpg:2fa:fail:%d", userID)
}

// record2FAFail bumps the per-user 2FA failure counter with a rolling window.
// Called on EVERY 2FA failure (totp/webauthn/backup/sms/email). Best-effort:
// Redis errors fall open so an outage can't lock everyone out of 2FA.
func (h *AuthHandlers) record2FAFail(ctx context.Context, userID int64) {
	if h.RDB == nil {
		return
	}
	key := h.twoFAFailKey(userID)
	if n, err := h.RDB.Incr(ctx, key).Result(); err == nil && n == 1 {
		_ = h.RDB.Expire(ctx, key, loginFailWindow).Err()
	}
}

// twoFALocked reports whether the user is over the per-user 2FA failure
// threshold. Checked before accepting any 2FA code, independent of the ticket.
func (h *AuthHandlers) twoFALocked(ctx context.Context, userID int64) bool {
	if h.RDB == nil {
		return false
	}
	n, err := h.RDB.Get(ctx, h.twoFAFailKey(userID)).Int()
	return err == nil && n >= twoFAFailLimit
}

// clear2FAFails resets the per-user 2FA counter. Called ONLY on a successful
// 2FA verify - never on a fresh login/ticket, else the amplification returns.
func (h *AuthHandlers) clear2FAFails(ctx context.Context, userID int64) {
	if h.RDB == nil {
		return
	}
	_ = h.RDB.Del(ctx, h.twoFAFailKey(userID)).Err()
}

// emailFailCount returns the per-email failure count (cross-IP). Used to force
// captcha once an account is under a horizontal scan from many source IPs.
func (h *AuthHandlers) emailFailCount(ctx context.Context, email string) int {
	if h.RDB == nil {
		return 0
	}
	n, err := h.RDB.Get(ctx, h.failKeyEmail(email)).Int()
	if err != nil {
		return 0
	}
	return n
}

// markTOTPConsumed records a successfully-used TOTP counter so the same code
// can't be replayed within its validity window. Returns false when the counter
// was already consumed (replay). Best-effort: Redis errors fall open.
func (h *AuthHandlers) markTOTPConsumed(ctx context.Context, userID int64, code string) bool {
	if h.RDB == nil {
		return true
	}
	// 30s counter = unix/period; a code is valid for its own counter (+/- skew).
	counter := time.Now().Unix() / 30
	key := fmt.Sprintf("hpg:totp:used:%d:%d", userID, counter)
	ok, err := h.RDB.SetNX(ctx, key, "1", 90*time.Second).Result()
	if err != nil {
		return true
	}
	return ok
}

func (h *AuthHandlers) locked(ctx context.Context, email, ip string) bool {
	if h.RDB == nil {
		return false
	}
	if ip != "" {
		n, err := h.RDB.Get(ctx, h.failKeyEmailIP(email, ip)).Int()
		if err == nil && n >= loginFailIPLimit {
			return true
		}
	}
	// Per-email is informational only; we don't hard-lock to avoid the
	// admin-lockout-by-known-email DoS. Captcha already gates the form.
	return false
}

func (h *AuthHandlers) recordFail(ctx context.Context, email, ip string) {
	if h.RDB == nil {
		return
	}
	if ip != "" {
		if n, err := h.RDB.Incr(ctx, h.failKeyEmailIP(email, ip)).Result(); err == nil && n == 1 {
			_ = h.RDB.Expire(ctx, h.failKeyEmailIP(email, ip), loginFailWindow).Err()
		}
	}
	if n, err := h.RDB.Incr(ctx, h.failKeyEmail(email)).Result(); err == nil && n == 1 {
		_ = h.RDB.Expire(ctx, h.failKeyEmail(email), loginFailWindow).Err()
	}
}

func (h *AuthHandlers) clearFails(ctx context.Context, email, ip string) {
	if h.RDB == nil {
		return
	}
	_ = h.RDB.Del(ctx, h.failKeyEmail(email)).Err()
	if ip != "" {
		_ = h.RDB.Del(ctx, h.failKeyEmailIP(email, ip)).Err()
	}
}

// ---- Pending 2FA tickets (short-lived Redis records) -------------------

type pending2FA struct {
	UserID   int64  `json:"u"`
	Email    string `json:"e"`
	Role     string `json:"r"`
	ClientID int64  `json:"c"`
	// Via marks how the user reached the 2FA challenge ("password"|"oidc").
	// Audit relies on this so login.success Meta.via reflects the real entry
	// point even after a redirect-bounce through /auth/2fa.
	Via string `json:"v,omitempty"`
}

func (h *AuthHandlers) issuePending2FA(ctx context.Context, userID int64, email, role string, clientID int64, via ...string) (string, error) {
	id := make([]byte, 24)
	if _, err := rand.Read(id); err != nil {
		return "", err
	}
	ticket := base64.RawURLEncoding.EncodeToString(id)
	v := "password"
	if len(via) > 0 && via[0] != "" {
		v = via[0]
	}
	payload := pending2FA{UserID: userID, Email: email, Role: role, ClientID: clientID, Via: v}
	b, _ := json.Marshal(payload)
	if err := h.RDB.Set(ctx, "hpg:2fa:"+ticket, b, pending2FATTL).Err(); err != nil {
		return "", err
	}
	return ticket, nil
}

func (h *AuthHandlers) readPending2FA(r *http.Request) (pending2FA, bool) {
	c, err := r.Cookie("hpg_2fa_pending")
	if err != nil || c.Value == "" {
		return pending2FA{}, false
	}
	b, err := h.RDB.Get(r.Context(), "hpg:2fa:"+c.Value).Bytes()
	if err != nil {
		return pending2FA{}, false
	}
	var p pending2FA
	if err := json.Unmarshal(b, &p); err != nil {
		return pending2FA{}, false
	}
	return p, true
}

func (h *AuthHandlers) consumePending2FA(r *http.Request) {
	c, err := r.Cookie("hpg_2fa_pending")
	if err != nil {
		return
	}
	_ = h.RDB.Del(r.Context(), "hpg:2fa:"+c.Value).Err()
}

// signTrustToken returns an AES-GCM-sealed (userID|exp) token. Sealing key
// is APP_SECRET-derived (via installstate.Manager), so a leaked cookie
// cannot be forged off-host and the integrity check is free.
func (h *AuthHandlers) signTrustToken(userID int64, ttl time.Duration) (string, error) {
	if h.State == nil {
		return "", errors.New("trust: state not wired")
	}
	exp := time.Now().Add(ttl).Unix()
	return h.State.Encrypt(fmt.Sprintf("%d|%d", userID, exp))
}

// verifyTrustToken returns true when the cookie value decrypts cleanly,
// matches userID, and has not expired.
func (h *AuthHandlers) verifyTrustToken(token string, userID int64) bool {
	if h.State == nil || token == "" {
		return false
	}
	pt, err := h.State.Decrypt(token)
	if err != nil {
		return false
	}
	parts := strings.SplitN(pt, "|", 2)
	if len(parts) != 2 {
		return false
	}
	uid, err1 := strconv.ParseInt(parts[0], 10, 64)
	exp, err2 := strconv.ParseInt(parts[1], 10, 64)
	if err1 != nil || err2 != nil || uid != userID {
		return false
	}
	return time.Now().Unix() < exp
}

// issueTrustCookie writes hpg_2fa_trust to the response with a 30d TTL.
// Best-effort: signing failure just skips it (user will see 2FA again).
func (h *AuthHandlers) issueTrustCookie(w http.ResponseWriter, userID int64) {
	token, err := h.signTrustToken(userID, trustDeviceTTL)
	if err != nil {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: trustCookie, Value: token, Path: "/", HttpOnly: true,
		Secure: h.Sessions.CookieSecure(), SameSite: http.SameSiteLaxMode,
		Expires: time.Now().Add(trustDeviceTTL),
	})
}

// clientIPFromReq is a thin alias kept for handler readability. All client
// IP attribution flows through internal/security.ClientIP - the single
// trusted source after chimw.RealIP + CloudflareIP middlewares have run.
func clientIPFromReq(r *http.Request) string { return security.ClientIP(r) }

// firstNonEmpty returns the first non-empty string from the arguments.
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// firstLine trims the first line of an error string and caps the length,
// so a provider's multi-line stack trace can't pollute a response body.
// Used when surfacing upstream send-failure causes to the admin UI.
func firstLine(s string) string {
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	const max = 240
	if len(s) > max {
		s = s[:max] + "…"
	}
	return s
}

// ---- OIDC --------------------------------------------------------------

const oidcStateTTL = 10 * time.Minute

// OIDCStart redirects the browser to the IdP authorization endpoint.
// State + nonce are stored in Redis with a short TTL and a matching
// cookie so the callback can verify CSRF + replay.
// When ?link=1 is present and user is already logged in, embeds
// link_user_id into the state payload so OIDCCallback does link-not-login.
func (h *AuthHandlers) OIDCStart(w http.ResponseWriter, r *http.Request) {
	if h.OIDC == nil {
		http.Error(w, "oidc not wired", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	authURL, state, nonce, verifier, _, err := h.OIDC.AuthURL(ctx)
	if err != nil {
		h.Logger.Warn("oidc start", "err", err)
		// Redirect to login with a friendly flash instead of a blank error
		// page so the operator sees "issuer unreachable" in-context.
		http.Redirect(w, r, "/auth/login?flash=SSO+unavailable%3A+"+url.QueryEscape(sanitizeErr(err)), http.StatusSeeOther)
		return
	}
	// For link flow: embed the current user's ID so the callback links
	// instead of logging in. Only valid when user is already authenticated.
	statePayload := map[string]string{"nonce": nonce, "verifier": verifier}
	if r.URL.Query().Get("link") == "1" {
		if sess, _ := h.Sessions.Load(ctx, r); sess != nil {
			statePayload["link_user_id"] = strconv.FormatInt(sess.UserID, 10)
		}
	}
	payload, _ := json.Marshal(statePayload)
	_ = h.RDB.Set(ctx, "hpg:oidc:"+state, payload, oidcStateTTL).Err()
	// Cookie keeps the state value so the callback can look it up.
	http.SetCookie(w, &http.Cookie{
		Name: "hpg_oidc_state", Value: state, Path: "/", HttpOnly: true,
		Secure: h.Sessions.CookieSecure(), SameSite: http.SameSiteLaxMode,
		Expires: time.Now().Add(oidcStateTTL),
	})
	http.Redirect(w, r, authURL, http.StatusSeeOther)
}

// OIDCCallback exchanges the code, verifies the ID token, upserts a
// local user, and creates a session.
func (h *AuthHandlers) OIDCCallback(w http.ResponseWriter, r *http.Request) {
	if h.OIDC == nil {
		http.Error(w, "oidc not wired", http.StatusServiceUnavailable)
		return
	}
	q := r.URL.Query()
	if errStr := q.Get("error"); errStr != "" {
		http.Redirect(w, r, "/auth/login?flash=OIDC+sign-in+failed", http.StatusSeeOther)
		return
	}
	state := q.Get("state")
	code := q.Get("code")
	if state == "" || code == "" {
		http.Error(w, "missing state/code", http.StatusBadRequest)
		return
	}
	cookie, err := r.Cookie("hpg_oidc_state")
	if err != nil || subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(state)) != 1 {
		http.Error(w, "state mismatch", http.StatusForbidden)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	stored, err := h.RDB.Get(ctx, "hpg:oidc:"+state).Bytes()
	if err != nil {
		http.Error(w, "state expired", http.StatusForbidden)
		return
	}
	_ = h.RDB.Del(ctx, "hpg:oidc:"+state).Err()
	var s struct {
		Nonce      string `json:"nonce"`
		Verifier   string `json:"verifier"`
		LinkUserID string `json:"link_user_id,omitempty"`
	}
	_ = json.Unmarshal(stored, &s)

	info, err := h.OIDC.Exchange(ctx, code, s.Nonce, s.Verifier)
	if err != nil {
		h.Logger.Warn("oidc exchange", "err", err)
		http.Redirect(w, r, "/auth/login?flash=SSO+sign-in+failed%3A+"+url.QueryEscape(sanitizeErr(err)), http.StatusSeeOther)
		return
	}

	cfg, _ := h.OIDC.CurrentConfigForUI(ctx)
	db := h.DB()
	// NFKC + lowercase + strip BOM so Unicode lookalikes (Cyrillic А vs
	// Latin A, full-width letters) don't create sibling-admin accounts.
	email := strings.ToLower(xnorm.NFKC.String(info.Email))

	// Link flow: user is already logged in and wants to add this OIDC
	// provider as an additional login method.
	if s.LinkUserID != "" {
		http.SetCookie(w, &http.Cookie{Name: "hpg_oidc_state", Value: "", Path: "/", MaxAge: -1})
		linkUID, linkErr := strconv.ParseInt(s.LinkUserID, 10, 64)
		if linkErr != nil {
			http.Error(w, "invalid link state", http.StatusBadRequest)
			return
		}
		// Re-validate at callback: the state alone is not authority to link. The
		// caller must STILL be logged in as that same user. Blocks linking onto a
		// victim via a stale/shared-browser state, a forged ?link=1 start, or an
		// IdP-session mixup - any of which would otherwise add a login path.
		sess, _ := h.Sessions.Load(ctx, r)
		if sess == nil || sess.UserID != linkUID {
			audit.Write(ctx, db, h.Logger, r, audit.Entry{
				Action: "oauth.link.denied", Entity: "user", EntityID: s.LinkUserID,
				Meta: map[string]any{"reason": "session_mismatch", "issuer": info.Issuer},
			})
			http.Redirect(w, r, "/auth/login?flash=Please+sign+in+again+to+link+a+provider", http.StatusSeeOther)
			return
		}
		h.oidcLinkIdentity(ctx, w, r, db, linkUID, info, cfg.AllowUnverifiedEmail)
		return
	}

	// Refuse OIDC sign-in when the IdP says the email isn't verified. Without
	// this gate a public-signup IdP (Authentik with self-registration, Google
	// Workspace test tenant, generic OIDC) lets anyone register
	// `victim@panel.example.com` on that issuer and take over the matching
	// local account.
	if !info.EmailVerified && !cfg.AllowUnverifiedEmail {
		audit.Write(ctx, db, h.Logger, r, audit.Entry{
			Action: "oidc.login.denied", Entity: "auth", EntityID: email,
			Meta: map[string]any{"reason": "email_unverified", "issuer": info.Issuer},
		})
		http.Redirect(w, r, "/auth/login?flash=Email+not+verified+at+identity+provider", http.StatusSeeOther)
		return
	}

	// Authoritative identity lookup: an explicitly linked provider+issuer+subject
	// in oauth_identities owns the account, even if its email differs from this
	// callback's email claim. Without this a linked identity is counted as a
	// login method but can never actually authenticate (it would only match by
	// email, which a linked second provider need not share).
	var (
		userID        int64
		role          string
		isActive      bool
		emailVerified bool
	)
	var linkedUID int64
	linkLookupErr := db.QueryRowContext(ctx,
		`SELECT user_id FROM oauth_identities WHERE provider = 'oidc' AND issuer = ? AND subject = ? LIMIT 1`,
		info.Issuer, info.Subject,
	).Scan(&linkedUID)
	// Fail closed: a real error on the authoritative identity table (schema drift,
	// transient DB) must NOT degrade to email-based login - that would bypass
	// linked-provider ownership. Only a clean "no such row" may fall back to email.
	if linkLookupErr != nil && !errors.Is(linkLookupErr, sql.ErrNoRows) {
		h.Logger.Error("oidc identity lookup", "err", linkLookupErr, "issuer", info.Issuer)
		audit.Write(ctx, db, h.Logger, r, audit.Entry{
			Action: "oidc.login.denied", Entity: "auth", EntityID: email,
			Meta: map[string]any{"reason": "identity_lookup_error", "issuer": info.Issuer},
		})
		http.Redirect(w, r, "/auth/login?flash=SSO+temporarily+unavailable", http.StatusSeeOther)
		return
	}
	var queryErr error
	if linkLookupErr == nil && linkedUID > 0 {
		// Resolve the owning user by id, not email.
		queryErr = db.QueryRowContext(ctx,
			"SELECT id, role, is_active, email_verified FROM users WHERE id = ? LIMIT 1", linkedUID,
		).Scan(&userID, &role, &isActive, &emailVerified)
	} else {
		// No linked identity. Fall back to email lookup.
		queryErr = db.QueryRowContext(ctx,
			"SELECT id, role, is_active, email_verified FROM users WHERE email = ? LIMIT 1", email,
		).Scan(&userID, &role, &isActive, &emailVerified)
	}
	if errors.Is(queryErr, sql.ErrNoRows) {
		if !cfg.AutoProvision {
			audit.Write(ctx, db, h.Logger, r, audit.Entry{
				Action: "oidc.login.denied", Entity: "auth", EntityID: email,
				Meta: map[string]any{"reason": "auto_provision_disabled", "issuer": info.Issuer},
			})
			http.Redirect(w, r, "/auth/login?flash=No+account+for+this+email.+Ask+an+admin+to+create+one.", http.StatusSeeOther)
			return
		}
		// Random non-usable password (login still needs OIDC; reset flow
		// can issue a real one later if user wants password sign-in too).
		raw := make([]byte, 32)
		_, _ = rand.Read(raw)
		dummy, _ := auth.HashPassword(base64.RawURLEncoding.EncodeToString(raw))
		role = cfg.DefaultRole
		if role == "" {
			role = "support"
		}
		full := info.Name
		if full == "" {
			full = email
		}
		// email_verified=1: the IdP already vouched for this email (the
		// verified-email gate above ran), so a fresh OIDC-provisioned row is
		// trusted - unlike a self-registered local row.
		res, ierr := db.ExecContext(ctx,
			`INSERT INTO users (email, password_hash, password_set, role, full_name, is_active, email_verified)
			 VALUES (?, ?, 0, ?, ?, 1, 1)`,
			email, dummy, role, full)
		if ierr != nil {
			h.Logger.Error("oidc auto-provision", "err", ierr)
			http.Redirect(w, r, "/auth/login?flash=Provisioning+failed", http.StatusSeeOther)
			return
		}
		userID, _ = res.LastInsertId()
		isActive = true
		audit.Write(ctx, db, h.Logger, r, audit.Entry{
			UserID: &userID, Action: "oidc.user.provisioned", Entity: "user",
			EntityID: fmt.Sprintf("%d", userID),
			Meta:     map[string]any{"email": email, "issuer": info.Issuer, "role": role},
		})
	} else if queryErr != nil {
		h.Logger.Error("oidc user lookup", "err", queryErr)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	} else if linkedUID > 0 {
		// User resolved via authoritative oauth_identities row - no further checks needed.
	} else {
		// Email-based lookup; this subject+issuer is not yet in oauth_identities.
		// AUTH-02: refuse to adopt an UNVERIFIED local row via email. A
		// self-registered account (email_verified=0) is attacker-chosen; adopting
		// it by email would hand the attacker whatever the OIDC login grants.
		// Existing users were backfilled to 1, so they are unaffected.
		if !emailVerified {
			audit.Write(ctx, db, h.Logger, r, audit.Entry{
				UserID: &userID, Action: "oidc.login.denied", Entity: "auth", EntityID: email,
				Meta: map[string]any{"reason": "local_email_unverified", "issuer": info.Issuer},
			})
			http.Redirect(w, r, "/auth/login?flash=Verify+your+email+before+signing+in+with+SSO", http.StatusSeeOther)
			return
		}
		// Reject if this user already has a DIFFERENT oidc identity linked -
		// prevents email-claim takeover from a second IdP.
		var existingSubj, existingIss sql.NullString
		idErr := db.QueryRowContext(ctx,
			`SELECT subject, issuer FROM oauth_identities WHERE user_id = ? AND provider = 'oidc' LIMIT 1`,
			userID,
		).Scan(&existingSubj, &existingIss)
		if idErr != nil && !errors.Is(idErr, sql.ErrNoRows) {
			h.Logger.Error("oidc identity check", "err", idErr, "user_id", userID)
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		if idErr == nil && existingSubj.Valid && existingSubj.String != "" {
			// User has a different OIDC identity - deny to prevent takeover.
			if existingSubj.String != info.Subject || existingIss.String != info.Issuer {
				audit.Write(ctx, db, h.Logger, r, audit.Entry{
					UserID: &userID, Action: "oidc.login.denied", Entity: "auth", EntityID: email,
					Meta: map[string]any{"reason": "subject_issuer_mismatch", "expected_issuer": existingIss.String, "got_issuer": info.Issuer},
				})
				http.Redirect(w, r, "/auth/login?flash=OIDC+identity+does+not+match+the+account+previously+linked", http.StatusSeeOther)
				return
			}
		}
		// First-time link: SaveIdentity below will atomically claim via unique constraint.
	}

	if !isActive {
		audit.Write(ctx, db, h.Logger, r, audit.Entry{
			UserID: &userID, Action: "oidc.login.denied", Entity: "auth", EntityID: email,
			Meta: map[string]any{"reason": "disabled"},
		})
		http.Redirect(w, r, "/auth/login?flash=Account+disabled", http.StatusSeeOther)
		return
	}

	var clientID int64
	if role == "client" {
		_ = db.QueryRowContext(ctx, "SELECT id FROM clients WHERE user_id = ?", userID).Scan(&clientID)
	}

	// Populate oauth_identities so real SSO users have something to view/unlink.
	// A plain write error is best-effort (doesn't block login), but if this
	// subject is already owned by a DIFFERENT user the login itself is a
	// takeover attempt and must be denied.
	if saveErr := SaveIdentity(ctx, db, userID, "oidc", info.Subject, info.Email, info.Issuer); saveErr != nil {
		if errors.Is(saveErr, ErrIdentityOwnedByOther) {
			audit.Write(ctx, db, h.Logger, r, audit.Entry{
				UserID: &userID, Action: "oidc.login.denied", Entity: "auth", EntityID: email,
				Meta: map[string]any{"reason": "identity_owned_by_other", "issuer": info.Issuer},
			})
			http.Redirect(w, r, "/auth/login?flash=OIDC+identity+belongs+to+another+account", http.StatusSeeOther)
			return
		}
		h.Logger.Warn("oidc login: save identity", "err", saveErr, "user_id", userID)
	}

	// Clear the state cookie now that we're done with it.
	http.SetCookie(w, &http.Cookie{Name: "hpg_oidc_state", Value: "", Path: "/", MaxAge: -1})

	// SSO IdP already performed any MFA it owns - don't double-prompt with
	// our local TOTP. Same trust model as passkey login.
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: &userID, Action: "oidc.login.success", Entity: "auth", EntityID: email,
		Meta: map[string]any{"issuer": info.Issuer, "role": role},
	})
	h.finalizeLogin(ctx, w, r, userID, email, role, clientID, "oidc", "sso")
}

// oidcLinkIdentity handles the account-linking branch of OIDCCallback. The
// user is already authenticated (linkUID came from their session); we add the
// OIDC subject to oauth_identities and redirect back to their account page.
func (h *AuthHandlers) oidcLinkIdentity(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	db *sql.DB,
	linkUID int64,
	info hpgoidc.UserInfo,
	allowUnverified bool,
) {
	// Email verification gate - same as the normal login flow.
	if !info.EmailVerified && !allowUnverified {
		audit.Write(ctx, db, h.Logger, r, audit.Entry{
			UserID: &linkUID, Action: "oauth.link.denied", Entity: "user",
			EntityID: fmt.Sprintf("%d", linkUID),
			Meta:     map[string]any{"reason": "email_unverified", "provider": "oidc", "issuer": info.Issuer},
		})
		returnURL := oidcLinkReturnURL(r, linkUID)
		http.Redirect(w, r, returnURL+"?err=Email+not+verified+at+identity+provider", http.StatusSeeOther)
		return
	}

	// Refuse if this subject+issuer pair is already linked to a DIFFERENT user.
	var existingUID int64
	err := db.QueryRowContext(ctx,
		`SELECT user_id FROM oauth_identities WHERE provider = 'oidc' AND issuer = ? AND subject = ? LIMIT 1`,
		info.Issuer, info.Subject,
	).Scan(&existingUID)
	if err == nil && existingUID != linkUID {
		audit.Write(ctx, db, h.Logger, r, audit.Entry{
			UserID: &linkUID, Action: "oauth.link.denied", Entity: "user",
			EntityID: fmt.Sprintf("%d", linkUID),
			Meta:     map[string]any{"reason": "subject_taken", "provider": "oidc", "issuer": info.Issuer},
		})
		returnURL := oidcLinkReturnURL(r, linkUID)
		http.Redirect(w, r, returnURL+"?err=This+OIDC+account+is+already+linked+to+another+user", http.StatusSeeOther)
		return
	}

	if linkErr := SaveIdentity(ctx, db, linkUID, "oidc", info.Subject, info.Email, info.Issuer); linkErr != nil {
		h.Logger.Error("oauth link save", "err", linkErr, "user_id", linkUID)
		returnURL := oidcLinkReturnURL(r, linkUID)
		// A concurrent link can take the subject between the precheck above and
		// this write; SaveIdentity refuses to steal it and reports the conflict.
		msg := "Link+failed"
		if errors.Is(linkErr, ErrIdentityOwnedByOther) {
			msg = "This+OIDC+account+is+already+linked+to+another+user"
		}
		http.Redirect(w, r, returnURL+"?err="+msg, http.StatusSeeOther)
		return
	}

	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: &linkUID, Action: "oauth.link", Entity: "user",
		EntityID: fmt.Sprintf("%d", linkUID),
		Meta: map[string]any{
			"provider": "oidc",
			"issuer":   info.Issuer,
			"email":    info.Email,
		},
	})
	returnURL := oidcLinkReturnURL(r, linkUID)
	http.Redirect(w, r, returnURL+"?flash=OIDC+provider+linked", http.StatusSeeOther)
}

// oidcLinkReturnURL picks the correct account page based on the session role.
// Falls back to /admin/account when role cannot be determined.
func oidcLinkReturnURL(r *http.Request, _ int64) string {
	// Session role is available from the middleware context.
	if sess := middleware.SessionFromContext(r.Context()); sess != nil {
		if sess.Role == "client" {
			return "/app/account"
		}
	}
	return "/admin/account"
}

// SSOJump handles GET /auth/sso/jump - signed jump-login from external systems
// (FOSSBilling, etc.). Validates HMAC-SHA256 token, then creates a session.
func (h *AuthHandlers) SSOJump(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	db := h.DB()
	if db == nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	// Feature flag - return 404 to hide the endpoint when disabled.
	var enabledVal string
	_ = db.QueryRowContext(ctx,
		"SELECT value FROM settings WHERE `key` = 'sso_jump.enabled' LIMIT 1",
	).Scan(&enabledVal)
	if enabledVal != "1" {
		http.NotFound(w, r)
		return
	}

	q := r.URL.Query()
	email := strings.ToLower(strings.TrimSpace(q.Get("email")))
	expStr := q.Get("exp")
	sig := strings.ToLower(strings.TrimSpace(q.Get("sig")))

	// Basic format validation before any DB or crypto work.
	if email == "" || expStr == "" || sig == "" {
		http.Error(w, "missing parameters", http.StatusBadRequest)
		return
	}
	if !ssoJumpEmailRe.MatchString(email) {
		http.Error(w, "invalid email format", http.StatusBadRequest)
		return
	}
	if !ssoJumpSigRe.MatchString(sig) {
		http.Error(w, "invalid sig format", http.StatusBadRequest)
		return
	}

	expUnix, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil {
		http.Error(w, "invalid exp", http.StatusBadRequest)
		return
	}

	now := time.Now().UTC()
	exp := time.Unix(expUnix, 0).UTC()

	// Window: not expired + not suspiciously far in the future (replay guard).
	if exp.Before(now) {
		http.Error(w, "token expired", http.StatusForbidden)
		return
	}
	if exp.After(now.Add(600 * time.Second)) {
		http.Error(w, "exp too far in future", http.StatusForbidden)
		return
	}

	// Load and decrypt the shared secret.
	var secretEnc string
	_ = db.QueryRowContext(ctx,
		"SELECT value FROM settings WHERE `key` = 'sso_jump.secret_e2' LIMIT 1",
	).Scan(&secretEnc)
	if secretEnc == "" || h.State == nil {
		h.Logger.Warn("sso_jump: no secret configured")
		http.Error(w, "sso jump not configured", http.StatusForbidden)
		return
	}
	secretPlain, err := h.State.Decrypt(secretEnc)
	if err != nil || secretPlain == "" {
		h.Logger.Error("sso_jump: decrypt secret failed", "err", err)
		http.Error(w, "sso jump misconfigured", http.StatusForbidden)
		return
	}

	// Recompute HMAC and compare in constant time.
	message := fmt.Sprintf("email=%s&exp=%s", url.QueryEscape(email), expStr)
	mac := hmac.New(sha256.New, []byte(secretPlain))
	mac.Write([]byte(message))
	expected := mac.Sum(nil)
	sigBytes, err := hex.DecodeString(sig)
	if err != nil || !hmac.Equal(sigBytes, expected) {
		audit.Write(ctx, db, h.Logger, r, audit.Entry{
			Action: "sso_jump.denied", Entity: "auth", EntityID: email,
			Meta: map[string]any{"reason": "invalid_sig"},
		})
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	// Replay protection: nonce stored in Redis with TTL until exp+60s.
	nonceKey := "sso_jump:nonce:" + sig
	ttl := time.Until(exp) + 60*time.Second
	set, err := h.RDB.SetNX(ctx, nonceKey, "1", ttl).Result()
	if err != nil {
		h.Logger.Error("sso_jump: redis setnx", "err", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	if !set {
		audit.Write(ctx, db, h.Logger, r, audit.Entry{
			Action: "sso_jump.denied", Entity: "auth", EntityID: email,
			Meta: map[string]any{"reason": "replay"},
		})
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	// Look up user by email.
	var (
		userID   int64
		role     string
		clientID int64
		isActive bool
	)
	err = db.QueryRowContext(ctx,
		"SELECT id, role, COALESCE(client_id,0), is_active FROM users WHERE LOWER(email)=? LIMIT 1",
		email,
	).Scan(&userID, &role, &clientID, &isActive)
	if err != nil {
		audit.Write(ctx, db, h.Logger, r, audit.Entry{
			Action: "sso_jump.denied", Entity: "auth", EntityID: email,
			Meta: map[string]any{"reason": "unknown_user"},
		})
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if !isActive {
		audit.Write(ctx, db, h.Logger, r, audit.Entry{
			UserID: &userID, Action: "sso_jump.denied", Entity: "auth", EntityID: email,
			Meta: map[string]any{"reason": "disabled"},
		})
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	// Admin role failsafe: block unless allow_admin_login=1.
	if role == "super_admin" || role == "admin" {
		var allowAdmin string
		_ = db.QueryRowContext(ctx,
			"SELECT value FROM settings WHERE `key` = 'sso_jump.allow_admin_login' LIMIT 1",
		).Scan(&allowAdmin)
		if allowAdmin != "1" {
			audit.Write(ctx, db, h.Logger, r, audit.Entry{
				UserID: &userID, Action: "sso_jump.denied", Entity: "auth", EntityID: email,
				Meta: map[string]any{"reason": "admin_blocked"},
			})
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
	}

	// Enrolled 2FA must still be presented: the SSO-jump token is a single
	// factor (a shared HMAC secret travelling in billing rotate flows), so on
	// its own it would let anyone holding that secret bypass an admin's TOTP
	// and RequireAdmin2FA. Mirror the password path: if a second factor is
	// enrolled, bounce through /auth/2fa instead of minting a full session.
	totpEnabled, smsEnabled, emailEnabled, _, _ := h.twoFAOptions(ctx, userID)
	if totpEnabled || smsEnabled || emailEnabled {
		ticket, err := h.issuePending2FA(ctx, userID, email, role, clientID, "sso")
		if err != nil {
			h.Logger.Error("sso_jump: pending 2fa issue", "err", err)
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name: "hpg_2fa_pending", Value: ticket, Path: "/", HttpOnly: true,
			Secure: h.Sessions.CookieSecure(), SameSite: http.SameSiteLaxMode,
			Expires: time.Now().Add(pending2FATTL),
		})
		audit.Write(ctx, db, h.Logger, r, audit.Entry{
			UserID: &userID, Action: "sso_jump.2fa_required", Entity: "auth", EntityID: email,
			Meta: map[string]any{"role": role, "ip": security.ClientIP(r)},
		})
		http.Redirect(w, r, "/auth/2fa", http.StatusSeeOther)
		return
	}

	// No second factor enrolled - create session and redirect.
	if _, err := h.Sessions.Create(ctx, w, userID, email, role, clientID, lookupResellerID(ctx, h.DB(), userID)); err != nil {
		h.Logger.Error("sso_jump: session create", "err", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	_, _ = db.ExecContext(ctx, "UPDATE users SET last_login_at = NOW() WHERE id = ?", userID)
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: &userID, Action: "sso_jump.success", Entity: "auth", EntityID: email,
		Meta: map[string]any{"role": role, "ip": security.ClientIP(r)},
	})

	dest := "/admin"
	if role == "client" {
		dest = "/app"
	}
	http.Redirect(w, r, dest, http.StatusSeeOther)
}

// ssoJumpEmailRe and ssoJumpSigRe are pre-compiled for SSOJump validation.
var (
	ssoJumpEmailRe = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
	ssoJumpSigRe   = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// ---- SMS OTP challenge -------------------------------------------------

type smsOTPViewData struct {
	Error    string
	CSPNonce string
	Lang     string
	Brand    Branding
}

// startSMSOTPChallenge generates a code, sends it via SMS, stores the hash
// in Redis, sets a cookie, and redirects to /auth/sms-otp.
func (h *AuthHandlers) startSMSOTPChallenge(ctx context.Context, w http.ResponseWriter, r *http.Request, db *sql.DB, userID int64, email, role string, clientID int64) error {
	// Read user's phone number.
	var phone sql.NullString
	_ = db.QueryRowContext(ctx, "SELECT phone_e164 FROM users WHERE id = ?", userID).Scan(&phone)
	if !phone.Valid || phone.String == "" {
		return fmt.Errorf("no phone on file")
	}
	if h.SMS == nil {
		return fmt.Errorf("sms sender not wired")
	}
	code, err := auth.GenerateSMSOTP()
	if err != nil {
		return err
	}
	// Re-issue pending2FA ticket so we know who to log in after verify.
	pending, err := h.issuePending2FA(ctx, userID, email, role, clientID)
	if err != nil {
		return err
	}
	otpTicket, err := auth.StoreSMSOTP(ctx, h.RDB, userID, code)
	if err != nil {
		return err
	}
	if err := h.SMS.Send(ctx, phone.String, fmt.Sprintf("Your Hostyt Proxy verification code: %s", code)); err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name: "hpg_2fa_pending", Value: pending, Path: "/", HttpOnly: true,
		Secure: h.Sessions.CookieSecure(), SameSite: http.SameSiteLaxMode,
		Expires: time.Now().Add(pending2FATTL),
	})
	http.SetCookie(w, &http.Cookie{
		Name: "hpg_smsotp", Value: otpTicket, Path: "/", HttpOnly: true,
		Secure: h.Sessions.CookieSecure(), SameSite: http.SameSiteLaxMode,
		Expires: time.Now().Add(auth.SMSOTPTTLSeconds * time.Second),
	})
	http.Redirect(w, r, "/auth/sms-otp", http.StatusSeeOther)
	return nil
}

func (h *AuthHandlers) SMSOTPChallenge(w http.ResponseWriter, r *http.Request) {
	if _, err := r.Cookie("hpg_smsotp"); err != nil {
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}
	nonce, lang := authBase(r)
	d := smsOTPViewData{CSPNonce: nonce, Lang: lang}
	if db := h.DB(); db != nil {
		d.Brand = LoadBranding(r.Context(), db)
	}
	h.renderSMSOTP(w, http.StatusOK, d)
}

func (h *AuthHandlers) SMSOTPVerify(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	code := strings.TrimSpace(r.FormValue("code"))

	otpCookie, err := r.Cookie("hpg_smsotp")
	if err != nil || otpCookie.Value == "" {
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}
	pend, ok := h.readPending2FA(r)
	if !ok {
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// Per-user 2FA lock: independent of the ticket, blocks the fresh-ticket loop.
	if h.twoFALocked(ctx, pend.UserID) {
		h.consumePending2FA(r)
		http.SetCookie(w, &http.Cookie{Name: "hpg_smsotp", Value: "", Path: "/", MaxAge: -1})
		http.Redirect(w, r, "/auth/login?flash=Too+many+failed+codes", http.StatusSeeOther)
		return
	}

	ticket := pending2FATicket(r)
	userID, err := auth.VerifySMSOTP(ctx, h.RDB, otpCookie.Value, code)
	if err != nil || userID != pend.UserID {
		nonce, lang := authBase(r)
		d := smsOTPViewData{Error: "Invalid or expired code.", CSPNonce: nonce, Lang: lang}
		if db := h.DB(); db != nil {
			d.Brand = LoadBranding(r.Context(), db)
		}
		h.record2FAFail(ctx, pend.UserID)
		audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
			UserID: &pend.UserID, Action: "2fa.sms.fail", Entity: "auth", EntityID: pend.Email,
		})
		h.Metrics.OTPAttempt("sms", "fail")
		if h.burnAttempt(ctx, ticket) || h.twoFALocked(ctx, pend.UserID) {
			h.consumePending2FA(r)
			http.SetCookie(w, &http.Cookie{Name: "hpg_smsotp", Value: "", Path: "/", MaxAge: -1})
			http.Redirect(w, r, "/auth/login?flash=Too+many+failed+codes", http.StatusSeeOther)
			return
		}
		h.renderSMSOTP(w, http.StatusUnauthorized, d)
		return
	}
	h.clearAttempts(ctx, ticket)
	h.clear2FAFails(ctx, pend.UserID)

	// Consume both cookies.
	h.consumePending2FA(r)
	http.SetCookie(w, &http.Cookie{Name: "hpg_smsotp", Value: "", Path: "/", MaxAge: -1})

	audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
		UserID: &pend.UserID, Action: "2fa.sms.success", Entity: "auth", EntityID: pend.Email,
	})
	h.Metrics.OTPAttempt("sms", "success")
	h.finalizeLogin(ctx, w, r, pend.UserID, pend.Email, pend.Role, pend.ClientID, pendViaOrPassword(pend), "sms")
}

func (h *AuthHandlers) renderSMSOTP(w http.ResponseWriter, status int, d smsOTPViewData) {
	var buf bytes.Buffer
	if err := h.Templates.Render(&buf, "sms_otp_challenge.html.tmpl", d); err != nil {
		h.Logger.Error("render sms otp", "err", err)
		http.Error(w, "render failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

// ---- Email OTP challenge ------------------------------------------------

type emailOTPViewData struct {
	Error    string
	CSPNonce string
	Lang     string
	Brand    Branding
}

// startEmailOTPChallenge generates a code, emails it, stores the hash in
// Redis, sets a cookie, and redirects to /auth/email-otp.
func (h *AuthHandlers) startEmailOTPChallenge(ctx context.Context, w http.ResponseWriter, r *http.Request, db *sql.DB, userID int64, email, role string, clientID int64) error {
	if h.Mailer == nil {
		return fmt.Errorf("mailer not wired")
	}
	var fullName sql.NullString
	_ = db.QueryRowContext(ctx, "SELECT full_name FROM users WHERE id = ?", userID).Scan(&fullName)
	code, err := auth.GenerateEmailOTP()
	if err != nil {
		return err
	}
	pending, err := h.issuePending2FA(ctx, userID, email, role, clientID)
	if err != nil {
		return err
	}
	otpTicket, err := auth.StoreEmailOTP(ctx, h.RDB, userID, code)
	if err != nil {
		return err
	}
	name := ""
	if fullName.Valid {
		name = fullName.String
	}
	if err := sendOTPEmail(ctx, h.Mailer, db, r, email, name, code,
		"Sign-in verification code",
		"Someone (hopefully you) is signing in to your account.",
		int(auth.EmailOTPTTLSeconds/60)); err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name: "hpg_2fa_pending", Value: pending, Path: "/", HttpOnly: true,
		Secure: h.Sessions.CookieSecure(), SameSite: http.SameSiteLaxMode,
		Expires: time.Now().Add(pending2FATTL),
	})
	http.SetCookie(w, &http.Cookie{
		Name: "hpg_emailotp", Value: otpTicket, Path: "/", HttpOnly: true,
		Secure: h.Sessions.CookieSecure(), SameSite: http.SameSiteLaxMode,
		Expires: time.Now().Add(auth.EmailOTPTTLSeconds * time.Second),
	})
	http.Redirect(w, r, "/auth/email-otp", http.StatusSeeOther)
	return nil
}

func (h *AuthHandlers) EmailOTPChallenge(w http.ResponseWriter, r *http.Request) {
	if _, err := r.Cookie("hpg_emailotp"); err != nil {
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}
	nonce, lang := authBase(r)
	d := emailOTPViewData{CSPNonce: nonce, Lang: lang}
	if db := h.DB(); db != nil {
		d.Brand = LoadBranding(r.Context(), db)
	}
	h.renderEmailOTP(w, http.StatusOK, d)
}

func (h *AuthHandlers) EmailOTPVerify(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	code := strings.TrimSpace(r.FormValue("code"))
	otpCookie, err := r.Cookie("hpg_emailotp")
	if err != nil || otpCookie.Value == "" {
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}
	pend, ok := h.readPending2FA(r)
	if !ok {
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	// Per-user 2FA lock: independent of the ticket, blocks the fresh-ticket loop.
	if h.twoFALocked(ctx, pend.UserID) {
		h.consumePending2FA(r)
		http.SetCookie(w, &http.Cookie{Name: "hpg_emailotp", Value: "", Path: "/", MaxAge: -1})
		http.Redirect(w, r, "/auth/login?flash=Too+many+failed+codes", http.StatusSeeOther)
		return
	}
	ticket := pending2FATicket(r)
	userID, err := auth.VerifyEmailOTP(ctx, h.RDB, otpCookie.Value, code)
	if err != nil || userID != pend.UserID {
		nonce, lang := authBase(r)
		d := emailOTPViewData{Error: "Invalid or expired code.", CSPNonce: nonce, Lang: lang}
		if db := h.DB(); db != nil {
			d.Brand = LoadBranding(r.Context(), db)
		}
		h.record2FAFail(ctx, pend.UserID)
		audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
			UserID: &pend.UserID, Action: "2fa.email.fail", Entity: "auth", EntityID: pend.Email,
		})
		h.Metrics.OTPAttempt("email", "fail")
		if h.burnAttempt(ctx, ticket) || h.twoFALocked(ctx, pend.UserID) {
			h.consumePending2FA(r)
			http.SetCookie(w, &http.Cookie{Name: "hpg_emailotp", Value: "", Path: "/", MaxAge: -1})
			http.Redirect(w, r, "/auth/login?flash=Too+many+failed+codes", http.StatusSeeOther)
			return
		}
		h.renderEmailOTP(w, http.StatusUnauthorized, d)
		return
	}
	h.clearAttempts(ctx, ticket)
	h.clear2FAFails(ctx, pend.UserID)
	h.consumePending2FA(r)
	http.SetCookie(w, &http.Cookie{Name: "hpg_emailotp", Value: "", Path: "/", MaxAge: -1})
	audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
		UserID: &pend.UserID, Action: "2fa.email.success", Entity: "auth", EntityID: pend.Email,
	})
	h.Metrics.OTPAttempt("email", "success")
	h.finalizeLogin(ctx, w, r, pend.UserID, pend.Email, pend.Role, pend.ClientID, pendViaOrPassword(pend), "email")
}

func (h *AuthHandlers) renderEmailOTP(w http.ResponseWriter, status int, d emailOTPViewData) {
	var buf bytes.Buffer
	if err := h.Templates.Render(&buf, "email_otp_challenge.html.tmpl", d); err != nil {
		h.Logger.Error("render email otp", "err", err)
		http.Error(w, "render failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

