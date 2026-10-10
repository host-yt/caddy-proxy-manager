package handlers

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/host-yt/caddy-proxy-manager/internal/audit"
	"github.com/host-yt/caddy-proxy-manager/internal/auth"
	"github.com/host-yt/caddy-proxy-manager/internal/domain/portal"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
	"github.com/host-yt/caddy-proxy-manager/internal/installstate"
	"github.com/host-yt/caddy-proxy-manager/internal/oauth2x"
	"github.com/host-yt/caddy-proxy-manager/internal/security"
)

// PortalHandlers serves the built-in forward-auth portal that protects
// customer routes. It runs ON the protected host (reached through Caddy's
// forward_auth / passthrough at /hpg-portal/*), NOT on the panel domain, so
// the portal session cookie is set on the protected host and is naturally
// forwarded by Caddy on the verify subrequest. This sidesteps cross-domain
// cookie problems without any shared parent-domain assumption.
type PortalHandlers struct {
	DB       func() *sql.DB
	RDB      *redis.Client
	Logger   *slog.Logger
	Portal   *portal.Service
	Metrics  metricsLoginEmitter
	Secure   bool                  // cookie Secure flag, mirrors the panel auth cookie
	SameSite http.SameSite         // mirrors the panel auth cookie SameSite
	TTL      time.Duration         // portal session lifetime
	State    *installstate.Manager // for decrypting totp_secret_enc
	OAuth2X  *oauth2x.Service      // social login for the portal; nil disables buttons
	AppURL   string                // panel base URL, used to build OAuth callback URLs
	// Auth supplies the panel's second-factor policy (methods, lockout, OTP
	// delivery). nil fails closed: an MFA-enrolled user cannot finish.
	Auth *AuthHandlers
}

// metricsLoginEmitter is the subset of obs.Metrics the portal touches; kept
// as an interface so wiring stays nil-safe and decoupled.
type metricsLoginEmitter interface {
	LoginEvent(result, via, mfa string)
}

const (
	portalCookie      = "hpg_portal"
	portalCSRFCookie  = "hpg_portal_csrf"
	portalSessPrefix  = auth.PortalSessionKeyPrefix
	portalLoginPath   = "/hpg-portal/login"
	portalFailWindow  = 15 * time.Minute
	portalFailIPLimit = 10
	portalMaxBackLen  = 2048
	portalDefaultTTL  = 12 * time.Hour
)

// portalSession is the Redis-stored record keyed by a random id in the cookie.
type portalSession struct {
	UserID   int64  `json:"u"`
	Email    string `json:"e"`
	Username string `json:"n"` // full_name, used for X-Forwarded-User
	// Epoch is users.auth_epoch at mint time; every verification re-reads it,
	// so disabling or re-scoping an account kills the portal session too.
	Epoch int64 `json:"ep"`
	// Ver rejects pre-epoch sessions rather than trusting a zero epoch.
	Ver       int       `json:"v,omitempty"`
	CreatedAt time.Time `json:"c"`
	ExpiresAt time.Time `json:"x"`
}

// portalSessionVer 1 adds Epoch. Anything older is dropped on sight.
const portalSessionVer = 1

// ParseSameSite maps the config string to http.SameSite, defaulting to Lax
// (same default the session manager uses) so the portal cookie matches.
func ParseSameSite(s string) http.SameSite {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "strict":
		return http.SameSiteStrictMode
	case "none":
		return http.SameSiteNoneMode
	default:
		return http.SameSiteLaxMode
	}
}

func (h *PortalHandlers) ttl() time.Duration {
	if h.TTL > 0 {
		return h.TTL
	}
	return portalDefaultTTL
}

// issuePortalCSRF mints a double-submit CSRF token, sets it as a portal-scoped
// cookie, and returns it for embedding as a hidden form field. The portal runs
// on the protected host (not the panel origin) and has no panel CSRF session,
// so its POST flows use double-submit: an attacker cannot read the victim's
// cookie to place its value in a forged form.
func (h *PortalHandlers) issuePortalCSRF(w http.ResponseWriter) string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	tok := base64.RawURLEncoding.EncodeToString(b)
	http.SetCookie(w, &http.Cookie{
		Name: portalCSRFCookie, Value: tok, Path: "/hpg-portal",
		HttpOnly: true, Secure: h.Secure, SameSite: h.SameSite,
	})
	return tok
}

// verifyPortalCSRF checks the double-submit token: the csrf_token form field
// must match the portal CSRF cookie (constant-time). Fails closed on absence.
func (h *PortalHandlers) verifyPortalCSRF(r *http.Request) bool {
	c, err := r.Cookie(portalCSRFCookie)
	if err != nil || c.Value == "" {
		return false
	}
	got := r.FormValue("csrf_token")
	if got == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(c.Value)) == 1
}

// loadPortalSession returns the session bound to the request cookie, or nil.
// Fail closed: any decode / expiry / Redis problem returns nil (deny).
func (h *PortalHandlers) loadPortalSession(ctx context.Context, r *http.Request) *portalSession {
	c, err := r.Cookie(portalCookie)
	if err != nil || c.Value == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	b, err := h.RDB.Get(ctx, portalSessPrefix+c.Value).Bytes()
	if err != nil {
		return nil
	}
	var s portalSession
	if json.Unmarshal(b, &s) != nil {
		return nil
	}
	if s.Ver < portalSessionVer || time.Now().After(s.ExpiresAt) {
		h.RDB.Del(ctx, portalSessPrefix+c.Value)
		return nil
	}
	// The account behind the cookie is re-checked on every use: a "remember"
	// session otherwise outlives a disabled account by up to 30 days.
	if h.Portal == nil {
		return nil
	}
	ok, err := h.Portal.IdentityStillValid(ctx, s.UserID, s.Epoch)
	if err != nil {
		// Indeterminate (DB blip): deny, but do not destroy a session that may
		// still be valid once the database recovers.
		return nil
	}
	if !ok {
		h.RDB.Del(ctx, portalSessPrefix+c.Value)
		return nil
	}
	return &s
}

// Verify is the endpoint Caddy's forward_auth calls. It returns 2xx when the
// portal session is valid AND allowed for the requested host, otherwise 302 to
// the login page (browsers follow the redirect). Fail closed on every error.
func (h *PortalHandlers) Verify(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	host := portalRequestHost(r)
	db := h.DB()
	if db == nil || h.Portal == nil {
		h.denyVerify(w, r, host, 0, 0, "no_backend")
		return
	}
	// Resource identity, not host identity: several routes can share a host
	// with different grants, and one of them may be public.
	path, ok := portalRequestPath(r)
	if !ok {
		// No trusted URI => the call did not come through the emitted gate.
		h.denyVerify(w, r, host, 0, 0, "no_route_identity")
		return
	}
	routeID, protect, err := h.Portal.RouteForRequest(ctx, host, path)
	if err != nil || routeID == 0 {
		// Unknown, ambiguous, or unreadable: deny (fail closed).
		h.denyVerify(w, r, host, 0, 0, "unknown_route")
		return
	}
	if !protect {
		// Portal disabled for this route: nothing to enforce, allow through.
		w.WriteHeader(http.StatusOK)
		return
	}
	sess := h.loadPortalSession(ctx, r)
	if sess == nil {
		h.denyVerify(w, r, host, routeID, 0, "no_session")
		return
	}
	allowed, aerr := h.Portal.IsAllowed(ctx, routeID, sess.UserID)
	if aerr != nil {
		// Query error => deny.
		h.denyVerify(w, r, host, routeID, sess.UserID, "lookup_error")
		return
	}
	if !allowed {
		audit.Write(ctx, db, h.Logger, r, audit.Entry{
			UserID: &sess.UserID, ActorType: audit.ActorUser, Action: "portal.access.deny",
			Entity: "route", EntityID: itoa64(routeID),
			Meta: map[string]any{"host": host, "email": sess.Email},
		})
		h.denyVerify(w, r, host, routeID, sess.UserID, "not_member")
		return
	}
	// Allowed: surface identity headers so Caddy can forward them upstream.
	user := sess.Username
	if user == "" {
		user = sess.Email
	}
	w.Header().Set("X-Forwarded-User", user)
	w.Header().Set("X-Forwarded-Email", sess.Email)
	w.WriteHeader(http.StatusOK)
}

// denyVerify redirects browsers to the login page with a validated same-host
// "back" param. Caddy passes the 302 through to the client. (Deny audit for
// not_member is written by the caller; this only handles the redirect.)
func (h *PortalHandlers) denyVerify(w http.ResponseWriter, r *http.Request, host string, routeID, userID int64, reason string) {
	back := portalOriginalURL(r, host)
	loc := portalLoginURL(host, back, h.Secure)
	http.Redirect(w, r, loc, http.StatusFound)
}

// portalOAuthProvider is the minimal provider info passed to the login template.
type portalOAuthProvider struct {
	Provider string // slug: "github", "google"
	Label    string // display name
}

// portalViewData is the login template payload.
type portalViewData struct {
	Error          string
	Back           string
	Host           string
	CSPNonce       string
	CSRFToken      string
	OAuthProviders []portalOAuthProvider
}

// LoginPage renders the portal login form (served on the protected host).
func (h *PortalHandlers) LoginPage(w http.ResponseWriter, r *http.Request) {
	host := portalRequestHost(r)
	back := portalSafeBack(r.URL.Query().Get("back"), host)
	d := portalViewData{Back: back, Host: host}
	d.OAuthProviders = h.loadPortalOAuthProviders(r.Context())
	h.renderLogin(w, r, http.StatusOK, d)
}

// LoginSubmit validates credentials against the users table (reusing argon2),
// creates a portal session, and redirects back to the originally-requested URL
// (validated same-host) or "/".
func (h *PortalHandlers) LoginSubmit(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	host := portalRequestHost(r)
	if !h.verifyPortalCSRF(r) {
		back := portalSafeBack(r.FormValue("back"), host)
		h.renderLogin(w, r, http.StatusForbidden, portalViewData{Error: "Session expired. Please try again.", Back: back, Host: host})
		return
	}
	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	password := r.FormValue("password")
	back := portalSafeBack(r.FormValue("back"), host)

	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	db := h.DB()
	if db == nil {
		h.renderLogin(w, r, http.StatusServiceUnavailable, portalViewData{Error: "Service unavailable.", Back: back, Host: host})
		return
	}
	if email == "" || password == "" {
		h.renderLogin(w, r, http.StatusBadRequest, portalViewData{Error: "Email and password are required.", Back: back, Host: host})
		return
	}

	ip := security.ClientIP(r)
	if h.portalLocked(ctx, email, ip) {
		h.renderLogin(w, r, http.StatusTooManyRequests, portalViewData{Error: "Too many failed attempts. Try again later.", Back: back, Host: host})
		return
	}

	routeID, protect, _ := h.Portal.RouteForRequest(ctx, host, portalPathOf(back))

	var (
		userID      int64
		hash        string
		isActive    bool
		fullName    sql.NullString
		totpEnabled bool
		smsEnabled  bool
		mailEnabled bool
	)
	err := db.QueryRowContext(ctx,
		`SELECT id, password_hash, is_active, full_name, totp_enabled, sms_otp_enabled, email_otp_enabled
		   FROM users WHERE email = ? LIMIT 1`, email).
		Scan(&userID, &hash, &isActive, &fullName, &totpEnabled, &smsEnabled, &mailEnabled)
	if errors.Is(err, sql.ErrNoRows) {
		// Equalize timing against account enumeration (same trick as panel login).
		_ = auth.VerifyPassword(decoyPasswordHash(), password)
		h.recordPortalFail(ctx, email, ip)
		h.auditPortalLogin(ctx, r, nil, "portal.login.fail", email, host, "unknown_email")
		h.renderLogin(w, r, http.StatusUnauthorized, portalViewData{Error: "Invalid email or password.", Back: back, Host: host})
		return
	}
	if err != nil {
		h.renderLogin(w, r, http.StatusInternalServerError, portalViewData{Error: "Server error.", Back: back, Host: host})
		return
	}
	if !isActive || auth.VerifyPassword(hash, password) != nil {
		h.recordPortalFail(ctx, email, ip)
		h.auditPortalLogin(ctx, r, &userID, "portal.login.fail", email, host, "bad_credentials")
		h.renderLogin(w, r, http.StatusUnauthorized, portalViewData{Error: "Invalid email or password.", Back: back, Host: host})
		return
	}

	// Authorization check: the user must be granted to this protected route.
	// We refuse to mint a session for someone with no access so a stolen
	// portal cookie can never be replayed on a route they aren't entitled to.
	if protect && routeID > 0 {
		allowed, aerr := h.Portal.IsAllowed(ctx, routeID, userID)
		if aerr != nil || !allowed {
			h.auditPortalLogin(ctx, r, &userID, "portal.access.deny", email, host, "not_member")
			h.renderLogin(w, r, http.StatusForbidden, portalViewData{Error: "Your account is not authorized for this application.", Back: back, Host: host})
			return
		}
	}

	rememberMe := r.FormValue("remember_me") == "1"

	// Any enrolled factor gates the session, same rule as the panel login.
	if totpEnabled || smsEnabled || mailEnabled {
		if err := h.startPortal2FA(ctx, w, r, userID, email, fullName.String, back, host, rememberMe); err != nil {
			h.renderLogin(w, r, http.StatusInternalServerError, portalViewData{Error: "Could not start 2FA challenge.", Back: back, Host: host})
			return
		}
		// clearPortalFails because password was correct; 2FA failures have own tracking.
		h.clearPortalFails(ctx, email, ip)
		http.Redirect(w, r, "/hpg-portal/2fa", http.StatusSeeOther)
		return
	}

	h.clearPortalFails(ctx, email, ip)
	if err := h.createPortalSession(ctx, w, userID, email, fullName.String, rememberMe); err != nil {
		h.renderLogin(w, r, http.StatusInternalServerError, portalViewData{Error: "Could not create session.", Back: back, Host: host})
		return
	}
	h.auditPortalLogin(ctx, r, &userID, "portal.login.success", email, host, "")
	if h.Metrics != nil {
		h.Metrics.LoginEvent("success", "portal", "none")
	}
	http.Redirect(w, r, back, http.StatusSeeOther)
}

// ---- TOTP 2FA challenge step --------------------------------------------

const (
	portal2FACookie   = "hpg_portal_2fa"
	portal2FARedisPfx = "hpg:portal:2fa:"
	portal2FATTR      = 5 * time.Minute
)

const portal2FAMaxAttempts = 3

type portal2FAState struct {
	UserID     int64  `json:"u"`
	Email      string `json:"e"`
	Username   string `json:"n"`
	Back       string `json:"b"`
	Host       string `json:"h"`
	RememberMe bool   `json:"r"`
	Attempts   int    `json:"a,omitempty"`
	ExpiresAt  int64  `json:"x,omitempty"` // unix seconds; do not extend TTL on bad code
	// OTPMethod/OTPTicket bind a sent sms|email code to this challenge.
	OTPMethod string `json:"om,omitempty"`
	OTPTicket string `json:"ot,omitempty"`
}

func (h *PortalHandlers) startPortal2FA(ctx context.Context, w http.ResponseWriter, r *http.Request,
	userID int64, email, username, back, host string, rememberMe bool) error {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return err
	}
	nonce := base64.RawURLEncoding.EncodeToString(raw)
	st := portal2FAState{
		UserID: userID, Email: email, Username: username, Back: back, Host: host, RememberMe: rememberMe,
		ExpiresAt: time.Now().Add(portal2FATTR).Unix(),
	}
	b, _ := json.Marshal(st)
	if err := h.RDB.Set(ctx, portal2FARedisPfx+nonce, b, portal2FATTR).Err(); err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name: portal2FACookie, Value: nonce, Path: "/hpg-portal",
		HttpOnly: true, Secure: h.Secure, SameSite: h.SameSite,
	})
	return nil
}

type portal2FAViewData struct {
	CSPNonce    string
	Host        string
	Error       string
	CSRFToken   string
	Method      string // factor this form verifies
	HasTOTP     bool
	HasSMS      bool
	HasEmail    bool
	HasRecovery bool
	Sent        bool // an sms|email code is out for Method
}

// loadPortal2FA reads the pending challenge without consuming it.
func (h *PortalHandlers) loadPortal2FA(ctx context.Context, r *http.Request) (string, *portal2FAState) {
	c, err := r.Cookie(portal2FACookie)
	if err != nil || c.Value == "" || h.RDB == nil {
		return "", nil
	}
	raw, err := h.RDB.Get(ctx, portal2FARedisPfx+c.Value).Bytes()
	if err != nil {
		return "", nil
	}
	var st portal2FAState
	if json.Unmarshal(raw, &st) != nil {
		return "", nil
	}
	return c.Value, &st
}

// portal2FAView fills the enrolled-factor picker for userID, selecting want
// when it is enrolled and otherwise the panel's default factor.
func (h *PortalHandlers) portal2FAView(ctx context.Context, userID int64, want string) portal2FAViewData {
	d := portal2FAViewData{}
	if h.Auth == nil {
		return d
	}
	var def string
	d.HasTOTP, d.HasSMS, d.HasEmail, d.HasRecovery, def = h.Auth.twoFAOptions(ctx, userID)
	d.Method = def
	switch want {
	case "totp", "sms", "email":
		if twoFAMethodEnrolled(want, d.HasTOTP, d.HasSMS, d.HasEmail) {
			d.Method = want
		}
	case "recovery":
		if d.HasRecovery {
			d.Method = want
		}
	}
	return d
}

func (h *PortalHandlers) Portal2FAPage(w http.ResponseWriter, r *http.Request) {
	_, st := h.loadPortal2FA(r.Context(), r)
	if st == nil {
		http.Redirect(w, r, "/hpg-portal/login", http.StatusSeeOther)
		return
	}
	d := h.portal2FAView(r.Context(), st.UserID, r.URL.Query().Get("m"))
	d.Host = portalRequestHost(r)
	d.Sent = st.OTPTicket != "" && st.OTPMethod == d.Method
	h.render2FA(w, r, http.StatusOK, d)
}

// Portal2FASend delivers an sms|email code for the pending challenge and binds
// its ticket to the challenge record, so only this challenge can redeem it.
func (h *PortalHandlers) Portal2FASend(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	nonce, st := h.loadPortal2FA(ctx, r)
	if st == nil {
		http.Redirect(w, r, "/hpg-portal/login", http.StatusSeeOther)
		return
	}
	method := r.FormValue("method")
	d := h.portal2FAView(ctx, st.UserID, method)
	d.Host = portalRequestHost(r)
	if !h.verifyPortalCSRF(r) {
		d.Error = "Session expired. Please try again."
		h.render2FA(w, r, http.StatusForbidden, d)
		return
	}
	if h.Auth == nil || d.Method != method || (method != "sms" && method != "email") {
		d.Error = "That method is not enabled for this account."
		h.render2FA(w, r, http.StatusBadRequest, d)
		return
	}
	ticket, err := h.Auth.sendLoginOTP(ctx, r, st.UserID, st.Email, method)
	if err != nil {
		d.Error = "Could not send a code. Try again later."
		var se *otpSendError
		if errors.As(err, &se) && se.status == http.StatusTooManyRequests {
			d.Error = "Please wait before requesting another code."
		}
		h.render2FA(w, r, http.StatusOK, d)
		return
	}
	st.OTPMethod, st.OTPTicket = method, ticket
	b, _ := json.Marshal(st)
	if err := h.RDB.Set(ctx, portal2FARedisPfx+nonce, b, redis.KeepTTL).Err(); err != nil {
		d.Error = "Could not send a code. Try again later."
		h.render2FA(w, r, http.StatusInternalServerError, d)
		return
	}
	http.Redirect(w, r, "/hpg-portal/2fa?m="+method, http.StatusSeeOther)
}

// verifyPortal2FA checks code against an enrolled factor with the panel's
// rules and returns the factor that matched ("" on failure).
func (h *PortalHandlers) verifyPortal2FA(ctx context.Context, db *sql.DB, st *portal2FAState, method, code string) string {
	a := h.Auth
	if a == nil {
		return ""
	}
	hasTOTP, hasSMS, hasEmail, _, def := a.twoFAOptions(ctx, st.UserID)
	if method == "" {
		method = def
	}
	if !twoFAMethodEnrolled(method, hasTOTP, hasSMS, hasEmail) {
		return ""
	}
	switch method {
	case "totp":
		secret, ok, needsUpgrade := readTOTPSecret(ctx, db, h.State, st.UserID)
		if ok && auth.ValidateTOTP(secret, code) == nil && a.markTOTPConsumed(ctx, st.UserID, code) {
			if needsUpgrade {
				upgradeTOTPSecret(ctx, db, h.State, st.UserID, secret)
			}
			return "totp"
		}
		if a.tryRecoveryCode(ctx, db, st.UserID, code) {
			return "recovery"
		}
	case "recovery":
		if a.tryRecoveryCode(ctx, db, st.UserID, code) {
			return "recovery"
		}
	case "sms":
		if st.OTPMethod == "sms" && st.OTPTicket != "" {
			uid, err := auth.VerifySMSOTP(ctx, h.RDB, st.OTPTicket, strings.ReplaceAll(code, "-", ""))
			if err == nil && uid == st.UserID {
				return "sms"
			}
		}
	case "email":
		if st.OTPMethod == "email" && st.OTPTicket != "" {
			uid, err := auth.VerifyEmailOTP(ctx, h.RDB, st.OTPTicket, code)
			if err == nil && uid == st.UserID {
				return "email"
			}
		}
	}
	return ""
}

func (h *PortalHandlers) Portal2FASubmit(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	host := portalRequestHost(r)
	if !h.verifyPortalCSRF(r) {
		h.render2FA(w, r, http.StatusForbidden, portal2FAViewData{Host: host, Error: "Session expired. Please try again."})
		return
	}

	c, err := r.Cookie(portal2FACookie)
	if err != nil || c.Value == "" {
		http.Redirect(w, r, "/hpg-portal/login", http.StatusSeeOther)
		return
	}
	nonce := c.Value

	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()

	raw, err := h.RDB.GetDel(ctx, portal2FARedisPfx+nonce).Bytes()
	if err != nil {
		h.clearPortal2FACookie(w)
		http.Redirect(w, r, "/hpg-portal/login", http.StatusSeeOther)
		return
	}
	var st portal2FAState
	if err := json.Unmarshal(raw, &st); err != nil {
		h.clearPortal2FACookie(w)
		http.Redirect(w, r, "/hpg-portal/login", http.StatusSeeOther)
		return
	}

	code := strings.TrimSpace(r.FormValue("code"))
	method := strings.TrimSpace(r.FormValue("method"))
	db := h.DB()
	if db == nil {
		h.render2FA(w, r, http.StatusServiceUnavailable, portal2FAViewData{Host: host, Error: "Service unavailable."})
		return
	}
	// Per-user lock shared with the panel: a fresh password login must not
	// reset the guessing budget.
	if h.Auth == nil || h.Auth.twoFALocked(ctx, st.UserID) {
		h.clearPortal2FACookie(w)
		http.Redirect(w, r, "/hpg-portal/login", http.StatusSeeOther)
		return
	}

	mfa := h.verifyPortal2FA(ctx, db, &st, method, code)
	if mfa == "" {
		st.Attempts++
		h.Auth.record2FAFail(ctx, st.UserID)
		h.auditPortalLogin(ctx, r, &st.UserID, "portal.2fa.fail", st.Email, st.Host, "bad_code")
		if h.Metrics != nil {
			h.Metrics.LoginEvent("fail", "portal", method)
		}
		if st.Attempts >= portal2FAMaxAttempts {
			// Consumed by GetDel above; do not re-mint. Force re-login.
			h.clearPortal2FACookie(w)
			http.Redirect(w, r, "/hpg-portal/login", http.StatusSeeOther)
			return
		}
		remaining := time.Until(time.Unix(st.ExpiresAt, 0))
		if remaining <= 0 {
			h.clearPortal2FACookie(w)
			http.Redirect(w, r, "/hpg-portal/login", http.StatusSeeOther)
			return
		}
		// Re-mint with original expiry (not a fresh portal2FATTR window).
		b2, _ := json.Marshal(st)
		_ = h.RDB.Set(ctx, portal2FARedisPfx+nonce, b2, remaining).Err()
		http.SetCookie(w, &http.Cookie{
			Name: portal2FACookie, Value: nonce, Path: "/hpg-portal",
			HttpOnly: true, Secure: h.Secure, SameSite: h.SameSite,
		})
		d := h.portal2FAView(ctx, st.UserID, method)
		d.Host, d.Error = host, "Invalid code. Try again."
		d.Sent = st.OTPTicket != "" && st.OTPMethod == d.Method
		h.render2FA(w, r, http.StatusUnauthorized, d)
		return
	}

	h.Auth.clear2FAFails(ctx, st.UserID)
	h.clearPortal2FACookie(w)
	if err := h.createPortalSession(ctx, w, st.UserID, st.Email, st.Username, st.RememberMe); err != nil {
		h.render2FA(w, r, http.StatusInternalServerError, portal2FAViewData{Host: host, Error: "Could not create session."})
		return
	}
	h.auditPortalLogin(ctx, r, &st.UserID, "portal.login.success", st.Email, st.Host, "")
	if h.Metrics != nil {
		h.Metrics.LoginEvent("success", "portal", mfa)
	}
	http.Redirect(w, r, st.Back, http.StatusSeeOther)
}

func (h *PortalHandlers) clearPortal2FACookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: portal2FACookie, Value: "", Path: "/hpg-portal",
		HttpOnly: true, Secure: h.Secure, SameSite: h.SameSite, MaxAge: -1,
	})
}

func (h *PortalHandlers) render2FA(w http.ResponseWriter, r *http.Request, status int, d portal2FAViewData) {
	d.CSPNonce = middleware.CSPNonce(r.Context())
	d.CSRFToken = h.issuePortalCSRF(w)
	var buf bytes.Buffer
	if err := portal2FATmpl.Execute(&buf, d); err != nil {
		http.Error(w, "render failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

var portal2FATmpl = template.Must(template.New("portal_2fa").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Two-factor authentication</title>
<style nonce="{{.CSPNonce}}">
 body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:#f1f5f9;margin:0;display:flex;min-height:100vh;align-items:center;justify-content:center}
 .card{background:#fff;border-radius:16px;box-shadow:0 10px 30px rgba(0,0,0,.08);padding:28px;width:340px}
 h1{font-size:18px;margin:0 0 4px}
 p.sub{color:#64748b;font-size:13px;margin:0 0 18px}
 label{display:block;font-size:12px;color:#334155;margin:12px 0 4px}
 input[type=text]{width:100%;box-sizing:border-box;padding:10px 12px;border:1px solid #cbd5e1;border-radius:10px;font-size:18px;letter-spacing:.15em;text-align:center}
 button{margin-top:16px;width:100%;padding:10px;border:0;border-radius:10px;background:#4f46e5;color:#fff;font-size:14px;cursor:pointer}
 .err{background:#fef2f2;color:#b91c1c;border:1px solid #fecaca;border-radius:10px;padding:8px 10px;font-size:13px;margin-bottom:8px}
 a{display:block;margin-top:14px;font-size:13px;color:#64748b;text-align:center;text-decoration:none}
 button.alt{background:#fff;color:#4f46e5;border:1px solid #c7d2fe}
 .alts a{margin-top:8px}
</style></head><body>
<div class="card">
 <h1>Two-factor authentication</h1>
 <p class="sub">{{.Host}}</p>
 {{if .Error}}<div class="err">{{.Error}}</div>{{end}}
 {{if or (eq .Method "sms") (eq .Method "email")}}
 <form method="POST" action="/hpg-portal/2fa/send">
  <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
  <input type="hidden" name="method" value="{{.Method}}">
  <button type="submit" class="alt">{{if .Sent}}Resend code{{else}}Send code by {{if eq .Method "sms"}}SMS{{else}}email{{end}}{{end}}</button>
 </form>
 {{end}}
 {{if .Method}}
 <form method="POST" action="/hpg-portal/2fa">
  <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
  <input type="hidden" name="method" value="{{.Method}}">
  <label for="code">{{if eq .Method "totp"}}Authenticator code{{else if eq .Method "recovery"}}Recovery code{{else}}Code we sent you{{end}}</label>
  <input id="code" name="code" type="text" autocomplete="one-time-code" autofocus required maxlength="32">
  <button type="submit">Verify</button>
 </form>
 {{end}}
 <div class="alts">
  {{if and .HasTOTP (ne .Method "totp")}}<a href="/hpg-portal/2fa?m=totp">Use authenticator app</a>{{end}}
  {{if and .HasSMS (ne .Method "sms")}}<a href="/hpg-portal/2fa?m=sms">Use SMS</a>{{end}}
  {{if and .HasEmail (ne .Method "email")}}<a href="/hpg-portal/2fa?m=email">Use email</a>{{end}}
  {{if and .HasRecovery (ne .Method "recovery")}}<a href="/hpg-portal/2fa?m=recovery">Use a recovery code</a>{{end}}
 </div>
 <a href="/hpg-portal/login">Back to sign in</a>
</div>
</body></html>`))

// portalLogoutViewData is the logout confirmation page payload.
type portalLogoutViewData struct {
	Host      string
	CSPNonce  string
	CSRFToken string
}

// LogoutConfirm renders a GET confirmation page. HPG-SEC-007: logout is a
// state change, so GET must never perform it - this page only asks; the
// form it renders POSTs to Logout.
func (h *PortalHandlers) LogoutConfirm(w http.ResponseWriter, r *http.Request) {
	d := portalLogoutViewData{Host: portalRequestHost(r), CSPNonce: middleware.CSPNonce(r.Context())}
	d.CSRFToken = h.issuePortalCSRF(w)
	var buf bytes.Buffer
	if err := portalLogoutTmpl.Execute(&buf, d); err != nil {
		http.Error(w, "render failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(buf.Bytes())
}

// Logout destroys the portal session. POST-only (HPG-SEC-007): a GET here
// used to log the caller out too, so a third-party page could force a logout
// with a plain image tag or link (the public portal has no panel session and
// bypasses the panel's CSRF middleware). The double-submit token below is the
// same mechanism LoginSubmit/Portal2FASubmit already use.
func (h *PortalHandlers) Logout(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	if !h.verifyPortalCSRF(r) {
		h.LogoutConfirm(w, r)
		return
	}
	if c, err := r.Cookie(portalCookie); err == nil && c.Value != "" {
		_ = h.RDB.Del(r.Context(), portalSessPrefix+c.Value).Err()
	}
	http.SetCookie(w, &http.Cookie{
		Name: portalCookie, Value: "", Path: "/", HttpOnly: true,
		Secure: h.Secure, SameSite: h.SameSite, MaxAge: -1,
	})
	host := portalRequestHost(r)
	http.Redirect(w, r, portalLoginURL(host, "/", h.Secure), http.StatusSeeOther)
}

// portalLogoutTmpl mirrors portalLoginTmpl's minimal self-contained style.
var portalLogoutTmpl = template.Must(template.New("portal_logout").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign out</title>
<style nonce="{{.CSPNonce}}">
 body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:#f1f5f9;margin:0;display:flex;min-height:100vh;align-items:center;justify-content:center}
 .card{background:#fff;border-radius:16px;box-shadow:0 10px 30px rgba(0,0,0,.08);padding:28px;width:340px;text-align:center}
 h1{font-size:18px;margin:0 0 4px}
 p.sub{color:#64748b;font-size:13px;margin:0 0 18px}
 button{width:100%;padding:10px;border:0;border-radius:10px;background:#4f46e5;color:#fff;font-size:14px;cursor:pointer}
</style></head><body>
<div class="card">
 <h1>Sign out</h1>
 <p class="sub">{{.Host}}</p>
 <form method="POST" action="/hpg-portal/logout">
  <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
  <button type="submit">Sign out</button>
 </form>
</div>
</body></html>`))

func (h *PortalHandlers) createPortalSession(ctx context.Context, w http.ResponseWriter, userID int64, email, username string, rememberMe bool) error {
	idb := make([]byte, 32)
	if _, err := rand.Read(idb); err != nil {
		return err
	}
	id := base64.RawURLEncoding.EncodeToString(idb)
	// Stamp the epoch the session is minted against; an unreadable epoch must
	// not mint a session that can never be revoked.
	epoch, err := auth.UserEpoch(ctx, h.DB(), userID)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	ttl := h.ttl()
	if rememberMe {
		ttl = 30 * 24 * time.Hour
	}
	s := portalSession{
		UserID: userID, Email: email, Username: username,
		Epoch: epoch, Ver: portalSessionVer,
		CreatedAt: now, ExpiresAt: now.Add(ttl),
	}
	b, _ := json.Marshal(s)
	if err := h.RDB.Set(ctx, portalSessPrefix+id, b, ttl).Err(); err != nil {
		return err
	}
	cookie := &http.Cookie{
		Name: portalCookie, Value: id, Path: "/", HttpOnly: true,
		Secure: h.Secure, SameSite: h.SameSite,
	}
	if rememberMe {
		// Persist cookie for 30 days; session-only (no MaxAge) otherwise.
		cookie.MaxAge = int(ttl.Seconds())
		cookie.Expires = s.ExpiresAt
	}
	http.SetCookie(w, cookie)
	return nil
}

func (h *PortalHandlers) auditPortalLogin(ctx context.Context, r *http.Request, userID *int64, action, email, host, reason string) {
	db := h.DB()
	if db == nil {
		return
	}
	meta := map[string]any{"host": host, "email": maskEmail(email)}
	if reason != "" {
		meta["reason"] = reason
	}
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: userID, ActorType: audit.ActorUser, Action: action,
		Entity: "auth", EntityID: maskEmail(email), Meta: meta,
	})
}

// ---- brute-force lockout (Redis, mirrors panel login) -------------------

func (h *PortalHandlers) portalFailKey(email, ip string) string {
	return "hpg:portal:fail:" + ip + ":" + email
}

func (h *PortalHandlers) portalLocked(ctx context.Context, email, ip string) bool {
	if h.RDB == nil || ip == "" {
		return false
	}
	n, err := h.RDB.Get(ctx, h.portalFailKey(email, ip)).Int()
	return err == nil && n >= portalFailIPLimit
}

func (h *PortalHandlers) recordPortalFail(ctx context.Context, email, ip string) {
	if h.RDB == nil || ip == "" {
		return
	}
	if n, err := h.RDB.Incr(ctx, h.portalFailKey(email, ip)).Result(); err == nil && n == 1 {
		_ = h.RDB.Expire(ctx, h.portalFailKey(email, ip), portalFailWindow).Err()
	}
}

func (h *PortalHandlers) clearPortalFails(ctx context.Context, email, ip string) {
	if h.RDB == nil || ip == "" {
		return
	}
	_ = h.RDB.Del(ctx, h.portalFailKey(email, ip)).Err()
}

// ---- helpers ------------------------------------------------------------

// portalRequestHost returns the protected host. Caddy preserves the original
// Host on the verify/passthrough subrequest; X-Forwarded-Host is the explicit
// signal on the verify call. Strip any port.
func portalRequestHost(r *http.Request) string {
	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = r.Host
	}
	if i := strings.IndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	return strings.ToLower(strings.TrimSpace(host))
}

// portalRequestPath returns the path of the originally-requested URL, and
// whether it is usable as a resource identity. The gate config the panel emits
// SETs X-Forwarded-Uri (overriding whatever the client sent), so this - never a
// route id the browser hands us - is what the policy lookup is bound to.
// Fails closed: absent or non-absolute means "no identity".
func portalRequestPath(r *http.Request) (string, bool) {
	raw := r.Header.Get("X-Forwarded-Uri")
	if !strings.HasPrefix(raw, "/") {
		return "", false
	}
	u, err := url.Parse(raw)
	// A protocol-relative "//host/path" parses with a Host: that is a different
	// origin's path, never this route's.
	if err != nil || u.Host != "" || u.Scheme != "" || !strings.HasPrefix(u.Path, "/") {
		return "", false
	}
	return u.Path, true
}

// portalPathOf strips the query from an already-validated same-host "back"
// target, giving the path the login-time authorization pre-check applies to.
func portalPathOf(back string) string {
	path, _, _ := strings.Cut(back, "?")
	return path
}

// portalOriginalURL reconstructs the user's originally-requested URL from the
// forward_auth X-Forwarded-* headers so login can redirect them back.
func portalOriginalURL(r *http.Request, host string) string {
	uri := r.Header.Get("X-Forwarded-Uri")
	if uri == "" || !strings.HasPrefix(uri, "/") {
		uri = "/"
	}
	return uri
}

// portalLoginURL builds an absolute login URL on the protected host. Absolute
// (with scheme+host) because the 302 is followed by the browser on the
// protected origin, not the panel.
func portalLoginURL(host, back string, secure bool) string {
	scheme := "https"
	if !secure {
		scheme = "http"
	}
	u := scheme + "://" + host + portalLoginPath
	if back != "" {
		u += "?back=" + url.QueryEscape(back)
	}
	return u
}

// portalSafeBack validates the post-login redirect target. Open-redirect
// protection: only a same-host absolute path is accepted; anything with a
// scheme, host, backslash, or protocol-relative form is rejected to "/". This
// is the load-bearing security check for the login handshake.
func portalSafeBack(raw, host string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > portalMaxBackLen {
		return "/"
	}
	// Reject protocol-relative ("//evil") and backslash tricks outright.
	if strings.HasPrefix(raw, "//") || strings.Contains(raw, "\\") {
		return "/"
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "/"
	}
	// Must be a path-only reference: no scheme, no host (same-origin only).
	if u.IsAbs() || u.Host != "" || u.Scheme != "" {
		return "/"
	}
	// u.Path is decoded: "/%2F/evil.com" becomes "//evil.com", which browsers
	// follow cross-origin, so re-check the decoded form.
	if !strings.HasPrefix(u.Path, "/") || strings.HasPrefix(u.Path, "//") || strings.Contains(u.Path, "\\") {
		return "/"
	}
	out := u.Path
	if u.RawQuery != "" {
		out += "?" + u.RawQuery
	}
	return out
}

// loadPortalOAuthProviders returns enabled OAuth providers for the login page.
func (h *PortalHandlers) loadPortalOAuthProviders(ctx context.Context) []portalOAuthProvider {
	if h.OAuth2X == nil {
		return nil
	}
	slugs := []string{oauth2x.ProviderGitHub, oauth2x.ProviderGoogle}
	var out []portalOAuthProvider
	for _, s := range slugs {
		if h.OAuth2X.Enabled(ctx, s) {
			out = append(out, portalOAuthProvider{Provider: s, Label: FormatProviderLabel(s)})
		}
	}
	return out
}

// renderLogin writes the portal login page. Inline-template (no panel layout)
// since it is served on the customer host; CSP nonce is applied to the form.
func (h *PortalHandlers) renderLogin(w http.ResponseWriter, r *http.Request, status int, d portalViewData) {
	d.CSPNonce = middleware.CSPNonce(r.Context())
	d.CSRFToken = h.issuePortalCSRF(w)
	// Populate OAuth buttons on every render (including error re-renders).
	if d.OAuthProviders == nil {
		d.OAuthProviders = h.loadPortalOAuthProviders(r.Context())
	}
	var buf bytes.Buffer
	if err := portalLoginTmpl.Execute(&buf, d); err != nil {
		http.Error(w, "render failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

// portalLoginTmpl is a minimal self-contained login page. No external assets so
// it renders even when the protected backend is down / unreachable.
var portalLoginTmpl = template.Must(template.New("portal_login").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in</title>
<style nonce="{{.CSPNonce}}">
 body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:#f1f5f9;margin:0;display:flex;min-height:100vh;align-items:center;justify-content:center}
 .card{background:#fff;border-radius:16px;box-shadow:0 10px 30px rgba(0,0,0,.08);padding:28px;width:340px}
 h1{font-size:18px;margin:0 0 4px}
 p.sub{color:#64748b;font-size:13px;margin:0 0 18px}
 label{display:block;font-size:12px;color:#334155;margin:12px 0 4px}
 input[type=email],input[type=password]{width:100%;box-sizing:border-box;padding:10px 12px;border:1px solid #cbd5e1;border-radius:10px;font-size:14px}
 .remember{display:flex;align-items:center;gap:8px;margin-top:14px}
 .remember input{width:auto}
 .remember span{font-size:13px;color:#334155}
 button{margin-top:16px;width:100%;padding:10px;border:0;border-radius:10px;background:#4f46e5;color:#fff;font-size:14px;cursor:pointer;cursor:pointer}
 .err{background:#fef2f2;color:#b91c1c;border:1px solid #fecaca;border-radius:10px;padding:8px 10px;font-size:13px;margin-bottom:8px}
 .divider{display:flex;align-items:center;gap:8px;margin:18px 0 2px;color:#94a3b8;font-size:12px}
 .divider::before,.divider::after{content:"";flex:1;border-top:1px solid #e2e8f0}
 .oauth-btn{display:block;margin-top:10px;width:100%;box-sizing:border-box;padding:10px;border:1px solid #cbd5e1;border-radius:10px;background:#fff;font-size:14px;color:#334155;text-align:center;text-decoration:none;cursor:pointer;transition:background .15s}
 .oauth-btn:hover{background:#f8fafc}
</style></head><body>
<div class="card">
 <h1>Sign in</h1>
 <p class="sub">{{.Host}}</p>
 {{if .Error}}<div class="err">{{.Error}}</div>{{end}}
 <form method="POST" action="/hpg-portal/login">
  <input type="hidden" name="back" value="{{.Back}}">
  <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
  <label for="email">Email</label>
  <input id="email" name="email" type="email" autocomplete="username" autofocus required>
  <label for="password">Password</label>
  <input id="password" name="password" type="password" autocomplete="current-password" required>
  <div class="remember">
   <input type="checkbox" id="remember_me" name="remember_me" value="1">
   <span>Remember me for 30 days</span>
  </div>
  <button type="submit">Sign in</button>
 </form>
 {{if .OAuthProviders}}
 <div class="divider">or continue with</div>
 {{range .OAuthProviders}}
 <a class="oauth-btn" href="/hpg-portal/oauth/{{.Provider}}?back={{$.Back}}">{{.Label}}</a>
 {{end}}
 {{end}}
</div>
</body></html>`))
