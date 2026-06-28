package handlers

import (
	"bytes"
	"context"
	"crypto/rand"
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
	Secure   bool          // cookie Secure flag, mirrors the panel auth cookie
	SameSite http.SameSite // mirrors the panel auth cookie SameSite
	TTL      time.Duration      // portal session lifetime
	State    *installstate.Manager // for decrypting totp_secret_enc
	OAuth2X  *oauth2x.Service      // social login for the portal; nil disables buttons
	AppURL   string                // panel base URL, used to build OAuth callback URLs
}

// metricsLoginEmitter is the subset of obs.Metrics the portal touches; kept
// as an interface so wiring stays nil-safe and decoupled.
type metricsLoginEmitter interface {
	LoginEvent(result, via, mfa string)
}

const (
	portalCookie      = "hpg_portal"
	portalSessPrefix  = "hpg:portal:sess:"
	portalLoginPath   = "/hpg-portal/login"
	portalFailWindow  = 15 * time.Minute
	portalFailIPLimit = 10
	portalMaxBackLen  = 2048
	portalDefaultTTL  = 12 * time.Hour
)

// portalSession is the Redis-stored record keyed by a random id in the cookie.
type portalSession struct {
	UserID    int64     `json:"u"`
	Email     string    `json:"e"`
	Username  string    `json:"n"` // full_name, used for X-Forwarded-User
	CreatedAt time.Time `json:"c"`
	ExpiresAt time.Time `json:"x"`
}

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
	if time.Now().After(s.ExpiresAt) {
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
	routeID, protect, err := h.Portal.RouteByHost(ctx, host)
	if err != nil || routeID == 0 {
		// Unknown host or lookup error: deny (fail closed).
		h.denyVerify(w, r, host, 0, 0, "unknown_host")
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

	routeID, protect, _ := h.Portal.RouteByHost(ctx, host)

	var (
		userID      int64
		hash        string
		isActive    bool
		fullName    sql.NullString
		totpEnabled bool
	)
	err := db.QueryRowContext(ctx,
		`SELECT id, password_hash, is_active, full_name, totp_enabled FROM users WHERE email = ? LIMIT 1`, email).
		Scan(&userID, &hash, &isActive, &fullName, &totpEnabled)
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

	// If 2FA enrolled, issue a short-lived challenge instead of a full session.
	if totpEnabled {
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
	CSPNonce string
	Host     string
	Error    string
}

func (h *PortalHandlers) Portal2FAPage(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(portal2FACookie)
	if err != nil || c.Value == "" {
		http.Redirect(w, r, "/hpg-portal/login", http.StatusSeeOther)
		return
	}
	host := portalRequestHost(r)
	h.render2FA(w, r, http.StatusOK, portal2FAViewData{Host: host})
}

func (h *PortalHandlers) Portal2FASubmit(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	host := portalRequestHost(r)

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
	db := h.DB()
	if db == nil {
		h.render2FA(w, r, http.StatusServiceUnavailable, portal2FAViewData{Host: host, Error: "Service unavailable."})
		return
	}
	secret, ok, needsUpgrade := readTOTPSecret(ctx, db, h.State, st.UserID)
	if !ok {
		// TOTP disabled or secret missing; fall through to session (edge case: disabled between steps).
		h.clearPortal2FACookie(w)
		if err := h.createPortalSession(ctx, w, st.UserID, st.Email, st.Username, st.RememberMe); err != nil {
			h.render2FA(w, r, http.StatusInternalServerError, portal2FAViewData{Host: host, Error: "Could not create session."})
			return
		}
		http.Redirect(w, r, st.Back, http.StatusSeeOther)
		return
	}
	if needsUpgrade {
		upgradeTOTPSecret(ctx, db, h.State, st.UserID, secret)
	}

	if err := auth.ValidateTOTP(secret, code); err != nil {
		st.Attempts++
		h.auditPortalLogin(ctx, r, &st.UserID, "portal.2fa.fail", st.Email, st.Host, "bad_totp")
		if h.Metrics != nil {
			h.Metrics.LoginEvent("fail", "portal", "totp")
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
		h.render2FA(w, r, http.StatusUnauthorized, portal2FAViewData{Host: host, Error: "Invalid code. Try again."})
		return
	}

	h.clearPortal2FACookie(w)
	if err := h.createPortalSession(ctx, w, st.UserID, st.Email, st.Username, st.RememberMe); err != nil {
		h.render2FA(w, r, http.StatusInternalServerError, portal2FAViewData{Host: host, Error: "Could not create session."})
		return
	}
	if h.Metrics != nil {
		h.Metrics.LoginEvent("success", "portal", "totp")
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
</style></head><body>
<div class="card">
 <h1>Two-factor authentication</h1>
 <p class="sub">{{.Host}}</p>
 {{if .Error}}<div class="err">{{.Error}}</div>{{end}}
 <form method="POST" action="/hpg-portal/2fa">
  <label for="code">Authenticator code</label>
  <input id="code" name="code" type="text" inputmode="numeric" pattern="[0-9 ]*" autocomplete="one-time-code" autofocus required maxlength="10" placeholder="000 000">
  <button type="submit">Verify</button>
 </form>
 <a href="/hpg-portal/login">Back to sign in</a>
</div>
</body></html>`))

// Logout destroys the portal session.
func (h *PortalHandlers) Logout(w http.ResponseWriter, r *http.Request) {
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

func (h *PortalHandlers) createPortalSession(ctx context.Context, w http.ResponseWriter, userID int64, email, username string, rememberMe bool) error {
	idb := make([]byte, 32)
	if _, err := rand.Read(idb); err != nil {
		return err
	}
	id := base64.RawURLEncoding.EncodeToString(idb)
	now := time.Now().UTC()
	ttl := h.ttl()
	if rememberMe {
		ttl = 30 * 24 * time.Hour
	}
	s := portalSession{UserID: userID, Email: email, Username: username, CreatedAt: now, ExpiresAt: now.Add(ttl)}
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
	if !strings.HasPrefix(u.Path, "/") {
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
