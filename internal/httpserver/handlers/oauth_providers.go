package handlers

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	xnorm "golang.org/x/text/unicode/norm"

	"github.com/host-yt/caddy-proxy-manager/internal/audit"
	"github.com/host-yt/caddy-proxy-manager/internal/auth"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
	"github.com/host-yt/caddy-proxy-manager/internal/oauth2x"
	"github.com/host-yt/caddy-proxy-manager/internal/store"
)

// oauth2StateTTL bounds how long a started social-login flow stays valid.
// Mirrors oidcStateTTL.
const oauth2StateTTL = 10 * time.Minute

// oauth2CallbackPath builds this provider's callback URL from the configured
// AppURL. The IdP must have this exact URL whitelisted on its side.
func (h *AuthHandlers) oauth2CallbackPath(provider string) string {
	return strings.TrimRight(h.AppURL, "/") + "/auth/" + provider + "/callback"
}

// oauth2StateCookie names the per-provider CSRF state cookie so two flows in
// parallel tabs (e.g. github + google) do not clobber each other.
func oauth2StateCookie(provider string) string { return "hpg_oauth_state_" + provider }

// OAuth2Start kicks off a GitHub/Google sign-in. Provider comes from the URL.
// State + PKCE verifier live in a short Redis ticket keyed by a random state,
// with a matching cookie so the callback can verify CSRF. ?link=1 embeds the
// session user id so the callback links instead of logging in - same contract
// as OIDCStart.
func (h *AuthHandlers) OAuth2Start(w http.ResponseWriter, r *http.Request) {
	provider := strings.ToLower(strings.TrimSpace(chi.URLParam(r, "provider")))
	if !oauth2x.IsSupported(provider) || h.OAuth2X == nil {
		http.NotFound(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	state, err := randToken(16)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	authURL, verifier, err := h.OAuth2X.AuthURL(ctx, provider, h.oauth2CallbackPath(provider), state)
	if err != nil {
		h.Logger.Warn("oauth2 start", "provider", provider, "err", err)
		http.Redirect(w, r, "/auth/login?flash="+oauth2Label(provider)+"+unavailable", http.StatusSeeOther)
		return
	}
	statePayload := map[string]string{"verifier": verifier}
	if r.URL.Query().Get("link") == "1" {
		if sess, _ := h.Sessions.Load(ctx, r); sess != nil {
			statePayload["link_user_id"] = strconv.FormatInt(sess.UserID, 10)
		}
	}
	payload, _ := json.Marshal(statePayload)
	if err := h.RDB.Set(ctx, oauth2RedisKey(provider, state), payload, oauth2StateTTL).Err(); err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: oauth2StateCookie(provider), Value: state, Path: "/", HttpOnly: true,
		Secure: h.Sessions.CookieSecure(), SameSite: http.SameSiteLaxMode,
		Expires: time.Now().Add(oauth2StateTTL),
	})
	http.Redirect(w, r, authURL, http.StatusSeeOther)
}

// OAuth2Callback completes a GitHub/Google sign-in. It resolves the provider
// identity then routes into the SAME hardened ownership / fail-closed path as
// OIDC: an authoritative oauth_identities lookup owns the account, a clean
// "no row" may fall back to email, and SaveIdentity refuses cross-account
// theft. This handler deliberately reimplements NONE of those guarantees in a
// weaker form.
func (h *AuthHandlers) OAuth2Callback(w http.ResponseWriter, r *http.Request) {
	provider := strings.ToLower(strings.TrimSpace(chi.URLParam(r, "provider")))
	if !oauth2x.IsSupported(provider) || h.OAuth2X == nil {
		http.NotFound(w, r)
		return
	}
	q := r.URL.Query()
	if errStr := q.Get("error"); errStr != "" {
		http.Redirect(w, r, "/auth/login?flash="+oauth2Label(provider)+"+sign-in+failed", http.StatusSeeOther)
		return
	}
	state := q.Get("state")
	code := q.Get("code")
	if state == "" || code == "" {
		http.Error(w, "missing state/code", http.StatusBadRequest)
		return
	}
	cookie, err := r.Cookie(oauth2StateCookie(provider))
	if err != nil || subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(state)) != 1 {
		http.Error(w, "state mismatch", http.StatusForbidden)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	stored, err := h.RDB.Get(ctx, oauth2RedisKey(provider, state)).Bytes()
	if err != nil {
		http.Error(w, "state expired", http.StatusForbidden)
		return
	}
	// Single-use: consume the ticket so the code cannot be replayed.
	_ = h.RDB.Del(ctx, oauth2RedisKey(provider, state)).Err()
	var s struct {
		Verifier   string `json:"verifier"`
		LinkUserID string `json:"link_user_id,omitempty"`
	}
	_ = json.Unmarshal(stored, &s)
	// Always clear the state cookie - flow is over either way.
	clearCookie := func() {
		http.SetCookie(w, &http.Cookie{Name: oauth2StateCookie(provider), Value: "", Path: "/", MaxAge: -1})
	}

	info, err := h.OAuth2X.Exchange(ctx, provider, h.oauth2CallbackPath(provider), code, s.Verifier)
	if err != nil {
		clearCookie()
		h.Logger.Warn("oauth2 exchange", "provider", provider, "err", err)
		http.Redirect(w, r, "/auth/login?flash="+oauth2Label(provider)+"+sign-in+failed", http.StatusSeeOther)
		return
	}
	db := h.DB()
	if db == nil {
		clearCookie()
		http.Error(w, "db unavailable", http.StatusServiceUnavailable)
		return
	}
	cfg, _ := h.OAuth2X.LoadConfig(ctx, provider)
	// NFKC + lowercase so Unicode lookalikes can't mint sibling accounts -
	// identical normalization to the OIDC path.
	email := strings.ToLower(xnorm.NFKC.String(info.Email))
	// issuer for oauth_identities is the provider slug: these are global
	// providers whose subjects are unique within the provider, so the slug is a
	// stable namespace and keeps the table provider-agnostic.
	issuer := provider

	// Link flow: user is already authenticated and is adding this provider.
	if s.LinkUserID != "" {
		clearCookie()
		linkUID, perr := strconv.ParseInt(s.LinkUserID, 10, 64)
		if perr != nil {
			http.Error(w, "invalid link state", http.StatusBadRequest)
			return
		}
		// Re-validate at callback: state is not authority. The caller must STILL
		// be the same logged-in user - blocks linking onto a victim via a stale
		// or forged ?link=1 start.
		sess, _ := h.Sessions.Load(ctx, r)
		if sess == nil || sess.UserID != linkUID {
			audit.Write(ctx, db, h.Logger, r, audit.Entry{
				Action: "oauth.link.denied", Entity: "user", EntityID: s.LinkUserID,
				Meta: map[string]any{"reason": "session_mismatch", "provider": provider},
			})
			http.Redirect(w, r, "/auth/login?flash=Please+sign+in+again+to+link+a+provider", http.StatusSeeOther)
			return
		}
		h.oauth2LinkIdentity(ctx, w, r, db, linkUID, provider, issuer, info, email)
		return
	}

	// Email-verification gate: refuse login when the provider does not vouch
	// for the email. Without this, a provider where the email is unverified
	// lets an attacker register victim@panel.example.com and take over the
	// matching local account. auto_provision per-provider does not relax this.
	if !info.EmailVerified || email == "" {
		clearCookie()
		audit.Write(ctx, db, h.Logger, r, audit.Entry{
			Action: "oauth.login.denied", Entity: "auth", EntityID: maskEmail(email),
			Meta: map[string]any{"reason": "email_unverified", "provider": provider},
		})
		http.Redirect(w, r, "/auth/login?flash=Email+not+verified+at+provider", http.StatusSeeOther)
		return
	}

	// Authoritative identity lookup by (provider, issuer, subject). A linked
	// identity owns the account even if its email differs from this callback.
	var linkedUID int64
	linkErr := db.QueryRowContext(ctx,
		`SELECT user_id FROM oauth_identities WHERE provider = ? AND issuer = ? AND subject = ? LIMIT 1`,
		provider, issuer, info.Subject,
	).Scan(&linkedUID)
	// Fail closed: a real DB error must NOT degrade to email-based login (that
	// would bypass linked-provider ownership). Only a clean ErrNoRows falls back.
	if linkErr != nil && !errors.Is(linkErr, sql.ErrNoRows) {
		clearCookie()
		h.Logger.Error("oauth2 identity lookup", "provider", provider, "err", linkErr)
		audit.Write(ctx, db, h.Logger, r, audit.Entry{
			Action: "oauth.login.denied", Entity: "auth", EntityID: maskEmail(email),
			Meta: map[string]any{"reason": "identity_lookup_error", "provider": provider},
		})
		http.Redirect(w, r, "/auth/login?flash=Sign-in+temporarily+unavailable", http.StatusSeeOther)
		return
	}

	var (
		userID   int64
		role     string
		isActive bool
	)
	var queryErr error
	if linkErr == nil && linkedUID > 0 {
		queryErr = db.QueryRowContext(ctx,
			"SELECT id, role, is_active FROM users WHERE id = ? LIMIT 1", linkedUID,
		).Scan(&userID, &role, &isActive)
	} else {
		queryErr = db.QueryRowContext(ctx,
			"SELECT id, role, is_active FROM users WHERE email = ? LIMIT 1", email,
		).Scan(&userID, &role, &isActive)
	}

	if errors.Is(queryErr, sql.ErrNoRows) {
		if !cfg.AutoProvision {
			clearCookie()
			audit.Write(ctx, db, h.Logger, r, audit.Entry{
				Action: "oauth.login.denied", Entity: "auth", EntityID: maskEmail(email),
				Meta: map[string]any{"reason": "auto_provision_disabled", "provider": provider},
			})
			http.Redirect(w, r, "/auth/login?flash=No+account+for+this+email.+Ask+an+admin+to+create+one.", http.StatusSeeOther)
			return
		}
		// Refuse auto-provisioning straight into a privileged role - mirror the
		// OIDC settings guard so a provider-side signup cannot mint an admin.
		role = cfg.DefaultRole
		if role == "" || role == "admin" || role == "super_admin" {
			role = "support"
		}
		raw := make([]byte, 32)
		if _, rerr := rand.Read(raw); rerr != nil {
			clearCookie()
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		dummy, _ := auth.HashPassword(base64.RawURLEncoding.EncodeToString(raw))
		full := info.Name
		if full == "" {
			full = email
		}
		res, ierr := db.ExecContext(ctx,
			`INSERT INTO users (email, password_hash, password_set, role, full_name, is_active)
			 VALUES (?, ?, 0, ?, ?, 1)`,
			email, dummy, role, full)
		if ierr != nil {
			clearCookie()
			h.Logger.Error("oauth2 auto-provision", "provider", provider, "err", ierr)
			http.Redirect(w, r, "/auth/login?flash=Provisioning+failed", http.StatusSeeOther)
			return
		}
		userID, _ = res.LastInsertId()
		isActive = true
		audit.Write(ctx, db, h.Logger, r, audit.Entry{
			UserID: &userID, Action: "oauth.user.provisioned", Entity: "user",
			EntityID: itoa64(userID),
			Meta:     map[string]any{"email": email, "provider": provider, "role": role},
		})
	} else if queryErr != nil {
		clearCookie()
		h.Logger.Error("oauth2 user lookup", "provider", provider, "err", queryErr)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	if !isActive {
		clearCookie()
		audit.Write(ctx, db, h.Logger, r, audit.Entry{
			UserID: &userID, Action: "oauth.login.denied", Entity: "auth", EntityID: maskEmail(email),
			Meta: map[string]any{"reason": "disabled", "provider": provider},
		})
		http.Redirect(w, r, "/auth/login?flash=Account+disabled", http.StatusSeeOther)
		return
	}

	var clientID int64
	if role == "client" {
		_ = db.QueryRowContext(ctx, "SELECT id FROM clients WHERE user_id = ?", userID).Scan(&clientID)
	}

	// Persist the identity. ErrIdentityOwnedByOther means this subject is
	// already linked to a DIFFERENT user - the login itself is a takeover
	// attempt and must be denied (NOT best-effort).
	if saveErr := SaveIdentity(ctx, db, userID, provider, info.Subject, info.Email, issuer); saveErr != nil {
		if errors.Is(saveErr, ErrIdentityOwnedByOther) {
			clearCookie()
			audit.Write(ctx, db, h.Logger, r, audit.Entry{
				UserID: &userID, Action: "oauth.login.denied", Entity: "auth", EntityID: maskEmail(email),
				Meta: map[string]any{"reason": "identity_owned_by_other", "provider": provider},
			})
			http.Redirect(w, r, "/auth/login?flash=This+account+belongs+to+another+user", http.StatusSeeOther)
			return
		}
		h.Logger.Warn("oauth2 login: save identity", "provider", provider, "err", saveErr, "user_id", userID)
	}

	clearCookie()
	// Provider already authenticated the user; like OIDC/passkey we do not
	// double-prompt for the local TOTP factor.
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: &userID, Action: "oauth.login.success", Entity: "auth", EntityID: email,
		Meta: map[string]any{"provider": provider, "role": role},
	})
	h.finalizeLogin(ctx, w, r, userID, email, role, clientID, provider, "sso")
}

// oauth2LinkIdentity adds the provider identity to an already-authenticated
// user. Reuses SaveIdentity, so the immutable-ownership + fail-closed
// guarantees are identical to the OIDC link path.
func (h *AuthHandlers) oauth2LinkIdentity(
	ctx context.Context, w http.ResponseWriter, r *http.Request, db *sql.DB,
	linkUID int64, provider, issuer string, info oauth2x.UserInfo, email string,
) {
	if !info.EmailVerified || email == "" {
		audit.Write(ctx, db, h.Logger, r, audit.Entry{
			UserID: &linkUID, Action: "oauth.link.denied", Entity: "user",
			EntityID: itoa64(linkUID),
			Meta:     map[string]any{"reason": "email_unverified", "provider": provider},
		})
		http.Redirect(w, r, oauth2LinkReturnURL(r)+"?err=Email+not+verified+at+provider", http.StatusSeeOther)
		return
	}
	// Refuse if this subject is already linked to a DIFFERENT user.
	var existingUID int64
	err := db.QueryRowContext(ctx,
		`SELECT user_id FROM oauth_identities WHERE provider = ? AND issuer = ? AND subject = ? LIMIT 1`,
		provider, issuer, info.Subject,
	).Scan(&existingUID)
	if err == nil && existingUID != linkUID {
		audit.Write(ctx, db, h.Logger, r, audit.Entry{
			UserID: &linkUID, Action: "oauth.link.denied", Entity: "user",
			EntityID: itoa64(linkUID),
			Meta:     map[string]any{"reason": "subject_taken", "provider": provider},
		})
		http.Redirect(w, r, oauth2LinkReturnURL(r)+"?err=This+account+is+already+linked+to+another+user", http.StatusSeeOther)
		return
	}
	if linkErr := SaveIdentity(ctx, db, linkUID, provider, info.Subject, info.Email, issuer); linkErr != nil {
		h.Logger.Error("oauth2 link save", "provider", provider, "err", linkErr, "user_id", linkUID)
		msg := "Link+failed"
		if errors.Is(linkErr, ErrIdentityOwnedByOther) {
			msg = "This+account+is+already+linked+to+another+user"
		}
		http.Redirect(w, r, oauth2LinkReturnURL(r)+"?err="+msg, http.StatusSeeOther)
		return
	}
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: &linkUID, Action: "oauth.link", Entity: "user",
		EntityID: itoa64(linkUID),
		Meta:     map[string]any{"provider": provider, "email": info.Email},
	})
	http.Redirect(w, r, oauth2LinkReturnURL(r)+"?flash="+oauth2Label(provider)+"+linked", http.StatusSeeOther)
}

// LinkProvider starts a link flow for the named provider from the account page.
func (h *OAuthIdentityHandlers) LinkProvider(w http.ResponseWriter, r *http.Request) {
	provider := strings.ToLower(strings.TrimSpace(chi.URLParam(r, "provider")))
	if !oauth2x.IsSupported(provider) {
		http.NotFound(w, r)
		return
	}
	http.Redirect(w, r, "/auth/"+provider+"/start?link=1", http.StatusSeeOther)
}

// oauth2LinkReturnURL picks the right account page from the session role.
func oauth2LinkReturnURL(r *http.Request) string {
	if sess := middleware.SessionFromContext(r.Context()); sess != nil && sess.Role == "client" {
		return "/app/account"
	}
	return "/admin/account"
}

func oauth2RedisKey(provider, state string) string {
	return "hpg:oauth:" + provider + ":" + state
}

// oauth2Label returns a URL-query-safe display label for flash messages.
func oauth2Label(provider string) string {
	return url.QueryEscape(FormatProviderLabel(provider))
}

// randToken returns a base64url random string of n bytes of entropy.
func randToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// loadOAuthProviderViews builds the settings-form view for each supported
// social provider. Missing rows render as a blank, disabled form. The secret
// is never decrypted here - we only report whether one is stored.
func (h *AdminHandlers) loadOAuthProviderViews(ctx context.Context, db *sql.DB, appURL string) []oauthProviderView {
	order := []string{oauth2x.ProviderGitHub, oauth2x.ProviderGoogle}
	stored := map[string]oauthProviderView{}
	rows, err := db.QueryContext(ctx,
		`SELECT provider, enabled, client_id, COALESCE(client_secret,''), scopes, auto_provision, default_role
		   FROM oauth_providers`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var (
				p        string
				enabled  bool
				clientID string
				secret   string
				scopes   string
				autoProv bool
				role     string
			)
			if err := rows.Scan(&p, &enabled, &clientID, &secret, &scopes, &autoProv, &role); err != nil {
				continue
			}
			stored[p] = oauthProviderView{
				Provider: p, Enabled: enabled, ClientID: clientID,
				HasSecret: secret != "", Scopes: scopes,
				AutoProvision: autoProv, DefaultRole: role,
			}
		}
	}
	base := strings.TrimRight(appURL, "/")
	out := make([]oauthProviderView, 0, len(order))
	for _, p := range order {
		v := stored[p]
		v.Provider = p
		v.Label = FormatProviderLabel(p)
		if v.DefaultRole == "" {
			v.DefaultRole = "support"
		}
		v.DefaultRedirect = base + "/auth/" + p + "/callback"
		out = append(out, v)
	}
	return out
}

// ---- Admin: provider config save --------------------------------------

// SettingsOAuthProvider upserts one social-login provider's config. The client
// secret is encrypted at rest with the SAME crypto helper used for the OIDC
// secret (installstate AES-GCM); it is never logged and never echoed back.
func (h *AdminHandlers) SettingsOAuthProvider(w http.ResponseWriter, r *http.Request) {
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	_ = r.ParseForm()
	provider := strings.ToLower(strings.TrimSpace(chi.URLParam(r, "provider")))
	if !oauth2x.IsSupported(provider) {
		http.NotFound(w, r)
		return
	}
	enabled := r.FormValue("enabled") == "1"
	clientID := strings.TrimSpace(r.FormValue("client_id"))
	clientSecret := r.FormValue("client_secret")
	clearSecret := r.FormValue("clear_secret") == "1"
	scopes := strings.TrimSpace(r.FormValue("scopes"))
	autoProvision := r.FormValue("auto_provision") == "1"
	defaultRole := strings.TrimSpace(r.FormValue("default_role"))

	if enabled && clientID == "" {
		redirectWithFlash(w, r, "/admin/settings", "", FormatProviderLabel(provider)+": client_id is required when enabled")
		return
	}
	if defaultRole != "support" && defaultRole != "client" {
		// Never auto-provision into admin via a social provider.
		defaultRole = "support"
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// Resolve the secret column without ever decrypting+re-encrypting needlessly:
	//   clear -> empty; new value -> encrypt; blank -> keep existing.
	var secretVal sql.NullString
	var isEnc int
	switch {
	case clearSecret:
		secretVal = sql.NullString{String: "", Valid: true}
		isEnc = 0
	case clientSecret != "":
		ct, err := h.encryptSetting(clientSecret)
		if err != nil {
			redirectWithFlash(w, r, "/admin/settings", "", "encrypt client_secret failed")
			return
		}
		secretVal = sql.NullString{String: ct, Valid: true}
		isEnc = 1
	default:
		// Keep existing secret untouched.
	}

	enabledInt := 0
	if enabled {
		enabledInt = 1
	}
	autoInt := 0
	if autoProvision {
		autoInt = 1
	}

	if secretVal.Valid {
		var oauthQ string
		if store.Driver() == "sqlite3" {
			oauthQ = `INSERT INTO oauth_providers (provider, enabled, client_id, client_secret, is_encrypted, scopes, auto_provision, default_role) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(provider) DO UPDATE SET enabled=excluded.enabled, client_id=excluded.client_id, client_secret=excluded.client_secret, is_encrypted=excluded.is_encrypted, scopes=excluded.scopes, auto_provision=excluded.auto_provision, default_role=excluded.default_role`
		} else {
			oauthQ = `INSERT INTO oauth_providers (provider, enabled, client_id, client_secret, is_encrypted, scopes, auto_provision, default_role) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE enabled=VALUES(enabled), client_id=VALUES(client_id), client_secret=VALUES(client_secret), is_encrypted=VALUES(is_encrypted), scopes=VALUES(scopes), auto_provision=VALUES(auto_provision), default_role=VALUES(default_role)`
		}
		_, err := db.ExecContext(ctx, oauthQ, provider, enabledInt, clientID, secretVal.String, isEnc, scopes, autoInt, defaultRole)
		if err != nil {
			redirectWithFlash(w, r, "/admin/settings", "", "save failed: "+sanitizeErr(err))
			return
		}
	} else {
		// No secret change: leave client_secret/is_encrypted as-is.
		var oauthQ string
		if store.Driver() == "sqlite3" {
			oauthQ = `INSERT INTO oauth_providers (provider, enabled, client_id, scopes, auto_provision, default_role) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(provider) DO UPDATE SET enabled=excluded.enabled, client_id=excluded.client_id, scopes=excluded.scopes, auto_provision=excluded.auto_provision, default_role=excluded.default_role`
		} else {
			oauthQ = `INSERT INTO oauth_providers (provider, enabled, client_id, scopes, auto_provision, default_role) VALUES (?, ?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE enabled=VALUES(enabled), client_id=VALUES(client_id), scopes=VALUES(scopes), auto_provision=VALUES(auto_provision), default_role=VALUES(default_role)`
		}
		_, err := db.ExecContext(ctx, oauthQ, provider, enabledInt, clientID, scopes, autoInt, defaultRole)
		if err != nil {
			redirectWithFlash(w, r, "/admin/settings", "", "save failed: "+sanitizeErr(err))
			return
		}
	}

	sess := middleware.SessionFromContext(r.Context())
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "settings.oauth_provider.save", Entity: "settings",
		EntityID: provider,
		Meta:     map[string]any{"enabled": enabled, "has_secret": secretVal.Valid && secretVal.String != ""},
	})
	redirectWithFlash(w, r, "/admin/settings", FormatProviderLabel(provider)+" saved", "")
}
