package handlers

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/host-yt/caddy-proxy-manager/internal/audit"
	"github.com/host-yt/caddy-proxy-manager/internal/oauth2x"
)

const (
	portalOAuthStateCookie = "hpg_portal_oauth_state"
	portalOAuthStateTTL    = 10 * time.Minute
	portalOAuthRedisPrefix = "hpg:portal:oauth:"
)

// portalOAuthStatePayload is stored in Redis and tied to the state cookie.
type portalOAuthStatePayload struct {
	Back     string `json:"back"`
	Verifier string `json:"verifier"`
}

// PortalOAuthStart begins the OAuth2 flow for a portal login. Provider id comes
// from the URL. On success redirects to the provider's authorization endpoint.
func (h *PortalHandlers) PortalOAuthStart(w http.ResponseWriter, r *http.Request) {
	provider := strings.ToLower(strings.TrimSpace(chi.URLParam(r, "provider")))
	if !oauth2x.IsSupported(provider) || h.OAuth2X == nil {
		http.NotFound(w, r)
		return
	}

	host := portalRequestHost(r)
	back := portalSafeBack(r.URL.Query().Get("back"), host)

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	state, err := randToken(16)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	callbackURL := h.portalOAuthCallbackURL(provider)
	authURL, verifier, err := h.OAuth2X.AuthURL(ctx, provider, callbackURL, state)
	if err != nil {
		h.Logger.Warn("portal oauth start", "provider", provider, "err", err)
		h.renderLogin(w, r, http.StatusBadGateway, portalViewData{
			Error: FormatProviderLabel(provider) + " is unavailable.", Back: back, Host: host,
		})
		return
	}

	payload, _ := json.Marshal(portalOAuthStatePayload{Back: back, Verifier: verifier})
	if err := h.RDB.Set(ctx, portalOAuthRedisPrefix+state, payload, portalOAuthStateTTL).Err(); err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     portalOAuthStateCookie,
		Value:    state,
		Path:     "/hpg-portal",
		HttpOnly: true,
		Secure:   h.Secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(portalOAuthStateTTL.Seconds()),
	})
	http.Redirect(w, r, authURL, http.StatusSeeOther)
}

// PortalOAuthCallback completes the OAuth2 flow for the portal. Verifies state,
// exchanges code, fetches user email, checks access grants, and mints a portal
// session. Access check mirrors LoginSubmit: the user must be in an access group
// granted to the route that triggered the portal login.
func (h *PortalHandlers) PortalOAuthCallback(w http.ResponseWriter, r *http.Request) {
	provider := strings.ToLower(strings.TrimSpace(chi.URLParam(r, "provider")))
	if !oauth2x.IsSupported(provider) || h.OAuth2X == nil {
		http.NotFound(w, r)
		return
	}

	host := portalRequestHost(r)
	q := r.URL.Query()

	if errStr := q.Get("error"); errStr != "" {
		h.renderLogin(w, r, http.StatusBadRequest, portalViewData{
			Error: FormatProviderLabel(provider) + " sign-in was cancelled.", Host: host,
		})
		return
	}

	state := q.Get("state")
	code := q.Get("code")
	if state == "" || code == "" {
		http.Error(w, "missing state or code", http.StatusBadRequest)
		return
	}

	// CSRF: state must match the cookie set in PortalOAuthStart.
	cookie, err := r.Cookie(portalOAuthStateCookie)
	if err != nil || subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(state)) != 1 {
		http.Error(w, "state mismatch", http.StatusForbidden)
		return
	}
	// Clear the state cookie immediately regardless of outcome.
	http.SetCookie(w, &http.Cookie{
		Name: portalOAuthStateCookie, Value: "", Path: "/hpg-portal",
		HttpOnly: true, Secure: h.Secure, SameSite: http.SameSiteLaxMode, MaxAge: -1,
	})

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	// Retrieve and consume the Redis ticket (single-use).
	stored, err := h.RDB.GetDel(ctx, portalOAuthRedisPrefix+state).Bytes()
	if err != nil {
		http.Error(w, "state expired", http.StatusForbidden)
		return
	}
	var payload portalOAuthStatePayload
	_ = json.Unmarshal(stored, &payload)
	back := portalSafeBack(payload.Back, host)

	callbackURL := h.portalOAuthCallbackURL(provider)
	info, err := h.OAuth2X.Exchange(ctx, provider, callbackURL, code, payload.Verifier)
	if err != nil {
		h.Logger.Warn("portal oauth exchange", "provider", provider, "err", err)
		h.renderLogin(w, r, http.StatusBadGateway, portalViewData{
			Error: FormatProviderLabel(provider) + " sign-in failed. Try again.", Back: back, Host: host,
		})
		return
	}

	// Require a verified email - same gate as the panel OAuth path.
	if !info.EmailVerified || info.Email == "" {
		h.renderLogin(w, r, http.StatusUnauthorized, portalViewData{
			Error: "Email not verified at " + FormatProviderLabel(provider) + ".", Back: back, Host: host,
		})
		return
	}

	email := strings.ToLower(strings.TrimSpace(info.Email))
	db := h.DB()
	if db == nil {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}

	// Resolve the user from the local users table by email.
	var (
		userID   int64
		isActive bool
		fullName string
	)
	err = db.QueryRowContext(ctx,
		`SELECT id, is_active, COALESCE(full_name,'') FROM users WHERE email = ? LIMIT 1`, email,
	).Scan(&userID, &isActive, &fullName)
	if err != nil {
		// No local account -> deny; portal does not auto-provision.
		h.Logger.Info("portal oauth: no local account", "email", email, "provider", provider)
		h.auditPortalLogin(ctx, r, nil, "portal.oauth.deny", email, host, "no_local_account")
		h.renderLogin(w, r, http.StatusForbidden, portalViewData{
			Error: "No account found for this email. Contact your administrator.", Back: back, Host: host,
		})
		return
	}
	if !isActive {
		h.auditPortalLogin(ctx, r, &userID, "portal.oauth.deny", email, host, "account_disabled")
		h.renderLogin(w, r, http.StatusForbidden, portalViewData{
			Error: "Your account is disabled.", Back: back, Host: host,
		})
		return
	}

	// Check route access: user must be in a group granted to the protected route.
	routeID, protect, _ := h.Portal.RouteByHost(ctx, host)
	if protect && routeID > 0 {
		allowed, aerr := h.Portal.IsAllowed(ctx, routeID, userID)
		if aerr != nil || !allowed {
			h.auditPortalLogin(ctx, r, &userID, "portal.oauth.deny", email, host, "not_member")
			h.renderLogin(w, r, http.StatusForbidden, portalViewData{
				Error: "Your account is not authorized for this application.", Back: back, Host: host,
			})
			return
		}
	}

	if err := h.createPortalSession(ctx, w, userID, email, fullName, false); err != nil {
		h.renderLogin(w, r, http.StatusInternalServerError, portalViewData{
			Error: "Could not create session.", Back: back, Host: host,
		})
		return
	}

	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: &userID, ActorType: audit.ActorUser, Action: "portal.oauth.login.success",
		Entity: "auth", EntityID: email,
		Meta: map[string]any{"host": host, "provider": provider},
	})
	if h.Metrics != nil {
		h.Metrics.LoginEvent("success", "portal_oauth", provider)
	}
	http.Redirect(w, r, back, http.StatusSeeOther)
}

// portalOAuthCallbackURL builds the absolute callback URL that the IdP must
// redirect to. It uses the panel AppURL so the callback hits the panel domain,
// not the protected host (the panel handles the code exchange).
func (h *PortalHandlers) portalOAuthCallbackURL(provider string) string {
	base := strings.TrimRight(h.AppURL, "/")
	return base + "/hpg-portal/oauth/" + provider + "/callback"
}
