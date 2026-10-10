package handlers

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/host-yt/caddy-proxy-manager/internal/audit"
	"github.com/host-yt/caddy-proxy-manager/internal/auth"
	"github.com/host-yt/caddy-proxy-manager/internal/oauth2x"
)

const (
	portalOAuthStateCookie   = "hpg_portal_oauth_state"
	portalOAuthStateTTL      = 10 * time.Minute
	portalOAuthRedisPrefix   = "hpg:portal:oauth:"
	portalOAuthHandoffPrefix = "hpg:portal:oauth:handoff:"
	portalOAuthHandoffTTL    = time.Minute
	portalOAuthCompletePath  = "/hpg-portal/oauth/complete"
)

// portalOAuthStatePayload is stored in Redis under the OAuth state. Host and
// Nonce bind the attempt to the protected origin and the browser that began it.
type portalOAuthStatePayload struct {
	Back     string `json:"back"`
	Verifier string `json:"verifier"`
	Host     string `json:"host"`
	Nonce    string `json:"nonce"`
}

// portalOAuthHandoff carries a panel-verified identity to the protected host,
// where the portal cookie has to be set.
type portalOAuthHandoff struct {
	UserID   int64  `json:"u"`
	Epoch    int64  `json:"ep"`
	Email    string `json:"e"`
	Name     string `json:"n"`
	Back     string `json:"b"`
	Host     string `json:"h"`
	Nonce    string `json:"nonce"`
	Provider string `json:"p"`
}

// PortalOAuthStart begins the OAuth2 flow for a portal login. Provider id comes
// from the URL. On success redirects to the provider's authorization endpoint.
func (h *PortalHandlers) PortalOAuthStart(w http.ResponseWriter, r *http.Request) {
	provider := strings.ToLower(strings.TrimSpace(chi.URLParam(r, "provider")))
	if !oauth2x.IsSupported(provider) || h.OAuth2X == nil || h.Portal == nil {
		http.NotFound(w, r)
		return
	}

	host := portalRequestHost(r)
	back := portalSafeBack(r.URL.Query().Get("back"), host)

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// The handoff later redirects to this host, so it must be one the panel serves.
	if routeID, _, err := h.Portal.RouteForRequest(ctx, host, portalPathOf(back)); err != nil || routeID == 0 {
		http.NotFound(w, r)
		return
	}

	state, err := randToken(16)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	nonce, err := randToken(32)
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

	payload, _ := json.Marshal(portalOAuthStatePayload{Back: back, Verifier: verifier, Host: host, Nonce: nonce})
	if err := h.RDB.Set(ctx, portalOAuthRedisPrefix+state, payload, portalOAuthStateTTL).Err(); err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     portalOAuthStateCookie,
		Value:    nonce,
		Path:     "/hpg-portal",
		HttpOnly: true,
		Secure:   h.Secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(portalOAuthStateTTL.Seconds()),
	})
	http.Redirect(w, r, authURL, http.StatusSeeOther)
}

// PortalOAuthCallback runs on the panel domain: it verifies state, exchanges
// the code and resolves the local user, then hands the identity to the
// protected host through a single-use ticket. No session is minted here - the
// panel origin is the wrong cookie scope and holds no browser binding.
func (h *PortalHandlers) PortalOAuthCallback(w http.ResponseWriter, r *http.Request) {
	provider := strings.ToLower(strings.TrimSpace(chi.URLParam(r, "provider")))
	if !oauth2x.IsSupported(provider) || h.OAuth2X == nil {
		http.NotFound(w, r)
		return
	}

	q := r.URL.Query()
	if errStr := q.Get("error"); errStr != "" {
		h.renderLogin(w, r, http.StatusBadRequest, portalViewData{
			Error: FormatProviderLabel(provider) + " sign-in was cancelled.", Host: portalRequestHost(r),
		})
		return
	}

	state := q.Get("state")
	code := q.Get("code")
	if state == "" || code == "" {
		http.Error(w, "missing state or code", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	// Retrieve and consume the Redis ticket (single-use).
	stored, err := h.RDB.GetDel(ctx, portalOAuthRedisPrefix+state).Bytes()
	if err != nil {
		http.Error(w, "state expired", http.StatusForbidden)
		return
	}
	var payload portalOAuthStatePayload
	if json.Unmarshal(stored, &payload) != nil || payload.Host == "" || payload.Nonce == "" {
		http.Error(w, "state expired", http.StatusForbidden)
		return
	}
	host := payload.Host
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
	epoch, err := auth.UserEpoch(ctx, db, userID)
	if err != nil {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}

	ticket, err := randToken(32)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	hf, _ := json.Marshal(portalOAuthHandoff{
		UserID: userID, Epoch: epoch, Email: email, Name: fullName,
		Back: back, Host: host, Nonce: payload.Nonce, Provider: provider,
	})
	if err := h.RDB.Set(ctx, portalOAuthHandoffPrefix+ticket, hf, portalOAuthHandoffTTL).Err(); err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, portalHostURL(host, portalOAuthCompletePath, h.Secure)+"?ticket="+url.QueryEscape(ticket), http.StatusSeeOther)
}

// PortalOAuthComplete runs on the protected host. It redeems the handoff
// ticket only in the browser that started the flow (nonce cookie), rechecks
// the account and route grant, and sets the portal cookie on this host.
func (h *PortalHandlers) PortalOAuthComplete(w http.ResponseWriter, r *http.Request) {
	host := portalRequestHost(r)
	nonceCookie, cerr := r.Cookie(portalOAuthStateCookie)
	http.SetCookie(w, &http.Cookie{
		Name: portalOAuthStateCookie, Value: "", Path: "/hpg-portal",
		HttpOnly: true, Secure: h.Secure, SameSite: http.SameSiteLaxMode, MaxAge: -1,
	})
	ticket := r.URL.Query().Get("ticket")
	if ticket == "" || h.Portal == nil {
		http.Error(w, "missing ticket", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()

	raw, err := h.RDB.GetDel(ctx, portalOAuthHandoffPrefix+ticket).Bytes()
	if err != nil {
		h.renderLogin(w, r, http.StatusForbidden, portalViewData{Error: "Sign-in expired. Please try again.", Host: host})
		return
	}
	var hf portalOAuthHandoff
	if json.Unmarshal(raw, &hf) != nil {
		h.renderLogin(w, r, http.StatusForbidden, portalViewData{Error: "Sign-in expired. Please try again.", Host: host})
		return
	}
	back := portalSafeBack(hf.Back, host)
	if hf.Host != host || cerr != nil || hf.Nonce == "" ||
		subtle.ConstantTimeCompare([]byte(nonceCookie.Value), []byte(hf.Nonce)) != 1 {
		// Login CSRF: someone else's callback replayed into this browser.
		h.auditPortalLogin(ctx, r, &hf.UserID, "portal.oauth.deny", hf.Email, host, "browser_mismatch")
		h.renderLogin(w, r, http.StatusForbidden, portalViewData{Error: "Sign-in could not be verified. Please try again.", Back: back, Host: host})
		return
	}

	if ok, err := h.Portal.IdentityStillValid(ctx, hf.UserID, hf.Epoch); err != nil || !ok {
		h.auditPortalLogin(ctx, r, &hf.UserID, "portal.oauth.deny", hf.Email, host, "account_changed")
		h.renderLogin(w, r, http.StatusForbidden, portalViewData{Error: "Your account is disabled.", Back: back, Host: host})
		return
	}
	routeID, protect, _ := h.Portal.RouteForRequest(ctx, host, portalPathOf(back))
	if protect && routeID > 0 {
		allowed, aerr := h.Portal.IsAllowed(ctx, routeID, hf.UserID)
		if aerr != nil || !allowed {
			h.auditPortalLogin(ctx, r, &hf.UserID, "portal.oauth.deny", hf.Email, host, "not_member")
			h.renderLogin(w, r, http.StatusForbidden, portalViewData{
				Error: "Your account is not authorized for this application.", Back: back, Host: host,
			})
			return
		}
	}

	if err := h.createPortalSession(ctx, w, hf.UserID, hf.Email, hf.Name, false); err != nil {
		h.renderLogin(w, r, http.StatusInternalServerError, portalViewData{
			Error: "Could not create session.", Back: back, Host: host,
		})
		return
	}
	if db := h.DB(); db != nil {
		audit.Write(ctx, db, h.Logger, r, audit.Entry{
			UserID: &hf.UserID, ActorType: audit.ActorUser, Action: "portal.oauth.login.success",
			Entity: "auth", EntityID: hf.Email,
			Meta: map[string]any{"host": host, "provider": hf.Provider},
		})
	}
	if h.Metrics != nil {
		h.Metrics.LoginEvent("success", "portal_oauth", hf.Provider)
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
