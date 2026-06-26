package handlers

import (
	"context"
	"database/sql"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/host-yt/caddy-proxy-manager/internal/audit"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
)

var clientPhoneRe = regexp.MustCompile(`^\+[1-9]\d{1,14}$`)

type clientAccountData struct {
	baseAppData
	Phone        string
	PhoneEnabled bool // admin-controlled visibility flag

	StatusPageURL  string // non-empty when the public status page is enabled
	StatusPageSlug string // raw slug for display

	OAuthIdentities []oauthIdentityRow // linked OAuth providers
	OIDCEnabled     bool               // true when admin has OIDC configured
	GitHubEnabled   bool               // GitHub social-login configured + enabled
	GoogleEnabled   bool               // Google social-login configured + enabled
}

// AccountPage renders /app/account - user-editable profile fields.
func (h *ClientHandlers) AccountPage(w http.ResponseWriter, r *http.Request) {
	d := clientAccountData{baseAppData: h.base(r, "Account")}
	sess := middleware.SessionFromContext(r.Context())
	db := h.DB()
	if db == nil || sess == nil {
		h.render(w, "account", d)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	d.PhoneEnabled = adminPhoneCollectionEnabled(ctx, db)
	if d.PhoneEnabled {
		var phone sql.NullString
		_ = db.QueryRowContext(ctx,
			`SELECT phone_e164 FROM users WHERE id = ?`, sess.UserID).Scan(&phone)
		if phone.Valid {
			d.Phone = phone.String
		}
	}
	// Public status page state (slug present = enabled).
	var statusSlug sql.NullString
	_ = db.QueryRowContext(ctx,
		`SELECT c.status_slug FROM clients c WHERE c.user_id = ?`, sess.UserID).Scan(&statusSlug)
	if statusSlug.Valid && statusSlug.String != "" {
		d.StatusPageSlug = statusSlug.String
		d.StatusPageURL = "/status/" + statusSlug.String
	}
	// Linked OAuth providers.
	identities, _ := listIdentities(ctx, db, sess.UserID)
	d.OAuthIdentities = identities
	d.OIDCEnabled = oidcConfiguredInDB(ctx, db)
	d.GitHubEnabled = oauthProviderEnabledInDB(ctx, db, "github")
	d.GoogleEnabled = oauthProviderEnabledInDB(ctx, db, "google")
	h.render(w, "account", d)
}

// AccountUpdate handles POST /app/account.
func (h *ClientHandlers) AccountUpdate(w http.ResponseWriter, r *http.Request) {
	sess := middleware.SessionFromContext(r.Context())
	db := h.DB()
	if sess == nil || db == nil {
		clientRedirectFlash(w, r, "/app/account", "", "session expired")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	// Hard refuse phone writes when admin has disabled collection.
	if !adminPhoneCollectionEnabled(ctx, db) {
		clientRedirectFlash(w, r, "/app/account", "", "phone collection is disabled by the operator")
		return
	}
	phone := strings.TrimSpace(r.FormValue("phone_e164"))
	if phone != "" && !clientPhoneRe.MatchString(phone) {
		clientRedirectFlash(w, r, "/app/account", "", "phone must be E.164 (e.g. +48555111222)")
		return
	}
	var arg any
	if phone == "" {
		arg = nil
	} else {
		arg = phone
	}
	if _, err := db.ExecContext(ctx,
		`UPDATE users SET phone_e164 = ? WHERE id = ?`, arg, sess.UserID); err != nil {
		clientRedirectFlash(w, r, "/app/account", "", "save failed: "+sanitizeErr(err))
		return
	}
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "client.account.phone.update", Entity: "user",
		EntityID: itoa64(sess.UserID),
		Meta:     map[string]any{"set": phone != ""},
	})
	clientRedirectFlash(w, r, "/app/account", "Account updated", "")
}

// adminPhoneCollectionEnabled reads the panel-wide flag set by admin.
func adminPhoneCollectionEnabled(ctx context.Context, db *sql.DB) bool {
	var v string
	_ = db.QueryRowContext(ctx,
		`SELECT value FROM settings WHERE `+"`key`"+` = 'customer.phone_collection_enabled'`).Scan(&v)
	return v == "1"
}

// oidcConfiguredInDB checks whether admin has OIDC enabled in the settings
// table. Used to show/hide the "Link OIDC" button without importing the full
// OIDC service into the client handler.
func oidcConfiguredInDB(ctx context.Context, db *sql.DB) bool {
	var v string
	_ = db.QueryRowContext(ctx,
		`SELECT value FROM settings WHERE `+"`key`"+` = 'oidc.enabled' LIMIT 1`).Scan(&v)
	return v == "1"
}

// oauthProviderEnabledInDB reports whether a social-login provider is enabled
// and has a client_id - used to decide whether to render its link button.
func oauthProviderEnabledInDB(ctx context.Context, db *sql.DB, provider string) bool {
	var enabled bool
	var clientID string
	_ = db.QueryRowContext(ctx,
		`SELECT enabled, client_id FROM oauth_providers WHERE provider = ? LIMIT 1`, provider,
	).Scan(&enabled, &clientID)
	return enabled && clientID != ""
}
