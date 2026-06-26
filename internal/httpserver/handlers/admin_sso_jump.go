package handlers

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/host-yt/caddy-proxy-manager/internal/audit"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
)

// ssoJumpSecret is the one-shot payload stashed in Redis after rotate.
type ssoJumpSecret struct {
	Plaintext string `json:"pt"`
}

// stashSSOSecret stores the plaintext secret under a short-lived nonce.
// Caller redirects with ?show_sso_secret=<nonce> so it's shown once.
func (h *AdminHandlers) stashSSOSecret(ctx context.Context, plain string) string {
	if h.RDB == nil {
		return ""
	}
	var nb [16]byte
	if _, err := rand.Read(nb[:]); err != nil {
		return ""
	}
	nonce := hex.EncodeToString(nb[:])
	payload, _ := json.Marshal(ssoJumpSecret{Plaintext: plain})
	key := "sso_secret:" + nonce
	if err := h.RDB.Set(ctx, key, payload, 10*time.Minute).Err(); err != nil {
		return ""
	}
	return nonce
}

// fetchSSOSecret reads + deletes (one-shot) the stashed plaintext secret.
func (h *AdminHandlers) fetchSSOSecret(ctx context.Context, nonce string) string {
	if h.RDB == nil || nonce == "" {
		return ""
	}
	key := "sso_secret:" + nonce
	raw, err := h.RDB.GetDel(ctx, key).Bytes()
	if err != nil || len(raw) == 0 {
		return ""
	}
	var s ssoJumpSecret
	if err := json.Unmarshal(raw, &s); err != nil {
		return ""
	}
	return s.Plaintext
}

// SettingsSSOJumpSave handles POST /admin/settings/sso-jump.
// Saves the two boolean flags; secret is managed by Rotate only.
func (h *AdminHandlers) SettingsSSOJumpSave(w http.ResponseWriter, r *http.Request) {
	db := h.DB()
	if db == nil {
		redirectWithFlash(w, r, "/admin/settings#sso-jump", "", "no db")
		return
	}
	_ = r.ParseForm()
	enabled := "0"
	if r.FormValue("sso_jump_enabled") == "1" {
		enabled = "1"
	}
	allowAdmin := "0"
	if r.FormValue("sso_jump_allow_admin") == "1" {
		allowAdmin = "1"
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if err := h.saveSettings(ctx, db, map[string]string{
		"sso_jump.enabled":           enabled,
		"sso_jump.allow_admin_login": allowAdmin,
	}, false); err != nil {
		redirectWithFlash(w, r, "/admin/settings#sso-jump", "", "save failed: "+sanitizeErr(err))
		return
	}
	sess := middleware.SessionFromContext(r.Context())
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "admin.sso_jump.settings.save", Entity: "settings",
		EntityID: "sso_jump",
		Meta:     map[string]any{"enabled": enabled, "allow_admin": allowAdmin},
	})
	redirectWithFlash(w, r, "/admin/settings#sso-jump", "SSO Jump settings saved.", "")
}

// SettingsSSOJumpRotate handles POST /admin/settings/sso-jump/rotate.
// Generates a fresh 64-byte random secret, encrypts and stores it, then
// stashes the plaintext in Redis under a nonce for one-time display.
func (h *AdminHandlers) SettingsSSOJumpRotate(w http.ResponseWriter, r *http.Request) {
	db := h.DB()
	if db == nil {
		redirectWithFlash(w, r, "/admin/settings#sso-jump", "", "no db")
		return
	}
	if h.State == nil {
		redirectWithFlash(w, r, "/admin/settings#sso-jump", "", "encryption manager not wired")
		return
	}

	var rawSecret [64]byte
	if _, err := rand.Read(rawSecret[:]); err != nil {
		redirectWithFlash(w, r, "/admin/settings#sso-jump", "", "entropy failure")
		return
	}
	// Hex string — 128 chars, safe for copy-paste in .env files.
	plain := hex.EncodeToString(rawSecret[:])
	enc, err := h.State.Encrypt(plain)
	if err != nil {
		redirectWithFlash(w, r, "/admin/settings#sso-jump", "", "encrypt failed: "+sanitizeErr(err))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if err := h.saveSettings(ctx, db, map[string]string{
		"sso_jump.secret_e2": enc,
	}, true); err != nil {
		redirectWithFlash(w, r, "/admin/settings#sso-jump", "", "save failed: "+sanitizeErr(err))
		return
	}

	sess := middleware.SessionFromContext(r.Context())
	// Log only the key prefix — never the full secret.
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "admin.sso_jump.rotate", Entity: "settings",
		EntityID: "sso_jump.secret_e2",
		Meta:     map[string]any{"prefix": plain[:8] + "..."},
	})

	nonce := h.stashSSOSecret(ctx, plain)
	if nonce != "" {
		http.Redirect(w, r, "/admin/settings?show_sso_secret="+nonce+"#sso-jump", http.StatusSeeOther)
		return
	}
	// Redis unavailable — redirect without the secret (operator must rotate again).
	redirectWithFlash(w, r, "/admin/settings#sso-jump", "Secret rotated (Redis unavailable — new secret not shown; rotate again).", "")
}

// ssoJumpSettingsView is the SSO Jump sub-section of the settings page.
type ssoJumpSettingsView struct {
	Enabled    bool
	AllowAdmin bool
	HasSecret  bool
	// NewSecret is non-empty only on the first render after rotate (one-shot).
	NewSecret     string
	CallbackURLEx string
}

// loadSSOJumpSettingsView reads the three SSO-jump keys and, if a
// show_sso_secret nonce is present in the request, fetches + deletes it.
func (h *AdminHandlers) loadSSOJumpSettingsView(r *http.Request, appURL string) ssoJumpSettingsView {
	v := ssoJumpSettingsView{}
	db := h.DB()
	if db == nil {
		return v
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	kv := h.loadSettings(ctx, db, []string{
		"sso_jump.enabled", "sso_jump.allow_admin_login", "sso_jump.secret_e2",
	})
	v.Enabled = kv["sso_jump.enabled"] == "1"
	v.AllowAdmin = kv["sso_jump.allow_admin_login"] == "1"
	v.HasSecret = kv["sso_jump.secret_e2"] != ""

	if nonce := r.URL.Query().Get("show_sso_secret"); nonce != "" {
		v.NewSecret = h.fetchSSOSecret(ctx, nonce)
	}

	base := strings.TrimRight(appURL, "/")
	v.CallbackURLEx = base + "/auth/sso/jump?email=customer@example.com&exp=<unix>&sig=<hex>"
	return v
}
