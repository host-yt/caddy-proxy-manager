package handlers

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/host-yt/caddy-proxy-manager/internal/aichat"
	"github.com/host-yt/caddy-proxy-manager/internal/audit"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
)

// aiProviderView is one provider row in the AI settings UI. Configured is the
// only key-derived signal we expose - the key itself is never sent to the browser.
type aiProviderView struct {
	ID         string // lowercase provider id, e.g. "anthropic"
	Label      string // human label
	Configured bool   // a key is stored
	Model      string // currently-saved model id ("" = adapter default)
}

// aiView backs the "AI assistant" settings pane.
type aiView struct {
	DefaultProvider string
	Providers       []aiProviderView
}

// aiKeySetting maps a provider id to its encrypted settings row.
var aiKeySetting = map[string]string{
	"anthropic":  "ai.anthropic_key_enc",
	"openai":     "ai.openai_key_enc",
	"gemini":     "ai.gemini_key_enc",
	"openrouter": "ai.openrouter_key_enc",
}

var aiProviderLabels = map[string]string{
	"anthropic":  "Anthropic (Claude)",
	"openai":     "OpenAI",
	"gemini":     "Google Gemini",
	"openrouter": "OpenRouter",
}

// aiModelSetting maps a provider id to its plaintext selected-model row.
var aiModelSetting = map[string]string{
	"anthropic":  "ai.anthropic_model",
	"openai":     "ai.openai_model",
	"gemini":     "ai.gemini_model",
	"openrouter": "ai.openrouter_model",
}

// loadAIView reads the AI settings rows and reports which keys are configured.
// It checks the raw stored value for presence so it never needs to decrypt.
func (h *AdminHandlers) loadAIView(ctx context.Context) aiView {
	v := aiView{}
	db := h.DB()
	if db == nil {
		return v
	}
	// Read raw stored values; non-empty ciphertext means "configured".
	keys := []string{"ai.default_provider"}
	for _, p := range aichat.SupportedProviders() {
		keys = append(keys, aiKeySetting[p], aiModelSetting[p])
	}
	raw := h.loadSettingsRaw(ctx, db, keys)
	v.DefaultProvider = raw["ai.default_provider"]
	for _, p := range aichat.SupportedProviders() {
		v.Providers = append(v.Providers, aiProviderView{
			ID:         p,
			Label:      aiProviderLabels[p],
			Configured: strings.TrimSpace(raw[aiKeySetting[p]]) != "",
			Model:      strings.TrimSpace(raw[aiModelSetting[p]]),
		})
	}
	return v
}

// SettingsAI POST /admin/settings/ai - save default provider + any supplied
// keys. Keys are write-only: a blank field keeps the existing value; a value
// is encrypted at rest via the existing settings path.
func (h *AdminHandlers) SettingsAI(w http.ResponseWriter, r *http.Request) {
	if !h.aiAdminAllowed(w, r) {
		return
	}
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	_ = r.ParseForm()

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	provider := strings.ToLower(strings.TrimSpace(r.FormValue("default_provider")))
	if provider != "" && aiKeySetting[provider] == "" {
		redirectWithFlash(w, r, "/admin/settings", "", "unknown AI provider")
		return
	}
	if err := h.saveSettings(ctx, db, map[string]string{"ai.default_provider": provider}, false); err != nil {
		redirectWithFlash(w, r, "/admin/settings", "", "save failed: "+sanitizeErr(err))
		return
	}

	// Per-provider selected model (plaintext, optional). Blank clears it so the
	// adapter falls back to its default model.
	for _, p := range aichat.SupportedProviders() {
		model := strings.TrimSpace(r.FormValue("model_" + p))
		if err := h.saveSettings(ctx, db, map[string]string{aiModelSetting[p]: model}, false); err != nil {
			redirectWithFlash(w, r, "/admin/settings", "", "model save failed")
			return
		}
	}

	// Per-provider key writes. Blank = keep existing; "clear_<p>"=1 wipes it.
	for _, p := range aichat.SupportedProviders() {
		if r.FormValue("clear_"+p) == "1" {
			if err := h.saveSettings(ctx, db, map[string]string{aiKeySetting[p]: ""}, true); err != nil {
				redirectWithFlash(w, r, "/admin/settings", "", "clear failed")
				return
			}
			continue
		}
		key := strings.TrimSpace(r.FormValue("key_" + p))
		if key == "" {
			continue
		}
		ct, err := h.encryptSetting(key)
		if err != nil {
			redirectWithFlash(w, r, "/admin/settings", "", "encrypt failed")
			return
		}
		if err := h.saveSettings(ctx, db, map[string]string{aiKeySetting[p]: ct}, true); err != nil {
			redirectWithFlash(w, r, "/admin/settings", "", "key save failed")
			return
		}
	}

	sess := middleware.SessionFromContext(r.Context())
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "settings.ai.save", Entity: "settings", EntityID: "ai",
		Meta: map[string]any{"default_provider": provider}, // never log keys
	})
	redirectWithFlash(w, r, "/admin/settings", "AI assistant settings saved", "")
}

// SettingsAITest POST /admin/settings/ai/test - minimal 1-token call to verify
// a provider's stored key. Returns JSON {ok, error}; never echoes the key.
func (h *AdminHandlers) SettingsAITest(w http.ResponseWriter, r *http.Request) {
	if !h.aiAdminAllowed(w, r) {
		writeJSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": "forbidden"})
		return
	}
	if h.State == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "error": "crypto not configured"})
		return
	}
	db := h.DB()
	if db == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "error": "no db"})
		return
	}
	_ = r.ParseForm()
	provider := strings.ToLower(strings.TrimSpace(r.FormValue("provider")))

	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()

	factory := aichat.NewFactory(db, h.State.Decrypt)
	var (
		client aichat.Client
		err    error
	)
	if provider == "" {
		client, err = factory.Default(ctx)
	} else {
		client, err = factory.For(ctx, provider)
	}
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": sanitizeErr(err)})
		return
	}
	if err := client.Verify(ctx); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": sanitizeErr(err)})
		return
	}
	// Report the model that was actually exercised so the admin can confirm.
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "provider": client.Provider(), "model": client.Model()})
}

// SettingsAIModels GET /admin/settings/ai/models?provider=X - admin-only live
// fetch of the provider's available model ids using the stored key. Returns
// JSON {"models":[...]} or {"error":...}; the key is never echoed.
func (h *AdminHandlers) SettingsAIModels(w http.ResponseWriter, r *http.Request) {
	if !h.aiAdminAllowed(w, r) {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "forbidden"})
		return
	}
	if h.State == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "crypto not configured"})
		return
	}
	db := h.DB()
	if db == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "no db"})
		return
	}
	provider := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("provider")))
	if provider == "" || aiKeySetting[provider] == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "unknown provider"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()

	factory := aichat.NewFactory(db, h.State.Decrypt)
	client, err := factory.For(ctx, provider)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"error": sanitizeErr(err)})
		return
	}
	models, err := client.ListModels(ctx)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"error": sanitizeErr(err)})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"models": models})
}

// aiAdminAllowed restricts AI settings to super_admin/admin (support is
// read-only across the panel and must not manage provider keys). Writes 403.
func (h *AdminHandlers) aiAdminAllowed(w http.ResponseWriter, r *http.Request) bool {
	sess := middleware.SessionFromContext(r.Context())
	if sess == nil || (sess.Role != "super_admin" && sess.Role != "admin") {
		http.Error(w, "forbidden", http.StatusForbidden)
		return false
	}
	return true
}
