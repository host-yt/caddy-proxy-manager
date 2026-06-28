package handlers

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/host-yt/caddy-proxy-manager/internal/audit"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
)

// SettingsSelfRegistration handles POST /admin/settings/self-registration.
// Saves the allow_self_registration toggle and optional default_plan_id.
func (h *AdminHandlers) SettingsSelfRegistration(w http.ResponseWriter, r *http.Request) {
	db := h.DB()
	if db == nil {
		redirectWithFlash(w, r, "/admin/settings", "", "db not ready")
		return
	}
	_ = r.ParseForm()
	enabled := "0"
	if r.FormValue("allow_self_registration") == "1" {
		enabled = "1"
	}
	planID := strings.TrimSpace(r.FormValue("default_plan_id"))

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	kv := map[string]string{
		"auth.allow_self_registration": enabled,
		"auth.default_plan_id":         planID,
	}
	if err := h.saveSettings(ctx, db, kv, false); err != nil {
		redirectWithFlash(w, r, "/admin/settings", "", "save failed: "+sanitizeErr(err))
		return
	}

	sess := middleware.SessionFromContext(r.Context())
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "admin.settings.self_registration", Entity: "settings",
		EntityID: "auth.allow_self_registration",
		Meta:     map[string]any{"enabled": enabled == "1", "default_plan_id": planID},
	})
	redirectWithFlash(w, r, "/admin/settings", "Self-registration settings updated", "")
}
