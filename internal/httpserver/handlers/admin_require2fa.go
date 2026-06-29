package handlers

import (
	"context"
	"net/http"
	"time"

	"github.com/host-yt/caddy-proxy-manager/internal/audit"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
	"github.com/host-yt/caddy-proxy-manager/internal/store"
)

// SettingsRequire2FA handles POST /admin/settings/require-2fa.
// Single checkbox: when on, admins/super_admins without an enrolled 2FA method
// are redirected to setup. The env REQUIRE_ADMIN_2FA still force-enables it.
func (h *AdminHandlers) SettingsRequire2FA(w http.ResponseWriter, r *http.Request) {
	db := h.DB()
	if db == nil {
		redirectWithFlash(w, r, "/admin/settings", "", "db not ready")
		return
	}
	_ = r.ParseForm()
	val := "0"
	if r.FormValue("require_admin_2fa") == "1" {
		val = "1"
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	if _, err := db.ExecContext(ctx, store.UpsertSettingSQL(), "security.require_admin_2fa", val, 0); err != nil {
		redirectWithFlash(w, r, "/admin/settings", "", "save failed: "+sanitizeErr(err))
		return
	}
	sess := middleware.SessionFromContext(r.Context())
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "admin.settings.require_2fa", Entity: "settings",
		EntityID: "security.require_admin_2fa",
		Meta:     map[string]any{"enabled": val == "1"},
	})
	redirectWithFlash(w, r, "/admin/settings", "Admin 2FA enforcement updated", "")
}
