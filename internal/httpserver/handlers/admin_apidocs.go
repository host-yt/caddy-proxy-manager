package handlers

import (
	"context"
	"net/http"
	"time"

	"github.com/hostyt/proxy-gateway/internal/audit"
	"github.com/hostyt/proxy-gateway/internal/httpserver/middleware"
)

// SettingsAPIDocs handles POST /admin/settings/apidocs.
// Single checkbox: enabled = public /api-docs reachable without session.
// When unchecked, only admins (session.Role != "") can render it.
func (h *AdminHandlers) SettingsAPIDocs(w http.ResponseWriter, r *http.Request) {
	db := h.DB()
	if db == nil {
		redirectWithFlash(w, r, "/admin/settings", "", "db not ready")
		return
	}
	_ = r.ParseForm()
	val := "0"
	if r.FormValue("public_enabled") == "1" {
		val = "1"
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	if _, err := db.ExecContext(ctx,
		"INSERT INTO settings (`key`, value) VALUES ('apidocs.public_enabled', ?) "+
			"ON DUPLICATE KEY UPDATE value = VALUES(value)", val); err != nil {
		redirectWithFlash(w, r, "/admin/settings", "", "save failed: "+sanitizeErr(err))
		return
	}
	sess := middleware.SessionFromContext(r.Context())
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "admin.settings.apidocs", Entity: "settings",
		EntityID: "apidocs.public_enabled",
		Meta:     map[string]any{"public": val == "1"},
	})
	redirectWithFlash(w, r, "/admin/settings", "API docs visibility updated", "")
}
