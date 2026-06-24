package handlers

import (
	"context"
	"database/sql"
	"net/http"
	"time"

	"github.com/hostyt/proxy-gateway/internal/audit"
	"github.com/hostyt/proxy-gateway/internal/httpserver/middleware"
)

// StatusPageToggle enables or disables the client's public status page.
// POST /app/status-page/toggle - generates a slug when absent, clears it when present.
func (h *ClientHandlers) StatusPageToggle(w http.ResponseWriter, r *http.Request) {
	sess := middleware.SessionFromContext(r.Context())
	db := h.DB()
	if sess == nil || db == nil {
		http.Redirect(w, r, "/app/account", http.StatusSeeOther)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	var clientID int64
	if err := db.QueryRowContext(ctx,
		"SELECT id FROM clients WHERE user_id=?", sess.UserID,
	).Scan(&clientID); err != nil {
		clientRedirectFlash(w, r, "/app/account", "", "no client record")
		return
	}

	var existing sql.NullString
	_ = db.QueryRowContext(ctx,
		"SELECT status_slug FROM clients WHERE id=?", clientID,
	).Scan(&existing)

	uid := sess.UserID
	if existing.Valid && existing.String != "" {
		// Disable - clear the slug.
		if _, err := db.ExecContext(ctx, "UPDATE clients SET status_slug=NULL WHERE id=?", clientID); err != nil {
			clientRedirectFlash(w, r, "/app/account", "", "update failed")
			return
		}
		audit.Write(ctx, db, h.Logger, r, audit.Entry{
			UserID: &uid, Action: "client.status_page.disable", Entity: "client",
			EntityID: itoa64(clientID),
		})
		clientRedirectFlash(w, r, "/app/account", "Status page disabled.", "")
	} else {
		// Enable with new random slug.
		slug := newStatusSlug()
		if _, err := db.ExecContext(ctx, "UPDATE clients SET status_slug=? WHERE id=?", slug, clientID); err != nil {
			clientRedirectFlash(w, r, "/app/account", "", "update failed")
			return
		}
		audit.Write(ctx, db, h.Logger, r, audit.Entry{
			UserID: &uid, Action: "client.status_page.enable", Entity: "client",
			EntityID: itoa64(clientID),
		})
		clientRedirectFlash(w, r, "/app/account", "Status page enabled.", "")
	}
}
