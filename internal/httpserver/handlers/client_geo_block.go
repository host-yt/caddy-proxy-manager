package handlers

import (
	"context"
	"database/sql"
	"net/http"
	"strings"
	"time"

	"github.com/host-yt/caddy-proxy-manager/internal/audit"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
)

// clientGeoBlock holds the geo-block response customisation a client controls.
// Action "" inherits the panel-wide default; "page" shows a branded HTML page;
// "redirect" sends blocked visitors to RedirectURL.
type clientGeoBlock struct {
	Action      string
	RedirectURL string
	Title       string
	Message     string
	LogoURL     string
	BgColor     string
}

// loadClientGeoBlock reads the client's own geo-block customisation.
func loadClientGeoBlock(ctx context.Context, db *sql.DB, clientID int64) clientGeoBlock {
	var g clientGeoBlock
	if db == nil || clientID == 0 {
		return g
	}
	var msg sql.NullString
	_ = db.QueryRowContext(ctx,
		`SELECT COALESCE(geo_block_action,''), COALESCE(geo_block_redirect_url,''),
		        COALESCE(geo_block_title,''), geo_block_message,
		        COALESCE(geo_block_logo_url,''), COALESCE(geo_block_bg_color,'')
		   FROM clients WHERE id = ?`, clientID,
	).Scan(&g.Action, &g.RedirectURL, &g.Title, &msg, &g.LogoURL, &g.BgColor)
	g.Message = msg.String
	return g
}

// loadGeoBlockDefaults reads the panel-wide geo-block default (settings KV) so
// the client UI can show what "inherit" resolves to.
func loadGeoBlockDefaults(ctx context.Context, db *sql.DB) clientGeoBlock {
	var g clientGeoBlock
	if db == nil {
		return g
	}
	rows, err := db.QueryContext(ctx,
		"SELECT `key`, value FROM settings WHERE `key` IN ("+
			"'geoblock.action','geoblock.redirect_url','geoblock.title',"+
			"'geoblock.message','geoblock.logo_url','geoblock.bg_color')")
	if err != nil {
		return g
	}
	defer rows.Close()
	for rows.Next() {
		var k, v string
		if rows.Scan(&k, &v) != nil {
			continue
		}
		switch k {
		case "geoblock.action":
			g.Action = v
		case "geoblock.redirect_url":
			g.RedirectURL = v
		case "geoblock.title":
			g.Title = v
		case "geoblock.message":
			g.Message = v
		case "geoblock.logo_url":
			g.LogoURL = v
		case "geoblock.bg_color":
			g.BgColor = v
		}
	}
	return g
}

// GeoBlockUpdate handles POST /app/geo-block - a client edits the page shown
// (or redirect target) when one of their hosts blocks a request by geo/CIDR.
func (h *ClientHandlers) GeoBlockUpdate(w http.ResponseWriter, r *http.Request) {
	sess := middleware.SessionFromContext(r.Context())
	db := h.DB()
	if sess == nil || db == nil {
		clientRedirectFlash(w, r, "/app/account", "", "session expired")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
	defer cancel()

	var clientID int64
	if err := db.QueryRowContext(ctx,
		"SELECT id FROM clients WHERE user_id = ?", sess.UserID).Scan(&clientID); err != nil {
		clientRedirectFlash(w, r, "/app/account", "", "no client record")
		return
	}

	action := strings.ToLower(strings.TrimSpace(r.FormValue("geo_block_action")))
	switch action {
	case "", "page", "redirect":
	default:
		clientRedirectFlash(w, r, "/app/account", "", "invalid block action")
		return
	}
	redirectURL := strings.TrimSpace(r.FormValue("geo_block_redirect_url"))
	title := strings.TrimSpace(r.FormValue("geo_block_title"))
	message := strings.TrimSpace(r.FormValue("geo_block_message"))
	logoURL := strings.TrimSpace(r.FormValue("geo_block_logo_url"))
	bgColor := strings.TrimSpace(r.FormValue("geo_block_bg_color"))

	// These values land in <img src>, an HTTP redirect Location, and inline
	// CSS on a public page, so validate exactly like the admin branding form.
	if action == "redirect" && redirectURL == "" {
		clientRedirectFlash(w, r, "/app/account", "", "redirect needs a target URL")
		return
	}
	for _, u := range []string{redirectURL, logoURL} {
		if u != "" && !isHTTPURL(u) {
			clientRedirectFlash(w, r, "/app/account", "", "URLs must be http(s)://")
			return
		}
	}
	if bgColor != "" && !isSafeCSSColor(bgColor) {
		clientRedirectFlash(w, r, "/app/account", "", "background colour must be #RGB / #RRGGBB / #RRGGBBAA or rgb()/rgba()")
		return
	}
	if len(title) > 128 {
		title = title[:128]
	}
	if len(message) > 1000 {
		message = message[:1000]
	}

	if _, err := db.ExecContext(ctx,
		`UPDATE clients SET geo_block_action = ?, geo_block_redirect_url = ?,
		        geo_block_title = ?, geo_block_message = ?,
		        geo_block_logo_url = ?, geo_block_bg_color = ?
		  WHERE id = ?`,
		action, redirectURL, title, message, logoURL, bgColor, clientID,
	); err != nil {
		clientRedirectFlash(w, r, "/app/account", "", "save failed: "+sanitizeErr(err))
		return
	}
	uid := sess.UserID
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: &uid, Action: "client.geo_block.update", Entity: "client",
		EntityID: itoa64(clientID), Meta: map[string]any{"action": action},
	})
	// Block-page config is read at route-build time; re-push so it takes effect.
	if h.Routes != nil {
		h.Routes.SchedulePushForClient(h.Routes.BackgroundCtx(), clientID)
	}
	clientRedirectFlash(w, r, "/app/account", "Block page saved.", "")
}
