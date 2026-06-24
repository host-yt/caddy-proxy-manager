package handlers

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/hostyt/proxy-gateway/internal/audit"
	"github.com/hostyt/proxy-gateway/internal/httpserver/middleware"
)

// ClientsStatusSlugGenerate sets a fresh random 32-hex-char slug on the client,
// enabling their public status page.
func (h *AdminHandlers) ClientsStatusSlugGenerate(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	slug := newStatusSlug()
	db := h.DB()
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	_, err := db.ExecContext(ctx,
		"UPDATE clients SET status_slug=? WHERE id=?", slug, id)
	if err != nil {
		redirectWithFlash(w, r, fmt.Sprintf("/admin/clients/%d", id), "", "failed to set slug: "+sanitizeErr(err))
		return
	}
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(middleware.SessionFromContext(r.Context())),
		Action: "client.status_slug.generate", Entity: "client", EntityID: itoa64(id),
	})
	redirectWithFlash(w, r, fmt.Sprintf("/admin/clients/%d", id), "Status page URL generated.", "")
}

// ClientsStatusSlugRevoke clears the slug, disabling the public status page.
func (h *AdminHandlers) ClientsStatusSlugRevoke(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	db := h.DB()
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	_, err := db.ExecContext(ctx,
		"UPDATE clients SET status_slug=NULL WHERE id=?", id)
	if err != nil {
		redirectWithFlash(w, r, fmt.Sprintf("/admin/clients/%d", id), "", "failed")
		return
	}
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(middleware.SessionFromContext(r.Context())),
		Action: "client.status_slug.revoke", Entity: "client", EntityID: itoa64(id),
	})
	redirectWithFlash(w, r, fmt.Sprintf("/admin/clients/%d", id), "Status page disabled.", "")
}

// ClientsStatusToggleTraffic flips the status_show_traffic flag for a client.
func (h *AdminHandlers) ClientsStatusToggleTraffic(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	db := h.DB()
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	_, err := db.ExecContext(ctx,
		"UPDATE clients SET status_show_traffic = NOT status_show_traffic WHERE id=?", id)
	if err != nil {
		redirectWithFlash(w, r, fmt.Sprintf("/admin/clients/%d", id), "", "update failed")
		return
	}
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(middleware.SessionFromContext(r.Context())),
		Action: "client.status_show_traffic.toggle", Entity: "client", EntityID: itoa64(id),
	})
	redirectWithFlash(w, r, fmt.Sprintf("/admin/clients/%d", id), "Traffic visibility toggled.", "")
}

// newStatusSlug generates a cryptographically random 32-hex-char slug.
func newStatusSlug() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// ClientsShowDetail renders a detail page for a single client with status slug controls.
// Redirects to /admin/clients if the client does not exist.
func (h *AdminHandlers) ClientsShowDetail(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	d := clientDetailData{baseAdminData: h.base(r, "Client detail")}
	var slug sql.NullString
	err := db.QueryRowContext(ctx,
		`SELECT c.id, COALESCE(c.display_name, u.full_name, u.email), u.email,
		        COALESCE(c.status_slug,''), c.status_show_traffic
		 FROM clients c JOIN users u ON u.id = c.user_id
		 WHERE c.id = ?`, id,
	).Scan(&d.ID, &d.DisplayName, &d.Email, &slug, &d.ShowTraffic)
	if err != nil {
		redirectWithFlash(w, r, "/admin/clients", "", "client not found")
		return
	}
	if slug.Valid && slug.String != "" {
		d.StatusSlug = slug.String
		d.StatusURL = "/status/" + slug.String
	}
	h.render(w, "client_detail", d)
}

type clientDetailData struct {
	baseAdminData
	ID          int64
	DisplayName string
	Email       string
	StatusSlug  string // empty if not yet generated
	StatusURL   string // e.g. /status/abcdef...
	ShowTraffic bool
}
