package handlers

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/host-yt/caddy-proxy-manager/internal/audit"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
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

	// Load services with route counts.
	rows, err := db.QueryContext(ctx,
		`SELECT s.id, s.name, p.name, s.status,
		        COUNT(r.id) AS total_routes,
		        SUM(CASE WHEN r.status='active' THEN 1 ELSE 0 END) AS active_routes
		 FROM services s
		 JOIN plans p ON p.id = s.plan_id
		 LEFT JOIN routes r ON r.service_id = s.id
		 WHERE s.client_id = ?
		 GROUP BY s.id, s.name, p.name, s.status
		 ORDER BY s.id DESC`, id)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var row clientDetailServiceRow
			if scanErr := rows.Scan(&row.ID, &row.Name, &row.PlanName, &row.Status,
				&row.RouteCount, &row.ActiveRoutes); scanErr == nil {
				d.Services = append(d.Services, row)
				d.TotalRoutes += row.RouteCount
				d.ActiveRoutes += row.ActiveRoutes
			}
		}
	}

	// Load 7-day bandwidth; ignore errors if column/table missing.
	_ = db.QueryRowContext(ctx,
		`SELECT COALESCE(SUM(l.bytes_resp), 0)
		 FROM host_access_log l
		 JOIN routes r ON r.id = l.route_id
		 JOIN services s ON s.id = r.service_id
		 WHERE s.client_id = ? AND l.ts >= UNIX_TIMESTAMP(NOW() - INTERVAL 7 DAY)`, id,
	).Scan(&d.BandwidthBytes7d)

	// Load routes for all services owned by this client (up to 200).
	rrows, rerr := db.QueryContext(ctx,
		`SELECT r.id, r.domain, COALESCE(r.path_prefix,''), r.upstream_port,
		        r.status, COALESCE(r.ssl_enabled,0), n.name, s.name, COALESCE(r.tag,'')
		 FROM routes r
		 JOIN services s ON s.id=r.service_id
		 JOIN caddy_nodes n ON n.id=r.caddy_node_id
		 WHERE s.client_id=? ORDER BY r.status, r.domain LIMIT 200`, id)
	if rerr == nil {
		defer rrows.Close()
		for rrows.Next() {
			var row clientDetailRouteRow
			if err := rrows.Scan(&row.RouteID, &row.Domain, &row.PathPrefix, &row.Port,
				&row.Status, &row.SSL, &row.NodeName, &row.ServiceName, &row.Tag); err == nil {
				d.Routes = append(d.Routes, row)
			}
		}
	}

	// Load admin notes; ignore errors if column not yet migrated.
	var notes sql.NullString
	_ = db.QueryRowContext(ctx, "SELECT COALESCE(notes,'') FROM clients WHERE id=?", id).Scan(&notes)
	d.Notes = notes.String

	h.render(w, "client_detail", d)
}

type clientDetailServiceRow struct {
	ID           int64
	Name         string
	PlanName     string
	Status       string
	RouteCount   int
	ActiveRoutes int
}

type clientDetailRouteRow struct {
	RouteID     int64
	Domain      string
	PathPrefix  string
	Port        int
	Status      string
	SSL         bool
	NodeName    string
	ServiceName string
	Tag         string
}

type clientDetailData struct {
	baseAdminData
	ID               int64
	DisplayName      string
	Email            string
	StatusSlug       string // empty if not yet generated
	StatusURL        string // e.g. /status/abcdef...
	ShowTraffic      bool
	Services         []clientDetailServiceRow
	Routes           []clientDetailRouteRow
	TotalRoutes      int
	ActiveRoutes     int
	BandwidthBytes7d int64  // last 7 days from host_access_log
	Notes            string // admin-only internal notes
}

// ClientsUpdateNotes saves admin-only notes for a client (POST /admin/clients/{id}/notes).
func (h *AdminHandlers) ClientsUpdateNotes(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	_ = r.ParseForm()
	notes := strings.TrimSpace(r.FormValue("notes"))
	if len(notes) > 10000 {
		notes = notes[:10000]
	}
	db := h.DB()
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	_, err := db.ExecContext(ctx, "UPDATE clients SET notes=? WHERE id=?",
		sql.NullString{String: notes, Valid: notes != ""}, id)
	if err != nil {
		redirectWithFlash(w, r, fmt.Sprintf("/admin/clients/%d", id), "", "save failed: "+sanitizeErr(err))
		return
	}
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(middleware.SessionFromContext(r.Context())),
		Action: "admin.client.notes.update", Entity: "client", EntityID: itoa64(id),
	})
	redirectWithFlash(w, r, fmt.Sprintf("/admin/clients/%d", id), "Notes saved", "")
}
