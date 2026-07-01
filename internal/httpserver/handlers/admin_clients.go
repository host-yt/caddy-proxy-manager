package handlers

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/host-yt/caddy-proxy-manager/internal/audit"
	"github.com/host-yt/caddy-proxy-manager/internal/customfields"
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
	// Scoped admins may only view clients they are assigned to.
	if !h.scopeCheckClient(ctx, middleware.SessionFromContext(r.Context()), id) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	d := clientDetailData{baseAdminData: h.base(r, "Client detail")}
	var slug sql.NullString
	err := db.QueryRowContext(ctx,
		`SELECT c.id, COALESCE(c.display_name, u.full_name, u.email), u.email,
		        COALESCE(c.status_slug,''), c.status_show_traffic, u.id
		 FROM clients c JOIN users u ON u.id = c.user_id
		 WHERE c.id = ?`, id,
	).Scan(&d.ID, &d.DisplayName, &d.Email, &slug, &d.ShowTraffic, &d.UserID)
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

	// Load 7-day bandwidth from rollups (hourly pre-aggregated, avoids full access-log scan).
	_ = db.QueryRowContext(ctx,
		`SELECT COALESCE(SUM(lr.bytes_resp), 0)
		 FROM log_rollups lr
		 JOIN routes r ON r.id = lr.route_id
		 JOIN services s ON s.id = r.service_id
		 WHERE s.client_id = ? AND lr.bucket_start >= NOW() - INTERVAL 7 DAY`, id,
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

	// Load last 15 audit entries for this client's user.
	arows, aerr := db.QueryContext(ctx,
		`SELECT al.id, al.action, al.entity, COALESCE(u.email,''), DATE_FORMAT(al.created_at,'%Y-%m-%d %H:%i')
		 FROM audit_log al LEFT JOIN users u ON u.id=al.user_id
		 WHERE al.user_id = (SELECT user_id FROM clients WHERE id=?)
		 ORDER BY al.id DESC LIMIT 15`, id)
	if aerr == nil {
		defer arows.Close()
		for arows.Next() {
			var row clientAuditRow
			if scanErr := arows.Scan(&row.ID, &row.Action, &row.Entity, &row.Email, &row.FiredAt); scanErr == nil {
				d.ClientAudit = append(d.ClientAudit, row)
			}
		}
	}

	// Load admin notes, tag, category, and custom fields.
	var notes, tag, category, cfRaw sql.NullString
	_ = db.QueryRowContext(ctx,
		"SELECT COALESCE(notes,''), COALESCE(tag,''), COALESCE(category,''), COALESCE(custom_fields,'') FROM clients WHERE id=?", id,
	).Scan(&notes, &tag, &category, &cfRaw)
	d.Notes = notes.String
	d.Tag = tag.String
	d.Category = category.String
	if cfDefs, err := customfields.LoadDefs(ctx, db, "client"); err == nil {
		d.CustomFields = customfields.Merge(cfDefs, customfields.Decode(cfRaw.String))
	}

	// Load all plans for plan-change select.
	prows, perr := db.QueryContext(ctx, "SELECT id, name FROM plans ORDER BY name")
	if perr == nil {
		defer prows.Close()
		for prows.Next() {
			var p planRow
			if scanErr := prows.Scan(&p.ID, &p.Name); scanErr == nil {
				d.AllPlans = append(d.AllPlans, p)
			}
		}
	}
	// Detect current plan from first service.
	if len(d.Services) > 0 {
		_ = db.QueryRowContext(ctx,
			"SELECT COALESCE(plan_id,0) FROM services WHERE client_id=? ORDER BY id LIMIT 1", id,
		).Scan(&d.CurrentPlanID)
	}

	h.render(w, "client_detail", d)
}

type clientAuditRow struct {
	ID      int64
	Action  string
	Entity  string
	Email   string
	FiredAt string
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
	UserID           int64
	DisplayName      string
	Email            string
	StatusSlug       string // empty if not yet generated
	StatusURL        string // e.g. /status/abcdef...
	ShowTraffic      bool
	Services         []clientDetailServiceRow
	Routes           []clientDetailRouteRow
	TotalRoutes      int
	ActiveRoutes     int
	BandwidthBytes7d int64                // last 7 days from host_access_log
	Notes            string               // admin-only internal notes
	Tag              string               // grouping label
	Category         string               // billing/segment category
	ClientAudit      []clientAuditRow     // last 15 audit entries for this client
	AllPlans         []planRow            // for plan change select
	CurrentPlanID    int64                // plan_id of the first service (representative)
	CustomFields     []customfields.View  // decoded custom field values merged with defs
}

// ClientsExport streams the full client list as a CSV download.
func (h *AdminHandlers) ClientsExport(w http.ResponseWriter, r *http.Request) {
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	const query = `SELECT COALESCE(c.display_name, u.full_name, u.email), u.email,
	               COALESCE((SELECT GROUP_CONCAT(DISTINCT p2.name ORDER BY p2.name SEPARATOR '/') FROM services s2 JOIN plans p2 ON p2.id=s2.plan_id WHERE s2.client_id=c.id),''),
	               u.is_active, u.role,
	               (SELECT COUNT(*) FROM services s WHERE s.client_id=c.id),
	               (SELECT COUNT(*) FROM routes r JOIN services s ON s.id=r.service_id WHERE s.client_id=c.id AND r.status='active'),
	               DATE_FORMAT(u.created_at, '%Y-%m-%d')
	               FROM clients c JOIN users u ON u.id=c.user_id
	               ORDER BY c.id DESC`

	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=clients.csv")
	w.Header().Set("Cache-Control", "no-store")

	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"name", "email", "plan", "active", "role", "services", "active_routes", "created_at"})
	for rows.Next() {
		var name, email, plan, role, createdAt string
		var isActive bool
		var services, activeRoutes int
		if err := rows.Scan(&name, &email, &plan, &isActive, &role, &services, &activeRoutes, &createdAt); err != nil {
			continue
		}
		active := "0"
		if isActive {
			active = "1"
		}
		_ = cw.Write([]string{name, email, plan, active, role, strconv.Itoa(services), strconv.Itoa(activeRoutes), createdAt})
	}
	cw.Flush()
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
	// Scoped admins may only edit clients they are assigned to.
	if !h.scopeCheckClient(ctx, middleware.SessionFromContext(r.Context()), id) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
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

// ClientsBulk suspends or activates multiple clients in one POST.
func (h *AdminHandlers) ClientsBulk(w http.ResponseWriter, r *http.Request) {
	sess := middleware.SessionFromContext(r.Context())
	_ = r.ParseForm()
	action := r.FormValue("action")
	ids := r.Form["ids"]
	if action == "" || len(ids) == 0 {
		redirectWithFlash(w, r, "/admin/clients", "", "select rows and an action")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	ok, fail := 0, 0
	for _, s := range ids {
		id, _ := strconv.ParseInt(s, 10, 64)
		if id == 0 {
			fail++
			continue
		}
		var userID int64
		if err := h.DB().QueryRowContext(ctx, "SELECT user_id FROM clients WHERE id=?", id).Scan(&userID); err != nil {
			fail++
			continue
		}
		switch action {
		case "suspend":
			if _, err := h.DB().ExecContext(ctx, "UPDATE users SET is_active=0 WHERE id=?", userID); err != nil {
				fail++
				continue
			}
			if h.Sessions != nil {
				_, _ = h.Sessions.DestroyAllForUser(ctx, userID)
			}
		case "activate":
			if _, err := h.DB().ExecContext(ctx, "UPDATE users SET is_active=1 WHERE id=?", userID); err != nil {
				fail++
				continue
			}
		default:
			fail++
			continue
		}
		ok++
	}
	audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "admin.client.bulk", Entity: "client",
		Meta: map[string]any{"action": action, "ok": ok, "fail": fail},
	})
	redirectWithFlash(w, r, "/admin/clients", strconv.Itoa(ok)+" client(s) "+action+"d", "")
}

// ClientChangePlan updates plan_id for all services of a client.
func (h *AdminHandlers) ClientChangePlan(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	db := h.DB()
	if db == nil || id == 0 {
		redirectWithFlash(w, r, "/admin/clients", "", "invalid id")
		return
	}
	_ = r.ParseForm()
	newPlanID, _ := strconv.ParseInt(r.FormValue("plan_id"), 10, 64)
	if newPlanID == 0 {
		redirectWithFlash(w, r, "/admin/clients/"+strconv.FormatInt(id, 10), "", "plan required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	// Scoped admins may only change plans for clients they are assigned to.
	if !h.scopeCheckClient(ctx, middleware.SessionFromContext(r.Context()), id) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	// Verify plan exists.
	var planName string
	if err := db.QueryRowContext(ctx, "SELECT name FROM plans WHERE id=?", newPlanID).Scan(&planName); err != nil {
		redirectWithFlash(w, r, "/admin/clients/"+strconv.FormatInt(id, 10), "", "plan not found")
		return
	}

	// Update all services for this client to the new plan.
	_, err := db.ExecContext(ctx,
		"UPDATE services SET plan_id=?, updated_at=NOW() WHERE client_id=?",
		newPlanID, id)
	if err != nil {
		redirectWithFlash(w, r, "/admin/clients/"+strconv.FormatInt(id, 10), "", "update failed")
		return
	}

	sess := middleware.SessionFromContext(r.Context())
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "admin.client.change_plan", Entity: "client",
		EntityID: itoa64(id), Meta: map[string]any{"new_plan_id": newPlanID, "plan_name": planName},
	})

	redirectWithFlash(w, r, "/admin/clients/"+strconv.FormatInt(id, 10), "Plan changed to "+planName, "")
}
