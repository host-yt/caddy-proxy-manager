package handlers

// Backend-server registry: named IPs admins pick from a dropdown on the
// service form instead of retyping raw IPs. Scoping mirrors Plans: reseller_id
// NULL = global (every admin/reseller), set = owned by one reseller.

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/host-yt/caddy-proxy-manager/internal/audit"
	"github.com/host-yt/caddy-proxy-manager/internal/auth"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
)

type backendServerRow struct {
	ID           int64
	Name         string
	IP           string
	ExternalRef  string
	ResellerID   int64  // 0 = global
	ResellerName string // "" when global
	Notes        string
	Owned        bool // caller may edit/delete (own reseller row, or platform admin)
}

type backendServersData struct {
	baseAdminData
	Servers        []backendServerRow
	CanManage      bool
	ResellerScoped bool
}

// serverScope mirrors planScope: reseller-admins are scoped to their own
// reseller's servers; platform admins see/manage every server.
func (h *AdminHandlers) serverScope(ctx context.Context, sess *auth.Session) (resellerID int64, all, ok bool) {
	if sess == nil {
		return 0, false, false
	}
	if sess.ResellerID > 0 {
		return sess.ResellerID, false, true
	}
	if _, sAll, sOk := h.adminClientScope(ctx, sess); sOk && sAll {
		return 0, true, true
	}
	return 0, false, false
}

// serverManageable reports whether the caller may edit/delete a specific
// server row: platform admins any row, reseller-admins only their own.
func (h *AdminHandlers) serverManageable(ctx context.Context, sess *auth.Session, id int64) bool {
	rid, all, ok := h.serverScope(ctx, sess)
	if !ok {
		return false
	}
	if all {
		return true
	}
	var sr sql.NullInt64
	if err := h.DB().QueryRowContext(ctx, "SELECT reseller_id FROM backend_servers WHERE id=?", id).Scan(&sr); err != nil {
		return false
	}
	return sr.Valid && sr.Int64 == rid
}

func (h *AdminHandlers) ServersList(w http.ResponseWriter, r *http.Request) {
	d := backendServersData{baseAdminData: h.base(r, "Backend servers")}
	db := h.DB()
	if db == nil {
		h.render(w, "servers", d)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3_000_000_000)
	defer cancel()

	rid, all, ok := h.serverScope(ctx, middleware.SessionFromContext(r.Context()))
	d.CanManage = ok
	d.ResellerScoped = ok && !all
	where := ""
	var args []any
	if d.ResellerScoped {
		where = " WHERE (bs.reseller_id IS NULL OR bs.reseller_id = ?)"
		args = append(args, rid)
	}
	rows, err := db.QueryContext(ctx,
		`SELECT bs.id, bs.name, bs.ip, bs.external_ref, COALESCE(bs.reseller_id,0),
		        COALESCE(res.name,''), bs.notes
		 FROM backend_servers bs LEFT JOIN resellers res ON res.id = bs.reseller_id`+where+`
		 ORDER BY bs.id DESC`, args...)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var s backendServerRow
			if err := rows.Scan(&s.ID, &s.Name, &s.IP, &s.ExternalRef, &s.ResellerID, &s.ResellerName, &s.Notes); err == nil {
				s.Owned = all || (d.ResellerScoped && s.ResellerID == rid)
				d.Servers = append(d.Servers, s)
			}
		}
	}
	h.render(w, "servers", d)
}

func (h *AdminHandlers) ServersCreate(w http.ResponseWriter, r *http.Request) {
	sctx, scancel := context.WithTimeout(r.Context(), 3*time.Second)
	rid, all, ok := h.serverScope(sctx, middleware.SessionFromContext(r.Context()))
	scancel()
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	_ = r.ParseForm()
	name := strings.TrimSpace(r.FormValue("name"))
	ip := strings.TrimSpace(r.FormValue("ip"))
	externalRef := strings.TrimSpace(r.FormValue("external_ref"))
	notes := strings.TrimSpace(r.FormValue("notes"))
	if len(notes) > 512 {
		notes = notes[:512]
	}
	if name == "" || ip == "" {
		redirectWithFlash(w, r, "/admin/servers", "", "name and ip are required")
		return
	}
	if net.ParseIP(ip) == nil {
		redirectWithFlash(w, r, "/admin/servers", "", "ip is not a valid IP")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5_000_000_000)
	defer cancel()
	// A reseller-admin's servers are owned by their reseller; platform admins
	// create global servers (reseller_id NULL).
	var resellerCol any
	if !all {
		resellerCol = rid
	}
	res, err := db.ExecContext(ctx,
		`INSERT INTO backend_servers (name, ip, external_ref, reseller_id, notes) VALUES (?, ?, ?, ?, ?)`,
		name, ip, externalRef, resellerCol, notes)
	if err != nil {
		h.Logger.Error("backend server create", "err", err)
		redirectWithFlash(w, r, "/admin/servers", "", "insert failed: "+sanitizeErr(err))
		return
	}
	id, _ := res.LastInsertId()
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(middleware.SessionFromContext(r.Context())),
		Action: "backend_server.create", Entity: "backend_server", EntityID: fmt.Sprintf("%d", id),
		Meta: map[string]any{"name": name, "ip": ip},
	})
	redirectWithFlash(w, r, "/admin/servers", "Server created", "")
}

func (h *AdminHandlers) ServersUpdate(w http.ResponseWriter, r *http.Request) {
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	mctx, mcancel := context.WithTimeout(r.Context(), 3*time.Second)
	manage := h.serverManageable(mctx, middleware.SessionFromContext(r.Context()), id)
	mcancel()
	if !manage {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	_ = r.ParseForm()
	name := strings.TrimSpace(r.FormValue("name"))
	ip := strings.TrimSpace(r.FormValue("ip"))
	externalRef := strings.TrimSpace(r.FormValue("external_ref"))
	notes := strings.TrimSpace(r.FormValue("notes"))
	if len(notes) > 512 {
		notes = notes[:512]
	}
	if name == "" || ip == "" {
		redirectWithFlash(w, r, "/admin/servers", "", "name and ip are required")
		return
	}
	if net.ParseIP(ip) == nil {
		redirectWithFlash(w, r, "/admin/servers", "", "ip is not a valid IP")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5_000_000_000)
	defer cancel()
	// reseller_id is immutable on update (ownership doesn't move), same as plans.
	if _, err := db.ExecContext(ctx,
		`UPDATE backend_servers SET name=?, ip=?, external_ref=?, notes=? WHERE id=?`,
		name, ip, externalRef, notes, id); err != nil {
		h.Logger.Error("backend server update", "err", err)
		redirectWithFlash(w, r, "/admin/servers", "", "update failed: "+sanitizeErr(err))
		return
	}
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(middleware.SessionFromContext(r.Context())),
		Action: "backend_server.update", Entity: "backend_server", EntityID: fmt.Sprintf("%d", id),
		Meta: map[string]any{"name": name, "ip": ip},
	})
	redirectWithFlash(w, r, "/admin/servers", "Server updated", "")
}

func (h *AdminHandlers) ServersDelete(w http.ResponseWriter, r *http.Request) {
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	mctx, mcancel := context.WithTimeout(r.Context(), 3*time.Second)
	manage := h.serverManageable(mctx, middleware.SessionFromContext(r.Context()), id)
	mcancel()
	if !manage {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5_000_000_000)
	defer cancel()
	if _, err := db.ExecContext(ctx, "DELETE FROM backend_servers WHERE id = ?", id); err != nil {
		redirectWithFlash(w, r, "/admin/servers", "", "delete failed")
		return
	}
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(middleware.SessionFromContext(r.Context())),
		Action: "backend_server.delete", Entity: "backend_server", EntityID: fmt.Sprintf("%d", id),
	})
	redirectWithFlash(w, r, "/admin/servers", "Server deleted", "")
}
