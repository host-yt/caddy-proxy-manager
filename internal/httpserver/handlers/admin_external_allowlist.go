package handlers

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/host-yt/caddy-proxy-manager/internal/audit"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
	"github.com/host-yt/caddy-proxy-manager/internal/store"
)

// extAllowRow is one DB-managed external-upstream allowlist entry.
type extAllowRow struct {
	ID      int64
	Host    string
	Note    string
	Created string
}

type extAllowData struct {
	baseAdminData
	Hosts []extAllowRow
	// EnvHosts are hosts from the env CSV (EXTERNAL_UPSTREAM_ALLOWLIST), shown
	// read-only so the operator sees the full effective union.
	EnvHosts []string
}

// ExternalAllowlistPage GET /admin/settings/external-allowlist.
func (h *AdminHandlers) ExternalAllowlistPage(w http.ResponseWriter, r *http.Request) {
	d := extAllowData{baseAdminData: h.base(r, "External upstream allowlist")}
	if h.Routes != nil {
		d.EnvHosts = h.Routes.ExternalUpstreamAllowlist
	}
	db := h.DB()
	if db == nil {
		h.render(w, "external_allowlist", d)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	rows, err := db.QueryContext(ctx,
		`SELECT id, host, COALESCE(note,''), DATE_FORMAT(created_at,'%Y-%m-%d')
		   FROM external_upstream_allowlist ORDER BY host ASC`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var e extAllowRow
			if err := rows.Scan(&e.ID, &e.Host, &e.Note, &e.Created); err == nil {
				d.Hosts = append(d.Hosts, e)
			}
		}
	}
	h.render(w, "external_allowlist", d)
}

// ExternalAllowlistCreate POST /admin/settings/external-allowlist. Adds a host
// to the DB allowlist (union with the env CSV). The host is the open-relay
// gate, not a secret - stored in clear, validated as a bare FQDN.
func (h *AdminHandlers) ExternalAllowlistCreate(w http.ResponseWriter, r *http.Request) {
	const page = "/admin/settings/external-allowlist"
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	_ = r.ParseForm()
	host := strings.ToLower(strings.TrimSpace(r.FormValue("host")))
	note := strings.TrimSpace(r.FormValue("note"))
	if len(note) > 255 {
		note = note[:255]
	}
	if host == "" || !isHostname(host) {
		redirectWithFlash(w, r, page, "", "host must be a valid FQDN (e.g. adm.tools)")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	var allowQ string
	if store.Driver() == "sqlite3" {
		allowQ = `INSERT INTO external_upstream_allowlist (host, note) VALUES (?, ?) ON CONFLICT(host) DO UPDATE SET note=excluded.note`
	} else {
		allowQ = `INSERT INTO external_upstream_allowlist (host, note) VALUES (?, ?) ON DUPLICATE KEY UPDATE note=VALUES(note)`
	}
	if _, err := db.ExecContext(ctx, allowQ, host, note); err != nil {
		redirectWithFlash(w, r, page, "", "save failed: "+sanitizeErr(err))
		return
	}
	sess := middleware.SessionFromContext(r.Context())
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "external_allowlist.add", Entity: "external_allowlist",
		EntityID: host,
	})
	redirectWithFlash(w, r, page, "Allowlist host added.", "")
}

// ExternalAllowlistDelete POST /admin/settings/external-allowlist/{id}/delete.
func (h *AdminHandlers) ExternalAllowlistDelete(w http.ResponseWriter, r *http.Request) {
	const page = "/admin/settings/external-allowlist"
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if _, err := db.ExecContext(ctx, "DELETE FROM external_upstream_allowlist WHERE id = ?", id); err != nil {
		redirectWithFlash(w, r, page, "", "delete failed: "+sanitizeErr(err))
		return
	}
	sess := middleware.SessionFromContext(r.Context())
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "external_allowlist.delete", Entity: "external_allowlist",
		EntityID: strconv.FormatInt(id, 10),
	})
	redirectWithFlash(w, r, page, "Allowlist host removed.", "")
}
