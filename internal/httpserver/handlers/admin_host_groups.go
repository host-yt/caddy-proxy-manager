package handlers

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
)

func (h *AdminHandlers) HostGroupCreate(w http.ResponseWriter, r *http.Request) {
	// Global taxonomy: unrestricted admins only (see HostGroupUpdate).
	if !h.requireGlobalAdmin(w, r) {
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	color := strings.TrimSpace(r.FormValue("color"))
	if name == "" {
		redirectWithFlash(w, r, "/admin/hosts", "", "group name required")
		return
	}
	if color == "" || len(color) != 7 || color[0] != '#' {
		color = "#6366f1"
	}
	db := h.DB()
	if db == nil {
		redirectWithFlash(w, r, "/admin/hosts", "", "db unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	_, err := db.ExecContext(ctx, "INSERT INTO host_groups (name, color) VALUES (?, ?)", name, color)
	if err != nil {
		redirectWithFlash(w, r, "/admin/hosts", "", "create failed: "+sanitizeErr(err)) // nosemgrep: go.lang.security.injection.tainted-sql-string.tainted-sql-string -- flash text, not SQL
		return
	}
	redirectWithFlash(w, r, "/admin/hosts", "Group created", "")
}

func (h *AdminHandlers) HostGroupUpdate(w http.ResponseWriter, r *http.Request) {
	// host_groups are global (not client-scoped); only an unrestricted admin
	// may rename them so a scoped/reseller admin cannot touch shared taxonomy.
	if !h.requireGlobalAdmin(w, r) {
		return
	}
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		redirectWithFlash(w, r, "/admin/hosts", "", "invalid id")
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	color := strings.TrimSpace(r.FormValue("color"))
	if name == "" {
		redirectWithFlash(w, r, "/admin/hosts", "", "group name required")
		return
	}
	if color == "" || len(color) != 7 || color[0] != '#' {
		color = "#6366f1"
	}
	db := h.DB()
	if db == nil {
		redirectWithFlash(w, r, "/admin/hosts", "", "db unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	_, err = db.ExecContext(ctx, "UPDATE host_groups SET name=?, color=? WHERE id=?", name, color, id)
	if err != nil {
		redirectWithFlash(w, r, "/admin/hosts", "", "update failed: "+sanitizeErr(err)) // nosemgrep: go.lang.security.injection.tainted-sql-string.tainted-sql-string -- flash text, not SQL
		return
	}
	redirectWithFlash(w, r, "/admin/hosts", "Group updated", "")
}

func (h *AdminHandlers) HostGroupDelete(w http.ResponseWriter, r *http.Request) {
	// Global taxonomy: unrestricted admins only (see HostGroupUpdate).
	if !h.requireGlobalAdmin(w, r) {
		return
	}
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		redirectWithFlash(w, r, "/admin/hosts", "", "invalid id")
		return
	}
	db := h.DB()
	if db == nil {
		redirectWithFlash(w, r, "/admin/hosts", "", "db unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	// ON DELETE SET NULL clears routes.group_id automatically.
	_, err = db.ExecContext(ctx, "DELETE FROM host_groups WHERE id=?", id)
	if err != nil {
		redirectWithFlash(w, r, "/admin/hosts", "", "delete failed: "+sanitizeErr(err))
		return
	}
	redirectWithFlash(w, r, "/admin/hosts", "Group deleted", "")
}
