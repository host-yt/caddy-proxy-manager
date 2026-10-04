package handlers

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"golang.org/x/crypto/bcrypt"

	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
	"github.com/host-yt/caddy-proxy-manager/internal/store"
)

// bcryptHash returns a bcrypt hash of pw with the default cost (Caddy's
// http_basic provider accepts bcrypt natively; cost 10 is standard).
func bcryptHash(pw []byte) ([]byte, error) {
	return bcrypt.GenerateFromPassword(pw, bcrypt.DefaultCost)
}

// BasicAuthAddUser handles POST /admin/hosts/{id}/basic-auth.
// Adds or updates a basic auth account for the route.
func (h *AdminHandlers) BasicAuthAddUser(w http.ResponseWriter, r *http.Request) {
	if h.DB() == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	routeID, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || routeID <= 0 {
		http.Redirect(w, r, "/admin/hosts", http.StatusSeeOther)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	sess := middleware.SessionFromContext(r.Context())
	if !h.scopeCheckRoute(ctx, sess, routeID) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	editURL := fmt.Sprintf("/admin/hosts/%d/edit", routeID)
	_ = r.ParseForm()
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	if username == "" {
		redirectWithFlash(w, r, editURL, "", "username is required")
		return
	}
	if len(password) < 8 {
		redirectWithFlash(w, r, editURL, "", "password must be at least 8 characters")
		return
	}
	hash, herr := bcryptHash([]byte(password))
	if herr != nil {
		redirectWithFlash(w, r, editURL, "", "hash error: "+sanitizeErr(herr))
		return
	}
	var basicAuthQ string
	if store.Driver() == "sqlite3" {
		basicAuthQ = `INSERT INTO route_basic_auth_users (route_id, username, bcrypt_hash) VALUES (?, ?, ?) ON CONFLICT(route_id, username) DO UPDATE SET bcrypt_hash=excluded.bcrypt_hash`
	} else {
		basicAuthQ = `INSERT INTO route_basic_auth_users (route_id, username, bcrypt_hash) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE bcrypt_hash=VALUES(bcrypt_hash)`
	}
	_, dbErr := h.DB().ExecContext(ctx, basicAuthQ, routeID, username, string(hash))
	if dbErr != nil {
		redirectWithFlash(w, r, editURL, "", "save failed: "+sanitizeErr(dbErr))
		return
	}
	if h.Routes != nil {
		var nodeID int64
		_ = h.DB().QueryRowContext(ctx, "SELECT caddy_node_id FROM routes WHERE id=?", routeID).Scan(&nodeID)
		if nodeID > 0 {
			h.Routes.SchedulePush(nodeID)
		}
	}
	redirectWithFlash(w, r, editURL, "User added", "")
}

// BasicAuthRemoveUser handles POST /admin/hosts/{id}/basic-auth/{username}/delete.
// Removes one basic auth account from the route.
func (h *AdminHandlers) BasicAuthRemoveUser(w http.ResponseWriter, r *http.Request) {
	if h.DB() == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	routeID, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || routeID <= 0 {
		http.Redirect(w, r, "/admin/hosts", http.StatusSeeOther)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	sess := middleware.SessionFromContext(r.Context())
	if !h.scopeCheckRoute(ctx, sess, routeID) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	editURL := fmt.Sprintf("/admin/hosts/%d/edit", routeID)
	username := chi.URLParam(r, "username")
	if username == "" {
		redirectWithFlash(w, r, editURL, "", "username missing")
		return
	}
	_, dbErr := h.DB().ExecContext(ctx,
		"DELETE FROM route_basic_auth_users WHERE route_id = ? AND username = ?",
		routeID, username)
	if dbErr != nil {
		redirectWithFlash(w, r, editURL, "", "delete failed: "+sanitizeErr(dbErr))
		return
	}
	if h.Routes != nil {
		var nodeID int64
		_ = h.DB().QueryRowContext(ctx, "SELECT caddy_node_id FROM routes WHERE id=?", routeID).Scan(&nodeID)
		if nodeID > 0 {
			h.Routes.SchedulePush(nodeID)
		}
	}
	redirectWithFlash(w, r, editURL, "User removed", "")
}
