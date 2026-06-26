package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
)

// savedFilterKeys lists the query params a saved filter may carry per view.
// Used as an allow-list when expanding a stored filter into a list URL so
// we never reflect arbitrary stored keys back into the redirect.
var savedFilterKeys = map[string][]string{
	"audit":    {"entity", "action", "actor", "since", "q", "sort", "dir"},
	"clients":  {"q", "sort", "dir"},
	"api_keys": {"q", "sort", "dir"},
}

// maybeApplySavedFilter handles ?saved_filter=ID on a list page: it loads the
// current user's stored filter and 303-redirects to the same list with the
// saved query params expanded. Returns true if it issued a redirect.
func (h *AdminHandlers) maybeApplySavedFilter(w http.ResponseWriter, r *http.Request, viewKey string) bool {
	idStr := strings.TrimSpace(r.URL.Query().Get("saved_filter"))
	if idStr == "" {
		return false
	}
	back := savedFilterBack(viewKey)
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		http.Redirect(w, r, back, http.StatusSeeOther)
		return true
	}
	sess := middleware.SessionFromContext(r.Context())
	db := h.DB()
	if db == nil || sess == nil {
		http.Redirect(w, r, back, http.StatusSeeOther)
		return true
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	// Ownership: only the owner's filter for this view is loadable.
	var raw string
	err = db.QueryRowContext(ctx,
		`SELECT query_json FROM saved_filters WHERE id=? AND user_id=? AND view_key=?`,
		id, sess.UserID, viewKey).Scan(&raw)
	if err != nil {
		http.Redirect(w, r, back, http.StatusSeeOther)
		return true
	}
	var fields map[string]string
	if json.Unmarshal([]byte(raw), &fields) != nil {
		http.Redirect(w, r, back, http.StatusSeeOther)
		return true
	}
	q := url.Values{}
	for _, k := range savedFilterKeys[viewKey] {
		if v := strings.TrimSpace(fields[k]); v != "" {
			q.Set(k, v)
		}
	}
	target := back
	if enc := q.Encode(); enc != "" {
		target += "?" + enc
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
	return true
}

// savedFilter is a single saved filter row.
type savedFilter struct {
	ID        int64
	Name      string
	QueryJSON string
}

// savedFiltersForView returns filters saved by the current user for viewKey.
func (h *AdminHandlers) savedFiltersForView(ctx context.Context, userID int64, viewKey string) []savedFilter {
	db := h.DB()
	if db == nil {
		return nil
	}
	rows, err := db.QueryContext(ctx,
		`SELECT id, name, query_json FROM saved_filters
		 WHERE user_id = ? AND view_key = ?
		 ORDER BY id DESC LIMIT 20`,
		userID, viewKey)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []savedFilter
	for rows.Next() {
		var f savedFilter
		if rows.Scan(&f.ID, &f.Name, &f.QueryJSON) == nil {
			out = append(out, f)
		}
	}
	return out
}

// SavedFilterSave handles POST /admin/saved-filters/{view}
// Saves current URL query as a named filter for the current user + view.
func (h *AdminHandlers) SavedFilterSave(w http.ResponseWriter, r *http.Request) {
	sess := middleware.SessionFromContext(r.Context())
	db := h.DB()
	if db == nil || sess == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	viewKey := strings.TrimSpace(chi.URLParam(r, "view"))
	if !isAllowedViewKey(viewKey) {
		http.Error(w, "unknown view", http.StatusBadRequest)
		return
	}
	_ = r.ParseForm()
	name := strings.TrimSpace(r.FormValue("filter_name"))
	queryRaw := strings.TrimSpace(r.FormValue("query_json"))
	if name == "" || queryRaw == "" {
		http.Error(w, "name and query required", http.StatusBadRequest)
		return
	}
	// Validate it is parseable JSON so we don't store garbage.
	var qcheck map[string]any
	if err := json.Unmarshal([]byte(queryRaw), &qcheck); err != nil {
		http.Error(w, "query_json must be valid JSON", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	// Cap per-user-per-view at 10 to avoid unbounded growth.
	var cnt int
	_ = db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM saved_filters WHERE user_id=? AND view_key=?`,
		sess.UserID, viewKey).Scan(&cnt)
	if cnt >= 10 {
		http.Error(w, "saved filter limit reached (10 per view)", http.StatusBadRequest)
		return
	}

	_, err := db.ExecContext(ctx,
		`INSERT INTO saved_filters (user_id, view_key, name, query_json) VALUES (?,?,?,?)`,
		sess.UserID, viewKey, name, queryRaw)
	if err != nil {
		h.Logger.Error("save filter insert", "err", err)
		http.Error(w, "insert failed", http.StatusInternalServerError)
		return
	}
	back := savedFilterBack(viewKey)
	http.Redirect(w, r, back+"?flash=Filter+saved.", http.StatusSeeOther)
}

// SavedFilterDelete handles POST /admin/saved-filters/{view}/{id}/delete
func (h *AdminHandlers) SavedFilterDelete(w http.ResponseWriter, r *http.Request) {
	sess := middleware.SessionFromContext(r.Context())
	db := h.DB()
	if db == nil || sess == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	viewKey := strings.TrimSpace(chi.URLParam(r, "view"))
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if id == 0 || !isAllowedViewKey(viewKey) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	// Only allow deleting own filters.
	_, err := db.ExecContext(ctx,
		`DELETE FROM saved_filters WHERE id=? AND user_id=? AND view_key=?`,
		id, sess.UserID, viewKey)
	if err != nil {
		h.Logger.Error("save filter delete", "err", err)
	}
	back := savedFilterBack(viewKey)
	http.Redirect(w, r, back, http.StatusSeeOther)
}

// isAllowedViewKey gates which views can have saved filters.
func isAllowedViewKey(v string) bool {
	switch v {
	case "audit", "clients", "api_keys":
		return true
	}
	return false
}

// savedFilterBack maps view key to its list URL.
func savedFilterBack(v string) string {
	switch v {
	case "audit":
		return "/admin/audit"
	case "clients":
		return "/admin/clients"
	case "api_keys":
		return "/admin/api-keys"
	}
	return "/admin"
}
