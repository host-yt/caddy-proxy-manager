package handlers

import (
	"context"
	"crypto/subtle"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/host-yt/caddy-proxy-manager/internal/audit"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
)

// SyncSlaveView is template data for one row in the Instances settings tab.
type SyncSlaveView struct {
	ID             int64
	Name           string
	URL            string
	LastSyncAt     string
	LastSyncStatus string
	LastSyncError  string
}

// SlaveAdd POST /admin/settings/instances - register a new slave instance.
func (h *AdminHandlers) SlaveAdd(w http.ResponseWriter, r *http.Request) {
	db := h.DB()
	if db == nil {
		redirectWithFlash(w, r, "/admin/settings", "", "db not ready")
		return
	}
	if err := r.ParseForm(); err != nil {
		redirectWithFlash(w, r, "/admin/settings#instances", "", "form error")
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	slaveURL := strings.TrimSpace(r.FormValue("url"))
	token := strings.TrimSpace(r.FormValue("token"))
	if name == "" || slaveURL == "" || token == "" {
		redirectWithFlash(w, r, "/admin/settings#instances", "", "name, URL and token required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	enc, err := h.encryptSetting(token)
	if err != nil {
		redirectWithFlash(w, r, "/admin/settings#instances", "", "encrypt error: "+sanitizeErr(err))
		return
	}

	_, err = db.ExecContext(ctx,
		"INSERT INTO sync_slaves (name, url, token_enc) VALUES (?, ?, ?)", name, slaveURL, enc)
	if err != nil {
		redirectWithFlash(w, r, "/admin/settings#instances", "", "add failed: "+sanitizeErr(err))
		return
	}

	sess := middleware.SessionFromContext(r.Context())
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), ActorType: audit.ActorUser, Action: "admin.sync.slave.add",
		Entity: "sync_slave", EntityID: name,
	})
	redirectWithFlash(w, r, "/admin/settings#instances", "Slave instance added.", "")
}

// SlaveDelete POST /admin/settings/instances/{id}/delete - remove a slave.
func (h *AdminHandlers) SlaveDelete(w http.ResponseWriter, r *http.Request) {
	db := h.DB()
	if db == nil {
		redirectWithFlash(w, r, "/admin/settings#instances", "", "db not ready")
		return
	}
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		redirectWithFlash(w, r, "/admin/settings#instances", "", "invalid id")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	_, err = db.ExecContext(ctx, "DELETE FROM sync_slaves WHERE id=?", id)
	if err != nil {
		redirectWithFlash(w, r, "/admin/settings#instances", "", "delete failed: "+sanitizeErr(err))
		return
	}
	sess := middleware.SessionFromContext(r.Context())
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), ActorType: audit.ActorUser, Action: "admin.sync.slave.delete",
		Entity: "sync_slave", EntityID: strconv.FormatInt(id, 10),
	})
	redirectWithFlash(w, r, "/admin/settings#instances", "Slave removed.", "")
}

// SlaveSync POST /admin/settings/instances/{id}/sync - trigger immediate sync to all slaves.
func (h *AdminHandlers) SlaveSync(w http.ResponseWriter, r *http.Request) {
	if h.SyncNotifier == nil {
		redirectWithFlash(w, r, "/admin/settings#instances", "", "sync notifier not configured")
		return
	}
	h.SyncNotifier.Notify(r.Context())
	redirectWithFlash(w, r, "/admin/settings#instances", "Sync triggered.", "")
}

// SyncPushReceive POST /internal/sync/push - slave endpoint; master calls this.
// Validates bearer token then triggers PushAll on local Caddy nodes.
func (h *AdminHandlers) SyncPushReceive(w http.ResponseWriter, r *http.Request) {
	if !h.SlaveMode {
		http.Error(w, "not a slave", http.StatusForbidden)
		return
	}
	auth := r.Header.Get("Authorization")
	expectedBearer := "Bearer " + h.SlaveToken
	// Constant-time compare: avoid leaking token bytes via response timing.
	match := subtle.ConstantTimeCompare([]byte(auth), []byte(expectedBearer)) == 1
	if h.SlaveToken == "" || !match {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if h.Routes == nil {
		http.Error(w, "routes service not ready", http.StatusServiceUnavailable)
		return
	}
	// Push async; return 202 immediately so master doesn't wait.
	go func() {
		ctx2, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		h.Routes.PushAll(ctx2)
		h.Logger.Info("slave sync push: PushAll complete")
	}()
	w.WriteHeader(http.StatusAccepted)
}

// loadSyncSlaves queries sync_slaves for the Instances settings tab.
func (h *AdminHandlers) loadSyncSlaves(ctx context.Context) []SyncSlaveView {
	db := h.DB()
	if db == nil {
		return nil
	}
	rows, err := db.QueryContext(ctx,
		"SELECT id, name, url, COALESCE(last_sync_at,''), COALESCE(last_sync_status,''), COALESCE(last_sync_error,'') FROM sync_slaves ORDER BY id")
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []SyncSlaveView
	for rows.Next() {
		var s SyncSlaveView
		var syncAt string
		_ = rows.Scan(&s.ID, &s.Name, &s.URL, &syncAt, &s.LastSyncStatus, &s.LastSyncError)
		if syncAt != "" && len(syncAt) >= 19 {
			s.LastSyncAt = syncAt[:19]
		}
		out = append(out, s)
	}
	return out
}
