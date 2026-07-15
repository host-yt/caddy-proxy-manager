package handlers

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/host-yt/caddy-proxy-manager/internal/audit"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
	"github.com/host-yt/caddy-proxy-manager/internal/store"
)

type webhookRow struct {
	ID              int64
	Name            string
	URL             string
	Events          string
	Enabled         bool
	Created         string
	LastDelivStatus string // "success"/"failed"/"pending"/"never"
	LastDelivHTTP   int
	LastDelivAge    string // e.g. "2m ago"
	LastDelivErr    string // truncated to 60 chars
}

type webhookDeliveryRow struct {
	ID         int64
	EndpointID int64
	EventType  string
	Status     string
	HTTPCode   int
	Attempts   int
	LastError  string
	CreatedAt  string
}

type webhooksData struct {
	baseAdminData
	Endpoints  []webhookRow
	Deliveries []webhookDeliveryRow
}

// WebhooksPage GET /admin/webhooks.
func (h *AdminHandlers) WebhooksPage(w http.ResponseWriter, r *http.Request) {
	d := webhooksData{baseAdminData: h.base(r, "Webhooks")}
	db := h.DB()
	if db == nil {
		h.render(w, "webhooks", d)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	rows, err := db.QueryContext(ctx,
		`SELECT e.id, e.name, e.url, e.events, e.is_enabled,
		        DATE_FORMAT(e.created_at,'%Y-%m-%d'),
		        COALESCE(ld.status,'never'),
		        COALESCE(ld.http_code,0),
		        CASE
		          WHEN ld.created_at IS NULL THEN ''
		          WHEN `+store.TimestampDiff("SECOND", "ld.created_at", "NOW()")+` < 120 THEN CONCAT(`+store.TimestampDiff("SECOND", "ld.created_at", "NOW()")+`,'s ago')
		          WHEN `+store.TimestampDiff("MINUTE", "ld.created_at", "NOW()")+` < 120 THEN CONCAT(`+store.TimestampDiff("MINUTE", "ld.created_at", "NOW()")+`,'m ago')
		          ELSE CONCAT(`+store.TimestampDiff("HOUR", "ld.created_at", "NOW()")+`,'h ago')
		        END,
		        COALESCE(LEFT(ld.last_error,60),'')
		 FROM webhook_endpoints e
		 LEFT JOIN webhook_deliveries ld ON ld.id = (
		   SELECT id FROM webhook_deliveries WHERE endpoint_id=e.id ORDER BY id DESC LIMIT 1
		 )
		 ORDER BY e.id DESC`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var r webhookRow
			if err := rows.Scan(&r.ID, &r.Name, &r.URL, &r.Events, &r.Enabled, &r.Created,
				&r.LastDelivStatus, &r.LastDelivHTTP, &r.LastDelivAge, &r.LastDelivErr); err == nil {
				d.Endpoints = append(d.Endpoints, r)
			}
		}
	}
	drows, err := db.QueryContext(ctx,
		`SELECT id, endpoint_id, event_type, status, COALESCE(http_code,0), attempts,
		        COALESCE(last_error,''), DATE_FORMAT(created_at,'%Y-%m-%d %H:%i')
		 FROM webhook_deliveries ORDER BY id DESC LIMIT 50`)
	if err == nil {
		defer drows.Close()
		for drows.Next() {
			var r webhookDeliveryRow
			if err := drows.Scan(&r.ID, &r.EndpointID, &r.EventType, &r.Status, &r.HTTPCode, &r.Attempts, &r.LastError, &r.CreatedAt); err == nil {
				d.Deliveries = append(d.Deliveries, r)
			}
		}
	}
	h.render(w, "webhooks", d)
}

// WebhooksCreate POST /admin/webhooks.
func (h *AdminHandlers) WebhooksCreate(w http.ResponseWriter, r *http.Request) {
	if h.Webhooks == nil {
		http.Error(w, "webhook service not wired", http.StatusServiceUnavailable)
		return
	}
	_ = r.ParseForm()
	name := strings.TrimSpace(r.FormValue("name"))
	url := strings.TrimSpace(r.FormValue("url"))
	secret := r.FormValue("secret")
	events := strings.TrimSpace(r.FormValue("events"))
	enabled := r.FormValue("enabled") != "0"
	if events == "" {
		events = "*"
	}
	sess := middleware.SessionFromContext(r.Context())
	var uid int64
	if sess != nil {
		uid = sess.UserID
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	id, err := h.Webhooks.SaveEndpoint(ctx, name, url, secret, events, enabled, uid)
	if err != nil {
		h.Logger.Warn("webhook save failed", "err", err)
		redirectWithFlash(w, r, "/admin/webhooks", "", "save failed")
		return
	}
	audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
		UserID: &uid, Action: "webhook.create", Entity: "webhook_endpoint",
		EntityID: strconv.FormatInt(id, 10),
		Meta:     map[string]any{"name": name, "url": url},
	})
	redirectWithFlash(w, r, "/admin/webhooks", "saved", "")
}

// WebhooksDelete POST /admin/webhooks/{id}/delete.
func (h *AdminHandlers) WebhooksDelete(w http.ResponseWriter, r *http.Request) {
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if _, err := db.ExecContext(ctx, "DELETE FROM webhook_endpoints WHERE id = ?", id); err != nil {
		h.Logger.Warn("webhook delete failed", "err", err)
		redirectWithFlash(w, r, "/admin/webhooks", "", "delete failed")
		return
	}
	sess := middleware.SessionFromContext(r.Context())
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "webhook.delete", Entity: "webhook_endpoint",
		EntityID: strconv.FormatInt(id, 10),
	})
	redirectWithFlash(w, r, "/admin/webhooks", "deleted", "")
}

// WebhookDeliveryRetry POST /admin/webhooks/deliveries/{did}/retry — resets a failed delivery to pending.
func (h *AdminHandlers) WebhookDeliveryRetry(w http.ResponseWriter, r *http.Request) {
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	did, _ := strconv.ParseInt(chi.URLParam(r, "did"), 10, 64)
	if did == 0 {
		redirectWithFlash(w, r, "/admin/webhooks", "", "invalid delivery id")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	res, err := db.ExecContext(ctx,
		"UPDATE webhook_deliveries SET status=?, next_retry_at=NOW() WHERE id=? AND status IN (?, ?, ?)",
		"pending", did, "failed", "dead", "error")
	if err != nil {
		redirectWithFlash(w, r, "/admin/webhooks", "", "update failed: "+sanitizeErr(err))
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		redirectWithFlash(w, r, "/admin/webhooks", "", "delivery not found or already pending")
		return
	}
	redirectWithFlash(w, r, "/admin/webhooks", "Delivery queued for retry", "")
}

// WebhooksTest POST /admin/webhooks/{id}/test — emits a synthetic event so
// the operator can confirm signature + delivery before relying on it.
func (h *AdminHandlers) WebhooksTest(w http.ResponseWriter, r *http.Request) {
	if h.Webhooks == nil {
		http.Error(w, "webhook service not wired", http.StatusServiceUnavailable)
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	// Insert a "test" delivery directly addressed at this endpoint.
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	_, _ = db.ExecContext(ctx,
		`INSERT INTO webhook_deliveries (endpoint_id, event_type, payload, status, next_retry_at)
		 VALUES (?, 'panel.test', JSON_OBJECT('event','panel.test','data', JSON_OBJECT('ok',true)), 'pending', NOW())`,
		id)
	// Kick the dispatcher synchronously so the operator sees outcome immediately.
	h.Webhooks.Dispatch(ctx)
	redirectWithFlash(w, r, "/admin/webhooks", "test event queued + dispatched", "")
}

// WebhooksRotateSecret POST /admin/webhooks/{id}/rotate-secret — replaces the
// signing secret with a fresh 64-char hex value; shows plaintext once via flash.
func (h *AdminHandlers) WebhooksRotateSecret(w http.ResponseWriter, r *http.Request) {
	if h.Webhooks == nil || h.Webhooks.State == nil {
		http.Error(w, "webhook service not wired", http.StatusServiceUnavailable)
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	db := h.DB()
	if db == nil || id == 0 {
		http.Error(w, "not ready", http.StatusServiceUnavailable)
		return
	}
	// Generate 32 random bytes, hex-encoded = 64-char secret.
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		http.Error(w, "rng failed", http.StatusInternalServerError)
		return
	}
	secret := hex.EncodeToString(raw)
	enc, err := h.Webhooks.State.Encrypt(secret)
	if err != nil {
		http.Error(w, "encrypt failed", http.StatusInternalServerError)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if _, err := db.ExecContext(ctx,
		"UPDATE webhook_endpoints SET secret_enc=?, updated_at=NOW() WHERE id=?", enc, id); err != nil {
		redirectWithFlash(w, r, "/admin/webhooks", "", "rotate failed: "+sanitizeErr(err))
		return
	}
	sess := middleware.SessionFromContext(r.Context())
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "webhook.rotate_secret", Entity: "webhook_endpoint",
		EntityID: strconv.FormatInt(id, 10),
	})
	// Plaintext shown exactly once via flash; never persisted.
	redirectWithFlash(w, r, "/admin/webhooks", "New signing secret (save now, shown once): "+secret, "")
}
