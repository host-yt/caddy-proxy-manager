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
)

type webhookRow struct {
	ID      int64
	Name    string
	URL     string
	Events  string
	Enabled bool
	Created string
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
		`SELECT id, name, url, events, is_enabled, DATE_FORMAT(created_at,'%Y-%m-%d')
		 FROM webhook_endpoints ORDER BY id DESC`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var r webhookRow
			if err := rows.Scan(&r.ID, &r.Name, &r.URL, &r.Events, &r.Enabled, &r.Created); err == nil {
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
		redirectWithFlash(w, r, "/admin/webhooks", "", "save failed: "+err.Error())
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
		redirectWithFlash(w, r, "/admin/webhooks", "", "delete failed: "+err.Error())
		return
	}
	sess := middleware.SessionFromContext(r.Context())
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "webhook.delete", Entity: "webhook_endpoint",
		EntityID: strconv.FormatInt(id, 10),
	})
	redirectWithFlash(w, r, "/admin/webhooks", "deleted", "")
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
