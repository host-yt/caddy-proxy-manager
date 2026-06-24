package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/hostyt/proxy-gateway/internal/accesslog"
)

// hostLogsData drives the host_logs template.
type hostLogsData struct {
	baseAdminData
	RouteID int64
	Domain  string
	Entries []accesslog.Entry
}

// HostsLogs renders GET /admin/hosts/{id}/logs as an HTML page.
func (h *AdminHandlers) HostsLogs(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	d := hostLogsData{baseAdminData: h.base(r, "Access logs"), RouteID: id}
	db := h.DB()
	if db == nil || id == 0 {
		h.render(w, "host_logs", d)
		return
	}
	ctx := r.Context()
	_ = db.QueryRowContext(ctx, "SELECT domain FROM routes WHERE id = ?", id).Scan(&d.Domain)

	if h.AccessLogs != nil {
		entries, err := h.AccessLogs.Recent(ctx, id, 100)
		if err != nil {
			h.Logger.Warn("host logs query", "id", id, "err", err)
		}
		d.Entries = entries
	}
	h.render(w, "host_logs", d)
}

// HostsLogsJSON returns the last 100 entries as JSON for GET /admin/hosts/{id}/logs.json.
func (h *AdminHandlers) HostsLogsJSON(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if id == 0 || h.AccessLogs == nil {
		apiJSON(w, http.StatusOK, []any{})
		return
	}
	entries, err := h.AccessLogs.Recent(r.Context(), id, 100)
	if err != nil {
		h.Logger.Warn("host logs json", "id", id, "err", err)
		apiJSON(w, http.StatusInternalServerError, map[string]string{"error": "query failed"})
		return
	}
	type row struct {
		ID        int64  `json:"id"`
		TS        string `json:"ts"`
		Method    string `json:"method"`
		URI       string `json:"uri"`
		Status    int    `json:"status"`
		LatencyMS int    `json:"latency_ms"`
		RemoteIP  string `json:"remote_ip"`
		UserAgent string `json:"user_agent"`
	}
	out := make([]row, 0, len(entries))
	for _, e := range entries {
		out = append(out, row{
			ID:        e.ID,
			TS:        e.TS.UTC().Format(time.RFC3339Nano),
			Method:    e.Method,
			URI:       e.URI,
			Status:    e.Status,
			LatencyMS: e.LatencyMS,
			RemoteIP:  e.RemoteIP,
			UserAgent: e.UserAgent,
		})
	}
	apiJSON(w, http.StatusOK, out)
}

// HostsLogsStream serves GET /admin/hosts/{id}/logs/stream as SSE.
// The client receives a "log" event for each new request forwarded by Caddy.
func (h *AdminHandlers) HostsLogsStream(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if id == 0 || h.AccessLogBroker == nil {
		http.Error(w, "not available", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no") // disable Nginx buffering

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	ch := h.AccessLogBroker.Subscribe(id)
	defer h.AccessLogBroker.Unsubscribe(id, ch)

	// heartbeat so the browser connection stays alive through idle periods.
	tick := time.NewTicker(25 * time.Second)
	defer tick.Stop()

	fmt.Fprint(w, "data: connected\n\n")
	flusher.Flush()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-tick.C:
			fmt.Fprint(w, ": heartbeat\n\n")
			flusher.Flush()
		case e, ok := <-ch:
			if !ok {
				return
			}
			b, err := json.Marshal(map[string]any{
				"id":         e.ID,
				"ts":         e.TS.UTC().Format(time.RFC3339Nano),
				"method":     e.Method,
				"uri":        e.URI,
				"status":     e.Status,
				"latency_ms": e.LatencyMS,
				"remote_ip":  e.RemoteIP,
				"user_agent": e.UserAgent,
			})
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "event: log\ndata: %s\n\n", b)
			flusher.Flush()
		}
	}
}
