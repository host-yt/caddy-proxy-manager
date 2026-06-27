package handlers

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/host-yt/caddy-proxy-manager/internal/accesslog"
	"github.com/host-yt/caddy-proxy-manager/internal/auth"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
)

var logsExportLimiter sync.Map

// hostLogsData drives the host_logs template.
type hostLogsData struct {
	baseAdminData
	RouteID         int64
	Domain          string
	Entries         []accesslog.Entry
	Filter          accesslog.Filter
	StatusBuckets   []accesslog.StatusBucket
	TopPaths        []accesslog.PathHit
	TopRemoteIPs    []accesslog.RemoteIPHit
	TopUserAgents   []accesslog.UserAgentHit
	TopMethods      []accesslog.MethodHit
	TopCountries    []accesslog.CountryHit
	Latency         accesslog.LatencyStats
	ErrorRateSeries []accesslog.ErrorRatePoint
	TrafficPoints   []accesslog.TrafficPoint
	AnalyticsTotal  int64
	ProtoBreakdown   []accesslog.ProtoHit
	BytesSummary     accesslog.BytesSummary
	TotalBandwidth7d int64
}

// parseLogsFilter reads filter query params from r.
func parseLogsFilter(r *http.Request) accesslog.Filter {
	q := r.URL.Query()
	var f accesslog.Filter
	f.StatusMin, _ = strconv.Atoi(q.Get("status_min"))
	f.StatusMax, _ = strconv.Atoi(q.Get("status_max"))
	f.Method = q.Get("method")
	f.RemoteIP = q.Get("remote_ip")
	f.URIPattern = q.Get("uri")
	if cc := strings.ToUpper(strings.TrimSpace(q.Get("country"))); len(cc) == 2 {
		f.Country = cc
	}
	if s := q.Get("from"); s != "" {
		f.From, _ = time.Parse("2006-01-02", s)
	}
	if s := q.Get("to"); s != "" {
		t, err := time.Parse("2006-01-02", s)
		if err == nil {
			f.To = t.Add(24*time.Hour - time.Second) // inclusive end of day
		}
	}
	return f
}

// hasFilter reports whether any filter field is set.
func hasFilter(f accesslog.Filter) bool {
	return f.StatusMin > 0 || f.StatusMax > 0 || f.Method != "" ||
		f.RemoteIP != "" || f.URIPattern != "" || f.Country != "" || !f.From.IsZero() || !f.To.IsZero()
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
	sess := middleware.SessionFromContext(r.Context())
	if !h.scopeCheckRoute(ctx, sess, id) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	_ = db.QueryRowContext(ctx, "SELECT domain FROM routes WHERE id = ?", id).Scan(&d.Domain)

	f := parseLogsFilter(r)
	d.Filter = f

	if h.AccessLogs != nil {
		var (
			entries []accesslog.Entry
			err     error
		)
		if hasFilter(f) {
			f.Limit = 200
			entries, err = h.AccessLogs.Filtered(ctx, id, f)
		} else {
			entries, err = h.AccessLogs.Recent(ctx, id, 100)
		}
		if err != nil {
			h.Logger.Warn("host logs query", "id", id, "err", err)
		}
		d.Entries = entries
		h.loadHostLogAnalytics(ctx, id, &d)
	}
	h.render(w, "host_logs", d)
}

func (h *AdminHandlers) loadHostLogAnalytics(ctx context.Context, routeID int64, d *hostLogsData) {
	if h.AccessLogs == nil || routeID == 0 {
		return
	}
	now := time.Now().UTC()
	f := accesslog.AnalyticsFilter{
		RouteID: routeID,
		From:    now.Add(-24 * time.Hour),
		To:      now,
		Step:    time.Hour,
	}

	buckets, err := h.AccessLogs.StatusBuckets(ctx, f)
	if err != nil {
		h.Logger.Warn("host logs status analytics", "id", routeID, "err", err)
	} else {
		d.StatusBuckets = buckets
		for _, b := range buckets {
			d.AnalyticsTotal += b.Count
		}
	}

	topPaths, err := h.AccessLogs.TopPaths(ctx, f, 5)
	if err != nil {
		h.Logger.Warn("host logs path analytics", "id", routeID, "err", err)
	} else {
		d.TopPaths = topPaths
	}

	topIPs, err := h.AccessLogs.TopRemoteIPs(ctx, f, 5)
	if err != nil {
		h.Logger.Warn("host logs remote ip analytics", "id", routeID, "err", err)
	} else {
		d.TopRemoteIPs = topIPs
	}

	topUAs, err := h.AccessLogs.TopUserAgents(ctx, f, 5)
	if err != nil {
		h.Logger.Warn("host logs user agent analytics", "id", routeID, "err", err)
	} else {
		d.TopUserAgents = topUAs
	}

	topMethods, err := h.AccessLogs.TopMethods(ctx, f, 10)
	if err != nil {
		h.Logger.Warn("host logs method analytics", "id", routeID, "err", err)
	} else {
		d.TopMethods = topMethods
	}

	topCountries, err := h.AccessLogs.TopCountries(ctx, f, 10)
	if err != nil {
		h.Logger.Warn("host logs country analytics", "id", routeID, "err", err)
	} else {
		d.TopCountries = topCountries
	}

	latency, err := h.AccessLogs.LatencyStats(ctx, f)
	if err != nil {
		h.Logger.Warn("host logs latency analytics", "id", routeID, "err", err)
	} else {
		d.Latency = latency
	}

	errSeries, err := h.AccessLogs.ErrorRateSeries(ctx, f)
	if err != nil {
		h.Logger.Warn("host logs error rate analytics", "id", routeID, "err", err)
	} else {
		if len(errSeries) > 12 {
			errSeries = errSeries[len(errSeries)-12:]
		}
		d.ErrorRateSeries = errSeries
	}

	points, err := h.AccessLogs.TrafficTimeseries(ctx, f)
	if err != nil {
		h.Logger.Warn("host logs traffic analytics", "id", routeID, "err", err)
		return
	}
	if len(points) > 12 {
		points = points[len(points)-12:]
	}
	d.TrafficPoints = points

	proto, err := h.AccessLogs.ProtoBreakdown(ctx, f)
	if err != nil {
		h.Logger.Warn("host logs proto analytics", "id", routeID, "err", err)
	} else {
		d.ProtoBreakdown = proto
	}

	bsum, err := h.AccessLogs.BytesSummary(ctx, f)
	if err != nil {
		h.Logger.Warn("host logs bytes analytics", "id", routeID, "err", err)
	} else {
		d.BytesSummary = bsum
	}

	// 7-day bandwidth from rollups (cheaper than scanning host_access_log).
	bw7d, err := h.AccessLogs.TotalBandwidthBytes(ctx, routeID, now.Add(-7*24*time.Hour), now)
	if err != nil {
		h.Logger.Warn("host logs bandwidth 7d", "id", routeID, "err", err)
	} else {
		d.TotalBandwidth7d = bw7d
	}
}

// HostsLogsJSON returns the last 100 entries as JSON for GET /admin/hosts/{id}/logs.json.
func (h *AdminHandlers) HostsLogsJSON(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if id == 0 || h.AccessLogs == nil {
		apiJSON(w, http.StatusOK, []any{})
		return
	}
	ctx := r.Context()
	sess := middleware.SessionFromContext(r.Context())
	if !h.scopeCheckRoute(ctx, sess, id) {
		apiJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
		return
	}
	entries, err := h.AccessLogs.Recent(ctx, id, 100)
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

// HostsLogsExport serves GET /admin/hosts/{id}/logs/export?format=csv|json
// with optional filter params. Max maxExportRows rows.
func (h *AdminHandlers) HostsLogsExport(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	format := r.URL.Query().Get("format")
	if format != "csv" && format != "json" {
		format = "csv"
	}
	if id == 0 || h.AccessLogs == nil {
		http.Error(w, "not available", http.StatusServiceUnavailable)
		return
	}
	ctx := r.Context()
	sess := middleware.SessionFromContext(r.Context())
	if !h.scopeCheckRoute(ctx, sess, id) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if !checkLogsExportRateLimit(logsExportLimiterKey(r, sess), time.Now()) {
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	f := parseLogsFilter(r)
	f.Limit = accesslog.MaxExportRows

	entries, err := h.AccessLogs.Filtered(ctx, id, f)
	if err != nil {
		h.Logger.Warn("host logs export", "id", id, "err", err)
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}

	// Resolve domain for filename.
	var domain string
	if db := h.DB(); db != nil {
		_ = db.QueryRowContext(ctx, "SELECT domain FROM routes WHERE id = ?", id).Scan(&domain)
	}
	if domain == "" {
		domain = strconv.FormatInt(id, 10)
	}

	if format == "csv" {
		filename := fmt.Sprintf("hosts-%d-logs.csv", id)
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
		cw := csv.NewWriter(w)
		_ = cw.Write([]string{"id", "ts", "method", "uri", "status", "latency_ms", "bytes_resp", "bytes_req", "proto", "country", "remote_ip", "user_agent"})
		for i, e := range entries {
			_ = cw.Write(csvSafeRow([]string{
				strconv.FormatInt(e.ID, 10),
				e.TS.UTC().Format(time.RFC3339Nano),
				e.Method,
				e.URI,
				strconv.Itoa(e.Status),
				strconv.Itoa(e.LatencyMS),
				strconv.FormatInt(e.BytesResp, 10),
				strconv.FormatInt(e.BytesReq, 10),
				e.Proto,
				e.Country,
				e.RemoteIP,
				e.UserAgent,
			}))
			if (i+1)%100 == 0 {
				cw.Flush()
			}
		}
		cw.Flush()
		return
	}

	// JSON streaming.
	filename := fmt.Sprintf("hosts-%d-logs.json", id)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	enc := json.NewEncoder(w)
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
	_ = enc.Encode(out)
}

// HostsLogsStream serves GET /admin/hosts/{id}/logs/stream as SSE.
// The client receives a "log" event for each new request forwarded by Caddy.
func (h *AdminHandlers) HostsLogsStream(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if id == 0 || h.AccessLogBroker == nil {
		http.Error(w, "not available", http.StatusServiceUnavailable)
		return
	}
	sess := middleware.SessionFromContext(r.Context())
	if !h.scopeCheckRoute(r.Context(), sess, id) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no") // disable Nginx buffering

	// Use ResponseController so we reach the underlying Flusher even when
	// outer middleware (request logger) wraps the ResponseWriter - a direct
	// w.(http.Flusher) cast fails through the wrapper and 500s the stream.
	rc := http.NewResponseController(w)
	if err := rc.Flush(); err != nil {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}
	// Clear the server WriteTimeout (30s) for this conn: it's an absolute
	// deadline from response start, so a long-lived SSE stream gets killed
	// mid-flight (Caddy then 502s the upstream -> browser ERR_HTTP2_PROTOCOL_ERROR).
	_ = rc.SetWriteDeadline(time.Time{})

	ch := h.AccessLogBroker.Subscribe(id)
	defer h.AccessLogBroker.Unsubscribe(id, ch)

	// heartbeat so the browser connection stays alive through idle periods.
	tick := time.NewTicker(25 * time.Second)
	defer tick.Stop()

	fmt.Fprint(w, "data: connected\n\n")
	rc.Flush()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-tick.C:
			fmt.Fprint(w, ": heartbeat\n\n")
			rc.Flush()
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
			rc.Flush()
		}
	}
}

func (h *AdminHandlers) scopeCheckRoute(ctx context.Context, sess *auth.Session, routeID int64) bool {
	if sess == nil || sess.Role == "super_admin" || h.AdminScope == nil {
		return true
	}
	ok, err := h.AdminScope.CanAccessRoute(ctx, sess.UserID, routeID)
	if err != nil {
		h.Logger.Warn("admin route scope check", "user_id", sess.UserID, "route_id", routeID, "err", err)
		return false
	}
	return ok
}

func logsExportLimiterKey(r *http.Request, sess *auth.Session) string {
	if sess != nil {
		if sess.CSRFToken != "" {
			return "sess:" + sess.CSRFToken
		}
		if sess.UserID > 0 {
			return "user:" + strconv.FormatInt(sess.UserID, 10)
		}
	}
	return "ip:" + r.RemoteAddr
}

func checkLogsExportRateLimit(key string, now time.Time) bool {
	if last, ok := logsExportLimiter.Load(key); ok {
		if t, ok := last.(time.Time); ok && now.Sub(t) < 10*time.Second {
			return false
		}
	}
	logsExportLimiter.Store(key, now)
	logsExportLimiter.Range(func(k, v any) bool {
		if t, ok := v.(time.Time); ok && now.Sub(t) > time.Hour {
			logsExportLimiter.Delete(k)
		}
		return true
	})
	return true
}
