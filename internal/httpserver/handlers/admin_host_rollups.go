package handlers

import (
	"encoding/csv"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
)

// HostsRollupJSON serves GET /admin/hosts/{id}/rollups.json?window=24h|7d|30d.
// Returns a summary and hourly series over the requested window from log_rollups.
func (h *AdminHandlers) HostsRollupJSON(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if id == 0 || h.AccessLogs == nil {
		apiJSON(w, http.StatusOK, map[string]any{"summary": nil, "series": []any{}})
		return
	}
	ctx := r.Context()
	sess := middleware.SessionFromContext(ctx)
	if !h.scopeCheckRoute(ctx, sess, id) {
		apiJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
		return
	}

	// Parse window; default 24h.
	window := 24 * time.Hour
	switch r.URL.Query().Get("window") {
	case "7d":
		window = 7 * 24 * time.Hour
	case "30d":
		window = 30 * 24 * time.Hour
	}

	now := time.Now().UTC()
	since := now.Add(-window)

	summary, err := h.AccessLogs.RollupSummary(ctx, id, since)
	if err != nil {
		h.Logger.Warn("host rollup summary", "id", id, "err", err)
		apiJSON(w, http.StatusInternalServerError, map[string]string{"error": "query failed"})
		return
	}

	series, err := h.AccessLogs.RollupSeries(ctx, id, since, now)
	if err != nil {
		h.Logger.Warn("host rollup series", "id", id, "err", err)
		apiJSON(w, http.StatusInternalServerError, map[string]string{"error": "query failed"})
		return
	}

	type bucketRow struct {
		BucketStart  string `json:"bucket_start"`
		Requests     int64  `json:"requests"`
		Errors4xx    int64  `json:"errors_4xx"`
		Errors5xx    int64  `json:"errors_5xx"`
		LatencySumMs int64  `json:"latency_sum_ms"`
		LatencyMaxMs int64  `json:"latency_max_ms"`
		BytesResp    int64  `json:"bytes_resp"`
	}
	type summaryRow struct {
		Requests     int64 `json:"requests"`
		Errors4xx    int64 `json:"errors_4xx"`
		Errors5xx    int64 `json:"errors_5xx"`
		LatencySumMs int64 `json:"latency_sum_ms"`
		LatencyMaxMs int64 `json:"latency_max_ms"`
		BytesResp    int64 `json:"bytes_resp"`
	}

	rows := make([]bucketRow, 0, len(series))
	for _, b := range series {
		rows = append(rows, bucketRow{
			BucketStart:  b.BucketStart.UTC().Format(time.RFC3339),
			Requests:     b.Requests,
			Errors4xx:    b.Errors4xx,
			Errors5xx:    b.Errors5xx,
			LatencySumMs: b.LatencySumMs,
			LatencyMaxMs: b.LatencyMaxMs,
			BytesResp:    b.BytesResp,
		})
	}

	apiJSON(w, http.StatusOK, map[string]any{
		"window": r.URL.Query().Get("window"),
		"summary": summaryRow{
			Requests:     summary.Requests,
			Errors4xx:    summary.Errors4xx,
			Errors5xx:    summary.Errors5xx,
			LatencySumMs: summary.LatencySumMs,
			LatencyMaxMs: summary.LatencyMaxMs,
			BytesResp:    summary.BytesResp,
		},
		"series": rows,
	})
}

// HostsRollupCSV serves GET /admin/hosts/{id}/rollups.csv?window=24h|7d|30d.
func (h *AdminHandlers) HostsRollupCSV(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if id == 0 || h.AccessLogs == nil {
		http.Error(w, "not available", http.StatusServiceUnavailable)
		return
	}
	ctx := r.Context()
	sess := middleware.SessionFromContext(ctx)
	if !h.scopeCheckRoute(ctx, sess, id) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	// Default window 30d for CSV export.
	window := 30 * 24 * time.Hour
	switch r.URL.Query().Get("window") {
	case "24h":
		window = 24 * time.Hour
	case "7d":
		window = 7 * 24 * time.Hour
	}

	now := time.Now().UTC()
	since := now.Add(-window)

	series, err := h.AccessLogs.RollupSeries(ctx, id, since, now)
	if err != nil {
		h.Logger.Warn("host rollup csv", "id", id, "err", err)
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}

	filename := fmt.Sprintf("rollup-%d.csv", id)
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)

	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"bucket_start", "requests", "errors_4xx", "errors_5xx", "latency_avg_ms", "latency_max_ms", "bytes_resp"})
	for i, b := range series {
		avg := int64(0)
		if b.Requests > 0 {
			avg = b.LatencySumMs / b.Requests
		}
		_ = cw.Write([]string{
			b.BucketStart.UTC().Format(time.RFC3339),
			strconv.FormatInt(b.Requests, 10),
			strconv.FormatInt(b.Errors4xx, 10),
			strconv.FormatInt(b.Errors5xx, 10),
			strconv.FormatInt(avg, 10),
			strconv.FormatInt(b.LatencyMaxMs, 10),
			strconv.FormatInt(b.BytesResp, 10),
		})
		if (i+1)%100 == 0 {
			cw.Flush()
		}
	}
	cw.Flush()
}
