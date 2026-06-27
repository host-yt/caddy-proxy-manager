package handlers

import (
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
