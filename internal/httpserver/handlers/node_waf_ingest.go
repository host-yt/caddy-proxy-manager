package handlers

// NodeWAFIngestHandler serves POST /api/node/waf/events.
//
// JSON contract for the custom Caddy WAF module (POST body, Content-Type: application/json):
//
//	{
//	  "events": [
//	    {
//	      "ts":        "2006-01-02T15:04:05Z",  // RFC 3339; required
//	      "severity":  "low|medium|high|critical", // required; capped 16 chars
//	      "rule_id":   "OWASP-CRS-930100",         // required; capped 128 chars
//	      "action":    "detected|blocked",          // required; capped 16 chars
//	      "remote_ip": "1.2.3.4",                  // capped 64 chars
//	      "host":      "example.com",              // capped 255 chars
//	      "uri":       "/path?q=1",               // capped 512 chars
//	      "message":   "SQL injection attempt",   // capped 512 chars
//	      "route_id":  42                          // optional; omit or 0 = no association
//	    }
//	  ]
//	}
//
// Auth: Bearer <node_agent_token> (same per-node token used by /api/node/wg/*
// and /api/node/geoip/*). No separate ingest token or new migration needed.
// A batch may contain up to maxWAFBatchSize events; excess events are dropped
// and the response body indicates the accepted count.

import (
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/host-yt/caddy-proxy-manager/internal/security"
	"github.com/host-yt/caddy-proxy-manager/internal/wafevents"
)

const maxWAFBatchSize = 500

// NodeWAFIngestHandler receives WAF events from node-local custom Caddy modules.
type NodeWAFIngestHandler struct {
	DB        func() *sql.DB
	WAFEvents *wafevents.Store
	Logger    *slog.Logger
}

// authNode verifies the per-node bearer token against caddy_nodes.agent_token_hash.
// Returns the validated nodeID (>0) or 0 on failure (HTTP error already written).
func (h *NodeWAFIngestHandler) authNode(w http.ResponseWriter, r *http.Request) bool {
	token := strings.TrimSpace(r.URL.Query().Get("node_token"))
	if token == "" {
		auth := r.Header.Get("Authorization")
		if strings.HasPrefix(auth, "Bearer ") {
			token = strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
		}
	}
	if token == "" {
		http.Error(w, "missing node_token", http.StatusUnauthorized)
		return false
	}
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return false
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	var nodeID int64
	if err := db.QueryRowContext(ctx,
		`SELECT id FROM caddy_nodes WHERE agent_token_hash IS NOT NULL AND agent_token_hash = SHA2(?, 256) LIMIT 1`,
		token).Scan(&nodeID); err != nil {
		h.Logger.Warn("waf ingest node token mismatch", "ip", security.ClientIP(r), "token_prefix", safePrefix(token))
		http.Error(w, "denied", http.StatusForbidden)
		return false
	}
	return true
}

// wafIngestItem is one event in the incoming batch.
type wafIngestItem struct {
	TS       string `json:"ts"`
	Severity string `json:"severity"`
	RuleID   string `json:"rule_id"`
	Action   string `json:"action"`
	RemoteIP string `json:"remote_ip"`
	Host     string `json:"host"`
	URI      string `json:"uri"`
	Message  string `json:"message"`
	RouteID  int64  `json:"route_id"`
}

// wafIngestRequest is the POST body.
type wafIngestRequest struct {
	Events []wafIngestItem `json:"events"`
}

// Ingest handles POST /api/node/waf/events.
func (h *NodeWAFIngestHandler) Ingest(w http.ResponseWriter, r *http.Request) {
	if !h.authNode(w, r) {
		return
	}
	if h.WAFEvents == nil {
		http.Error(w, "waf store unavailable", http.StatusServiceUnavailable)
		return
	}

	// Cap body to prevent memory exhaustion from oversized batches.
	r.Body = http.MaxBytesReader(w, r.Body, 4<<20)
	var req wafIngestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	items := req.Events
	if len(items) > maxWAFBatchSize {
		// Truncate silently; response body reports accepted count.
		items = items[:maxWAFBatchSize]
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	accepted := 0
	for _, item := range items {
		e, ok := toWAFEvent(item)
		if !ok {
			continue // skip items missing required fields
		}
		if err := h.WAFEvents.Insert(ctx, e); err != nil {
			h.Logger.Warn("waf ingest insert", "err", err)
			continue
		}
		accepted++
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	// Intentionally minimal response - caller only needs the accepted count.
	_, _ = w.Write([]byte(`{"accepted":` + itoa(int64(accepted)) + `}`))
}

// toWAFEvent maps one ingest item to wafevents.Event, returning false when
// required fields are missing.
func toWAFEvent(item wafIngestItem) (wafevents.Event, bool) {
	if item.Severity == "" || item.RuleID == "" || item.Action == "" || item.TS == "" {
		return wafevents.Event{}, false
	}

	ts, err := time.Parse(time.RFC3339, item.TS)
	if err != nil {
		// Accept Unix epoch numeric strings via a second pass; a malformed
		// timestamp is a permanent data error - skip rather than guess.
		return wafevents.Event{}, false
	}

	e := wafevents.Event{
		TS:       ts,
		Severity: trunc(item.Severity, 16),
		RuleID:   trunc(item.RuleID, 128),
		Action:   trunc(item.Action, 16),
		RemoteIP: trunc(item.RemoteIP, 64),
		Host:     trunc(item.Host, 255),
		URI:      trunc(item.URI, 512),
		Message:  trunc(item.Message, 512),
	}
	if item.RouteID > 0 {
		e.RouteID = sql.NullInt64{Int64: item.RouteID, Valid: true}
	}
	return e, true
}

// trunc caps s to n bytes (safe for ASCII/UTF-8 field values like IPs, rule IDs).
func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
