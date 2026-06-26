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
//	      "route_id":  42                          // optional; must be a route served by THIS node, else dropped
//	    }
//	  ]
//	}
//
// Auth: Bearer <node_agent_token> (same per-node token used by /api/node/wg/*
// and /api/node/geoip/*). No separate ingest token or new migration needed.
// A batch may contain up to maxWAFBatchSize events; excess events are rejected
// and the response body indicates the accepted count.

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/host-yt/caddy-proxy-manager/internal/security"
	"github.com/host-yt/caddy-proxy-manager/internal/wafevents"
)

const maxWAFBatchSize = 500

// validSeverities and validActions constrain free-text fields to known values.
var (
	validSeverities = map[string]struct{}{"low": {}, "medium": {}, "high": {}, "critical": {}}
	validActions    = map[string]struct{}{"detected": {}, "blocked": {}}
)

// NodeWAFIngestHandler receives WAF events from node-local custom Caddy modules.
type NodeWAFIngestHandler struct {
	DB        func() *sql.DB
	WAFEvents *wafevents.Store
	Logger    *slog.Logger
}

// authNode verifies the per-node bearer token against caddy_nodes.agent_token_hash.
// Returns the validated nodeID (>0) or 0 on failure (HTTP error already written).
func (h *NodeWAFIngestHandler) authNode(w http.ResponseWriter, r *http.Request) int64 {
	token := strings.TrimSpace(r.URL.Query().Get("node_token"))
	if token == "" {
		auth := r.Header.Get("Authorization")
		if strings.HasPrefix(auth, "Bearer ") {
			token = strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
		}
	}
	if token == "" {
		http.Error(w, "missing node_token", http.StatusUnauthorized)
		return 0
	}
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return 0
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	var nodeID int64
	if err := db.QueryRowContext(ctx,
		`SELECT id FROM caddy_nodes WHERE agent_token_hash IS NOT NULL AND agent_token_hash = SHA2(?, 256) LIMIT 1`,
		token).Scan(&nodeID); err != nil {
		h.Logger.Warn("waf ingest node token mismatch", "ip", security.ClientIP(r), "token_prefix", safePrefix(token))
		http.Error(w, "denied", http.StatusForbidden)
		return 0
	}
	return nodeID
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

// Ingest handles POST /api/node/waf/events.
func (h *NodeWAFIngestHandler) Ingest(w http.ResponseWriter, r *http.Request) {
	nodeID := h.authNode(w, r)
	if nodeID == 0 {
		return
	}
	if h.WAFEvents == nil {
		http.Error(w, "waf store unavailable", http.StatusServiceUnavailable)
		return
	}

	// Cap body sized to the batch limit (~few KB/event) to bound memory before parse.
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	items, err := decodeWAFBatch(r.Body)
	if err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	accepted := 0
	for _, item := range items {
		e, ok := toWAFEvent(item)
		if !ok {
			continue // skip items missing required fields or with invalid values
		}
		// Never trust a client-supplied route_id: only associate when the route is
		// served by THIS node; otherwise null it to avoid cross-tenant pollution/eviction.
		if e.RouteID.Valid && !h.routeOwnedByNode(ctx, e.RouteID.Int64, nodeID) {
			e.RouteID = sql.NullInt64{}
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

// routeOwnedByNode reports whether routeID is a route served by nodeID.
func (h *NodeWAFIngestHandler) routeOwnedByNode(ctx context.Context, routeID, nodeID int64) bool {
	db := h.DB()
	if db == nil {
		return false
	}
	var one int
	err := db.QueryRowContext(ctx,
		`SELECT 1 FROM routes WHERE id = ? AND caddy_node_id = ? LIMIT 1`,
		routeID, nodeID).Scan(&one)
	return err == nil
}

// decodeWAFBatch stream-decodes the {"events":[...]} body one element at a time,
// stopping after maxWAFBatchSize so an oversized array is never fully buffered.
func decodeWAFBatch(body io.Reader) ([]wafIngestItem, error) {
	dec := json.NewDecoder(body)
	// Expect the opening object brace.
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	var items []wafIngestItem
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return nil, err
		}
		name, _ := key.(string)
		if name != "events" {
			// Skip any other top-level value without buffering the array.
			var skip json.RawMessage
			if err := dec.Decode(&skip); err != nil {
				return nil, err
			}
			continue
		}
		// Opening array bracket.
		if _, err := dec.Token(); err != nil {
			return nil, err
		}
		for dec.More() {
			if len(items) >= maxWAFBatchSize {
				// Stop reading; excess events are rejected, not buffered.
				return items, nil
			}
			var item wafIngestItem
			if err := dec.Decode(&item); err != nil {
				return nil, err
			}
			items = append(items, item)
		}
		// Closing array bracket.
		if _, err := dec.Token(); err != nil {
			return nil, err
		}
	}
	return items, nil
}

// toWAFEvent maps one ingest item to wafevents.Event, returning false when
// required fields are missing or severity/action are not in the allowed set.
func toWAFEvent(item wafIngestItem) (wafevents.Event, bool) {
	if item.Severity == "" || item.RuleID == "" || item.Action == "" || item.TS == "" {
		return wafevents.Event{}, false
	}
	if _, ok := validSeverities[item.Severity]; !ok {
		return wafevents.Event{}, false
	}
	if _, ok := validActions[item.Action]; !ok {
		return wafevents.Event{}, false
	}

	ts, err := time.Parse(time.RFC3339, item.TS)
	if err != nil {
		// A malformed timestamp is a permanent data error - skip rather than guess.
		return wafevents.Event{}, false
	}

	e := wafevents.Event{
		TS:       ts,
		Severity: item.Severity,
		RuleID:   trunc(item.RuleID, 128),
		Action:   item.Action,
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

// trunc caps s to at most n bytes on a rune boundary so a multi-byte rune is
// never cut mid-sequence (invalid utf8mb4 would otherwise reject the INSERT).
func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for len(s) > 0 && !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}
