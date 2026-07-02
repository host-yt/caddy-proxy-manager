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
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/host-yt/caddy-proxy-manager/internal/security"
	"github.com/host-yt/caddy-proxy-manager/internal/wafevents"
)

const maxWAFBatchSize = 500

// wafSeenKeep caps the dedup ledger to its newest N rows. Chosen well above the
// visible event ceiling (maxPerRoute=10k per route) so a replay can never re-show
// a still-visible event, yet bounded (~8MB). The durable offset
// (HPG_AGENT_STATE_DIR) is the primary replay guard; this ledger is the backstop.
const wafSeenKeep = 100_000

// wafSeenPruneEvery throttles the ledger prune so it runs ~hourly, not per batch.
const wafSeenPruneEvery = time.Hour

// wafSeenLastPrune is the unix-seconds timestamp of the last ledger prune.
var wafSeenLastPrune atomic.Int64

// validSeverities and validActions constrain free-text fields to known values.
var (
	validSeverities = map[string]struct{}{"low": {}, "medium": {}, "high": {}, "critical": {}}
	validActions    = map[string]struct{}{"detected": {}, "blocked": {}}
)

// wafMetrics is the subset of obs.Metrics used by NodeWAFIngestHandler.
type wafMetrics interface {
	WAFEvent(severity, action string)
}

// NodeWAFIngestHandler receives WAF events from node-local custom Caddy modules.
type NodeWAFIngestHandler struct {
	DB        func() *sql.DB
	WAFEvents *wafevents.Store
	Logger    *slog.Logger
	Metrics   wafMetrics
}

// authNode verifies the per-node bearer token against caddy_nodes.agent_token_hash.
// Header only - a query-string token would leak into access/proxy logs (NODE_WG-03).
// Returns the validated nodeID (>0) or 0 on failure (HTTP error already written).
func (h *NodeWAFIngestHandler) authNode(w http.ResponseWriter, r *http.Request) int64 {
	token := ""
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		token = strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
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

	// Detach from the request context so the batch still commits if the node-agent
	// hits its own client timeout and disconnects mid-insert. Otherwise every
	// remaining insert failed with "context canceled", nothing committed, and the
	// node-agent re-shipped the same backlog forever (a self-sustaining loop).
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 30*time.Second)
	defer cancel()

	accepted := 0
	prunedRoutes := map[int64]struct{}{} // distinct routes to trim once after the batch
	for _, item := range items {
		e, ok := toWAFEvent(item)
		if !ok {
			continue // skip items missing required fields or with invalid values
		}
		// Attribute the event to a route on THIS node. Trust nothing from the
		// client: resolve server-side from the authenticated nodeID + the event's
		// host/uri (Coraza does not emit a route id). Unattributable events are
		// stored with NULL route_id. Correct attribution is what makes the
		// per-route WAF view, scoped-admin visibility, and per-route pruning work.
		if rid := h.resolveRoute(ctx, nodeID, item.Host, item.URI); rid > 0 {
			e.RouteID = sql.NullInt64{Int64: rid, Valid: true}
		} else {
			e.RouteID = sql.NullInt64{}
		}
		// Idempotent insert: a replay of an already-ingested line (or one cleared
		// by an operator) is silently dropped, never re-created.
		inserted, err := h.WAFEvents.InsertIfNew(ctx, e, wafEventKey(nodeID, e))
		if err != nil {
			h.Logger.Warn("waf ingest insert", "err", err)
			continue
		}
		if !inserted {
			continue // duplicate / replay / already cleared
		}
		if e.RouteID.Valid {
			prunedRoutes[e.RouteID.Int64] = struct{}{}
		}
		if h.Metrics != nil {
			h.Metrics.WAFEvent(e.Severity, e.Action)
		}
		accepted++
	}

	// Prune once per distinct route, not per event: the maxPerRoute sort is far
	// too slow to run 500x within the ingest window.
	for rid := range prunedRoutes {
		if err := h.WAFEvents.PruneRoute(ctx, rid); err != nil {
			h.Logger.Warn("waf ingest prune route", "route_id", rid, "err", err)
		}
	}

	h.maybePruneSeen()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	// Intentionally minimal response - caller only needs the accepted count.
	_, _ = w.Write([]byte(`{"accepted":` + itoa(int64(accepted)) + `}`))
}

// wafEventKey is the stable dedup identity of one event from one node. It must be
// deterministic across re-deliveries of the same Coraza audit line so the panel
// can drop replays. route_id is excluded on purpose: it is resolved server-side
// and may change over time, but the same line is still the same event.
func wafEventKey(nodeID int64, e wafevents.Event) string {
	const sep = "\x1f" // unit separator: cannot appear in the parsed fields
	parts := []string{
		strconv.FormatInt(nodeID, 10),
		e.TS.UTC().Format(time.RFC3339),
		e.RuleID, e.Action, e.RemoteIP, e.Host, e.URI, e.Message,
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, sep)))
	return hex.EncodeToString(sum[:])
}

// maybePruneSeen prunes the dedup ledger at most once per wafSeenPruneEvery,
// off the request path. The CAS guard means concurrent ingests never double-run.
func (h *NodeWAFIngestHandler) maybePruneSeen() {
	if h.WAFEvents == nil {
		return
	}
	now := time.Now()
	last := wafSeenLastPrune.Load()
	if last != 0 && now.Unix()-last < int64(wafSeenPruneEvery/time.Second) {
		return
	}
	if !wafSeenLastPrune.CompareAndSwap(last, now.Unix()) {
		return // another request is pruning
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := h.WAFEvents.PruneSeen(ctx, wafSeenKeep); err != nil {
			h.Logger.Warn("waf seen-ledger prune", "err", err)
		}
	}()
}

// resolveRoute maps a WAF event to a route served by nodeID, using the event's
// Host header and request path. Returns 0 when no route on this node matches.
// Server-side + nodeID-scoped so a node can never attribute events to another
// node's routes. For path-routed domains it prefers the longest matching
// path_prefix, falling back to a bare-domain (” or '/') route.
func (h *NodeWAFIngestHandler) resolveRoute(ctx context.Context, nodeID int64, host, uri string) int64 {
	db := h.DB()
	if db == nil {
		return 0
	}
	host = strings.ToLower(strings.TrimSpace(host))
	if i := strings.IndexByte(host, ':'); i >= 0 {
		host = host[:i] // strip :port
	}
	if host == "" {
		return 0
	}
	path := uri
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	rows, err := db.QueryContext(ctx,
		`SELECT id, COALESCE(path_prefix,'') FROM routes
		   WHERE caddy_node_id = ? AND status <> 'disabled' AND LOWER(domain) = ?
		   ORDER BY CHAR_LENGTH(COALESCE(path_prefix,'')) DESC`, nodeID, host)
	if err != nil {
		return 0
	}
	defer rows.Close()
	var fallback int64
	for rows.Next() {
		var id int64
		var pp string
		if rows.Scan(&id, &pp) != nil {
			continue
		}
		if pp == "" || pp == "/" {
			if fallback == 0 {
				fallback = id
			}
			continue
		}
		if strings.HasPrefix(path, pp) {
			return id // longest prefix first (ORDER BY length DESC)
		}
	}
	return fallback
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
