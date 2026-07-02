package handlers

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/host-yt/caddy-proxy-manager/internal/view"
)

// StatusPageHandlers serves the public per-client status page.
// No auth, no sessions - only a slug lookup.
type StatusPageHandlers struct {
	DB        func() *sql.DB
	Templates *view.StatusTemplates
	Logger    *slog.Logger
}

type statusRouteRow struct {
	Domain     string
	PathPrefix string
	Status     string // active | pending_dns | dns_ok | pending_ssl | failed | disabled
	SSL        bool
	NodeHealth string  // healthy | degraded | down | unknown
	UptimePct  float64 // 0-100, heuristic from status
	UpdatedAt  time.Time
}

type statusTunnelRow struct {
	Name            string
	AssignedIP      string
	Status          string // active | pending | revoked
	LastHandshakeAt *time.Time
	HandshakeStale  bool // true when >3 min or NULL
	RxBytes         uint64
	TxBytes         uint64
}

type statusPageData struct {
	ClientName  string
	GeneratedAt time.Time
	AllUp       bool
	ShowTraffic bool
	// Brand carries the reseller overlay for a reseller-owned client (empty =
	// global default; the template falls back to just the client name).
	Brand Branding
	Routes      []statusRouteRow
	Tunnels     []statusTunnelRow
	// Pre-serialised for inline sparkline (14-day per-node request deltas).
	TrafficLabels template.JS
	TrafficValues template.JS
}

// Page handles GET /status/{slug} - public, no auth.
func (h *StatusPageHandlers) Page(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "slug")
	if len(slug) != 32 || !isHex(slug) {
		http.NotFound(w, r)
		return
	}
	db := h.DB()
	if db == nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	var clientID int64
	var clientName string
	var showTraffic bool
	var resellerID sql.NullInt64
	err := db.QueryRowContext(ctx,
		`SELECT c.id, COALESCE(c.display_name, u.full_name, u.email), c.status_show_traffic, c.reseller_id
		 FROM clients c JOIN users u ON u.id = c.user_id
		 WHERE c.status_slug = ? AND u.is_active = 1`,
		slug,
	).Scan(&clientID, &clientName, &showTraffic, &resellerID)
	if err == sql.ErrNoRows {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		h.Logger.Error("status page client lookup", "err", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}

	d := statusPageData{
		ClientName:  clientName,
		GeneratedAt: time.Now().UTC(),
		ShowTraffic: showTraffic,
	}
	// White-label: a reseller-owned client shows its reseller's brand.
	if resellerID.Valid && resellerID.Int64 > 0 {
		d.Brand = LoadBrandingFor(ctx, db, resellerID.Int64)
	}
	d.Routes = h.loadRoutes(ctx, db, clientID)
	d.Tunnels = h.loadTunnels(ctx, db, clientID)
	if showTraffic {
		d.TrafficLabels, d.TrafficValues = h.trafficSparkline(ctx, db, clientID)
	}
	d.AllUp = allUp(d.Routes, d.Tunnels)

	w.Header().Set("Cache-Control", "public, max-age=30")
	w.Header().Set("X-Robots-Tag", "noindex")

	var buf bytes.Buffer
	if err := h.Templates.Render(&buf, "status_page", d); err != nil {
		h.Logger.Error("status page render", "err", err)
		http.Error(w, "render error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(buf.Bytes())
}

func (h *StatusPageHandlers) loadRoutes(
	ctx context.Context, db *sql.DB, clientID int64,
) []statusRouteRow {
	rows, err := db.QueryContext(ctx,
		`SELECT r.domain, COALESCE(r.path_prefix,''), r.status,
		        r.ssl_enabled, n.health_status, r.updated_at
		 FROM routes r
		 JOIN services s    ON s.id = r.service_id
		 JOIN caddy_nodes n ON n.id = r.caddy_node_id
		 WHERE s.client_id = ?
		   AND r.status != 'disabled'
		 ORDER BY r.domain, r.path_prefix`,
		clientID,
	)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []statusRouteRow
	for rows.Next() {
		var rr statusRouteRow
		if err := rows.Scan(
			&rr.Domain, &rr.PathPrefix, &rr.Status,
			&rr.SSL, &rr.NodeHealth, &rr.UpdatedAt,
		); err == nil {
			rr.UptimePct = uptimePctForStatus(rr.Status)
			out = append(out, rr)
		}
	}
	return out
}

// uptimePctForStatus is a coarse heuristic until a probes table exists.
func uptimePctForStatus(s string) float64 {
	switch s {
	case "active":
		return 100
	case "pending_ssl":
		return 95
	case "dns_ok":
		return 80
	case "pending_dns":
		return 50
	default:
		return 0
	}
}

func (h *StatusPageHandlers) loadTunnels(
	ctx context.Context, db *sql.DB, clientID int64,
) []statusTunnelRow {
	rows, err := db.QueryContext(ctx,
		`SELECT p.name, p.assigned_ip, p.status,
		        p.last_handshake_at, p.rx_bytes, p.tx_bytes
		 FROM customer_wg_peer p
		 WHERE p.client_id = ? AND p.status != 'revoked'
		 ORDER BY p.name`,
		clientID,
	)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []statusTunnelRow
	for rows.Next() {
		var tr statusTunnelRow
		var lastHS sql.NullTime
		var rx, tx sql.NullInt64
		if err := rows.Scan(
			&tr.Name, &tr.AssignedIP, &tr.Status,
			&lastHS, &rx, &tx,
		); err == nil {
			if lastHS.Valid {
				t := lastHS.Time
				tr.LastHandshakeAt = &t
				tr.HandshakeStale = time.Since(t) > 3*time.Minute
			} else {
				tr.HandshakeStale = true
			}
			if rx.Valid {
				tr.RxBytes = uint64(rx.Int64)
			}
			if tx.Valid {
				tr.TxBytes = uint64(tx.Int64)
			}
			out = append(out, tr)
		}
	}
	return out
}

// trafficSparkline sums 14-day per-node request deltas for nodes serving this client.
// Note: node_traffic_samples is global; figures are per-node totals, not per-client.
func (h *StatusPageHandlers) trafficSparkline(
	ctx context.Context, db *sql.DB, clientID int64,
) (template.JS, template.JS) {
	nrows, err := db.QueryContext(ctx,
		`SELECT DISTINCT r.caddy_node_id
		 FROM routes r JOIN services s ON s.id=r.service_id
		 WHERE s.client_id = ?`, clientID)
	if err != nil || nrows == nil {
		return "[]", "[]"
	}
	var nodeIDs []int64
	for nrows.Next() {
		var id int64
		if err := nrows.Scan(&id); err == nil {
			nodeIDs = append(nodeIDs, id)
		}
	}
	nrows.Close()
	if len(nodeIDs) == 0 {
		return "[]", "[]"
	}

	// nodeIDs are int64 from DB - no injection risk building the IN clause.
	inClause := make([]string, len(nodeIDs))
	args := make([]any, len(nodeIDs))
	for i, id := range nodeIDs {
		inClause[i] = "?"
		args[i] = id
	}
	q := fmt.Sprintf(
		`SELECT FLOOR(UNIX_TIMESTAMP(sampled_at)/86400)*86400 AS day,
		        node_id,
		        MAX(requests_total) - MIN(requests_total) AS delta
		 FROM node_traffic_samples
		 WHERE node_id IN (%s) AND sampled_at > NOW() - INTERVAL 14 DAY
		 GROUP BY day, node_id`,
		strings.Join(inClause, ","),
	)
	srows, err := db.QueryContext(ctx, q, args...)
	buckets := map[int64]uint64{}
	if err == nil {
		defer srows.Close()
		for srows.Next() {
			var day, nodeID int64
			var delta uint64
			if srows.Scan(&day, &nodeID, &delta) == nil {
				buckets[day] += delta
			}
		}
	}

	labels := make([]string, 14)
	values := make([]uint64, 14)
	now := time.Now().UTC().Truncate(24 * time.Hour)
	for i := 13; i >= 0; i-- {
		t := now.Add(-time.Duration(i) * 24 * time.Hour)
		labels[13-i] = t.Format("Jan 2")
		values[13-i] = buckets[t.Unix()]
	}
	return template.JS(statusMustJSON(labels)), template.JS(statusMustJSON(values))
}

func allUp(routes []statusRouteRow, tunnels []statusTunnelRow) bool {
	for _, r := range routes {
		if r.Status != "active" && r.Status != "pending_ssl" {
			return false
		}
		if r.NodeHealth == "down" {
			return false
		}
	}
	for _, t := range tunnels {
		if t.HandshakeStale {
			return false
		}
	}
	return true
}

func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// statusMustJSON marshals v to JSON; returns "[]" on error.
// Separate from handlers.mustJSON to avoid cross-file name collision.
func statusMustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "[]"
	}
	return string(b)
}
