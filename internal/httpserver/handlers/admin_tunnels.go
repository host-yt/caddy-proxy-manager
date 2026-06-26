package handlers

import (
	"context"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/host-yt/caddy-proxy-manager/internal/audit"
	"github.com/host-yt/caddy-proxy-manager/internal/auth"
	"github.com/host-yt/caddy-proxy-manager/internal/domain/wgpeer"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
)

// ---- Customer tunnels (admin surface) -----------------------------

type tunnelRow struct {
	ID              int64
	Name            string
	ClientID        int64
	ClientEmail     string
	NodeID          int64
	NodeName        string
	AssignedIP      string
	Endpoint        string // peer's observed IP:port (from wg dump), "" if none
	Status          string
	LastHandshake   string // human-formatted, "—" if null
	RxHuman         string // received bytes this session, human-formatted
	TxHuman         string // transmitted bytes this session, human-formatted
	CumRxHuman      string // lifetime received (survives rekey/restart resets)
	CumTxHuman      string // lifetime transmitted
	Healthy         bool   // last handshake within the staleness window
	CreatedAt       string
	PeerGroupID     string // non-empty when this row is part of an HA group
	LastRotatedAt   sql.NullTime
	LastKeyRotation sql.NullTime
	KeyAgeHuman     string // "3d ago", "never rotated", etc.
}

// wgStaleAfter: a peer is "healthy" when its last handshake is within this
// window. WireGuard rekeys ~every 120s even with PersistentKeepalive=25, so a
// healthy tunnel's last handshake can legitimately be up to ~120s old; 180s
// avoids false "stale" while still flagging a down tunnel promptly.
const wgStaleAfter = 180 * time.Second

// keyAgeHuman returns a human-readable key age string.
// Uses last_rotated_at first, falls back to last_key_rotation_at.
func keyAgeHuman(lastRotated, lastKeyRotation sql.NullTime) string {
	t := lastRotated
	if !t.Valid {
		t = lastKeyRotation
	}
	if !t.Valid {
		return "never rotated"
	}
	d := time.Since(t.Time)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}

// formatBytes renders a byte count as a short human string (KB/MB/GB).
func formatBytes(n int64) string {
	const k = 1024
	switch {
	case n >= k*k*k:
		return strconv.FormatFloat(float64(n)/(k*k*k), 'f', 1, 64) + " GB"
	case n >= k*k:
		return strconv.FormatFloat(float64(n)/(k*k), 'f', 1, 64) + " MB"
	case n >= k:
		return strconv.FormatFloat(float64(n)/k, 'f', 1, 64) + " KB"
	default:
		return strconv.FormatInt(n, 10) + " B"
	}
}

type tunnelsData struct {
	baseAdminData
	Tunnels []tunnelRow
	Clients []clientOption
	Nodes   []nodeOption
	// NewTunnel carries data for the just-created wizard step (when set,
	// template surfaces the install-command panel).
	NewTunnel *newTunnelView
}

type clientOption struct {
	ID    int64
	Email string
}

type nodeOption struct {
	ID   int64
	Name string
}

type newTunnelView struct {
	PeerID         int64
	Name           string
	ClientEmail    string
	NodeName       string
	AssignedIP     string
	InstallCommand string
	ConfURL        string
	StatusURL      string
	Token          string
	ExpiresAt      string // RFC3339 — surfaced in UI so operator sees the cutoff
}

// TunnelsList renders /admin/tunnels.
func (h *AdminHandlers) TunnelsList(w http.ResponseWriter, r *http.Request) {
	d := tunnelsData{baseAdminData: h.base(r, "Customer tunnels")}
	db := h.DB()
	if db == nil {
		h.render(w, "tunnels", d)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	sess := middleware.SessionFromContext(r.Context())
	allowedClients, allClients, scopeOK := h.adminClientScope(ctx, sess)
	if !scopeOK {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	rows, err := db.QueryContext(ctx,
		`SELECT p.id, p.name, p.client_id, u.email, p.node_id, n.name,
		        p.assigned_ip, COALESCE(p.endpoint,''), p.status,
		        COALESCE(DATE_FORMAT(p.last_handshake_at,'%Y-%m-%d %H:%i'),''),
		        COALESCE(p.rx_bytes,0), COALESCE(p.tx_bytes,0),
		        COALESCE(p.cumulative_rx_bytes,0), COALESCE(p.cumulative_tx_bytes,0),
		        COALESCE(p.last_handshake_epoch,0),
		        DATE_FORMAT(p.created_at,'%Y-%m-%d %H:%i'),
		        COALESCE(p.peer_group_id,''),
		        p.last_rotated_at, p.last_key_rotation_at
		 FROM customer_wg_peer p
		 JOIN clients c ON c.id = p.client_id
		 JOIN users u   ON u.id = c.user_id
		 JOIN caddy_nodes n ON n.id = p.node_id
		 ORDER BY p.id DESC LIMIT 500`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var t tunnelRow
			var rx, tx, cumRx, cumTx, epoch int64
			if err := rows.Scan(&t.ID, &t.Name, &t.ClientID, &t.ClientEmail,
				&t.NodeID, &t.NodeName, &t.AssignedIP, &t.Endpoint, &t.Status,
				&t.LastHandshake, &rx, &tx, &cumRx, &cumTx, &epoch,
				&t.CreatedAt, &t.PeerGroupID,
				&t.LastRotatedAt, &t.LastKeyRotation); err == nil {
				if !allClients && !allowedClients[t.ClientID] {
					continue
				}
				if t.LastHandshake == "" {
					t.LastHandshake = "—"
				}
				t.RxHuman = formatBytes(rx)
				t.TxHuman = formatBytes(tx)
				t.CumRxHuman = formatBytes(cumRx)
				t.CumTxHuman = formatBytes(cumTx)
				if epoch > 0 {
					t.Healthy = time.Since(time.Unix(epoch, 0)) < wgStaleAfter
				}
				t.KeyAgeHuman = keyAgeHuman(t.LastRotatedAt, t.LastKeyRotation)
				d.Tunnels = append(d.Tunnels, t)
			}
		}
		if rErr := rows.Err(); rErr != nil {
			h.Logger.Error("tunnels list rows", "err", rErr)
		}
	}

	d.Clients = filterClientOptions(loadClientOptions(ctx, db), allowedClients, allClients)
	d.Nodes = loadTunnelNodeOptions(ctx, db)

	if tok := strings.TrimSpace(r.URL.Query().Get("created")); tok != "" {
		d.NewTunnel = h.lookupNewTunnel(ctx, db, r, tok)
	}

	h.render(w, "tunnels", d)
}

// TunnelsCreate handles POST /admin/tunnels: allocates peer + bootstrap
// token, redirects back to the list with ?created=<token> so the
// template surfaces the install command. Form field `ha=1` plus
// `node_ids` (repeated) triggers HA replication instead of single-node.
func (h *AdminHandlers) TunnelsCreate(w http.ResponseWriter, r *http.Request) {
	if h.WGPeers == nil {
		redirectWithFlash(w, r, "/admin/tunnels", "", "WG service not wired")
		return
	}
	_ = r.ParseForm()
	rawClient := strings.TrimSpace(r.FormValue("client_id"))
	name := strings.TrimSpace(r.FormValue("name"))
	var clientID int64
	if rawClient == "self" {
		// Admin self-tunnel: bind tunnel to admin's own clients row,
		// creating that row on first use. Lets the operator dogfood
		// the WG flow without registering a separate customer account.
		sess := middleware.SessionFromContext(r.Context())
		if sess == nil {
			redirectWithFlash(w, r, "/admin/tunnels", "", "no session")
			return
		}
		id, err := ensureSelfClient(r.Context(), h.DB(), sess.UserID, sess.Email)
		if err != nil {
			redirectWithFlash(w, r, "/admin/tunnels", "", "self-client setup failed: "+sanitizeErr(err))
			return
		}
		clientID = id
	} else {
		clientID, _ = strconv.ParseInt(rawClient, 10, 64)
	}
	if clientID == 0 {
		redirectWithFlash(w, r, "/admin/tunnels", "", "client is required")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	sess := middleware.SessionFromContext(r.Context())
	if !h.scopeCheckClient(ctx, sess, clientID) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	// HA path: 2+ nodes, single keypair, one bootstrap token.
	if r.FormValue("ha") == "1" {
		var nodeIDs []int64
		for _, s := range r.Form["node_ids"] {
			if n, _ := strconv.ParseInt(s, 10, 64); n > 0 {
				nodeIDs = append(nodeIDs, n)
			}
		}
		if len(nodeIDs) < 2 {
			redirectWithFlash(w, r, "/admin/tunnels", "", "HA needs at least 2 tunnel-enabled nodes selected")
			return
		}
		_, peers, token, err := h.WGPeers.CreateHA(ctx, wgpeer.CreateHAInput{
			ClientID: clientID, NodeIDs: nodeIDs, Name: name,
		})
		if err != nil {
			redirectWithFlash(w, r, "/admin/tunnels", "", "HA create failed: "+sanitizeErr(err))
			return
		}
		audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
			UserID: actorUserID(sess), Action: "admin.tunnel.create.ha", Entity: "wg_peer",
			EntityID: itoa64(peers[0].ID),
			Meta:     map[string]any{"client_id": clientID, "node_ids": nodeIDs, "peers": len(peers)},
		})
		http.Redirect(w, r, "/admin/tunnels?created="+url.QueryEscape(token), http.StatusSeeOther)
		return
	}

	nodeID, _ := strconv.ParseInt(r.FormValue("node_id"), 10, 64)
	if nodeID == 0 {
		redirectWithFlash(w, r, "/admin/tunnels", "", "node is required (single-node mode)")
		return
	}
	// Defense in depth: ensure client + node both exist + are valid
	// before we burn a token. Prevents enumeration through Create error
	// messages and stops orphan rows from constraint races.
	if db := h.DB(); db != nil {
		var ok int
		_ = db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM clients c
			 JOIN caddy_nodes n ON n.id = ?
			 WHERE c.id = ? AND n.tunnel_enabled = 1`, nodeID, clientID).Scan(&ok)
		if ok == 0 {
			redirectWithFlash(w, r, "/admin/tunnels", "", "client or tunnel-enabled node not found")
			return
		}
	}
	peer, token, err := h.WGPeers.Create(ctx, wgpeer.CreateInput{
		ClientID: clientID, NodeID: nodeID, Name: name,
	})
	if err != nil {
		redirectWithFlash(w, r, "/admin/tunnels", "", "create failed: "+sanitizeErr(err))
		return
	}
	audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "admin.tunnel.create", Entity: "wg_peer",
		EntityID: itoa64(peer.ID),
		Meta:     map[string]any{"client_id": clientID, "node_id": nodeID, "ip": peer.AssignedIP},
	})
	http.Redirect(w, r, "/admin/tunnels?created="+url.QueryEscape(token), http.StatusSeeOther)
}

// TunnelsRevoke handles POST /admin/tunnels/{id}/revoke.
func (h *AdminHandlers) TunnelsRevoke(w http.ResponseWriter, r *http.Request) {
	if h.WGPeers == nil {
		redirectWithFlash(w, r, "/admin/tunnels", "", "WG service not wired")
		return
	}
	id, _ := strconv.ParseInt(chiURLParamHosts(r, "id"), 10, 64)
	if id == 0 {
		redirectWithFlash(w, r, "/admin/tunnels", "", "missing id")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	sess := middleware.SessionFromContext(r.Context())
	if !h.scopeCheckPeer(ctx, sess, id) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := h.WGPeers.Revoke(ctx, id); err != nil {
		redirectWithFlash(w, r, "/admin/tunnels", "", "revoke failed: "+sanitizeErr(err))
		return
	}
	audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "admin.tunnel.revoke", Entity: "wg_peer",
		EntityID: itoa64(id),
	})
	redirectWithFlash(w, r, "/admin/tunnels", "Tunnel revoked", "")
}

// TunnelsDelete handles POST /admin/tunnels/{id}/delete.
// Hard-removes the peer row + cascades bootstrap tokens via FK. Use to
// reclaim assigned_ip / clean up clutter. Revoke is the soft path that
// keeps audit trail in-row; this one wipes the row entirely.
func (h *AdminHandlers) TunnelsDelete(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chiURLParamHosts(r, "id"), 10, 64)
	if id == 0 {
		redirectWithFlash(w, r, "/admin/tunnels", "", "missing id")
		return
	}
	db := h.DB()
	if db == nil {
		redirectWithFlash(w, r, "/admin/tunnels", "", "no db")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	sess := middleware.SessionFromContext(r.Context())
	if !h.scopeCheckPeer(ctx, sess, id) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if h.WGPeers != nil {
		if err := h.WGPeers.Revoke(ctx, id); err != nil {
			redirectWithFlash(w, r, "/admin/tunnels", "", "revoke failed: "+sanitizeErr(err))
			return
		}
	}
	// Hard delete only after revoke so node agents can observe the removal intent.
	if _, err := db.ExecContext(ctx, `DELETE FROM customer_wg_peer WHERE id = ?`, id); err != nil {
		redirectWithFlash(w, r, "/admin/tunnels", "", "delete failed: "+sanitizeErr(err))
		return
	}
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "admin.tunnel.delete", Entity: "wg_peer",
		EntityID: itoa64(id),
	})
	redirectWithFlash(w, r, "/admin/tunnels", "Tunnel hard-deleted", "")
}

// TunnelsRotate handles POST /admin/tunnels/{id}/rotate.
func (h *AdminHandlers) TunnelsRotate(w http.ResponseWriter, r *http.Request) {
	if h.WGPeers == nil {
		redirectWithFlash(w, r, "/admin/tunnels", "", "WG service not wired")
		return
	}
	id, _ := strconv.ParseInt(chiURLParamHosts(r, "id"), 10, 64)
	if id == 0 {
		redirectWithFlash(w, r, "/admin/tunnels", "", "missing id")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	sess := middleware.SessionFromContext(r.Context())
	if !h.scopeCheckPeer(ctx, sess, id) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	token, err := h.WGPeers.RotateKey(ctx, id)
	if err != nil {
		redirectWithFlash(w, r, "/admin/tunnels", "", "rotate failed: "+sanitizeErr(err))
		return
	}
	audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "admin.tunnel.rotate", Entity: "wg_peer",
		EntityID: itoa64(id),
	})
	writeRotationLog(ctx, h.DB(), id, "manual", actorUserID(sess))
	http.Redirect(w, r, "/admin/tunnels?created="+url.QueryEscape(token), http.StatusSeeOther)
}

// TunnelsReissue handles POST /admin/tunnels/{id}/reissue.
// Generates a fresh bootstrap token for an existing peer WITHOUT
// rotating keys - lets ops re-download the .conf after panel-side
// template changes (MTU/MSS clamp updates etc).
func (h *AdminHandlers) TunnelsReissue(w http.ResponseWriter, r *http.Request) {
	if h.WGPeers == nil {
		redirectWithFlash(w, r, "/admin/tunnels", "", "WG service not wired")
		return
	}
	id, _ := strconv.ParseInt(chiURLParamHosts(r, "id"), 10, 64)
	if id == 0 {
		redirectWithFlash(w, r, "/admin/tunnels", "", "missing id")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	sess := middleware.SessionFromContext(r.Context())
	if !h.scopeCheckPeer(ctx, sess, id) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	token, err := h.WGPeers.ReissueBootstrap(ctx, id)
	if err != nil {
		redirectWithFlash(w, r, "/admin/tunnels", "", "reissue failed: "+sanitizeErr(err))
		return
	}
	// Stamp the rotation time so the "key age" view resets after a reissue.
	_, _ = h.DB().ExecContext(ctx, "UPDATE customer_wg_peer SET last_key_rotation_at = NOW() WHERE id = ?", id)
	audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "admin.tunnel.reissue", Entity: "wg_peer",
		EntityID: itoa64(id),
	})
	writeRotationLog(ctx, h.DB(), id, "reissue", actorUserID(sess))
	http.Redirect(w, r, "/admin/tunnels?created="+url.QueryEscape(token), http.StatusSeeOther)
}

// TunnelsBandwidthJSON handles GET /admin/tunnels/{id}/bandwidth.json?period=24h|7d|30d.
// Returns {labels, rx, tx} arrays for Chart.js line charts.
func (h *AdminHandlers) TunnelsBandwidthJSON(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chiURLParamHosts(r, "id"), 10, 64)
	if id == 0 {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	sess := middleware.SessionFromContext(r.Context())
	if !h.scopeCheckPeer(ctx, sess, id) {
		apiJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
		return
	}
	period := r.URL.Query().Get("period")
	if period != "7d" && period != "30d" {
		period = "24h"
	}

	// Build query: GROUP BY hour for 24h, by date for 7d/30d.
	var query string
	switch period {
	case "7d":
		query = `SELECT DATE_FORMAT(sampled_at,'%Y-%m-%d') AS label,
			         COALESCE(SUM(rx_delta),0), COALESCE(SUM(tx_delta),0)
			  FROM customer_wg_peer_usage_sample
			  WHERE peer_id = ? AND sampled_at >= NOW() - INTERVAL 7 DAY
			  GROUP BY DATE(sampled_at)
			  ORDER BY DATE(sampled_at)`
	case "30d":
		query = `SELECT DATE_FORMAT(sampled_at,'%Y-%m-%d') AS label,
			         COALESCE(SUM(rx_delta),0), COALESCE(SUM(tx_delta),0)
			  FROM customer_wg_peer_usage_sample
			  WHERE peer_id = ? AND sampled_at >= NOW() - INTERVAL 30 DAY
			  GROUP BY DATE(sampled_at)
			  ORDER BY DATE(sampled_at)`
	default: // 24h - per-hour buckets
		query = `SELECT DATE_FORMAT(sampled_at,'%m-%d %H:00') AS label,
			         COALESCE(SUM(rx_delta),0), COALESCE(SUM(tx_delta),0)
			  FROM customer_wg_peer_usage_sample
			  WHERE peer_id = ? AND sampled_at >= NOW() - INTERVAL 24 HOUR
			  GROUP BY DATE(sampled_at), HOUR(sampled_at)
			  ORDER BY DATE(sampled_at), HOUR(sampled_at)`
	}

	rows, err := db.QueryContext(ctx, query, id)
	if err != nil {
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var labels []string
	var rx, tx []int64
	for rows.Next() {
		var label string
		var rxV, txV int64
		if err := rows.Scan(&label, &rxV, &txV); err == nil {
			labels = append(labels, label)
			rx = append(rx, rxV)
			tx = append(tx, txV)
		}
	}
	if rErr := rows.Err(); rErr != nil {
		h.Logger.Error("bandwidth query rows", "peer_id", id, "err", rErr)
	}
	// Return empty arrays (not null) when no data.
	if labels == nil {
		labels = []string{}
		rx = []int64{}
		tx = []int64{}
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"labels": labels,
		"rx":     rx,
		"tx":     tx,
	})
}

// tunnelDetailData drives the tunnel_detail template.
type tunnelDetailData struct {
	baseAdminData
	Peer         tunnelRow
	MonthRxHuman string // total RX this calendar month
	MonthTxHuman string // total TX this calendar month
	PeakHour     string // "14:00" or "" if no data
	RotationLog  []rotationLogRow
}

type rotationLogRow struct {
	RotatedAt string
	Source    string
	ActorID   int64
}

// TunnelDetail renders GET /admin/tunnels/{id}.
func (h *AdminHandlers) TunnelDetail(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chiURLParamHosts(r, "id"), 10, 64)
	if id == 0 {
		http.NotFound(w, r)
		return
	}
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	sess := middleware.SessionFromContext(r.Context())
	if !h.scopeCheckPeer(ctx, sess, id) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	d := tunnelDetailData{baseAdminData: h.base(r, "Tunnel detail")}

	// Load peer row.
	var t tunnelRow
	var rx, tx, cumRx, cumTx, epoch int64
	err := db.QueryRowContext(ctx,
		`SELECT p.id, p.name, p.client_id, u.email, p.node_id, n.name,
		        p.assigned_ip, COALESCE(p.endpoint,''), p.status,
		        COALESCE(DATE_FORMAT(p.last_handshake_at,'%Y-%m-%d %H:%i'),''),
		        COALESCE(p.rx_bytes,0), COALESCE(p.tx_bytes,0),
		        COALESCE(p.cumulative_rx_bytes,0), COALESCE(p.cumulative_tx_bytes,0),
		        COALESCE(p.last_handshake_epoch,0),
		        DATE_FORMAT(p.created_at,'%Y-%m-%d %H:%i'),
		        COALESCE(p.peer_group_id,''),
		        p.last_rotated_at, p.last_key_rotation_at
		 FROM customer_wg_peer p
		 JOIN clients c ON c.id = p.client_id
		 JOIN users u   ON u.id = c.user_id
		 JOIN caddy_nodes n ON n.id = p.node_id
		 WHERE p.id = ?`, id).Scan(
		&t.ID, &t.Name, &t.ClientID, &t.ClientEmail, &t.NodeID, &t.NodeName,
		&t.AssignedIP, &t.Endpoint, &t.Status, &t.LastHandshake,
		&rx, &tx, &cumRx, &cumTx, &epoch, &t.CreatedAt, &t.PeerGroupID,
		&t.LastRotatedAt, &t.LastKeyRotation)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if t.LastHandshake == "" {
		t.LastHandshake = "-"
	}
	t.RxHuman = formatBytes(rx)
	t.TxHuman = formatBytes(tx)
	t.CumRxHuman = formatBytes(cumRx)
	t.CumTxHuman = formatBytes(cumTx)
	if epoch > 0 {
		t.Healthy = time.Since(time.Unix(epoch, 0)) < wgStaleAfter
	}
	t.KeyAgeHuman = keyAgeHuman(t.LastRotatedAt, t.LastKeyRotation)
	d.Peer = t

	// Monthly total (current calendar month).
	var monthRx, monthTx int64
	_ = db.QueryRowContext(ctx,
		`SELECT COALESCE(SUM(rx_delta),0), COALESCE(SUM(tx_delta),0)
		   FROM customer_wg_peer_usage_sample
		  WHERE peer_id = ? AND YEAR(sampled_at)=YEAR(NOW()) AND MONTH(sampled_at)=MONTH(NOW())`,
		id).Scan(&monthRx, &monthTx)
	d.MonthRxHuman = formatBytes(monthRx)
	d.MonthTxHuman = formatBytes(monthTx)

	// Peak hour over last 30d (hour-of-day with highest summed bytes).
	var peakHour sql.NullInt64
	_ = db.QueryRowContext(ctx,
		`SELECT HOUR(sampled_at) AS h
		   FROM customer_wg_peer_usage_sample
		  WHERE peer_id = ? AND sampled_at >= NOW() - INTERVAL 30 DAY
		  GROUP BY h
		  ORDER BY SUM(rx_delta+tx_delta) DESC
		  LIMIT 1`, id).Scan(&peakHour)
	if peakHour.Valid {
		d.PeakHour = fmt.Sprintf("%02d:00", peakHour.Int64)
	}

	// Rotation history (last 20).
	rrows, err := db.QueryContext(ctx,
		`SELECT DATE_FORMAT(rotated_at,'%Y-%m-%d %H:%i'), source, COALESCE(actor_user_id,0)
		   FROM wg_key_rotation_log
		  WHERE peer_id = ?
		  ORDER BY rotated_at DESC LIMIT 20`, id)
	if err == nil {
		defer rrows.Close()
		for rrows.Next() {
			var row rotationLogRow
			if err := rrows.Scan(&row.RotatedAt, &row.Source, &row.ActorID); err == nil {
				d.RotationLog = append(d.RotationLog, row)
			}
		}
		_ = rrows.Err()
	}

	h.render(w, "tunnel_detail", d)
}

// TunnelsUsageCSV handles GET /admin/tunnels/{id}/usage.csv.
// Exports raw usage samples for the given peer as CSV.
func (h *AdminHandlers) TunnelsUsageCSV(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chiURLParamHosts(r, "id"), 10, 64)
	if id == 0 {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	sess := middleware.SessionFromContext(r.Context())
	if !h.scopeCheckPeer(ctx, sess, id) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if !checkLogsExportRateLimit(logsExportLimiterKey(r, sess), time.Now()) {
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	rows, err := db.QueryContext(ctx,
		`SELECT sampled_at, rx_delta, tx_delta
		   FROM customer_wg_peer_usage_sample
		  WHERE peer_id = ?
		  ORDER BY sampled_at DESC LIMIT 50000`, id)
	if err != nil {
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="tunnel-%d-usage.csv"`, id))
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"sampled_at", "rx_delta", "tx_delta"})
	var i int
	for rows.Next() {
		var sampledAt time.Time
		var rxDelta, txDelta int64
		if err := rows.Scan(&sampledAt, &rxDelta, &txDelta); err == nil {
			_ = cw.Write(csvSafeRow([]string{
				sampledAt.UTC().Format(time.RFC3339),
				strconv.FormatInt(rxDelta, 10),
				strconv.FormatInt(txDelta, 10),
			}))
			i++
			if i%100 == 0 {
				cw.Flush()
			}
		}
	}
	cw.Flush()
	_ = rows.Err()
}

// writeRotationLog records one row in wg_key_rotation_log. Best-effort - never
// blocks the main rotation path if the insert fails.
func writeRotationLog(ctx context.Context, db *sql.DB, peerID int64, source string, actorID *int64) {
	if db == nil {
		return
	}
	var actor interface{}
	if actorID != nil && *actorID > 0 {
		actor = *actorID
	}
	_, _ = db.ExecContext(ctx,
		`INSERT INTO wg_key_rotation_log (peer_id, source, actor_user_id) VALUES (?, ?, ?)`,
		peerID, source, actor)
}

// ---- helpers ------------------------------------------------------

func (h *AdminHandlers) adminClientScope(ctx context.Context, sess *auth.Session) (map[int64]bool, bool, bool) {
	if sess == nil || sess.Role == "super_admin" || h.AdminScope == nil {
		return nil, true, true
	}
	clientIDs, all, err := h.AdminScope.ScopeFilter(ctx, sess.UserID)
	if err != nil {
		h.Logger.Warn("admin scope filter", "user_id", sess.UserID, "err", err)
		return nil, false, false
	}
	if all {
		return nil, true, true
	}
	allowed := make(map[int64]bool, len(clientIDs))
	for _, id := range clientIDs {
		allowed[id] = true
	}
	return allowed, false, true
}

func filterClientOptions(in []clientOption, allowed map[int64]bool, all bool) []clientOption {
	if all {
		return in
	}
	out := make([]clientOption, 0, len(in))
	for _, o := range in {
		if allowed[o.ID] {
			out = append(out, o)
		}
	}
	return out
}

func (h *AdminHandlers) scopeCheckClient(ctx context.Context, sess *auth.Session, clientID int64) bool {
	if sess == nil || sess.Role == "super_admin" || h.AdminScope == nil {
		return true
	}
	ok, err := h.AdminScope.CanAccessClient(ctx, sess.UserID, clientID)
	if err != nil {
		h.Logger.Warn("admin client scope check", "user_id", sess.UserID, "client_id", clientID, "err", err)
		return false
	}
	return ok
}

func (h *AdminHandlers) scopeCheckPeer(ctx context.Context, sess *auth.Session, peerID int64) bool {
	if sess == nil || sess.Role == "super_admin" || h.AdminScope == nil {
		return true
	}
	ok, err := h.AdminScope.CanAccessPeer(ctx, sess.UserID, peerID)
	if err != nil {
		h.Logger.Warn("admin peer scope check", "user_id", sess.UserID, "peer_id", peerID, "err", err)
		return false
	}
	return ok
}

// ensureSelfClient returns the clients row bound to the given admin user,
// creating it on first call. Admins are stored only in users; they don't
// auto-get a clients row at signup. WG peers FK to clients.id, so an
// admin self-tunnel needs one. Idempotent via unique (user_id) constraint.
func ensureSelfClient(ctx context.Context, db *sql.DB, userID int64, email string) (int64, error) {
	if db == nil || userID == 0 {
		return 0, errors.New("ensureSelfClient: no db or user")
	}
	qctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var id int64
	if err := db.QueryRowContext(qctx, "SELECT id FROM clients WHERE user_id = ?", userID).Scan(&id); err == nil {
		return id, nil
	}
	res, err := db.ExecContext(qctx,
		"INSERT INTO clients (user_id, display_name) VALUES (?, ?)",
		userID, email+" (admin self)")
	if err != nil {
		// Race: another request inserted between our SELECT and INSERT.
		// Re-read and return the existing row.
		var fallback int64
		if err2 := db.QueryRowContext(qctx, "SELECT id FROM clients WHERE user_id = ?", userID).Scan(&fallback); err2 == nil {
			return fallback, nil
		}
		return 0, err
	}
	newID, _ := res.LastInsertId()
	return newID, nil
}

func loadClientOptions(ctx context.Context, db *sql.DB) []clientOption {
	rows, err := db.QueryContext(ctx,
		`SELECT c.id, u.email
		 FROM clients c JOIN users u ON u.id = c.user_id
		 ORDER BY u.email LIMIT 500`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []clientOption
	for rows.Next() {
		var o clientOption
		if err := rows.Scan(&o.ID, &o.Email); err == nil {
			out = append(out, o)
		}
	}
	_ = rows.Err()
	return out
}

func loadTunnelNodeOptions(ctx context.Context, db *sql.DB) []nodeOption {
	// Only nodes with tunnel_enabled=1 are valid targets.
	rows, err := db.QueryContext(ctx,
		`SELECT id, name FROM caddy_nodes WHERE tunnel_enabled = 1 ORDER BY name LIMIT 100`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []nodeOption
	for rows.Next() {
		var o nodeOption
		if err := rows.Scan(&o.ID, &o.Name); err == nil {
			out = append(out, o)
		}
	}
	_ = rows.Err()
	return out
}

func (h *AdminHandlers) lookupNewTunnel(ctx context.Context, db *sql.DB, r *http.Request, token string) *newTunnelView {
	if len(token) != 192 {
		return nil
	}
	var (
		peerID      int64
		name        string
		assignedIP  string
		clientEmail string
		nodeName    string
		expiresAt   time.Time
	)
	err := db.QueryRowContext(ctx,
		`SELECT p.id, p.name, p.assigned_ip, u.email, n.name, b.expires_at
		 FROM customer_wg_bootstrap b
		 JOIN customer_wg_peer p ON p.id = b.peer_id
		 JOIN clients c ON c.id = p.client_id
		 JOIN users   u ON u.id = c.user_id
		 JOIN caddy_nodes n ON n.id = p.node_id
		 WHERE b.token = ? AND b.expires_at > NOW()`, token).Scan(&peerID, &name, &assignedIP, &clientEmail, &nodeName, &expiresAt)
	if err != nil {
		return nil
	}
	base := publicBaseURL(r, appURLFromInstallState(h.State))
	return &newTunnelView{
		PeerID:         peerID,
		Name:           name,
		ClientEmail:    clientEmail,
		NodeName:       nodeName,
		AssignedIP:     assignedIP,
		Token:          token,
		ConfURL:        base + "/api/wg/bootstrap?token=" + token,
		StatusURL:      base + "/api/wg/status?token=" + token,
		InstallCommand: "curl -fsSL " + base + "/api/wg/install.sh?token=" + token + " | sudo bash",
		ExpiresAt:      expiresAt.UTC().Format(time.RFC3339),
	}
}
