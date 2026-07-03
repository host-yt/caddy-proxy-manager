package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/host-yt/caddy-proxy-manager/internal/audit"
	"github.com/host-yt/caddy-proxy-manager/internal/domain/wgpeer"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
)

// WGPeers is wired by main.go so the client surface can reuse the
// admin's wgpeer service. Nil-safe: the page degrades to "no service"
// if the operator hasn't enabled the feature.
func (h *ClientHandlers) SetWGPeers(s *wgpeer.Service) { h.WGPeers = s }

// ClientHandlers struct gets WGPeers field via a small extension (see
// client.go declaration — we attach via a method so we don't touch
// every other field's wiring).
// (declared on the original struct via field below to avoid build noise)

type clientTunnelsData struct {
	baseAppData
	Tunnels   []tunnelRow // reuse admin row shape
	Nodes     []nodeOption
	NewTunnel *newTunnelView
}

// ClientTunnelsList renders /app/tunnels.
func (h *ClientHandlers) ClientTunnelsList(w http.ResponseWriter, r *http.Request) {
	d := clientTunnelsData{baseAppData: h.base(r, "Private network")}
	sess := middleware.SessionFromContext(r.Context())
	db := h.DB()
	if db == nil || sess == nil {
		h.render(w, "tunnels", d)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	clientID, err := clientIDFor(ctx, db, sess.UserID)
	if err != nil {
		h.render(w, "tunnels", d)
		return
	}

	rows, err := db.QueryContext(ctx,
		`SELECT p.id, p.name, p.client_id, '', p.node_id, n.name,
		        p.assigned_ip, COALESCE(p.endpoint,''), p.status,
		        COALESCE(DATE_FORMAT(p.last_handshake_at,'%Y-%m-%d %H:%i'),''),
		        COALESCE(p.rx_bytes,0), COALESCE(p.tx_bytes,0),
		        COALESCE(p.last_handshake_epoch,0),
		        DATE_FORMAT(p.created_at,'%Y-%m-%d %H:%i'),
		        COALESCE(p.peer_group_id,'')
		 FROM customer_wg_peer p
		 JOIN caddy_nodes n ON n.id = p.node_id
		 WHERE p.client_id = ?
		 ORDER BY p.id DESC LIMIT 200`, clientID)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var t tunnelRow
			var rx, tx, epoch int64
			if err := rows.Scan(&t.ID, &t.Name, &t.ClientID, &t.ClientEmail,
				&t.NodeID, &t.NodeName, &t.AssignedIP, &t.Endpoint, &t.Status,
				&t.LastHandshake, &rx, &tx, &epoch,
				&t.CreatedAt, &t.PeerGroupID); err == nil {
				if t.LastHandshake == "" {
					t.LastHandshake = "—"
				}
				t.RxHuman = formatBytes(rx)
				t.TxHuman = formatBytes(tx)
				if epoch > 0 {
					t.Healthy = time.Since(time.Unix(epoch, 0)) < wgStaleAfter
				}
				d.Tunnels = append(d.Tunnels, t)
			}
		}
	}

	d.Nodes = loadClientTunnelNodeOptions(ctx, db, clientID)
	if tok := strings.TrimSpace(r.URL.Query().Get("created")); tok != "" {
		d.NewTunnel = h.lookupClientNewTunnel(ctx, db, r, tok, clientID)
	}
	h.render(w, "tunnels", d)
}

// ClientTunnelsCreate handles POST /app/tunnels. Client-side flow is
// always single-node — HA tunnels remain admin-only for now (multi-
// node placement decisions belong to the operator).
func (h *ClientHandlers) ClientTunnelsCreate(w http.ResponseWriter, r *http.Request) {
	if h.WGPeers == nil {
		clientRedirectFlash(w, r, "/app/tunnels", "", "tunnels not available")
		return
	}
	sess := middleware.SessionFromContext(r.Context())
	if sess == nil {
		clientRedirectFlash(w, r, "/app/tunnels", "", "session expired")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	clientID, err := clientIDFor(ctx, h.DB(), sess.UserID)
	if err != nil {
		clientRedirectFlash(w, r, "/app/tunnels", "", "no client account")
		return
	}
	_ = r.ParseForm()
	nodeID, _ := strconv.ParseInt(r.FormValue("node_id"), 10, 64)
	name := strings.TrimSpace(r.FormValue("name"))
	if nodeID == 0 {
		clientRedirectFlash(w, r, "/app/tunnels", "", "node is required")
		return
	}
	// Scope: client may only peer a node in a group they hold a service in.
	if !clientTunnelNodeAllowed(ctx, h.DB(), clientID, nodeID) {
		clientRedirectFlash(w, r, "/app/tunnels", "", "node not available")
		return
	}
	peer, token, err := h.WGPeers.Create(ctx, wgpeer.CreateInput{
		ClientID: clientID, NodeID: nodeID, Name: name,
	})
	if err != nil {
		clientRedirectFlash(w, r, "/app/tunnels", "", "create failed: "+sanitizeErr(err))
		return
	}
	audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "client.tunnel.create", Entity: "wg_peer",
		EntityID: itoa64(peer.ID),
		Meta:     map[string]any{"client_id": clientID, "node_id": nodeID, "ip": peer.AssignedIP},
	})
	http.Redirect(w, r, "/app/tunnels?created="+token, http.StatusSeeOther)
}

// ClientTunnelsRevoke handles POST /app/tunnels/{id}/revoke. Ownership
// check: peer.client_id MUST equal session client's id.
func (h *ClientHandlers) ClientTunnelsRevoke(w http.ResponseWriter, r *http.Request) {
	if h.WGPeers == nil {
		clientRedirectFlash(w, r, "/app/tunnels", "", "tunnels not available")
		return
	}
	id, _ := strconv.ParseInt(chiURLParamHosts(r, "id"), 10, 64)
	sess := middleware.SessionFromContext(r.Context())
	if id == 0 || sess == nil {
		clientRedirectFlash(w, r, "/app/tunnels", "", "missing id")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	clientID, err := clientIDFor(ctx, h.DB(), sess.UserID)
	if err != nil {
		clientRedirectFlash(w, r, "/app/tunnels", "", "no client account")
		return
	}
	var ownerID int64
	if err := h.DB().QueryRowContext(ctx,
		`SELECT client_id FROM customer_wg_peer WHERE id = ?`, id).Scan(&ownerID); err != nil || ownerID != clientID {
		clientRedirectFlash(w, r, "/app/tunnels", "", "tunnel not found")
		return
	}
	if err := h.WGPeers.Revoke(ctx, id); err != nil {
		clientRedirectFlash(w, r, "/app/tunnels", "", "revoke failed: "+sanitizeErr(err))
		return
	}
	audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "client.tunnel.revoke", Entity: "wg_peer",
		EntityID: itoa64(id),
	})
	clientRedirectFlash(w, r, "/app/tunnels", "Tunnel revoked", "")
}

// lookupClientNewTunnel scopes the just-created token lookup to the
// session client so one customer can never see another's install URL.
func (h *ClientHandlers) lookupClientNewTunnel(ctx context.Context, db *sql.DB, r *http.Request, token string, clientID int64) *newTunnelView {
	if len(token) != 192 {
		return nil
	}
	var (
		peerID     int64
		name       string
		assignedIP string
		owner      int64
		nodeName   string
	)
	err := db.QueryRowContext(ctx,
		`SELECT p.id, p.name, p.assigned_ip, p.client_id, n.name
		 FROM customer_wg_bootstrap b
		 JOIN customer_wg_peer p ON p.id = b.peer_id
		 JOIN caddy_nodes n ON n.id = p.node_id
		 WHERE b.token = ?`, token).Scan(&peerID, &name, &assignedIP, &owner, &nodeName)
	if err != nil || owner != clientID {
		return nil
	}
	base := publicBaseURL(r, appURLFromInstallState(h.State))
	return &newTunnelView{
		PeerID:     peerID,
		Name:       name,
		AssignedIP: assignedIP,
		NodeName:   nodeName,
		Token:      token,
		// NODE_WG-03: token-in-URL is required for the one-command curl|bash
		// install UX; token is single-shot + short-TTL, unlike the durable
		// per-node agent token (which no longer accepts query-string auth).
		ConfURL:        base + "/api/wg/bootstrap?token=" + token,
		InstallCommand: "curl -fsSL " + base + "/api/wg/install.sh?token=" + token + " | sudo bash",
	}
}

// loadClientTunnelNodeOptions lists tunnel nodes in a group the client
// holds an active service in - not every tunnel_enabled node (B-02).
func loadClientTunnelNodeOptions(ctx context.Context, db *sql.DB, clientID int64) []nodeOption {
	rows, err := db.QueryContext(ctx,
		`SELECT DISTINCT n.id, n.name FROM caddy_nodes n
		 JOIN services s ON s.node_group_id = n.node_group_id
		 WHERE n.tunnel_enabled = 1 AND s.client_id = ? AND s.status = 'active'
		 ORDER BY n.name LIMIT 100`, clientID)
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

// clientTunnelNodeAllowed enforces the same scope server-side.
func clientTunnelNodeAllowed(ctx context.Context, db *sql.DB, clientID, nodeID int64) bool {
	if db == nil {
		return false
	}
	var n int
	err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM caddy_nodes n
		 JOIN services s ON s.node_group_id = n.node_group_id
		 WHERE n.id = ? AND n.tunnel_enabled = 1 AND s.client_id = ? AND s.status = 'active'`,
		nodeID, clientID).Scan(&n)
	return err == nil && n > 0
}

// clientRedirectFlash mirrors redirectWithFlash but lives in the
// client package (kept close to the handlers so wiring stays obvious).
func clientRedirectFlash(w http.ResponseWriter, r *http.Request, base, flash, err string) {
	redirectWithFlash(w, r, base, flash, err)
}

// ClientTunnelsBandwidthJSON handles GET /app/tunnels/{id}/bandwidth.json.
// Same response shape as admin bandwidth.json but scoped to the session client.
func (h *ClientHandlers) ClientTunnelsBandwidthJSON(w http.ResponseWriter, r *http.Request) {
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
	sess := middleware.SessionFromContext(r.Context())
	if sess == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// Verify peer belongs to this client - same ownership check as ClientTunnelsRevoke.
	clientID, err := clientIDFor(ctx, db, sess.UserID)
	if err != nil {
		http.Error(w, "no client account", http.StatusForbidden)
		return
	}
	var ownerID int64
	if err := db.QueryRowContext(ctx,
		`SELECT client_id FROM customer_wg_peer WHERE id = ?`, id).Scan(&ownerID); err != nil || ownerID != clientID {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	period := r.URL.Query().Get("period")
	if period != "7d" && period != "30d" {
		period = "24h"
	}

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
	default:
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
		h.Logger.Error("client bandwidth query rows", "peer_id", id, "err", rErr)
	}
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
