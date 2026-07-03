package handlers

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/host-yt/caddy-proxy-manager/internal/audit"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
	"github.com/host-yt/caddy-proxy-manager/internal/wireguard"
)

// tunnelCreds is the payload pushed to Redis after enable/rotate.
// Read once by /admin/nodes, then deleted. Never logged.
type tunnelCreds struct {
	NodeID       int64  `json:"node_id"`
	Token        string `json:"token"`
	PrivateKey   string `json:"priv"`
	ListenPort   int    `json:"port"`
	Transport    string `json:"transport"`     // udp|wss|auto
	WstunnelPort int    `json:"wstunnel_port"` // 0 = none
}

// resyncTunnelNode pushes the node's full Caddy config in the background after
// a tunnel change, so the synthetic /wg-tunnel WSS route actually goes live.
func (h *AdminHandlers) resyncTunnelNode(nodeID int64) {
	if h.Routes == nil {
		return
	}
	go func() {
		defer recoverBg(h.Logger, "tunnel-resync")
		ctx, cancel := context.WithTimeout(h.Routes.BackgroundCtx(), 30*time.Second)
		defer cancel()
		if err := h.Routes.Resync(ctx, nodeID); err != nil {
			h.Logger.Error("tunnel resync failed", "node_id", nodeID, "err", err)
		}
	}()
}

// stashTunnelCreds stores credentials under a one-shot nonce key in
// Redis with a short TTL. Returns the nonce. Falls back to empty
// (caller appends classic flash) when RDB is unavailable.
func (h *AdminHandlers) stashTunnelCreds(ctx context.Context, c tunnelCreds) string {
	if h.RDB == nil {
		return ""
	}
	var nb [16]byte
	if _, err := rand.Read(nb[:]); err != nil {
		return ""
	}
	nonce := hex.EncodeToString(nb[:])
	payload, err := json.Marshal(c)
	if err != nil {
		return ""
	}
	key := "tunnel_creds:" + nonce
	if err := h.RDB.Set(ctx, key, payload, 10*time.Minute).Err(); err != nil {
		return ""
	}
	return nonce
}

// fetchTunnelCreds reads + deletes (one-shot) the credentials payload
// for nonce. Returns nil when missing/expired/RDB-unavailable.
func (h *AdminHandlers) fetchTunnelCreds(ctx context.Context, nonce string) *tunnelCreds {
	if h.RDB == nil || nonce == "" {
		return nil
	}
	key := "tunnel_creds:" + nonce
	raw, err := h.RDB.GetDel(ctx, key).Bytes()
	if err != nil || len(raw) == 0 {
		return nil
	}
	var c tunnelCreds
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil
	}
	return &c
}

// applyTunnelEnableFirstTime generates keypair + agent token, persists
// them on the node row, and returns (token, privateKey, error). Shared
// between first-time Enable and the explicit Rotate flow.
func (h *AdminHandlers) applyTunnelEnableFirstTime(ctx context.Context, nodeID int64, listenPort int, endpoint, subnet, transport string, wstPort any) (string, string, error) {
	kp, err := wireguard.GenerateKeypair()
	if err != nil {
		return "", "", err
	}
	encPriv, err := h.encryptSetting(kp.PrivateKey)
	if err != nil {
		return "", "", err
	}
	var rawToken [32]byte
	if _, err := rand.Read(rawToken[:]); err != nil {
		return "", "", err
	}
	token := hex.EncodeToString(rawToken[:])
	sum := sha256.Sum256([]byte(token))
	tokenHash := hex.EncodeToString(sum[:])

	_, err = h.DB().ExecContext(ctx,
		`UPDATE caddy_nodes
		   SET tunnel_enabled = 1, tunnel_listen_port = ?, tunnel_endpoint = ?,
		       tunnel_subnet = ?, tunnel_transport = ?, tunnel_wstunnel_port = ?,
		       tunnel_pubkey = ?, tunnel_privkey_e2 = ?,
		       agent_token_hash = ?, tunnel_next_octet = 2
		 WHERE id = ?`,
		listenPort, endpoint, subnet, transport, wstPort, kp.PublicKey, []byte(encPriv), tokenHash, nodeID)
	if err != nil {
		return "", "", err
	}
	return token, kp.PrivateKey, nil
}

// parseTransport reads transport + wstunnel port from the form and enforces the
// invariant: non-UDP transport requires a valid backend port. Returns
// (transport, portArg-for-SQL, portInt, error). portArg is nil (SQL NULL) and
// portInt 0 for udp.
func parseTransport(r *http.Request) (string, any, int, error) {
	transport := strings.TrimSpace(r.FormValue("transport"))
	switch transport {
	case "", "udp":
		return "udp", nil, 0, nil
	case "wss", "auto":
	default:
		return "", nil, 0, fmt.Errorf("invalid transport %q", transport)
	}
	port, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("wstunnel_port")))
	if port < 1 || port > 65535 {
		// wss is broken without a port; auto would just degrade, but reject both
		// so the panel never advertises a transport it can't back.
		return "", nil, 0, fmt.Errorf("transport %s requires a valid wstunnel_port (1-65535)", transport)
	}
	return transport, port, port, nil
}

// NodeTunnelEnable handles POST /admin/nodes/{id}/tunnel/enable.
//
// Form fields:
//
//	listen_port  — UDP port wg-tun0 listens on (default 51821)
//	endpoint     — public host:port customers dial
//	subnet       — tenant /16 subnet (default 100.96.0.0/16)
//
// First-time call generates keypair + agent token and stashes them in
// Redis under a one-shot nonce; redirect carries ?show_creds=<nonce>
// so the nodes page can render a modal with copy buttons. Subsequent
// calls update metadata only (operator must Rotate to get fresh keys).
func (h *AdminHandlers) NodeTunnelEnable(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chiURLParamHosts(r, "id"), 10, 64)
	if id == 0 {
		redirectWithFlash(w, r, "/admin/nodes", "", "missing node id")
		return
	}
	_ = r.ParseForm()
	listenPort, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("listen_port")))
	if listenPort <= 0 || listenPort > 65535 {
		listenPort = 51821
	}
	endpoint := strings.TrimSpace(r.FormValue("endpoint"))
	subnet := strings.TrimSpace(r.FormValue("subnet"))
	if subnet == "" {
		subnet = "100.96.0.0/16"
	}
	transport, wstPort, wstPortInt, terr := parseTransport(r)
	if terr != nil {
		h.Logger.Warn("tunnel enable: invalid transport form", "err", terr)
		redirectWithFlash(w, r, "/admin/nodes", "", "invalid transport or wstunnel_port")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	db := h.DB()
	if db == nil {
		redirectWithFlash(w, r, "/admin/nodes", "", "no db")
		return
	}

	var (
		existingPubkey, publicHost string
		tunnelEnabled              bool
	)
	if err := db.QueryRowContext(ctx,
		`SELECT COALESCE(tunnel_pubkey,''), COALESCE(public_hostname,''), tunnel_enabled
		 FROM caddy_nodes WHERE id=?`, id).Scan(&existingPubkey, &publicHost, &tunnelEnabled); err != nil {
		redirectWithFlash(w, r, "/admin/nodes", "", "node not found")
		return
	}
	if endpoint == "" && publicHost != "" {
		endpoint = publicHost + ":" + strconv.Itoa(listenPort)
	}
	// wg-quick refuses bare hostnames with 'Unable to find port of
	// endpoint'. Append listen port automatically. Skip for IPv6 literals.
	if endpoint != "" && !strings.Contains(endpoint, ":") {
		endpoint = endpoint + ":" + strconv.Itoa(listenPort)
	}

	sess := middleware.SessionFromContext(r.Context())

	if existingPubkey == "" {
		token, privKey, err := h.applyTunnelEnableFirstTime(ctx, id, listenPort, endpoint, subnet, transport, wstPort)
		if err != nil {
			redirectWithFlash(w, r, "/admin/nodes", "", "save failed: "+sanitizeErr(err))
			return
		}
		audit.Write(ctx, db, h.Logger, r, audit.Entry{
			UserID: actorUserID(sess), Action: "admin.node.tunnel.enable", Entity: "caddy_node",
			EntityID: itoa64(id),
			Meta:     map[string]any{"port": listenPort, "endpoint": endpoint, "subnet": subnet, "transport": transport},
		})
		// WSS route lives only in the full Caddy config, so push it now -
		// otherwise installers advertise /wg-tunnel before Caddy serves it.
		h.resyncTunnelNode(id)
		nonce := h.stashTunnelCreds(ctx, tunnelCreds{
			NodeID: id, Token: token, PrivateKey: privKey, ListenPort: listenPort,
			Transport: transport, WstunnelPort: wstPortInt,
		})
		if nonce != "" {
			http.Redirect(w, r, "/admin/nodes?show_creds="+nonce, http.StatusSeeOther)
			return
		}
		// Redis unavailable: refuse to embed the WG private key in a
		// query-string flash (lands in access logs + browser history).
		// Operator must fix Redis and re-trigger; creds are still set in
		// the DB, just not displayed once here.
		h.Logger.Warn("tunnel enable: stash failed (Redis down), refusing URL flash with privkey",
			"node_id", id)
		redirectWithFlash(w, r, "/admin/nodes", "",
			"Tunnel enabled but credential display is unavailable (Redis down). Restart with Redis up + click Rotate to re-issue.")
		return
	}

	// Re-save metadata only (keys unchanged). Transport + port persisted
	// atomically here so the panel never advertises WSS without a backend.
	if _, err := db.ExecContext(ctx,
		`UPDATE caddy_nodes
		   SET tunnel_enabled = 1, tunnel_listen_port = ?, tunnel_endpoint = ?, tunnel_subnet = ?,
		       tunnel_transport = ?, tunnel_wstunnel_port = ?
		 WHERE id = ?`,
		listenPort, endpoint, subnet, transport, wstPort, id); err != nil {
		redirectWithFlash(w, r, "/admin/nodes", "", "save failed: "+sanitizeErr(err))
		return
	}
	h.resyncTunnelNode(id)
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "admin.node.tunnel.update", Entity: "caddy_node",
		EntityID: itoa64(id),
		Meta:     map[string]any{"port": listenPort, "endpoint": endpoint, "subnet": subnet, "transport": transport},
	})
	redirectWithFlash(w, r, "/admin/nodes", "Tunnel settings updated (keys unchanged — click Rotate to issue fresh credentials).", "")
}

// NodeTunnelRotate handles POST /admin/nodes/{id}/tunnel/rotate.
//
// Generates a fresh keypair + agent token, replacing the existing ones.
// Existing customer install URLs become invalid (server key changes),
// so all peers on this node must re-install their wg-quick configs.
// Use only when the operator can't recover the original credentials.
func (h *AdminHandlers) NodeTunnelRotate(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chiURLParamHosts(r, "id"), 10, 64)
	if id == 0 {
		redirectWithFlash(w, r, "/admin/nodes", "", "missing node id")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	db := h.DB()
	if db == nil {
		redirectWithFlash(w, r, "/admin/nodes", "", "no db")
		return
	}

	var (
		listenPort       sql.NullInt64
		endpoint, subnet sql.NullString
		transport        sql.NullString
		wstPortDB        sql.NullInt64
	)
	if err := db.QueryRowContext(ctx,
		`SELECT COALESCE(tunnel_listen_port,51821), COALESCE(tunnel_endpoint,''), COALESCE(tunnel_subnet,'100.96.0.0/16'),
		        COALESCE(tunnel_transport,'udp'), tunnel_wstunnel_port
		 FROM caddy_nodes WHERE id=?`, id).Scan(&listenPort, &endpoint, &subnet, &transport, &wstPortDB); err != nil {
		redirectWithFlash(w, r, "/admin/nodes", "", "node not found")
		return
	}
	port := int(listenPort.Int64)
	if port <= 0 {
		port = 51821
	}
	// Rotate keeps the existing transport/port (rotating keys must not silently
	// flip a WSS node back to UDP).
	tr := transport.String
	var wstArg any
	if wstPortDB.Valid {
		wstArg = wstPortDB.Int64
	}
	token, privKey, err := h.applyTunnelEnableFirstTime(ctx, id, port, endpoint.String, subnet.String, tr, wstArg)
	if err != nil {
		redirectWithFlash(w, r, "/admin/nodes", "", "rotate failed: "+sanitizeErr(err))
		return
	}
	sess := middleware.SessionFromContext(r.Context())
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "admin.node.tunnel.rotate", Entity: "caddy_node",
		EntityID: itoa64(id),
	})
	wstInt := 0
	if wstPortDB.Valid {
		wstInt = int(wstPortDB.Int64)
	}
	nonce := h.stashTunnelCreds(ctx, tunnelCreds{
		NodeID: id, Token: token, PrivateKey: privKey, ListenPort: port,
		Transport: tr, WstunnelPort: wstInt,
	})
	if nonce != "" {
		http.Redirect(w, r, "/admin/nodes?show_creds="+nonce, http.StatusSeeOther)
		return
	}
	// Same safeguard as the enable path: never embed the WG private key + node
	// token in a ?flash= query string (lands in access logs + browser history).
	h.Logger.Warn("tunnel rotate: stash failed (Redis down), refusing URL flash with privkey", "node_id", id)
	redirectWithFlash(w, r, "/admin/nodes", "",
		"Keys rotated but credential display is unavailable (Redis down). Bring Redis up and click Rotate again to re-issue.")
}

// NodeTunnelDisable handles POST /admin/nodes/{id}/tunnel/disable.
// Does NOT delete the keys/peers (so re-enable is non-destructive); only
// flips the flag so the agent stops reconciling on next pull (panel
// returns 403 when tunnel_enabled=0 — handled at PeersForNode).
func (h *AdminHandlers) NodeTunnelDisable(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chiURLParamHosts(r, "id"), 10, 64)
	if id == 0 {
		redirectWithFlash(w, r, "/admin/nodes", "", "missing node id")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	if _, err := h.DB().ExecContext(ctx,
		`UPDATE caddy_nodes SET tunnel_enabled = 0 WHERE id = ?`, id); err != nil {
		redirectWithFlash(w, r, "/admin/nodes", "", "disable failed: "+sanitizeErr(err))
		return
	}
	// Push config so the WSS /wg-tunnel route is removed from Caddy.
	h.resyncTunnelNode(id)
	sess := middleware.SessionFromContext(r.Context())
	audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "admin.node.tunnel.disable", Entity: "caddy_node",
		EntityID: itoa64(id),
	})
	redirectWithFlash(w, r, "/admin/nodes", "Tunnel disabled on node", "")
}
