package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/hostyt/proxy-gateway/internal/domain/wgpeer"
	"github.com/hostyt/proxy-gateway/internal/security"
)

// WGBootstrapHandler serves the customer-side WG tunnel configuration:
//
//	GET /api/wg/bootstrap?token=<64-hex>      → text/plain WireGuard .conf
//	GET /api/wg/install.sh?token=<64-hex>     → bash installer (iter 7)
//	GET /api/wg/qr.png?token=<64-hex>         → QR PNG of .conf (iter 10)
//	GET /api/node/wg/peers?node_token=<...>   → node-agent pulls peer list
//
// All endpoints are unauthenticated by session/cookie - they rely on
// the single-shot bootstrap token (24h TTL) or per-node API token.
// Rate-limited per IP via Redis to slow brute-force enumeration.
type WGBootstrapHandler struct {
	DB          func() *sql.DB
	Logger      *slog.Logger
	Peers       *wgpeer.Service
	RDB         *redis.Client
	PerIPPerMin int    // 0 disables
	AppURL      string // configured panel URL (cfg.App.URL); MUST be trusted source for installer script base
	// OnWstunnelHealthy fires when a node's wstunnel_healthy flips in EITHER
	// direction. The WSS /wg-tunnel route is health-gated AND ignored by drift,
	// so this resync is the only thing that adds it (healthy) or removes the
	// stale route (unhealthy).
	OnWstunnelHealthy func(nodeID int64)
}

func (h *WGBootstrapHandler) rateLimited(r *http.Request) bool {
	if h.PerIPPerMin <= 0 || h.RDB == nil {
		return false
	}
	ip := security.ClientIP(r)
	key := "hpg:wgboot:rl:" + ip
	ctx, cancel := context.WithTimeout(r.Context(), 200*time.Millisecond)
	defer cancel()
	n, err := h.RDB.Incr(ctx, key).Result()
	if err != nil {
		return false
	}
	if n == 1 {
		_ = h.RDB.Expire(ctx, key, time.Minute).Err()
	}
	return int(n) > h.PerIPPerMin
}

// BootstrapConf serves GET /api/wg/bootstrap?token=X.
func (h *WGBootstrapHandler) BootstrapConf(w http.ResponseWriter, r *http.Request) {
	if h.rateLimited(r) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
		return
	}
	token := r.URL.Query().Get("token")
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	res, err := h.Peers.ConsumeBootstrap(ctx, token)
	if err != nil {
		if errors.Is(err, wgpeer.ErrTokenInvalid) {
			http.Error(w, "bootstrap token invalid or expired", http.StatusForbidden)
			return
		}
		h.Logger.Warn("wg bootstrap", "err", err)
		http.Error(w, "bootstrap failed", http.StatusInternalServerError)
		return
	}
	body := wgpeer.RenderConfig(res)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition",
		`attachment; filename="hostyt-tunnel-`+strconv.FormatInt(res.Peer.ID, 10)+`.conf"`)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(body))
}

// Pinned wstunnel release: version + per-arch sha256 of the linux tarball.
// Bump together (fetch checksums.txt from the release) - never unpin to "latest".
const wstunnelVersion = "10.5.5"

var wstunnelSHA256 = map[string]string{
	"amd64": "b20ffa02e945ec0c0d6b153ba69a290593f0957ed2892aee8f987f715ccd95d6",
	"arm64": "db85183da9732f26c110a08e3fffdfcfc4a44d544035d01eeefa708ed23874bb",
	"armv7": "c61c804018bf8184a48aee1d543d144e2176fbc60ebf2eea9c716c07a9f83aba",
}

// installTransport carries node-level tunnel transport info for script rendering.
type installTransport struct {
	Mode          string // "udp"|"wss"|"auto"
	WssURL        string // e.g. "wss://p1-tunel.node.yt/wg-tunnel" (empty when mode=udp)
	ListenPort    int    // node WG listen port; wstunnel client must forward to this, not a hardcoded default
	Misconfigured bool   // non-UDP transport selected but no backend wstunnel port: emitting WSS would strand the client
	LookupFailed  bool   // transient DB error: caller must 503, NOT fall open to a UDP script
}

// queryInstallTransport fetches transport mode + WSS URL for a token WITHOUT
// consuming it. Token validity is still enforced so it can't be probed.
//
// WSS is only emitted when a backend wstunnel port exists AND the node recently
// reported a healthy wstunnel server (the Caddy /wg-tunnel route is built under
// the same conditions in buildNodePush). Otherwise:
//   - "wss"  -> Misconfigured (forced WSS can't work; caller must 503, not ship a broken installer)
//   - "auto" -> silently degrade to a plain UDP install (auto already prefers UDP)
//
// A DB error sets LookupFailed (caller 503s) instead of failing open to UDP: a
// transient timeout must not hand a UDP script to a forced-WSS node whose .conf
// the separate /bootstrap call will rewrite to 127.0.0.1:51822.
func queryInstallTransport(ctx context.Context, db *sql.DB, token string) installTransport {
	var transport, endpoint string
	var listenPort int
	var wstPort sql.NullInt64
	var wstHealthy sql.NullBool
	var wstReportedFresh sql.NullBool
	// Transport metadata must remain available AFTER the bootstrap token is
	// consumed: a WSS install that fetched the .conf then failed mid-way needs
	// the WSS repair block on rerun. We gate on the row existing, not on
	// consumed_at/expiry (the .conf fetch itself enforces single-shot in
	// ConsumeBootstrap; this lookup returns no secrets).
	err := db.QueryRowContext(ctx,
		`SELECT COALESCE(cn.tunnel_transport,'udp'), COALESCE(cn.tunnel_endpoint,''),
		        COALESCE(cn.tunnel_listen_port,51821), cn.tunnel_wstunnel_port,
		        cn.tunnel_wstunnel_healthy,
		        cn.tunnel_wstunnel_reported_at > NOW() - INTERVAL 3 MINUTE
		   FROM customer_wg_bootstrap b
		   JOIN customer_wg_peer p ON p.id = b.peer_id
		   JOIN caddy_nodes cn ON cn.id = p.node_id
		  WHERE b.token = ?`,
		token).Scan(&transport, &endpoint, &listenPort, &wstPort, &wstHealthy, &wstReportedFresh)
	if errors.Is(err, sql.ErrNoRows) {
		return installTransport{Mode: "udp"} // unknown/expired token: UDP script (bootstrap fetch 403s anyway)
	}
	if err != nil {
		return installTransport{LookupFailed: true} // transient: 503, do not fall open
	}
	if transport == "udp" {
		return installTransport{Mode: "udp"}
	}
	// Derive hostname from endpoint (strip :port).
	hostname := endpoint
	if h, _, err2 := net.SplitHostPort(endpoint); err2 == nil && h != "" {
		hostname = h
	}
	// WSS is only safe to advertise when: a valid backend port exists, the
	// hostname is shell-safe (interpolated into a root script), AND the node has
	// reported a healthy wstunnel within the freshness window. The "never
	// reported" case (NULL healthy) is allowed so a just-enabled node isn't
	// blocked before its first heartbeat; a node that reports unhealthy/stale is
	// withheld - that closes the "panel advertises WSS the node can't serve" gap.
	healthOK := !wstHealthy.Valid || (wstHealthy.Bool && wstReportedFresh.Valid && wstReportedFresh.Bool)
	hasBackend := wstPort.Valid && wstPort.Int64 > 0 && wstPort.Int64 < 65536 && validWSSHost(hostname) && healthOK
	if !hasBackend {
		if transport == "wss" {
			return installTransport{Mode: "wss", Misconfigured: true}
		}
		return installTransport{Mode: "udp"} // auto degrades to UDP
	}
	if listenPort < 1 || listenPort > 65535 {
		listenPort = 51821
	}
	return installTransport{
		Mode:       transport,
		WssURL:     "wss://" + hostname + "/wg-tunnel",
		ListenPort: listenPort,
	}
}

// validWSSHost accepts only DNS-hostname / IP-literal characters. It rejects
// every shell metacharacter ($ ( ) ` | ; space /), so the host is safe to
// embed in the root installer's systemd unit + echo lines.
func validWSSHost(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	for _, r := range h {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-') {
			return false
		}
	}
	return true
}

// InstallScript serves GET /api/wg/install.sh?token=X. The script is
// rendered server-side with the token embedded so `curl … | bash`
// installs WireGuard, downloads .conf via the bootstrap endpoint, and
// brings the tunnel up + persists a systemd unit.
func (h *WGBootstrapHandler) InstallScript(w http.ResponseWriter, r *http.Request) {
	if h.rateLimited(r) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
		return
	}
	token := strings.TrimSpace(r.URL.Query().Get("token"))
	if len(token) != 192 {
		http.Error(w, "missing token", http.StatusBadRequest)
		return
	}
	// Base URL MUST come from configured AppURL, not request headers,
	// otherwise an attacker can spoof X-Forwarded-Host and the bash
	// script tells the victim to `curl attacker.com/.../?token=`.
	// Validate that AppURL parses with an https scheme + host - operator
	// typo (`evil.com` without scheme) would otherwise still produce a
	// dial-able-by-shell relative-looking host.
	base := ""
	if h.AppURL != "" {
		if u, err := url.Parse(h.AppURL); err == nil && u.Scheme == "https" && u.Host != "" {
			base = strings.TrimRight(h.AppURL, "/")
		} else {
			h.Logger.Warn("install script: AppURL invalid, refusing render",
				"app_url_set", h.AppURL != "")
			http.Error(w, "install URL not configured (operator must set APP_URL to https://...)", http.StatusServiceUnavailable)
			return
		}
	} else {
		http.Error(w, "install URL not configured (operator must set APP_URL)", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	transport := installTransport{Mode: "udp"}
	if db := h.DB(); db != nil {
		transport = queryInstallTransport(ctx, db, token)
	}
	// Transient DB error: 503 + retry, never fall open to a UDP script (a
	// forced-WSS node's .conf would still be rewritten to the local wstunnel).
	if transport.LookupFailed {
		h.Logger.Warn("install script: transport lookup failed", "token_prefix", safePrefix(token))
		w.Header().Set("Retry-After", "5")
		http.Error(w, "tunnel transport lookup failed, retry in a few seconds", http.StatusServiceUnavailable)
		return
	}
	// Refuse to ship a forced-WSS installer with no backend port / unhealthy
	// node - it would rewrite the client to a local wstunnel with nowhere to go.
	if transport.Misconfigured {
		h.Logger.Error("install script: wss transport without a serving backend", "token_prefix", safePrefix(token))
		http.Error(w, "tunnel transport not ready (node not serving WSS yet, or wstunnel port unset)", http.StatusServiceUnavailable)
		return
	}
	script := renderInstallScript(base, token, transport)
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(script))
}

// NodePeersPull serves GET /api/node/wg/peers - called by hpg-node-agent
// every ~30s. Authenticated by per-node token (caddy_nodes.join_secret
// or a dedicated tunnel_node_token; for now reuse the join secret).
func (h *WGBootstrapHandler) NodePeersPull(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimSpace(r.URL.Query().Get("node_token"))
	if token == "" {
		// Allow Bearer for cleaner curl from the agent.
		auth := r.Header.Get("Authorization")
		if strings.HasPrefix(auth, "Bearer ") {
			token = strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
		}
	}
	if token == "" {
		http.Error(w, "missing node_token", http.StatusUnauthorized)
		return
	}
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	var nodeID int64
	if err := db.QueryRowContext(ctx,
		`SELECT id FROM caddy_nodes WHERE agent_token_hash IS NOT NULL AND agent_token_hash = SHA2(?, 256) LIMIT 1`,
		token).Scan(&nodeID); err != nil {
		// Log every miss so misconfigured agents are visible instead of
		// silently looping 403 every 30s with no signal.
		h.Logger.Warn("node-agent token mismatch", "ip", security.ClientIP(r), "token_prefix", safePrefix(token))
		http.Error(w, "denied", http.StatusForbidden)
		return
	}
	peers, err := h.Peers.PeersForNode(ctx, nodeID)
	if err != nil {
		http.Error(w, "lookup failed", http.StatusInternalServerError)
		return
	}
	// JSON: { "peers": [ { "pubkey": "...", "allowed_ip": "100.96.5.42/32", "status": "active" } ] }
	var b strings.Builder
	b.WriteString(`{"peers":[`)
	for i, p := range peers {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`{"pubkey":"`)
		b.WriteString(jsonEsc(p.Pubkey))
		b.WriteString(`","allowed_ip":"`)
		b.WriteString(jsonEsc(p.AssignedIP))
		b.WriteString(`/32","status":"`)
		b.WriteString(jsonEsc(p.Status))
		b.WriteString(`"}`)
	}
	b.WriteString(`]}`)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(b.String()))
}

// PeerStatus serves GET /api/wg/status?token=X used by the create-tunnel
// wizard to live-poll whether the customer has finished install. Returns
// minimal JSON: { "status": "pending|active", "last_handshake": "RFC3339|null" }
func (h *WGBootstrapHandler) PeerStatus(w http.ResponseWriter, r *http.Request) {
	if h.rateLimited(r) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
		return
	}
	token := strings.TrimSpace(r.URL.Query().Get("token"))
	if len(token) != 192 {
		http.Error(w, "missing token", http.StatusBadRequest)
		return
	}
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	var status string
	var hs sql.NullTime
	err := db.QueryRowContext(ctx,
		`SELECT p.status, p.last_handshake_at
		   FROM customer_wg_bootstrap b
		   JOIN customer_wg_peer p ON p.id = b.peer_id
		  WHERE b.token=?`, token).Scan(&status, &hs)
	if err != nil {
		http.Error(w, "unknown token", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	hsField := "null"
	if hs.Valid {
		hsField = `"` + hs.Time.UTC().Format(time.RFC3339) + `"`
	}
	_, _ = w.Write([]byte(`{"status":"` + jsonEsc(status) + `","last_handshake":` + hsField + `}`))
}

// NodeHandshakeReport receives POST /api/node/wg/handshakes from the
// node-agent: `{"reports":[{"pubkey":"...","last_handshake":"RFC3339"}]}`.
// Updates last_handshake_at so the UI can show "Connected".
func (h *WGBootstrapHandler) NodeHandshakeReport(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimSpace(r.URL.Query().Get("node_token"))
	if token == "" {
		auth := r.Header.Get("Authorization")
		if strings.HasPrefix(auth, "Bearer ") {
			token = strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
		}
	}
	if token == "" {
		http.Error(w, "missing node_token", http.StatusUnauthorized)
		return
	}
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	var nodeID int64
	if err := db.QueryRowContext(ctx,
		`SELECT id FROM caddy_nodes WHERE agent_token_hash IS NOT NULL AND agent_token_hash = SHA2(?, 256) LIMIT 1`,
		token).Scan(&nodeID); err != nil {
		// Log every miss so misconfigured agents are visible instead of
		// silently looping 403 every 30s with no signal.
		h.Logger.Warn("node-agent token mismatch", "ip", security.ClientIP(r), "token_prefix", safePrefix(token))
		http.Error(w, "denied", http.StatusForbidden)
		return
	}
	// Cap the body: this endpoint is in the public group (no APIKeyAuth/CSRF
	// size limit), so an authenticated node-token holder could otherwise
	// stream an unbounded form into memory.
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	// Minimal JSON parse without full struct (one-shot allocation savings).
	if err := r.ParseForm(); err == nil {
		// Optional: form-encoded reports for ultra-simple agents.
		if pubs, ok := r.Form["pubkey"]; ok {
			when := time.Now()
			for _, pk := range pubs {
				_, _ = db.ExecContext(ctx,
					`UPDATE customer_wg_peer SET last_handshake_at=? WHERE node_id=? AND pubkey=?`,
					when, nodeID, pk)
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

// bearerToken extracts the node token from ?node_token= or an Authorization
// Bearer header.
func bearerToken(r *http.Request) string {
	if t := strings.TrimSpace(r.URL.Query().Get("node_token")); t != "" {
		return t
	}
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
	}
	return ""
}

// NodePeerStatsReport receives POST /api/node/wg/stats from the node-agent with
// per-peer WireGuard stats (last handshake epoch, rx/tx bytes, observed
// endpoint) parsed from `wg show <iface> dump`. Authenticated by the per-node
// token. Supersedes /api/node/wg/handshakes (kept live for rolling deploys).
func (h *WGBootstrapHandler) NodePeerStatsReport(w http.ResponseWriter, r *http.Request) {
	token := bearerToken(r)
	if token == "" {
		http.Error(w, "missing node_token", http.StatusUnauthorized)
		return
	}
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	var nodeID int64
	if err := db.QueryRowContext(ctx,
		`SELECT id FROM caddy_nodes WHERE agent_token_hash IS NOT NULL AND agent_token_hash = SHA2(?, 256) LIMIT 1`,
		token).Scan(&nodeID); err != nil {
		h.Logger.Warn("node-agent token mismatch (stats)", "ip", security.ClientIP(r), "token_prefix", safePrefix(token))
		http.Error(w, "denied", http.StatusForbidden)
		return
	}

	var body struct {
		Stats []struct {
			Pubkey        string `json:"pubkey"`
			LastHandshake int64  `json:"last_handshake"`
			RxBytes       int64  `json:"rx_bytes"`
			TxBytes       int64  `json:"tx_bytes"`
			Endpoint      string `json:"endpoint"`
		} `json:"stats"`
		// Node is optional node-level forwarding diagnostics (added with the
		// hardened agent). Pointers so older agents that omit it stay NULL in
		// DB instead of overwriting with false negatives.
		Node *struct {
			IPForwardEnabled          *bool  `json:"ip_forward_enabled"`
			ForwardPolicyDropDetected *bool  `json:"forward_policy_drop_detected"`
			DockerRulesInstalled      *bool  `json:"docker_rules_installed"`
			FirewallBackend           string `json:"firewall_backend"`
			MTU                       int    `json:"mtu"`
			ListenPort                string `json:"listen_port"`
			LastSetupError            string `json:"last_setup_error"`
			WstunnelHealthy           *bool  `json:"wstunnel_healthy"`
		} `json:"node"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 64*1024)).Decode(&body); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}

	// Persist node forwarding diagnostics (best-effort) so the panel can show
	// WHY a peer is provisioned-but-dead. Truncate the error to the column width.
	if n := body.Node; n != nil {
		setupErr := n.LastSetupError
		if len(setupErr) > 512 {
			setupErr = setupErr[:512]
		}
		fwBackend := n.FirewallBackend
		if len(fwBackend) > 32 {
			fwBackend = fwBackend[:32]
		}
		_, _ = db.ExecContext(ctx,
			`UPDATE caddy_nodes
			    SET fwd_ip_forward_enabled    = ?,
			        fwd_policy_drop_detected   = ?,
			        fwd_docker_rules_installed = ?,
			        fwd_firewall_backend       = ?,
			        fwd_mtu                    = ?,
			        fwd_last_setup_error       = ?,
			        fwd_reported_at            = NOW()
			  WHERE id = ?`,
			boolPtrToNull(n.IPForwardEnabled), boolPtrToNull(n.ForwardPolicyDropDetected),
			boolPtrToNull(n.DockerRulesInstalled), nullStr(fwBackend), nullInt(n.MTU),
			nullStr(setupErr), nodeID)
		// Record wstunnel liveness + freshness so the panel can gate WSS
		// route/installer rendering. Only when the agent reported it (non-UDP).
		if n.WstunnelHealthy != nil {
			// Read prior state to detect a health TRANSITION (either direction).
			var was sql.NullBool
			_ = db.QueryRowContext(ctx,
				`SELECT tunnel_wstunnel_healthy FROM caddy_nodes WHERE id = ?`, nodeID).Scan(&was)
			_, _ = db.ExecContext(ctx,
				`UPDATE caddy_nodes
				    SET tunnel_wstunnel_healthy = ?, tunnel_wstunnel_reported_at = NOW()
				  WHERE id = ?`,
				boolPtrToNull(n.WstunnelHealthy), nodeID)
			// Resync on any health change: rising edge adds the now-eligible WSS
			// route, falling edge rebuilds without it (the route is health-gated in
			// buildNodePush, so a /load removes the now-stale /wg-tunnel route).
			// Nothing else triggers this - drift ignores infra routes.
			healthyBefore := was.Valid && was.Bool
			if *n.WstunnelHealthy != healthyBefore && h.OnWstunnelHealthy != nil {
				h.OnWstunnelHealthy(nodeID)
			}
		}
	}

	// Batch-load each peer's id + previous raw counters so we can compute
	// reset-safe deltas (wg counters zero on rekey/restart) without an N+1
	// SELECT inside the loop.
	type prevRow struct {
		id             int64
		prevRx, prevTx int64
	}
	prev := map[string]prevRow{}
	if rows, err := db.QueryContext(ctx,
		`SELECT pubkey, id, prev_rx_bytes, prev_tx_bytes FROM customer_wg_peer WHERE node_id = ? AND pubkey IS NOT NULL`,
		nodeID); err == nil {
		for rows.Next() {
			var pk string
			var pr prevRow
			if rows.Scan(&pk, &pr.id, &pr.prevRx, &pr.prevTx) == nil {
				prev[pk] = pr
			}
		}
		rows.Close()
	}

	for _, s := range body.Stats {
		// pubkey is base64 of a 32-byte key (44 chars). The agent now reports
		// EVERY configured peer including never-handshook ones (epoch 0) so the
		// panel can show "provisioned but never connected"; we still must NOT
		// clobber a good last_handshake with 0 - see the COALESCE-style guard.
		if len(s.Pubkey) != 44 {
			continue
		}
		ep := sql.NullString{String: s.Endpoint, Valid: s.Endpoint != ""}
		// Reset-safe delta: a counter that went backwards means wg reset it
		// (rekey/restart), so the new raw value IS the delta since last report.
		pr, known := prev[s.Pubkey]
		var rxDelta, txDelta int64
		if known {
			if s.RxBytes >= pr.prevRx {
				rxDelta = s.RxBytes - pr.prevRx
			} else {
				rxDelta = s.RxBytes
			}
			if s.TxBytes >= pr.prevTx {
				txDelta = s.TxBytes - pr.prevTx
			} else {
				txDelta = s.TxBytes
			}
		}
		// Keep handshake columns NULL-safe: when epoch is 0 (never connected)
		// pass NULL so the SET ... = COALESCE(?, existing) preserves any prior
		// good value while still recording bytes/endpoint for diagnostics.
		var hsEpoch, hsTime any
		if s.LastHandshake > 0 {
			hsEpoch = s.LastHandshake
			hsTime = s.LastHandshake
		}
		_, _ = db.ExecContext(ctx,
			`UPDATE customer_wg_peer
			    SET last_handshake_epoch = COALESCE(?, last_handshake_epoch),
			        last_handshake_at    = COALESCE(FROM_UNIXTIME(?), last_handshake_at),
			        rx_bytes             = ?,
			        tx_bytes             = ?,
			        cumulative_rx_bytes  = cumulative_rx_bytes + ?,
			        cumulative_tx_bytes  = cumulative_tx_bytes + ?,
			        prev_rx_bytes        = ?,
			        prev_tx_bytes        = ?,
			        endpoint             = ?
			  WHERE node_id = ? AND pubkey = ?`,
			hsEpoch, hsTime, s.RxBytes, s.TxBytes,
			rxDelta, txDelta, s.RxBytes, s.TxBytes, ep, nodeID, s.Pubkey)
		// Record a usage sample only when there was traffic, for history graphs.
		if known && (rxDelta > 0 || txDelta > 0) {
			_, _ = db.ExecContext(ctx,
				`INSERT INTO customer_wg_peer_usage_sample (peer_id, node_id, rx_delta, tx_delta) VALUES (?, ?, ?, ?)`,
				pr.id, nodeID, rxDelta, txDelta)
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

// publicBaseURL extracts the panel's external base URL from the request.
// Falls back to constructed host. Used to embed in installer scripts.
func publicBaseURL(r *http.Request) string {
	scheme := "https"
	if r.Header.Get("X-Forwarded-Proto") == "http" || r.TLS == nil && r.Header.Get("X-Forwarded-Proto") != "https" {
		// Best-effort: keep https for production deploys, drop only when explicit.
		if r.TLS == nil && r.Header.Get("X-Forwarded-Proto") == "" {
			scheme = "http"
		}
	}
	host := r.Host
	if h := r.Header.Get("X-Forwarded-Host"); h != "" {
		host = h
	}
	return scheme + "://" + host
}

// renderInstallScript returns the bash one-liner installer body. The
// script is intentionally small and dependency-light so it runs on any
// modern Linux. Currently Linux-only; we surface a friendly message on
// non-Linux platforms.
func renderInstallScript(baseURL, token string, tr installTransport) string {
	confURL := baseURL + "/api/wg/bootstrap?token=" + token

	// wstunnel fallback block - injected when mode is "wss" or "auto".
	// Version + per-arch checksums are PINNED: this script runs as root, so an
	// unpinned "latest" download is remote root code-exec on every customer host.
	wstFallback := ""
	if tr.WssURL != "" {
		lp := strconv.Itoa(tr.ListenPort)
		wstFallback = `
# wstunnel_install switches the WG endpoint to WebSocket-over-TLS when UDP is blocked.
wstunnel_install() {
  echo "[wstunnel] UDP blocked - switching to WebSocket transport..."
  WST_VER="` + wstunnelVersion + `"
  ARCH=$(uname -m)
  case "$ARCH" in
    x86_64|amd64)   WST_ASSET="wstunnel_${WST_VER}_linux_amd64.tar.gz"; WST_SHA="` + wstunnelSHA256["amd64"] + `" ;;
    aarch64|arm64)  WST_ASSET="wstunnel_${WST_VER}_linux_arm64.tar.gz"; WST_SHA="` + wstunnelSHA256["arm64"] + `" ;;
    armv7l|armv7)   WST_ASSET="wstunnel_${WST_VER}_linux_armv7.tar.gz"; WST_SHA="` + wstunnelSHA256["armv7"] + `" ;;
    *) echo "wstunnel: unsupported arch $ARCH"; return 1 ;;
  esac
  WST_URL="https://github.com/erebe/wstunnel/releases/download/v${WST_VER}/${WST_ASSET}"
  WST_TMP=$(mktemp -d)
  echo "[wstunnel] Downloading pinned v${WST_VER} (${WST_ASSET})..."
  curl -fsSL -o "${WST_TMP}/wst.tgz" "$WST_URL" || { echo "wstunnel download failed"; rm -rf "$WST_TMP"; return 1; }
  # Refuse to install a binary whose hash does not match the pinned release.
  if ! echo "${WST_SHA}  ${WST_TMP}/wst.tgz" | sha256sum -c - >/dev/null 2>&1; then
    echo "wstunnel: checksum MISMATCH - refusing to install (possible tampering)."
    rm -rf "$WST_TMP"; return 1
  fi
  tar -xzf "${WST_TMP}/wst.tgz" -C "$WST_TMP" || { echo "wstunnel extract failed"; rm -rf "$WST_TMP"; return 1; }
  WST_BIN=$(find "$WST_TMP" -type f -name wstunnel | head -n1)
  [ -n "$WST_BIN" ] || { echo "wstunnel binary not found in archive"; rm -rf "$WST_TMP"; return 1; }
  install -m 755 "$WST_BIN" /usr/local/bin/wstunnel
  rm -rf "$WST_TMP"

  # Redirect WG endpoint to local wstunnel client (listens on UDP:51822).
  sed -i 's|^Endpoint = .*|Endpoint = 127.0.0.1:51822|' /etc/wireguard/${IFACE}.conf

  # Systemd unit keeps wstunnel client alive; forwards UDP:51822 → wss node.
  # -P wg-tunnel: client ignores the URL path; without it it upgrades on /v1/events
  # which misses Caddy's /wg-tunnel* route. Prefix -> upgrade path /wg-tunnel/events.
  # Quoted delimiter: no shell expansion in the body (host is also validated).
  cat >/etc/systemd/system/hostyt-wstunnel.service <<'WSTUNIT'
[Unit]
Description=Hostyt WG tunnel WebSocket transport
After=network.target
Wants=network.target

[Service]
ExecStart=/usr/local/bin/wstunnel client --http-upgrade-path-prefix wg-tunnel -L 'udp://51822:127.0.0.1:` + lp + `' ` + tr.WssURL + `
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
WSTUNIT
  systemctl daemon-reload
  systemctl enable --now hostyt-wstunnel.service
  echo "[wstunnel] WebSocket client started (` + tr.WssURL + `)."
}
`
	}

	// Logic that runs after first WG bring-up; only in "auto" mode.
	wstAutoBlock := ""
	if tr.Mode == "auto" {
		wstAutoBlock = `
# Auto-detect: if UDP handshake failed, fall back to wstunnel WebSocket transport.
if ! health_check 2>/dev/null; then
  wg-quick down ${IFACE} 2>/dev/null || true
  if wstunnel_install; then
    wg-quick up ${IFACE}
  else
    echo "wstunnel install failed; tunnel remains down."
    exit 1
  fi
fi
`
	}

	// Force-wss: skip UDP entirely, set up wstunnel before bringing WG up.
	wstForceBlock := ""
	if tr.Mode == "wss" {
		wstForceBlock = `
echo "[2b/4] Setting up WebSocket transport (forced)..."
wstunnel_install || { echo "wstunnel install failed"; exit 1; }
`
	}

	// Rerun repair: if the existing conf already uses the local wstunnel client
	// but the sidecar is gone/stopped, reinstall it - else WG never comes up.
	wstRepairBlock := ""
	if tr.WssURL != "" {
		wstRepairBlock = `
  if grep -q '127.0.0.1:51822' /etc/wireguard/${IFACE}.conf 2>/dev/null; then
    if [ ! -x /usr/local/bin/wstunnel ] || ! systemctl is-active --quiet hostyt-wstunnel.service 2>/dev/null; then
      echo "WSS sidecar missing or stopped - reinstalling wstunnel before bringing tunnel up…"
      wstunnel_install || echo "wstunnel repair failed (tunnel may stay down)."
    fi
  fi
`
	}

	return `#!/usr/bin/env bash
set -euo pipefail

if [ "$(uname -s)" != "Linux" ]; then
  echo "hostyt-tunnel installer: only Linux is supported by this script."
  echo "On macOS/Windows download the .conf manually from the panel:"
  echo "  ` + confURL + `"
  exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
  echo "Re-running with sudo (needs root for wireguard + systemd)."
  exec sudo -E bash "$0" "$@"
fi

# Removal mode: ` + "`" + `curl ...install.sh?token=X | sudo bash -s -- remove` + "`" + ` tears the
# tunnel down (WG + wstunnel sidecar + conf) so a stale conf can't hang the
# rerun. No token needed; reinstall with a FRESH installer URL afterwards.
case "${1:-}" in
  remove|uninstall|--remove|--uninstall)
    echo "Removing hostyt tunnel…"
    systemctl disable --now wg-quick@hostyt 2>/dev/null || true
    systemctl disable --now hostyt-wstunnel.service 2>/dev/null || true
    rm -f /etc/systemd/system/hostyt-wstunnel.service
    systemctl daemon-reload 2>/dev/null || true
    wg-quick down hostyt 2>/dev/null || true
    rm -f /etc/wireguard/hostyt.conf
    echo "Removed. Reinstall with a fresh installer URL from the panel."
    exit 0
    ;;
esac

echo "[1/4] Installing wireguard-tools…"
if command -v apt >/dev/null 2>&1; then
  DEBIAN_FRONTEND=noninteractive apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq wireguard-tools curl tar
elif command -v dnf >/dev/null 2>&1; then
  dnf install -y -q wireguard-tools curl tar
elif command -v yum >/dev/null 2>&1; then
  yum install -y -q wireguard-tools curl tar
elif command -v apk >/dev/null 2>&1; then
  apk add --no-cache wireguard-tools curl tar
else
  echo "Unsupported package manager. Install wireguard-tools manually, then re-run."
  exit 1
fi

IFACE=hostyt

# health_check validates the tunnel is actually working and prints a CLEAR
# pass/fail with actionable reasons. Used after first install AND on rerun.
health_check() {
  echo "[health] Checking tunnel…"
  if ! wg show "$IFACE" >/dev/null 2>&1; then
    echo "  FAIL: interface $IFACE is not up."
    echo "        - kernel WireGuard module may be missing (try: modprobe wireguard)"
    echo "        - check: journalctl -u wg-quick@${IFACE} --no-pager | tail -n 30"
    return 1
  fi
  echo "  OK: interface $IFACE is up."
  # Gateway = the peer AllowedIPs (node gateway). Needed to actively kick traffic.
  GW=$(awk -F'= *' '/^AllowedIPs/ { split($2, a, "/"); print a[1]; exit }' /etc/wireguard/${IFACE}.conf 2>/dev/null)
  # WireGuard stays silent until the first outbound packet (or a keepalive up
  # to 25s away), so polling passively false-fails a healthy fresh tunnel. Kick
  # traffic to trigger the handshake, then re-kick each second while polling.
  GW_PINGABLE=0
  HS=0
  AGE=999999
  # Record probe start: only a handshake at/after START proves the tunnel is
  # live NOW. A pre-existing handshake (e.g. 60s old) could otherwise pass a
  # tunnel that died just before this check.
  START=$(date +%s 2>/dev/null || echo 0)
  FRESH=0
  for _ in $(seq 1 20); do
    if [ -n "$GW" ] && command -v ping >/dev/null 2>&1; then
      ping -c1 -W2 "$GW" >/dev/null 2>&1 && GW_PINGABLE=1
    fi
    HS=$(wg show "$IFACE" latest-handshakes 2>/dev/null | awk '{ if ($2+0 > 0) print $2 }' | sort -nr | head -n1)
    [ -z "$HS" ] && HS=0
    if [ "$HS" -gt 0 ] 2>/dev/null; then
      NOW=$(date +%s 2>/dev/null || echo 0)
      if [ "$NOW" -gt 0 ] 2>/dev/null && [ "$START" -gt 0 ] 2>/dev/null; then
        AGE=$((NOW - HS))
        # Require a handshake that happened during THIS probe (HS >= START).
        if [ "$HS" -ge "$START" ] 2>/dev/null; then FRESH=1; break; fi
      else
        AGE=0 # no clock available; accept handshake presence
        FRESH=1
        break
      fi
    fi
    sleep 1
  done
  if [ "$FRESH" = 1 ] 2>/dev/null; then
    echo "  OK: fresh handshake (${AGE}s ago)."
  else
    echo "  FAIL: no fresh handshake within 20s - the tunnel is not passing traffic."
    echo "        Most common causes:"
    echo "        - outbound UDP to the node endpoint is blocked (cloud security group / firewall)."
    echo "          Allow UDP egress to the Endpoint shown in /etc/wireguard/${IFACE}.conf."
    echo "        - kernel WireGuard module missing (try: modprobe wireguard; apt/dnf install wireguard)."
    echo "        - MTU/PMTU blackhole on this network (the .conf already sets MTU 1420 + MSS clamp)."
    return 1
  fi
  if [ "$GW_PINGABLE" = 1 ]; then
    echo "  OK: gateway $GW reachable over the tunnel."
  elif [ -n "$GW" ]; then
    # Non-fatal: many gateways drop ICMP; handshake already proves the path.
    echo "  WARN: gateway $GW did not answer ICMP (often filtered) - tunnel still up."
  fi
  echo "[health] PASS - tunnel is healthy."
  return 0
}
` + wstFallback + `
echo "[2/4] Fetching tunnel config…"
mkdir -p /etc/wireguard

# Rerun safety: the bootstrap token is single-shot, so on a rerun we must NOT
# refetch it (that would 403). Instead VALIDATE local service state and repair
# (restart + health check) rather than blindly declaring success.
if [ -f /etc/wireguard/${IFACE}.conf ]; then
  echo "/etc/wireguard/${IFACE}.conf already exists - validating existing tunnel (token is single-shot, not refetching)."
` + wstRepairBlock + `  systemctl enable --now wg-quick@${IFACE}.service 2>/dev/null || wg-quick up ${IFACE} 2>/dev/null || true
  if health_check; then
    echo "Tunnel already provisioned and healthy. Nothing to do."
    exit 0
  fi
  echo "Existing tunnel is unhealthy - attempting restart…"
  systemctl restart wg-quick@${IFACE}.service 2>/dev/null || { wg-quick down ${IFACE} 2>/dev/null; wg-quick up ${IFACE} 2>/dev/null; }
  if health_check; then
    echo "Tunnel repaired."
    exit 0
  fi
  echo "Tunnel still unhealthy after restart. See the FAIL reasons above."
  echo "If credentials are stale, ask the operator to rotate the key in /admin/tunnels, then:"
  echo "  sudo systemctl disable --now wg-quick@${IFACE}"
  echo "  sudo rm /etc/wireguard/${IFACE}.conf"
  echo "and re-run a fresh installer URL."
  exit 1
fi

TMP="$(mktemp)"
HTTP=$(curl -fsSL -o "$TMP" -w "%{http_code}" "` + confURL + `" || true)
if [ "$HTTP" = "403" ]; then
  echo "Bootstrap token rejected (HTTP 403)."
  echo "Likely cause: already consumed (single-shot) OR expired (TTL 1h)."
  echo "Ask the operator to create a fresh tunnel in /admin/tunnels and re-run a new install URL."
  rm -f "$TMP"
  exit 1
fi
if [ "$HTTP" != "200" ]; then
  echo "Bootstrap failed (HTTP $HTTP). Token may be expired or panel unreachable."
  rm -f "$TMP"
  exit 1
fi
install -m 600 "$TMP" /etc/wireguard/${IFACE}.conf
rm -f "$TMP"

echo "[3/4] Bringing tunnel up…"
` + wstForceBlock + `systemctl enable --now wg-quick@${IFACE}.service
` + wstAutoBlock + `
echo "[4/4] Verifying tunnel health…"
if health_check; then HC=0; else HC=1; fi
wg show ${IFACE} | sed 's/^/  /'
if [ "$HC" = 0 ]; then
  STATUS_LINE="✓ Hostyt tunnel installed and healthy."
else
  STATUS_LINE="⚠ Hostyt tunnel installed but the health check FAILED (see reasons above). It will not pass traffic until the cause is fixed."
fi

cat <<EOF

${STATUS_LINE}

To check status later:    sudo wg show ${IFACE}
To restart:               sudo systemctl restart wg-quick@${IFACE}
To remove:                sudo systemctl disable --now wg-quick@${IFACE} && sudo rm /etc/wireguard/${IFACE}.conf

EOF
# Non-zero exit so 'curl ... | bash' surfaces a failed install to the caller.
exit $HC
`
}

// boolPtrToNull maps an optional bool to a NULL-able 0/1 for MariaDB TINYINT,
// so an absent diagnostic field stays NULL ("unknown") rather than false.
func boolPtrToNull(b *bool) any {
	if b == nil {
		return nil
	}
	if *b {
		return 1
	}
	return 0
}

// nullStr returns nil for empty strings so they store as SQL NULL.
func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// nullInt returns nil for non-positive ints so they store as SQL NULL.
func nullInt(n int) any {
	if n <= 0 {
		return nil
	}
	return n
}

// safePrefix returns the first 8 chars of a token for log correlation
// without leaking enough material to authenticate.
func safePrefix(token string) string {
	if len(token) <= 8 {
		return ""
	}
	return token[:8] + "…"
}

func jsonEsc(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "\r", `\r`, "\t", `\t`)
	return r.Replace(s)
}
