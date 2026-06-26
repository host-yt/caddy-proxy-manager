// Package wgpeer drives the customer-side WireGuard tunnel lifecycle:
// peer creation, bootstrap-token issuance, .conf assembly, and
// revocation. The control-plane mesh (operator → Caddy nodes) lives in
// internal/wireguard; this package is strictly tenant-side and writes
// to its own tables (customer_wg_peer, customer_wg_bootstrap).
package wgpeer

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/host-yt/caddy-proxy-manager/internal/wireguard"
)

// wgWstunnelClientPort is the local UDP port wstunnel client listens on
// so WireGuard sends packets to localhost instead of the node directly.
const wgWstunnelClientPort = 51822

// bootstrapTTL is the install-token validity window. 1h balances
// secret exposure (long TTL = secret sitting in chat/scrollback) vs.
// real-world UX (operator opens panel, generates tunnel, gets coffee,
// then runs install — 10m was hitting expiry mid-coffee). Atomic
// 'WHERE consumed_at IS NULL' on Consume already makes tokens one-shot;
// TTL only caps the window for unused ones.
const bootstrapTTL = time.Hour

// Encryptor wraps the panel's AES-GCM cipher (returns/accepts base64
// strings) so this package stays import-cycle free.
type Encryptor interface {
	Encrypt(plain string) (string, error)
	Decrypt(cipherB64 string) (string, error)
}

// Service is the customer-WG aggregate.
type Service struct {
	DB     *sql.DB
	Logger *slog.Logger
	Enc    Encryptor
}

// Peer mirrors a row from customer_wg_peer.
type Peer struct {
	ID            int64
	ClientID      int64
	NodeID        int64
	Name          string
	Pubkey        string
	AssignedIP    string
	Status        string
	LastHandshake *time.Time
	CreatedAt     time.Time
	ActivatedAt   *time.Time
}

// CreateInput is what the UI/API hands to Create.
type CreateInput struct {
	ClientID int64
	NodeID   int64
	Name     string
}

// CreateHAInput drives multi-node tunnel replication. NodeIDs lists 2+
// Caddy nodes (typically all healthy nodes in the customer's plan
// group); the resulting .conf lists each as a separate [Peer] sharing
// the same customer-side keypair, so the kernel WG module picks
// whichever node has a live handshake.
type CreateHAInput struct {
	ClientID int64
	NodeIDs  []int64
	Name     string
}

// Create reserves a new tunnel slot: allocates an IP, generates a
// server-side keypair (the customer can later replace pubkey via the
// bootstrap POST), writes the peer row, and returns it along with a
// one-shot bootstrap token. The token is consumed by the installer to
// download the .conf file.
func (s *Service) Create(ctx context.Context, in CreateInput) (Peer, string, error) {
	if s.DB == nil {
		return Peer{}, "", errors.New("wgpeer: no db")
	}
	name := strings.TrimSpace(in.Name)
	if name == "" {
		name = "tunnel"
	}
	if len(name) > 64 {
		name = name[:64]
	}

	// Ensure the node has tunnel mode enabled + identity set up.
	subnet, _, err := s.nodeTunnelConfig(ctx, in.NodeID)
	if err != nil {
		return Peer{}, "", err
	}

	ip, err := s.allocateIP(ctx, in.NodeID, subnet)
	if err != nil {
		return Peer{}, "", err
	}

	kp, err := wireguard.GenerateKeypair()
	if err != nil {
		return Peer{}, "", fmt.Errorf("keygen: %w", err)
	}
	encPriv, err := s.Enc.Encrypt(kp.PrivateKey)
	if err != nil {
		return Peer{}, "", fmt.Errorf("encrypt priv: %w", err)
	}

	res, err := s.DB.ExecContext(ctx,
		`INSERT INTO customer_wg_peer (client_id, node_id, name, pubkey, server_privkey_e2, assigned_ip, status)
		 VALUES (?, ?, ?, ?, ?, ?, 'pending')`,
		in.ClientID, in.NodeID, name, kp.PublicKey, []byte(encPriv), ip)
	if err != nil {
		return Peer{}, "", fmt.Errorf("insert peer: %w", err)
	}
	peerID, _ := res.LastInsertId()

	token, err := s.issueBootstrap(ctx, peerID)
	if err != nil {
		return Peer{}, "", err
	}

	return Peer{
		ID:         peerID,
		ClientID:   in.ClientID,
		NodeID:     in.NodeID,
		Name:       name,
		Pubkey:     kp.PublicKey,
		AssignedIP: ip,
		Status:     "pending",
		CreatedAt:  time.Now(),
	}, token, nil
}

// CreateHA replicates a single customer keypair across multiple nodes
// so the customer can run one wg-quick config that survives a node
// failure. All resulting customer_wg_peer rows share peer_group_id and
// pubkey/privkey; each gets its own assigned_ip from its node's pool.
// Returns the peer-group id + a bootstrap token tied to the first
// (lowest-id) peer so the installer flow stays single-shot.
func (s *Service) CreateHA(ctx context.Context, in CreateHAInput) (string, []Peer, string, error) {
	if s.DB == nil {
		return "", nil, "", errors.New("wgpeer: no db")
	}
	if len(in.NodeIDs) < 2 {
		return "", nil, "", errors.New("wgpeer: HA needs at least 2 nodes")
	}
	name := strings.TrimSpace(in.Name)
	if name == "" {
		name = "ha-tunnel"
	}
	if len(name) > 64 {
		name = name[:64]
	}

	// Single customer-side keypair, replicated across nodes.
	kp, err := wireguard.GenerateKeypair()
	if err != nil {
		return "", nil, "", fmt.Errorf("keygen: %w", err)
	}
	encPriv, err := s.Enc.Encrypt(kp.PrivateKey)
	if err != nil {
		return "", nil, "", fmt.Errorf("encrypt priv: %w", err)
	}

	// peer_group_id: cheap UUID-shaped marker. We don't need uniqueness
	// guarantees beyond "distinct across rows" so a 32-hex random is fine.
	var groupRaw [16]byte
	if _, err := rand.Read(groupRaw[:]); err != nil {
		return "", nil, "", err
	}
	groupID := hex.EncodeToString(groupRaw[:])

	out := make([]Peer, 0, len(in.NodeIDs))
	var firstPeerID int64
	for _, nid := range in.NodeIDs {
		subnet, _, err := s.nodeTunnelConfig(ctx, nid)
		if err != nil {
			return "", nil, "", fmt.Errorf("node %d: %w", nid, err)
		}
		ip, err := s.allocateIP(ctx, nid, subnet)
		if err != nil {
			return "", nil, "", fmt.Errorf("node %d alloc: %w", nid, err)
		}
		res, err := s.DB.ExecContext(ctx,
			`INSERT INTO customer_wg_peer (client_id, node_id, name, peer_group_id, pubkey, server_privkey_e2, assigned_ip, status)
			 VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')`,
			in.ClientID, nid, name, groupID, kp.PublicKey, []byte(encPriv), ip)
		if err != nil {
			return "", nil, "", fmt.Errorf("insert peer node %d: %w", nid, err)
		}
		peerID, _ := res.LastInsertId()
		if firstPeerID == 0 {
			firstPeerID = peerID
		}
		out = append(out, Peer{
			ID:         peerID,
			ClientID:   in.ClientID,
			NodeID:     nid,
			Name:       name,
			Pubkey:     kp.PublicKey,
			AssignedIP: ip,
			Status:     "pending",
			CreatedAt:  time.Now(),
		})
	}

	token, err := s.issueBootstrap(ctx, firstPeerID)
	if err != nil {
		return "", nil, "", err
	}
	return groupID, out, token, nil
}

// Revoke marks the peer revoked. Node-agent reconciler picks it up on
// next pull and removes from wg-tun0.
func (s *Service) Revoke(ctx context.Context, peerID int64) error {
	_, err := s.DB.ExecContext(ctx,
		`UPDATE customer_wg_peer SET status='revoked', revoked_at=NOW() WHERE id=? AND status<>'revoked'`,
		peerID)
	return err
}

// RotateKey generates a fresh server-side keypair + bootstrap token so
// the customer can re-install with new credentials. Old key stays valid
// until the new .conf is downloaded and applied; reconciler swaps the
// peer block atomically on next pull.
func (s *Service) RotateKey(ctx context.Context, peerID int64) (string, error) {
	kp, err := wireguard.GenerateKeypair()
	if err != nil {
		return "", err
	}
	encPriv, err := s.Enc.Encrypt(kp.PrivateKey)
	if err != nil {
		return "", err
	}
	if _, err := s.DB.ExecContext(ctx,
		`UPDATE customer_wg_peer SET pubkey=?, server_privkey_e2=?, status='pending' WHERE id=?`,
		kp.PublicKey, []byte(encPriv), peerID); err != nil {
		return "", err
	}
	return s.issueBootstrap(ctx, peerID)
}

// ConsumeBootstrap looks up a bootstrap token, marks it consumed, and
// returns the peer + decrypted private key so the handler can render a
// .conf file. Returns ErrTokenInvalid if missing/expired/consumed.
var ErrTokenInvalid = errors.New("wgpeer: bootstrap token invalid or expired")

type BootstrapResult struct {
	Peer             Peer
	ServerPrivkey    string // base64 (one-shot; caller MUST NOT persist)
	NodeEndpoint     string // host:port (primary node)
	NodeTunnelPubkey string
	NodeTunnelSubnet string // for AllowedIPs gateway
	// HAPeers (when non-empty) describes additional nodes in the same
	// peer_group_id. RenderConfig emits one [Peer] per entry so wg-quick
	// has multi-node failover built in.
	HAPeers         []HAPeerInfo
	TunnelTransport string // "udp"|"wss"|"auto"
	WstunnelPort    int    // 0 = not configured
	NodeHostname    string // hostname part of tunnel_endpoint, for WSS URL
}

type HAPeerInfo struct {
	AssignedIP   string
	Endpoint     string
	TunnelPubkey string
	TunnelSubnet string
}

func (s *Service) ConsumeBootstrap(ctx context.Context, token string) (BootstrapResult, error) {
	token = strings.TrimSpace(token)
	if len(token) != 192 {
		return BootstrapResult{}, ErrTokenInvalid
	}

	// Atomic single-shot: the WHERE consumed_at IS NULL clause guarantees
	// only one concurrent call can win. RowsAffected==0 means race lost
	// or token already consumed/expired.
	res, err := s.DB.ExecContext(ctx,
		`UPDATE customer_wg_bootstrap
		   SET consumed_at = NOW()
		 WHERE token = ?
		   AND consumed_at IS NULL
		   AND expires_at > NOW()`, token)
	if err != nil {
		return BootstrapResult{}, err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return BootstrapResult{}, ErrTokenInvalid
	}

	var peerID int64
	if err := s.DB.QueryRowContext(ctx,
		`SELECT peer_id FROM customer_wg_bootstrap WHERE token=?`,
		token).Scan(&peerID); err != nil {
		return BootstrapResult{}, err
	}

	var (
		clientID   int64
		nodeID     int64
		name       string
		pubkey     string
		encPriv    []byte
		assignedIP string
		status     string
		peerGroup  sql.NullString
	)
	if err := s.DB.QueryRowContext(ctx,
		`SELECT client_id, node_id, name, pubkey, server_privkey_e2, assigned_ip, status, peer_group_id
		 FROM customer_wg_peer WHERE id=?`,
		peerID).Scan(&clientID, &nodeID, &name, &pubkey, &encPriv, &assignedIP, &status, &peerGroup); err != nil {
		return BootstrapResult{}, err
	}
	if status == "revoked" {
		return BootstrapResult{}, ErrTokenInvalid
	}

	priv, err := s.Enc.Decrypt(string(encPriv))
	if err != nil {
		return BootstrapResult{}, fmt.Errorf("decrypt priv: %w", err)
	}

	var (
		endpoint, tunPub, subnet sql.NullString
		listenPort               sql.NullInt64
		transport                sql.NullString
		wstunnelPort             sql.NullInt64
	)
	if err := s.DB.QueryRowContext(ctx,
		`SELECT tunnel_endpoint, tunnel_pubkey, tunnel_subnet, tunnel_listen_port, tunnel_transport, tunnel_wstunnel_port FROM caddy_nodes WHERE id=?`,
		nodeID).Scan(&endpoint, &tunPub, &subnet, &listenPort, &transport, &wstunnelPort); err != nil {
		return BootstrapResult{}, err
	}
	if !endpoint.Valid || !tunPub.Valid || !subnet.Valid {
		return BootstrapResult{}, errors.New("wgpeer: node tunnel not configured")
	}
	// Repair endpoint missing the :port (older rows saved before validation).
	// wg-quick rejects bare hostnames with 'Unable to find port of endpoint'.
	endpoint.String = ensureEndpointPort(endpoint.String, listenPort.Int64)

	// Extract hostname for WSS URL construction; fall back to full endpoint.
	nodeHostname, _, splitErr := net.SplitHostPort(endpoint.String)
	if splitErr != nil {
		nodeHostname = endpoint.String
	}
	tunnelTransport := transport.String
	if tunnelTransport == "" {
		tunnelTransport = "udp"
	}

	// Flip peer to active (idempotent — re-consume after race would noop).
	if _, err := s.DB.ExecContext(ctx,
		`UPDATE customer_wg_peer SET status='active', activated_at=COALESCE(activated_at, NOW()) WHERE id=?`,
		peerID); err != nil {
		return BootstrapResult{}, err
	}

	// If this peer is part of an HA group, surface every sibling so
	// RenderConfig can emit multi-[Peer] failover.
	var haPeers []HAPeerInfo
	if peerGroup.Valid && peerGroup.String != "" {
		rows, err := s.DB.QueryContext(ctx,
			`SELECT p.assigned_ip, n.tunnel_endpoint, n.tunnel_pubkey, n.tunnel_subnet, n.tunnel_listen_port
			   FROM customer_wg_peer p JOIN caddy_nodes n ON n.id = p.node_id
			  WHERE p.peer_group_id = ? AND p.id <> ? AND p.status <> 'revoked'`,
			peerGroup.String, peerID)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var (
					hp   HAPeerInfo
					port sql.NullInt64
				)
				// A scan error means an incomplete HA failover set - log it
				// instead of silently degrading.
				if err := rows.Scan(&hp.AssignedIP, &hp.Endpoint, &hp.TunnelPubkey, &hp.TunnelSubnet, &port); err != nil {
					s.Logger.Warn("ha peer scan", "peer_group", peerGroup.String, "err", err)
					continue
				}
				hp.Endpoint = ensureEndpointPort(hp.Endpoint, port.Int64)
				haPeers = append(haPeers, hp)
			}
			if err := rows.Err(); err != nil {
				s.Logger.Warn("ha peer rows", "peer_group", peerGroup.String, "err", err)
			}
		} else {
			s.Logger.Warn("ha peer query", "peer_group", peerGroup.String, "err", err)
		}
		// Bonus: flip ALL peers in the group to active on first consume
		// (they're equivalent from the customer's perspective).
		_, _ = s.DB.ExecContext(ctx,
			`UPDATE customer_wg_peer SET status='active', activated_at=COALESCE(activated_at, NOW())
			 WHERE peer_group_id=? AND status<>'revoked'`, peerGroup.String)
	}

	return BootstrapResult{
		HAPeers: haPeers,
		Peer: Peer{
			ID:         peerID,
			ClientID:   clientID,
			NodeID:     nodeID,
			Name:       name,
			Pubkey:     pubkey,
			AssignedIP: assignedIP,
			Status:     "active",
		},
		ServerPrivkey:    priv,
		NodeEndpoint:     endpoint.String,
		NodeTunnelPubkey: tunPub.String,
		NodeTunnelSubnet: subnet.String,
		TunnelTransport:  tunnelTransport,
		WstunnelPort:     int(wstunnelPort.Int64),
		NodeHostname:     nodeHostname,
	}, nil
}

// PeersForNode returns the active+pending peers for one Caddy node, in
// the shape the node-agent needs to drive `wg set wg-tun0 peer ...`.
type NodePeerSnapshot struct {
	Pubkey     string
	AssignedIP string // already includes /32 suffix when used in AllowedIPs
	Status     string
}

func (s *Service) PeersForNode(ctx context.Context, nodeID int64) ([]NodePeerSnapshot, error) {
	rows, err := s.DB.QueryContext(ctx,
		`SELECT pubkey, assigned_ip, status FROM customer_wg_peer
		 WHERE node_id=? AND pubkey IS NOT NULL`, nodeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []NodePeerSnapshot
	for rows.Next() {
		var p NodePeerSnapshot
		if err := rows.Scan(&p.Pubkey, &p.AssignedIP, &p.Status); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// ------------------------------------------------------------------
// internals

// ReissueBootstrap creates a fresh single-shot bootstrap token for an
// existing peer without rotating its keys. Lets ops re-download the
// .conf (e.g. after changes to RenderConfig defaults like MTU/MSS)
// without breaking sibling HA peers or invalidating the keypair.
func (s *Service) ReissueBootstrap(ctx context.Context, peerID int64) (string, error) {
	return s.issueBootstrap(ctx, peerID)
}

func (s *Service) issueBootstrap(ctx context.Context, peerID int64) (string, error) {
	// 96 bytes → 192 hex chars. Cryptographically 256-bit (64 hex) is
	// already infeasible to brute-force; longer is operator preference.
	// Schema mig 23 widened token column to VARCHAR(192).
	var raw [96]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	token := hex.EncodeToString(raw[:])
	// Use DB-side timestamp arithmetic (NOW() + INTERVAL N SECOND) so the
	// stored expires_at and the ConsumeBootstrap 'expires_at > NOW()' check
	// share the SAME clock and timezone. Mixing Go time.Now() (panel TZ)
	// with MariaDB NOW() (server TZ) caused tokens to look already-expired
	// the moment they were issued when the two containers had different TZ.
	ttlSeconds := int(bootstrapTTL / time.Second)
	_, err := s.DB.ExecContext(ctx,
		`INSERT INTO customer_wg_bootstrap (token, peer_id, expires_at)
		 VALUES (?, ?, DATE_ADD(NOW(), INTERVAL ? SECOND))`,
		token, peerID, ttlSeconds)
	return token, err
}

// nodeTunnelConfig returns subnet + next octet allocator hint. Errors if
// tunnel not enabled on the node (admin must Set tunnel listener first).
func (s *Service) nodeTunnelConfig(ctx context.Context, nodeID int64) (string, int, error) {
	var enabled bool
	var subnet sql.NullString
	var nextOctet int
	if err := s.DB.QueryRowContext(ctx,
		`SELECT tunnel_enabled, tunnel_subnet, tunnel_next_octet FROM caddy_nodes WHERE id=?`,
		nodeID).Scan(&enabled, &subnet, &nextOctet); err != nil {
		return "", 0, err
	}
	if !enabled || !subnet.Valid {
		return "", 0, errors.New("wgpeer: node tunnel not enabled")
	}
	return subnet.String, nextOctet, nil
}

// allocateIP picks the next free /32 from the node's tunnel subnet.
// Uses a row-locked counter on caddy_nodes.tunnel_next_octet so two
// concurrent Creates can't collide. Scans for gaps if the simple
// counter has wrapped/conflicts.
func (s *Service) allocateIP(ctx context.Context, nodeID int64, subnet string) (string, error) {
	_, ipnet, err := net.ParseCIDR(subnet)
	if err != nil {
		return "", fmt.Errorf("subnet %q: %w", subnet, err)
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()

	var next int
	if err := tx.QueryRowContext(ctx,
		`SELECT tunnel_next_octet FROM caddy_nodes WHERE id=? FOR UPDATE`, nodeID).Scan(&next); err != nil {
		return "", err
	}

	for tries := 0; tries < 2000; tries++ {
		candidate := offsetIP(ipnet, next)
		if candidate == nil {
			return "", errors.New("wgpeer: tunnel subnet exhausted")
		}
		// Skip gateway (.1) and broadcast.
		if last := candidate.To4(); last != nil && (last[3] == 0 || last[3] == 1 || last[3] == 255) {
			next++
			continue
		}
		// Count ALL rows regardless of status — uq_node_ip is unconditional,
		// so a row with status='revoked' still claims its IP at the SQL level
		// and would cause a duplicate-key error on INSERT. Allocator must
		// match constraint scope, not business state.
		var taken int
		if err := tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM customer_wg_peer WHERE node_id=? AND assigned_ip=?`,
			nodeID, candidate.String()).Scan(&taken); err != nil {
			return "", err
		}
		if taken == 0 {
			if _, err := tx.ExecContext(ctx,
				`UPDATE caddy_nodes SET tunnel_next_octet=? WHERE id=?`, next+1, nodeID); err != nil {
				return "", err
			}
			if err := tx.Commit(); err != nil {
				return "", err
			}
			return candidate.String(), nil
		}
		next++
	}
	return "", errors.New("wgpeer: no free IP after 2000 tries")
}

// offsetIP returns ipnet base + offset, or nil if outside the network.
func offsetIP(ipnet *net.IPNet, offset int) net.IP {
	base := ipnet.IP.To4()
	if base == nil {
		return nil
	}
	v := uint32(base[0])<<24 | uint32(base[1])<<16 | uint32(base[2])<<8 | uint32(base[3])
	v += uint32(offset)
	ip := net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	if !ipnet.Contains(ip) {
		return nil
	}
	return ip
}

// RenderConfig builds the customer-side .conf body from a bootstrap
// result. Caller serves it as text/plain. For HA groups, emits one
// [Peer] block per node so wg-quick picks whichever node is reachable.
func RenderConfig(r BootstrapResult) string {
	var b strings.Builder
	b.WriteString("[Interface]\n")
	b.WriteString("PrivateKey = ")
	b.WriteString(r.ServerPrivkey)
	b.WriteString("\n")
	b.WriteString("Address = ")
	// HA: bind ALL assigned IPs so kernel routing picks the right one
	// per outbound peer match.
	b.WriteString(r.Peer.AssignedIP)
	b.WriteString("/32")
	for _, hp := range r.HAPeers {
		b.WriteString(", ")
		b.WriteString(hp.AssignedIP)
		b.WriteString("/32")
	}
	b.WriteString("\n")
	// MTU 1420 avoids PMTU blackhole over WG/IPv4 (60B WG overhead).
	b.WriteString("MTU = 1420\n")
	// MSS clamp BOTH directions; one-way was asymmetric and replies still fragmented.
	b.WriteString("PostUp = iptables -t mangle -A FORWARD -o %i -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu || true\n")
	b.WriteString("PostUp = iptables -t mangle -A FORWARD -i %i -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu || true\n")
	b.WriteString("PostDown = iptables -t mangle -D FORWARD -o %i -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu || true\n")
	b.WriteString("PostDown = iptables -t mangle -D FORWARD -i %i -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu || true\n\n")

	writePeer := func(pub, endpoint, subnet string) {
		b.WriteString("[Peer]\n")
		b.WriteString("PublicKey = ")
		b.WriteString(pub)
		b.WriteString("\n")
		b.WriteString("Endpoint = ")
		b.WriteString(endpoint)
		b.WriteString("\n")
		// Customer-side AllowedIPs: only the gateway (.1 of this node's
		// tunnel subnet). Customer can't route to other tenants by design.
		gw := gatewayIP(subnet)
		b.WriteString("AllowedIPs = ")
		b.WriteString(gw)
		b.WriteString("/32\n")
		b.WriteString("PersistentKeepalive = 25\n\n")
	}
	// WSS mode: WireGuard talks to the local wstunnel client UDP port instead
	// of the node directly; wstunnel wraps traffic in WebSocket over TLS.
	primaryEndpoint := r.NodeEndpoint
	if r.TunnelTransport == "wss" {
		primaryEndpoint = fmt.Sprintf("127.0.0.1:%d", wgWstunnelClientPort)
	}
	writePeer(r.NodeTunnelPubkey, primaryEndpoint, r.NodeTunnelSubnet)
	for _, hp := range r.HAPeers {
		writePeer(hp.TunnelPubkey, hp.Endpoint, hp.TunnelSubnet)
	}
	return b.String()
}

// ensureEndpointPort appends ":<port>" to endpoint if missing. wg-quick
// refuses bare hostnames with 'Unable to find port of endpoint'. Older
// node rows were saved without the port; this repairs them at read.
// Bare IPv6 literals MUST be bracketed ([v6]:port) - the old contains(":")
// heuristic mistook every IPv6 colon for a port separator.
func ensureEndpointPort(endpoint string, port int64) string {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return endpoint
	}
	if port <= 0 {
		port = 51820
	}
	portStr := strconv.FormatInt(port, 10)
	// Already host:port or [v6]:port - SplitHostPort accepts both.
	if _, _, err := net.SplitHostPort(endpoint); err == nil {
		return endpoint
	}
	// No port. A bare IPv6 literal needs brackets before the appended port.
	if ip := net.ParseIP(endpoint); ip != nil && ip.To4() == nil {
		return "[" + endpoint + "]:" + portStr
	}
	// Already-bracketed IPv6 without a port, e.g. "[2001:db8::1]".
	if strings.HasPrefix(endpoint, "[") && strings.HasSuffix(endpoint, "]") {
		return endpoint + ":" + portStr
	}
	// Bare IPv4 or hostname.
	return endpoint + ":" + portStr
}

func gatewayIP(subnet string) string {
	_, ipnet, err := net.ParseCIDR(subnet)
	if err != nil {
		return "0.0.0.0"
	}
	return offsetIP(ipnet, 1).String()
}
