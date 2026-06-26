// Package nodejoin issues one-time tokens used by remote Caddy nodes to
// auto-register with the control plane (à la `docker swarm join`).
package nodejoin

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/host-yt/caddy-proxy-manager/internal/wireguard"
)

// TokenTTL — how long a generated join token stays valid.
const TokenTTL = 30 * time.Minute

// Token bundles the plaintext (shown ONCE on the manager) + identifiers.
type Token struct {
	Plain     string // hpg_join_<plain>
	Prefix    string // first 12 chars of the random part (lookup index)
	ExpiresAt time.Time
}

// Service mints + validates join tokens. The plaintext is returned only
// at mint time; we store a sha256 hash.
type Service struct {
	DB func() *sql.DB
	WG *wireguard.Service
	// WriteWGConfig is called after a successful Redeem so the WG sidecar
	// picks up the new peer. Nil-safe.
	WriteWGConfig func(ctx context.Context) error
}

// MintOpts shapes the join request from the admin UI.
type MintOpts struct {
	NodeGroupID int64
	MaxRoutes   int
	Priority    int
	NameHint    string
	CreatedBy   int64 // user id (for audit)
}

// Mint creates a new token row, returns the plaintext.
func (s *Service) Mint(ctx context.Context, o MintOpts) (Token, error) {
	if o.NodeGroupID == 0 {
		return Token{}, errors.New("node_group_id required")
	}
	if o.MaxRoutes <= 0 {
		o.MaxRoutes = 1000
	}
	if o.Priority == 0 {
		o.Priority = 100
	}
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return Token{}, err
	}
	plain := base64.RawURLEncoding.EncodeToString(raw)
	prefix := plain[:12]
	sum := sha256.Sum256([]byte(plain))
	hashHex := hex.EncodeToString(sum[:])
	expires := time.Now().UTC().Add(TokenTTL)

	db := s.DB()
	if db == nil {
		return Token{}, errors.New("db not ready")
	}
	var createdBy sql.NullInt64
	if o.CreatedBy != 0 {
		createdBy = sql.NullInt64{Int64: o.CreatedBy, Valid: true}
	}
	var nameHint sql.NullString
	if o.NameHint != "" {
		nameHint = sql.NullString{String: o.NameHint, Valid: true}
	}
	if _, err := db.ExecContext(ctx,
		`INSERT INTO node_join_tokens (token_hash, token_prefix, node_group_id, max_routes, priority,
		   name_hint, created_by, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		hashHex, prefix, o.NodeGroupID, o.MaxRoutes, o.Priority, nameHint, createdBy, expires,
	); err != nil {
		return Token{}, fmt.Errorf("insert token: %w", err)
	}
	return Token{
		Plain:     "hpg_join_" + plain,
		Prefix:    prefix,
		ExpiresAt: expires,
	}, nil
}

// resolved is the consumable shape after a successful token redemption.
type resolved struct {
	ID          int64
	NodeGroupID int64
	MaxRoutes   int
	Priority    int
	NameHint    string
}

// consume validates token plaintext, marks it used. Idempotent failure
// on second use.
func (s *Service) consume(ctx context.Context, db *sql.DB, plainWithPrefix string) (resolved, error) {
	if !strings.HasPrefix(plainWithPrefix, "hpg_join_") {
		return resolved{}, errors.New("invalid token format")
	}
	plain := strings.TrimPrefix(plainWithPrefix, "hpg_join_")
	if len(plain) < 12 {
		return resolved{}, errors.New("token too short")
	}
	prefix := plain[:12]
	sum := sha256.Sum256([]byte(plain))
	hashHex := hex.EncodeToString(sum[:])

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return resolved{}, err
	}
	defer tx.Rollback() //nolint:errcheck

	var r resolved
	var nameHint sql.NullString
	err = tx.QueryRowContext(ctx,
		`SELECT id, node_group_id, max_routes, priority, name_hint
		 FROM node_join_tokens
		 WHERE token_prefix = ? AND token_hash = ? AND used_at IS NULL AND expires_at > NOW()
		 LIMIT 1 FOR UPDATE`,
		prefix, hashHex,
	).Scan(&r.ID, &r.NodeGroupID, &r.MaxRoutes, &r.Priority, &nameHint)
	if errors.Is(err, sql.ErrNoRows) {
		return resolved{}, errors.New("token invalid, expired, or already used")
	}
	if err != nil {
		return resolved{}, err
	}
	if nameHint.Valid {
		r.NameHint = nameHint.String
	}
	if _, err := tx.ExecContext(ctx, "UPDATE node_join_tokens SET used_at = NOW() WHERE id = ?", r.ID); err != nil {
		return resolved{}, err
	}
	if err := tx.Commit(); err != nil {
		return resolved{}, err
	}
	return r, nil
}

// JoinRequest is what the bash bootstrap script sends in.
type JoinRequest struct {
	Token          string `json:"token"`
	PublicHostname string `json:"public_hostname,omitempty"`
	PublicIP       string `json:"public_ip,omitempty"`
}

// JoinResponse is the bootstrap config the node consumes.
type JoinResponse struct {
	NodeID      int64  `json:"node_id"`
	NodeName    string `json:"node_name"`
	Fingerprint string `json:"fingerprint"` // first 16 chars of node WG pubkey; admin matches in panel
	WireGuard   struct {
		InterfaceAddress string `json:"interface_address"` // 10.66.0.X/24
		PrivateKey       string `json:"private_key"`
		Peer             struct {
			PublicKey           string `json:"public_key"`
			Endpoint            string `json:"endpoint"`
			AllowedIPs          string `json:"allowed_ips"`
			PersistentKeepalive int    `json:"persistent_keepalive"`
		} `json:"peer"`
	} `json:"wireguard"`
	Caddy struct {
		AdminListen    string `json:"admin_listen"`
		AskEndpointURL string `json:"ask_endpoint_url"`
		ACMEEmail      string `json:"acme_email"`
	} `json:"caddy"`
	ManagerNote string `json:"manager_note,omitempty"`
}

// Redeem validates a token and provisions WG + DB state for a new node.
// Returns the bootstrap payload for the node, plus the WG peer block
// the operator needs to append on the manager (we surface it explicitly
// so they can `wg syncconf` without an out-of-band copy/paste).
func (s *Service) Redeem(ctx context.Context, req JoinRequest, askEndpointURL, acmeEmail string) (JoinResponse, string, error) {
	db := s.DB()
	if db == nil {
		return JoinResponse{}, "", errors.New("db not ready")
	}
	tk, err := s.consume(ctx, db, req.Token)
	if err != nil {
		return JoinResponse{}, "", err
	}

	cp, err := s.WG.EnsureKeypair(ctx)
	if err != nil {
		return JoinResponse{}, "", fmt.Errorf("wg keypair: %w", err)
	}
	if cp.Endpoint == "" {
		return JoinResponse{}, "", errors.New("wireguard.endpoint not configured — set it in admin Settings → WireGuard")
	}
	nodeKP, err := wireguard.GenerateKeypair()
	if err != nil {
		return JoinResponse{}, "", err
	}
	wgIP, err := s.WG.AllocateNodeIP(ctx)
	if err != nil {
		return JoinResponse{}, "", err
	}

	// Insert caddy_nodes row. api_url binds to the WG IP.
	apiURL := fmt.Sprintf("http://%s:2019", wgIP)
	nodeName := tk.NameHint
	if nodeName == "" {
		nodeName = fmt.Sprintf("node-%s", strings.ReplaceAll(wgIP, ".", "-"))
	}
	publicHostname := req.PublicHostname
	if publicHostname == "" {
		publicHostname = nodeName
	}
	var publicIP sql.NullString
	if req.PublicIP != "" {
		publicIP = sql.NullString{String: req.PublicIP, Valid: true}
	}

	// Auto-joined nodes land DISABLED + with a fingerprint, awaiting admin
	// approval. Until approved they receive no route placements and are
	// invisible to the lowest-usage scheduler. This closes the rogue-node
	// race: a stolen join token alone cannot start carrying customer
	// traffic — an admin must explicitly approve via /admin/nodes/{id}/approve.
	fingerprint := nodeKP.PublicKey
	if len(fingerprint) > 16 {
		fingerprint = fingerprint[:16]
	}
	res, err := db.ExecContext(ctx,
		`INSERT INTO caddy_nodes (name, api_url, public_hostname, public_ip, node_group_id,
		   max_routes, priority, is_enabled, health_status, wg_ip, wg_public_key, fingerprint)
		 VALUES (?, ?, ?, ?, ?, ?, ?, 0, 'unknown', ?, ?, ?)`,
		nodeName, apiURL, publicHostname, publicIP, tk.NodeGroupID,
		tk.MaxRoutes, tk.Priority, wgIP, nodeKP.PublicKey, fingerprint,
	)
	if err != nil {
		return JoinResponse{}, "", fmt.Errorf("insert node: %w", err)
	}
	nodeID, _ := res.LastInsertId()
	_, _ = db.ExecContext(ctx, "UPDATE node_join_tokens SET used_node_id = ? WHERE id = ?", nodeID, tk.ID)

	resp := JoinResponse{NodeID: nodeID, NodeName: nodeName, Fingerprint: fingerprint}
	resp.WireGuard.InterfaceAddress = wgIP + "/24"
	resp.WireGuard.PrivateKey = nodeKP.PrivateKey
	resp.WireGuard.Peer.PublicKey = cp.PublicKey
	resp.WireGuard.Peer.Endpoint = cp.Endpoint
	resp.WireGuard.Peer.AllowedIPs = cp.ControlIP + "/32"
	resp.WireGuard.Peer.PersistentKeepalive = 25
	resp.Caddy.AdminListen = wgIP + ":2019"
	resp.Caddy.AskEndpointURL = askEndpointURL
	resp.Caddy.ACMEEmail = acmeEmail

	// Trigger sidecar reload: rewrite wg0.conf with the new peer.
	if s.WriteWGConfig != nil {
		if err := s.WriteWGConfig(ctx); err != nil {
			// Don't fail the join — node is registered. Surface a hint so
			// the operator notices something went sideways with WG sync.
			resp.ManagerNote = "Node registered, but the manager-side WG sidecar didn't refresh automatically: " + err.Error() + ". Run the 'Apply WG config' button in the admin Nodes page."
		} else {
			resp.ManagerNote = "Node registered. The manager WG sidecar will pick up the new peer within ~10 s; no manual step needed."
		}
	} else {
		// Sidecar not enabled — fall back to the manual block.
		managerPeer := fmt.Sprintf(
			"# Node #%d (%s)\n[Peer]\nPublicKey = %s\nAllowedIPs = %s/32\n",
			nodeID, nodeName, nodeKP.PublicKey, wgIP,
		)
		resp.ManagerNote = "On the manager: append the [Peer] block below to /etc/wireguard/wg0.conf, then `sudo wg syncconf wg0 <(wg-quick strip wg0)`."
		return resp, managerPeer, nil
	}
	return resp, "", nil
}
