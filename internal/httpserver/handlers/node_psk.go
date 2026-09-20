package handlers

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/host-yt/caddy-proxy-manager/internal/audit"
	"github.com/host-yt/caddy-proxy-manager/internal/installstate"
	"github.com/host-yt/caddy-proxy-manager/internal/security"
	"github.com/host-yt/caddy-proxy-manager/internal/store"
	"github.com/host-yt/caddy-proxy-manager/internal/wireguard"
)

// NodePSKHandler serves the mesh-PSK rekey flow for nodes that joined before
// preshared keys existed:
//
//	GET  /install/node-psk.sh   → the rekey script (non-secret)
//	GET  /api/node/psk          → {"psk", "peer_public_key"} (does NOT burn the token)
//	POST /api/node/psk/confirm  → 204, promotes pending → active
//
// Both API calls authenticate with `Authorization: Bearer <token>`. The plan
// specified `?t=<token>` for the GET; a query string lands in every upstream
// proxy/CDN access log and in curl's argv (readable via /proc on the node),
// so the header wins over the written contract.
//
// Like the join endpoints these sit outside the session middleware: the
// token in caddy_nodes.wg_psk_token_hash IS the authn material. Every failure
// answers 404 so a caller cannot tell a bad token from an expired one.
type NodePSKHandler struct {
	DB     func() *sql.DB
	Logger *slog.Logger
	// Enc decrypts wg_psk_pending_enc (purpose-scoped "wg").
	Enc         *installstate.Manager
	RDB         *redis.Client
	PerIPPerMin int    // 0 disables
	ScriptBody  []byte // contents of scripts/node-psk.sh
	// WriteWGConfig re-renders the manager-side wg0.conf after a confirm.
	WriteWGConfig func(ctx context.Context) error
	// PeerPublicKey returns the manager's own WG public key. The node script
	// needs it to stamp the PSK onto the panel's [Peer] block only - any
	// hand-added peer on the same interface must keep its own key.
	PeerPublicKey func(ctx context.Context) (string, error)

	mem ipLimiter
}

// ipLimiter is a fixed-minute-bucket per-IP counter. It backs the rekey
// endpoints when Redis is absent or erroring: they are unauthenticated and
// Redis is optional in this deployment, so failing open would leave the
// token brute-forceable at line rate.
// ponytail: fixed buckets (a burst can straddle two windows); swap for a
// sliding window only if that ever matters here.
type ipLimiter struct {
	mu     sync.Mutex
	window time.Time
	hits   map[string]int
}

func (l *ipLimiter) allow(ip string, max int) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if now := time.Now().Truncate(time.Minute); !now.Equal(l.window) {
		l.window, l.hits = now, make(map[string]int)
	}
	l.hits[ip]++
	return l.hits[ip] <= max
}

// pskTokenHash validates the token shape (64 lowercase hex, 32 random bytes)
// and returns its sha256 hex, the form stored in wg_psk_token_hash.
func pskTokenHash(tok string) (string, bool) {
	if len(tok) != 64 {
		return "", false
	}
	for _, r := range tok {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return "", false
		}
	}
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:]), true
}

func pskBearer(r *http.Request) string {
	return strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
}

// rateLimited caps unauthenticated calls per source IP, writes the 429 and
// audits it (same precedent as node.join.ratelimited in nodejoin.go).
func (h *NodePSKHandler) rateLimited(w http.ResponseWriter, r *http.Request, op string) bool {
	if h.PerIPPerMin <= 0 {
		return false
	}
	ip := security.ClientIP(r)
	over := true
	if h.RDB != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 200*time.Millisecond)
		key := "hpg:nodepsk:rl:" + ip
		n, err := h.RDB.Incr(ctx, key).Result()
		if err == nil {
			if n == 1 {
				_ = h.RDB.Expire(ctx, key, time.Minute).Err()
			}
			over = int(n) > h.PerIPPerMin
		} else {
			over = !h.mem.allow(ip, h.PerIPPerMin)
		}
		cancel()
	} else {
		over = !h.mem.allow(ip, h.PerIPPerMin)
	}
	if !over {
		return false
	}
	h.Logger.Warn("node psk rate limited", "ip", ip, "op", op)
	audit.Write(r.Context(), h.DB(), h.Logger, r, audit.Entry{
		ActorType: audit.ActorSystem, Action: "node.psk.ratelimited",
		Entity: "node", Meta: map[string]any{"ip": ip, "op": op},
	})
	w.Header().Set("Retry-After", "60")
	http.Error(w, "rate limited", http.StatusTooManyRequests)
	return true
}

// pskDeny answers the uniform 404 and leaves a trace. Without it a stolen or
// brute-forced token produces no log line and no audit row at all.
func (h *NodePSKHandler) pskDeny(w http.ResponseWriter, r *http.Request, action, reason string) {
	ip := security.ClientIP(r)
	h.Logger.Warn("node psk denied", "action", action, "reason", reason, "ip", ip)
	audit.Write(r.Context(), h.DB(), h.Logger, r, audit.Entry{
		ActorType: audit.ActorSystem, Action: action, Entity: "node",
		Meta: map[string]any{"ip": ip, "reason": reason},
	})
	http.NotFound(w, r)
}

// Script serves GET /install/node-psk.sh. Non-secret, like /install/node.sh.
func (h *NodePSKHandler) Script(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(h.ScriptBody)
}

// Fetch handles GET /api/node/psk with a bearer token. It deliberately leaves
// the token usable: the script may need to retry after a transient write
// failure, and only Confirm changes state.
func (h *NodePSKHandler) Fetch(w http.ResponseWriter, r *http.Request) {
	if h.rateLimited(w, r, "fetch") {
		return
	}
	db := h.DB()
	hash, ok := pskTokenHash(pskBearer(r))
	if !ok || db == nil || h.Enc == nil {
		h.pskDeny(w, r, "node.psk.fetch.denied", "bad token")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	var nodeID int64
	var pending string
	err := db.QueryRowContext(ctx,
		`SELECT id, wg_psk_pending_enc FROM caddy_nodes
		 WHERE wg_psk_token_hash = ? AND wg_psk_token_expires > `+store.Now()+`
		   AND wg_psk_pending_enc IS NOT NULL`, hash).Scan(&nodeID, &pending)
	if err != nil {
		h.pskDeny(w, r, "node.psk.fetch.denied", "no staged key")
		return
	}
	psk, derr := h.Enc.Decrypt(pending)
	if derr != nil || !wireguard.ValidPresharedKey(psk) {
		h.Logger.Error("node psk fetch: pending key unusable", "node_id", nodeID, "err", derr)
		http.Error(w, "psk unavailable", http.StatusInternalServerError)
		return
	}
	// Without the manager's pubkey the script cannot tell our [Peer] block
	// apart from a hand-added one, so refuse rather than let it guess.
	var peerPub string
	if h.PeerPublicKey != nil {
		peerPub, derr = h.PeerPublicKey(ctx)
		if derr != nil {
			peerPub = ""
		}
	}
	if peerPub == "" {
		h.Logger.Error("node psk fetch: manager wg public key unavailable", "node_id", nodeID, "err", derr)
		http.Error(w, "psk unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	apiJSON(w, http.StatusOK, map[string]string{"psk": psk, "peer_public_key": peerPub})
}

// Confirm handles POST /api/node/psk/confirm with `Authorization: Bearer
// <token>`. The node calls it once it has the key live in its own wg0.conf;
// only then does the panel start using it, so the two sides are never more
// than one handshake apart.
//
// The token is NOT cleared on success - it stays valid for the rest of its
// TTL and a repeat confirm answers 204 again. A lost or timed-out RESPONSE
// would otherwise make the retry 404, the script roll the node back, and the
// mesh end up split across two keys with no way to retry.
func (h *NodePSKHandler) Confirm(w http.ResponseWriter, r *http.Request) {
	if h.rateLimited(w, r, "confirm") {
		return
	}
	db := h.DB()
	hash, ok := pskTokenHash(pskBearer(r))
	if !ok || db == nil {
		h.pskDeny(w, r, "node.psk.confirm.denied", "bad token")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		http.Error(w, "confirm failed", http.StatusInternalServerError)
		return
	}
	defer func() { _ = tx.Rollback() }()

	var nodeID int64
	var prevActive, pending, tokenEnc sql.NullString
	err = tx.QueryRowContext(ctx,
		`SELECT id, wg_psk_enc, wg_psk_pending_enc, wg_psk_token_enc
		 FROM caddy_nodes
		 WHERE wg_psk_token_hash = ? AND wg_psk_token_expires > `+store.Now()+store.ForUpdate(), hash,
	).Scan(&nodeID, &prevActive, &pending, &tokenEnc)
	if err != nil {
		h.pskDeny(w, r, "node.psk.confirm.denied", "no staged key")
		return
	}
	// Already promoted by an earlier call whose response the node never saw.
	if !pending.Valid {
		_ = tx.Rollback()
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE caddy_nodes
		 SET wg_psk_enc = wg_psk_pending_enc, wg_psk_pending_enc = NULL
		 WHERE id = ?`, nodeID); err != nil {
		http.Error(w, "confirm failed", http.StatusInternalServerError)
		return
	}
	if err := tx.Commit(); err != nil {
		http.Error(w, "confirm failed", http.StatusInternalServerError)
		return
	}

	uid := int64(0)
	// The node already switched; if we cannot render our own side, put the
	// previous state back and answer 500 so the script rolls the node back
	// too. Leaving the promotion in place would strand the mesh on a key the
	// sidecar never sees.
	if h.WriteWGConfig != nil {
		if werr := h.WriteWGConfig(ctx); werr != nil {
			h.Logger.Error("node psk confirm: wg render failed, compensating", "node_id", nodeID, "err", werr)
			// The two likeliest render failures are this very context
			// expiring or the client disconnecting, and the compensation is
			// needed exactly then - so it runs detached, on its own deadline.
			cctx, ccancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
			defer ccancel()
			if _, cerr := db.ExecContext(cctx,
				`UPDATE caddy_nodes SET wg_psk_enc = ?, wg_psk_pending_enc = ?, wg_psk_token_hash = ?,
				   wg_psk_token_enc = ?, wg_psk_token_expires = `+store.DateAddMinutes(pskTokenTTLMinutes)+`
				 WHERE id = ?`,
				prevActive, pending, hash, tokenEnc, nodeID); cerr != nil {
				// Unrecoverable without a human: the panel holds the new key,
				// the node is about to roll back to the old one.
				h.Logger.Error("node psk confirm: COMPENSATION FAILED - mesh will stay down until an operator clears the node PSK",
					"node_id", nodeID, "err", cerr)
				audit.Write(cctx, db, h.Logger, r, audit.Entry{
					UserID: &uid, ActorType: audit.ActorSystem, Action: "node.psk.compensate.failed",
					Entity: "node", EntityID: itoa64(nodeID),
					Meta: map[string]any{"render_err": werr.Error(), "compensate_err": cerr.Error()},
				})
			}
			_ = h.WriteWGConfig(cctx)
			http.Error(w, "confirm failed", http.StatusInternalServerError)
			return
		}
	}

	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: &uid, ActorType: audit.ActorSystem, Action: "node.psk.confirm",
		Entity: "node", EntityID: itoa64(nodeID),
		Meta: map[string]any{"rotated": prevActive.Valid},
	})
	w.WriteHeader(http.StatusNoContent)
}
