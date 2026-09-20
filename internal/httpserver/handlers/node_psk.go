package handlers

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"log/slog"
	"net/http"
	"strings"
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
//	GET  /install/node-psk.sh        → the rekey script (non-secret)
//	GET  /api/node/psk?t=<token>     → {"psk": "<base64 32B>"} (does NOT burn the token)
//	POST /api/node/psk/confirm       → 204, promotes pending → active (burns the token)
//
// Like the join endpoints these sit outside the session middleware: the
// one-shot token in caddy_nodes.wg_psk_token_hash IS the authn material.
// Every failure answers 404 so a caller cannot tell a bad token from an
// expired or already-used one.
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

func (h *NodePSKHandler) rateLimited(r *http.Request) bool {
	if h.PerIPPerMin <= 0 || h.RDB == nil {
		return false
	}
	ip := security.ClientIP(r)
	ctx, cancel := context.WithTimeout(r.Context(), 200*time.Millisecond)
	defer cancel()
	n, err := h.RDB.Incr(ctx, "hpg:nodepsk:rl:"+ip).Result()
	if err != nil {
		return false
	}
	if n == 1 {
		_ = h.RDB.Expire(ctx, "hpg:nodepsk:rl:"+ip, time.Minute).Err()
	}
	return int(n) > h.PerIPPerMin
}

// Script serves GET /install/node-psk.sh. Non-secret, like /install/node.sh.
func (h *NodePSKHandler) Script(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(h.ScriptBody)
}

// Fetch handles GET /api/node/psk?t=<token>. It deliberately leaves the token
// usable: the script may need to retry after a transient write failure, and
// only Confirm changes state.
func (h *NodePSKHandler) Fetch(w http.ResponseWriter, r *http.Request) {
	if h.rateLimited(r) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
		return
	}
	db := h.DB()
	hash, ok := pskTokenHash(strings.TrimSpace(r.URL.Query().Get("t")))
	if !ok || db == nil || h.Enc == nil {
		http.NotFound(w, r)
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
		http.NotFound(w, r)
		return
	}
	psk, derr := h.Enc.Decrypt(pending)
	if derr != nil || !wireguard.ValidPresharedKey(psk) {
		h.Logger.Error("node psk fetch: pending key unusable", "node_id", nodeID, "err", derr)
		http.Error(w, "psk unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	apiJSON(w, http.StatusOK, map[string]string{"psk": psk})
}

// Confirm handles POST /api/node/psk/confirm with `Authorization: Bearer
// <token>`. The node calls it once it has the key live in its own wg0.conf;
// only then does the panel start using it, so the two sides are never more
// than one handshake apart.
func (h *NodePSKHandler) Confirm(w http.ResponseWriter, r *http.Request) {
	if h.rateLimited(r) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
		return
	}
	db := h.DB()
	tok := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	hash, ok := pskTokenHash(tok)
	if !ok || db == nil {
		http.NotFound(w, r)
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
		 WHERE wg_psk_token_hash = ? AND wg_psk_token_expires > `+store.Now()+`
		   AND wg_psk_pending_enc IS NOT NULL`+store.ForUpdate(), hash,
	).Scan(&nodeID, &prevActive, &pending, &tokenEnc)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE caddy_nodes
		 SET wg_psk_enc = wg_psk_pending_enc, wg_psk_pending_enc = NULL,
		     wg_psk_token_hash = NULL, wg_psk_token_enc = NULL, wg_psk_token_expires = NULL
		 WHERE id = ?`, nodeID); err != nil {
		http.Error(w, "confirm failed", http.StatusInternalServerError)
		return
	}
	if err := tx.Commit(); err != nil {
		http.Error(w, "confirm failed", http.StatusInternalServerError)
		return
	}

	// The node already switched; if we cannot render our own side, put the
	// previous state back and answer 500 so the script rolls the node back
	// too. Leaving the promotion in place would strand the mesh on a key the
	// sidecar never sees.
	if h.WriteWGConfig != nil {
		if werr := h.WriteWGConfig(ctx); werr != nil {
			h.Logger.Error("node psk confirm: wg render failed, compensating", "node_id", nodeID, "err", werr)
			// The token window restarts rather than being restored to the
			// second: the operator is mid-run and needs it usable for the retry.
			if _, cerr := db.ExecContext(ctx,
				`UPDATE caddy_nodes SET wg_psk_enc = ?, wg_psk_pending_enc = ?, wg_psk_token_hash = ?,
				   wg_psk_token_enc = ?, wg_psk_token_expires = `+store.DateAddMinutes(pskTokenTTLMinutes)+`
				 WHERE id = ?`,
				prevActive, pending, hash, tokenEnc, nodeID); cerr != nil {
				h.Logger.Error("node psk confirm: compensation failed", "node_id", nodeID, "err", cerr)
			}
			_ = h.WriteWGConfig(ctx)
			http.Error(w, "confirm failed", http.StatusInternalServerError)
			return
		}
	}

	uid := int64(0)
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: &uid, ActorType: audit.ActorSystem, Action: "node.psk.confirm",
		Entity: "node", EntityID: itoa64(nodeID),
		Meta: map[string]any{"rotated": prevActive.Valid},
	})
	w.WriteHeader(http.StatusNoContent)
}
