package handlers

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/host-yt/caddy-proxy-manager/internal/audit"
	"github.com/host-yt/caddy-proxy-manager/internal/nodejoin"
	"github.com/host-yt/caddy-proxy-manager/internal/store"
)

// NodeJoinHandler is wired separately from APIHandlers because it MUST
// NOT sit behind the bearer-token middleware (the join token IS the
// authn material, sent in the request body).
type NodeJoinHandler struct {
	DB         func() *sql.DB
	Logger     *slog.Logger
	Joiner     *nodejoin.Service
	AskURL     string
	ACMEEmail  string
	ScriptBody []byte // contents of scripts/node-join.sh, served at /install/node.sh
	ScriptName string
	// RDB enables per-IP rate-limiting of /api/v1/nodes/join. Optional -
	// if nil the endpoint is unrate-limited (legacy behaviour).
	RDB         *redis.Client
	PerIPPerMin int

	// Webhooks is optional; emits node.joined.
	Webhooks interface {
		Emit(ctx context.Context, eventType string, payload map[string]any)
	}
}

// Join is POST /api/v1/nodes/join. Body: {token, public_hostname?, public_ip?}.
// Returns the bootstrap JSON the node script consumes.
func (h *NodeJoinHandler) Join(w http.ResponseWriter, r *http.Request) {
	// Per-IP rate limit. Tokens are 192-bit single-use, so brute force is
	// infeasible - but unbounded requests still hit the DB for the
	// sha256+SELECT lookup and pollute the audit log. Cap at PerIPPerMin.
	if h.RDB != nil && h.PerIPPerMin > 0 {
		ip := clientIPFromReq(r)
		key := "hpg:join:rl:" + ip
		rlCtx, cancel := context.WithTimeout(r.Context(), 300*time.Millisecond)
		n, err := h.RDB.Incr(rlCtx, key).Result()
		if err == nil {
			if n == 1 {
				_ = h.RDB.Expire(rlCtx, key, time.Minute).Err()
			}
			if int(n) > h.PerIPPerMin {
				cancel()
				h.Logger.Warn("node join rate limited", "ip", ip, "n", n)
				audit.Write(r.Context(), h.DB(), h.Logger, r, audit.Entry{
					ActorType: audit.ActorSystem, Action: "node.join.ratelimited",
					Entity: "node", Meta: map[string]any{"ip": ip, "n": n},
				})
				apiErr(w, http.StatusTooManyRequests, "rate limited")
				return
			}
		}
		cancel()
	}

	if r.Body == nil {
		apiErr(w, http.StatusBadRequest, "empty body")
		return
	}
	// Cap the join request body so a single hostile caller can't burn the
	// panel's memory via a giant streaming JSON decode (security review P1).
	// 64 KiB is plenty for the JoinRequest shape.
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	var req nodejoin.JoinRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apiErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if !strings.HasPrefix(req.Token, "hpg_join_") {
		apiErr(w, http.StatusUnauthorized, "invalid token")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	resp, managerPeer, err := h.Joiner.Redeem(ctx, req, h.AskURL, h.ACMEEmail)
	if err != nil {
		// Constant-text deny to avoid leaking which part failed.
		h.Logger.Warn("node join failed", "err", err, "remote", r.RemoteAddr)
		apiErr(w, http.StatusUnauthorized, "join failed: "+sanitizeErr(err))
		return
	}

	uid := int64(0)
	audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
		UserID: &uid, ActorType: audit.ActorSystem, Action: "node.join.success", Entity: "node",
		EntityID: itoa64(resp.NodeID),
		Meta: map[string]any{
			"name":      resp.NodeName,
			"wg_addr":   resp.WireGuard.InterfaceAddress,
			"public_ip": req.PublicIP,
		},
	})
	if h.Webhooks != nil {
		h.Webhooks.Emit(ctx, "node.joined", map[string]any{
			"node_id":     resp.NodeID,
			"node_name":   resp.NodeName,
			"fingerprint": resp.Fingerprint,
			"public_ip":   req.PublicIP,
		})
	}

	// Stash the peer block so the admin UI can show it on /admin/nodes.
	_, _ = h.DB().ExecContext(ctx, store.UpsertSettingSQL(),
		"wireguard.pending_peer.node_"+itoa64(resp.NodeID), managerPeer, 0)

	apiJSON(w, http.StatusOK, resp)
}

// Script serves the bash bootstrap. Anyone can GET it - content is
// non-secret; the value is only realised together with a join token.
func (h *NodeJoinHandler) Script(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(h.ScriptBody)
}

// LoadScriptFromFS reads scripts/node-join.sh out of an embed.FS.
func LoadScriptFromFS(fs embed.FS, path string) ([]byte, error) {
	return fs.ReadFile(path)
}

func itoa64(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
