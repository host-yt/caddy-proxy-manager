package handlers

import (
	"context"
	"database/sql"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/host-yt/caddy-proxy-manager/internal/geoip"
	"github.com/host-yt/caddy-proxy-manager/internal/security"
)

// NodeGeoIPHandler serves the centrally-downloaded GeoLite2 mmdb + its metadata
// to node-agents over the WG tunnel:
//
//	GET /api/node/geoip/meta  → {"sha256":"...","size":N,"fetched_at":"RFC3339|"}
//	GET /api/node/geoip/mmdb  → the raw .mmdb file (404 if not yet downloaded)
//
// Both require the per-node token (same scheme as NodePeersPull). The mmdb is
// not secret, but auth stays consistent across node endpoints.
type NodeGeoIPHandler struct {
	DB     func() *sql.DB
	Logger *slog.Logger
}

// authNode verifies the node token from a Bearer header only - a query-string
// token would leak into access/proxy logs (NODE_WG-03). Returns false (and
// writes the HTTP error) when the token is missing or unknown.
func (h *NodeGeoIPHandler) authNode(w http.ResponseWriter, r *http.Request) bool {
	token := ""
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		token = strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
	}
	if token == "" {
		http.Error(w, "missing node_token", http.StatusUnauthorized)
		return false
	}
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return false
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	var nodeID int64
	if err := db.QueryRowContext(ctx,
		`SELECT id FROM caddy_nodes WHERE agent_token_hash IS NOT NULL AND agent_token_hash = SHA2(?, 256) LIMIT 1`,
		token).Scan(&nodeID); err != nil {
		h.Logger.Warn("geoip node token mismatch", "ip", security.ClientIP(r), "token_prefix", safePrefix(token))
		http.Error(w, "denied", http.StatusForbidden)
		return false
	}
	return true
}

// Meta serves GET /api/node/geoip/meta. Returns empty sha256 if none yet.
func (h *NodeGeoIPHandler) Meta(w http.ResponseWriter, r *http.Request) {
	if !h.authNode(w, r) {
		return
	}
	var sha, fetched string
	var size int64
	if db := h.DB(); db != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		var fetchedAt sql.NullTime
		// Empty row is fine: defaults give empty sha + zero size.
		_ = db.QueryRowContext(ctx,
			`SELECT sha256, size_bytes, fetched_at FROM geoip_db_meta WHERE id = 1`,
		).Scan(&sha, &size, &fetchedAt)
		if fetchedAt.Valid {
			fetched = fetchedAt.Time.UTC().Format(time.RFC3339)
		}
	}
	var b strings.Builder
	b.WriteString(`{"sha256":"`)
	b.WriteString(jsonEsc(sha))
	b.WriteString(`","size":`)
	b.WriteString(itoa(size))
	b.WriteString(`,"fetched_at":"`)
	b.WriteString(jsonEsc(fetched))
	b.WriteString(`"}`)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(b.String()))
}

// MMDB serves GET /api/node/geoip/mmdb straight from disk; 404 if not present.
func (h *NodeGeoIPHandler) MMDB(w http.ResponseWriter, r *http.Request) {
	if !h.authNode(w, r) {
		return
	}
	f, err := os.Open(geoip.DBPath)
	if err != nil {
		http.Error(w, "geoip db not available", http.StatusNotFound)
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		http.Error(w, "stat failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	// ServeContent handles ranges/conditional requests and sets Content-Length.
	http.ServeContent(w, r, "GeoLite2-Country.mmdb", fi.ModTime(), f)
}

// itoa is a tiny int64->string helper to avoid importing strconv just for this.
func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
