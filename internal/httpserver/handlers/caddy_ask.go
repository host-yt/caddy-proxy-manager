package handlers

import (
	"context"
	"database/sql"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/host-yt/caddy-proxy-manager/internal/obs"
	"github.com/host-yt/caddy-proxy-manager/internal/security"
)

// AskHandler implements Caddy On-Demand TLS authorization.
//
// Caddy hits this before issuing a cert for a domain it has never seen.
// Returns 200 ONLY for exact domains that are in `routes` with a status
// allowing issuance. Default deny.
//
// Rate limit: per-IP via Redis. Global cap to prevent enumeration.
type AskHandler struct {
	DB          func() *sql.DB
	RDB         *redis.Client
	Logger      *slog.Logger
	Metrics     *obs.Metrics
	PerIPPerMin int    // requests per IP per minute; 0 disables
	PanelDomain string // panel's own APP_URL host; always allowed (first-run cert)
}

func (h *AskHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	domain := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("domain")))
	if domain == "" {
		http.Error(w, "missing domain", http.StatusBadRequest)
		return
	}

	// Strip trailing dot and validate shape cheaply.
	domain = strings.TrimSuffix(domain, ".")
	if len(domain) > 253 || !strings.Contains(domain, ".") {
		http.Error(w, "denied", http.StatusForbidden)
		return
	}

	// Panel's own domain: always allowed. On a clean install the panel host is
	// only in caddy_nodes, not routes, so the DB lookup below would deny it and
	// Caddy could never provision the panel's own cert (chicken-and-egg). This
	// is the operator-configured APP_URL host, not attacker-controlled input.
	if h.PanelDomain != "" && domain == h.PanelDomain {
		h.Metrics.AskDecision("allow")
		w.WriteHeader(http.StatusOK)
		return
	}

	// Rate limit per IP (Redis INCR + EXPIRE).
	if h.PerIPPerMin > 0 && h.RDB != nil {
		ip := security.ClientIP(r)
		key := "hpg:ask:rl:" + ip
		ctx, cancel := context.WithTimeout(r.Context(), 200*time.Millisecond)
		defer cancel()
		n, err := h.RDB.Incr(ctx, key).Result()
		if err == nil {
			if n == 1 {
				_ = h.RDB.Expire(ctx, key, time.Minute).Err()
			}
			if int(n) > h.PerIPPerMin {
				h.Logger.Warn("ask rate limited", "ip", ip, "n", n)
				h.Metrics.AskDecision("rate_limited")
				http.Error(w, "rate limited", http.StatusTooManyRequests)
				return
			}
		}
	}

	db := h.DB()
	if db == nil {
		h.Metrics.AskDecision("deny")
		http.Error(w, "denied", http.StatusForbidden)
		return
	}

	// Redis decision cache. Caddy re-asks for the same domain across handshakes
	// and scanners hammer unknown domains, so caching the allow/deny verdict
	// removes almost all DB load from this hot path. Allow is cached longer;
	// deny short so a freshly-created route isn't blocked for long.
	decKey := "hpg:ask:dec:" + domain
	if h.RDB != nil {
		rctx, cancel := context.WithTimeout(r.Context(), 150*time.Millisecond)
		v, err := h.RDB.Get(rctx, decKey).Result()
		cancel()
		switch {
		case err == nil && v == "1":
			h.Metrics.AskDecision("allow")
			w.WriteHeader(http.StatusOK)
			return
		case err == nil && v == "0":
			h.Metrics.AskDecision("deny")
			http.Error(w, "denied", http.StatusForbidden)
			return
		}
	}

	// Cold path (first issuance only). 200ms falsely denied legit domains on a
	// slow/large-table lookup, which Caddy treats as "no cert" - site down.
	ctx, cancel := context.WithTimeout(r.Context(), 1500*time.Millisecond)
	defer cancel()

	allowed := h.domainAllowed(ctx, db, domain)

	// Cache the verdict (best-effort, never block the response on Redis).
	if h.RDB != nil {
		ttl := 15 * time.Second // deny: short, don't block a new domain long
		val := "0"
		if allowed {
			ttl = 120 * time.Second // allow: longer, cuts re-ask DB hits
			val = "1"
		}
		rctx, c := context.WithTimeout(context.Background(), 150*time.Millisecond)
		_ = h.RDB.Set(rctx, decKey, val, ttl).Err()
		c()
	}

	if !allowed {
		h.Metrics.AskDecision("deny")
		http.Error(w, "denied", http.StatusForbidden)
		return
	}
	h.Metrics.AskDecision("allow")
	w.WriteHeader(http.StatusOK)
}

// domainAllowed returns true when an issuance-eligible route exists for the
// domain. Two-step so the common case stays index-backed:
//  1. exact `domain = ?` uses idx_route_domain (fast, no scan).
//  2. only on miss, fall back to the alias scan (FIND_IN_SET can't use an
//     index). Aliases are rare, so the scan almost never runs.
func (h *AskHandler) domainAllowed(ctx context.Context, db *sql.DB, domain string) bool {
	var n int
	// domain_verified = 1 required: an unverified (unproven-ownership) route must
	// never get a cert, else a squatter's pre-claim yields a valid LE cert for the
	// victim host once the real owner points DNS here.
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM routes
		 WHERE domain = ? AND status IN ('dns_ok','active','pending_ssl') AND ssl_enabled = 1 AND domain_verified = 1`,
		domain,
	).Scan(&n); err != nil {
		return false
	}
	if n > 0 {
		return true
	}
	// WSS transport: the node tunnel hostname needs its own cert (it serves the
	// /wg-tunnel WebSocket route, which is not a routes row). Allow it only when
	// WSS is actually configured for that node (transport<>udp AND a backend port).
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM caddy_nodes
		 WHERE tunnel_transport <> 'udp' AND tunnel_wstunnel_port IS NOT NULL
		   AND LOWER(SUBSTRING_INDEX(tunnel_endpoint, ':', 1)) = ?`,
		domain,
	).Scan(&n); err != nil {
		return false
	}
	if n > 0 {
		return true
	}
	// Alias fallback. FIND_IN_SET ignores leading/trailing spaces only inside
	// set entries, so aliases are stored space-stripped (admin_hosts). Narrow
	// the scan to rows that actually have aliases to shrink the work.
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM routes
		 WHERE aliases IS NOT NULL AND aliases <> ''
		   AND FIND_IN_SET(?, REPLACE(aliases, ' ', '')) > 0
		   AND status IN ('dns_ok','active','pending_ssl') AND ssl_enabled = 1 AND domain_verified = 1`,
		domain,
	).Scan(&n); err != nil {
		return false
	}
	return n > 0
}

// Legacy package-level handler kept so server.go old route registration
// compiles. Real /internal/ask is wired through AskHandler.
func CaddyAsk(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "denied", http.StatusForbidden)
}
