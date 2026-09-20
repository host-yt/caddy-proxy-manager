package handlers

import (
	"context"
	"database/sql"
	"go/version"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/host-yt/caddy-proxy-manager/internal/caddyapi"
)

// pqHostsShown caps the domain list in the readiness card; the count above it
// stays exact.
const pqHostsShown = 20

// pqNodeView is one edge node as the readiness card lists it.
type pqNodeView struct {
	Name         string
	CaddyVersion string
	HybridKEX    bool   // Caddy >= 2.10 negotiates X25519MLKEM768
	PSK          string // "active" | "pending" | ""
	AgentPSK     bool   // node-agent reported PSK support
}

// pqStatusView backs the read-only "Post-quantum readiness" settings card.
type pqStatusView struct {
	GoVersion   string
	GoHybrid    bool
	Nodes       []pqNodeView
	NodesHybrid int
	MeshActive  int
	MeshPending int
	AgentPSK    int
	PeerPSK     int
	PeerTotal   int
	PQHosts     []string // truncated to pqHostsShown
	PQHostCount int
}

// NodeTotal is the denominator of every per-node row in the card.
func (s pqStatusView) NodeTotal() int { return len(s.Nodes) }

// HostsTruncated reports whether PQHosts was cut short.
func (s pqStatusView) HostsTruncated() int { return s.PQHostCount - len(s.PQHosts) }

// settingsPQData wraps settingsData so the readiness card reaches the template
// without a second field in the (already huge) settings struct.
type settingsPQData struct {
	settingsData
	PQ pqStatusView
}

// pqStatus collects the post-quantum posture shown on the Settings page.
// Every query degrades to zero on error: this is a status panel, not a gate.
func (h *AdminHandlers) pqStatus(ctx context.Context) pqStatusView {
	s := pqStatusView{GoVersion: runtime.Version()}
	// Go 1.24 made X25519MLKEM768 the default key exchange in crypto/tls.
	s.GoHybrid = version.Compare(version.Lang(s.GoVersion), "go1.24") >= 0

	db := h.DB()
	if db == nil {
		return s
	}
	qctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	rows, err := db.QueryContext(qctx,
		`SELECT name, COALESCE(caddy_version,''), wg_psk_enc IS NOT NULL,
		        wg_psk_pending_enc IS NOT NULL, agent_psk
		 FROM caddy_nodes ORDER BY priority DESC, id ASC`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var n pqNodeView
			var active, pending bool
			if rows.Scan(&n.Name, &n.CaddyVersion, &active, &pending, &n.AgentPSK) != nil {
				continue
			}
			n.HybridKEX = caddyHybridKEX(n.CaddyVersion)
			switch {
			case active:
				n.PSK, s.MeshActive = "active", s.MeshActive+1
			case pending:
				n.PSK, s.MeshPending = "pending", s.MeshPending+1
			}
			if n.HybridKEX {
				s.NodesHybrid++
			}
			if n.AgentPSK {
				s.AgentPSK++
			}
			s.Nodes = append(s.Nodes, n)
		}
	}

	// Revoked peers keep their row but no longer hold a tunnel.
	_ = db.QueryRowContext(qctx,
		`SELECT COUNT(*), COALESCE(SUM(psk_enc IS NOT NULL), 0)
		 FROM customer_wg_peer WHERE status <> 'revoked'`).Scan(&s.PeerTotal, &s.PeerPSK)

	// Hosts, not routes: several path routes can share one domain. SSL off
	// means no TLS connection policy is emitted at all (build.go ANDs the two),
	// so such a route is not enforced and must not be counted as if it were.
	_ = db.QueryRowContext(qctx,
		`SELECT COUNT(DISTINCT domain) FROM routes WHERE tls_pq_only = 1 AND ssl_enabled = 1`).Scan(&s.PQHostCount)
	if s.PQHostCount > 0 {
		hrows, herr := db.QueryContext(qctx,
			`SELECT DISTINCT domain FROM routes WHERE tls_pq_only = 1 AND ssl_enabled = 1
			 ORDER BY domain LIMIT ?`, pqHostsShown)
		if herr == nil {
			defer hrows.Close()
			for hrows.Next() {
				var d string
				if hrows.Scan(&d) == nil {
					s.PQHosts = append(s.PQHosts, d)
				}
			}
		}
	}
	return s
}

// pqBlockingNode names a node serving the route that cannot negotiate
// x25519mlkem768. The node set mirrors the pusher exactly (anchor
// routes.caddy_node_id plus the route_node_assignments fan-out, as
// SchedulePushForRoute enumerates it) because push.go gates the PQ-only policy
// per node: one lagging fan-out peer and the policy is silently dropped there,
// so the edit page must not call the toggle enforced.
// Returns blocked=false when every serving node is capable or the query fails;
// the caller's anchor-only verdict then stands.
func pqBlockingNode(ctx context.Context, db *sql.DB, routeID int64) (name, version string, blocked bool) {
	if db == nil || routeID == 0 {
		return "", "", false
	}
	rows, err := db.QueryContext(ctx,
		`SELECT n.name, COALESCE(n.caddy_version,'')
		 FROM caddy_nodes n
		 WHERE n.id = (SELECT caddy_node_id FROM routes WHERE id = ?)
		    OR n.id IN (SELECT node_id FROM route_node_assignments WHERE route_id = ?)
		 ORDER BY n.id ASC`, routeID, routeID)
	if err != nil {
		return "", "", false
	}
	defer rows.Close()
	for rows.Next() {
		var n, v string
		if rows.Scan(&n, &v) != nil {
			continue
		}
		if !caddyapi.CaddySupportsPQCurve(v) {
			return n, v, true
		}
	}
	return "", "", false
}

// caddyHybridKEX reports whether a caddy_version string is >= 2.10, the first
// release built on Go 1.24. The column is operator-entered free text, so
// anything unparseable counts as "unknown", not "ready".
func caddyHybridKEX(v string) bool {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if i := strings.IndexAny(v, " \t-+"); i >= 0 {
		v = v[:i]
	}
	parts := strings.Split(v, ".")
	if len(parts) < 2 {
		return false
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return false
	}
	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return false
	}
	return major > 2 || (major == 2 && minor >= 10)
}
