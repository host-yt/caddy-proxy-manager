package handlers

import (
	"context"
	"go/version"
	"runtime"
	"strconv"
	"strings"
	"time"
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

	_ = db.QueryRowContext(qctx,
		`SELECT COUNT(*) FROM routes WHERE tls_pq_only = 1`).Scan(&s.PQHostCount)
	if s.PQHostCount > 0 {
		hrows, herr := db.QueryContext(qctx,
			`SELECT domain FROM routes WHERE tls_pq_only = 1 ORDER BY domain LIMIT ?`, pqHostsShown)
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
