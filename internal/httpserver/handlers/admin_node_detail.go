package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/host-yt/caddy-proxy-manager/internal/store"
)

// nodeDetailData is admin_hosts.go's neighbour because both surfaces
// reach into the routes table to give the operator an at-a-glance
// view of "what is this node actually doing right now".
type nodeDetailData struct {
	baseAdminData
	Node         nodeDetailRow
	RouteCount   int
	ActiveRoutes int
	FailedRoutes int
	RecentAudit  []nodeAuditLine
	NodeAlerts   []nodeAlertRow
	RecentRoutes []hostRow
	// GeoIPMeta surfaces DB status next to the GeoIP capability badge.
	GeoIPMeta geoipView
	// ModuleMismatches lists routes that require a module the node lacks.
	ModuleMismatches []nodeMismatch
	// PSK is the mesh WireGuard preshared-key state (PQ-01).
	PSK nodePSKView
	// 24h traffic aggregates for this node.
	NodeBandwidth24h int64
	NodeRequests24h  int64
	TopRoutesBW      []nodeBWRoute
}

// nodeMismatch is a route that requires a Caddy module not available on its node.
type nodeMismatch struct {
	RouteID int64
	Domain  string
	Missing string // human-readable module name, e.g. "WAF", "GeoIP", "rate_limit"
}

// nodeBWRoute holds per-route 24h bandwidth summary for the node detail cockpit.
type nodeBWRoute struct {
	RouteID   int64
	Domain    string
	BytesResp int64
	Requests  int64
}

type nodeDetailRow struct {
	ID            int64
	Name          string
	APIURL        string
	PublicHost    string
	PublicIP      string
	GroupName     string
	Health        string
	Enabled       bool
	Approved      bool
	LastSeen      string
	MaxRoutes     int
	CurrentRoutes int
	LastRTTMs     sql.NullInt32 // NULL until the first successful health probe

	// WG tunnel health surfaced in the detail cockpit.
	TunnelEnabled      bool
	TunnelMTU          sql.NullInt32
	WstunnelHealthy    sql.NullBool
	FwdIPForward       sql.NullBool
	FwdPolicyDrop      sql.NullBool
	FwdDockerRules     sql.NullBool // DOCKER-USER accept active -> Docker-routed forward is covered
	FwdFirewallBackend sql.NullString
	FwdLastSetupError  sql.NullString
	FwdReportedAt      sql.NullString
	WGKeepalive        int // always 25 (PersistentKeepalive set by agent)

	// Capability flags from Caddy module probe.
	HasWAF       bool
	HasL4        bool
	HasDNSModule bool
	HasRateLimit bool
	HasGeoIP     bool
	CaddyVersion string
}

type nodeAuditLine struct {
	When   string
	Action string
	Email  string
	Meta   string
}

type nodeAlertRow struct {
	RuleID   string
	Severity string
	Title    string
	FiredAt  string
}

// NodeDetail renders /admin/nodes/{id}: per-node ops cockpit.
func (h *AdminHandlers) NodeDetail(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chiURLParamHosts(r, "id"), 10, 64)
	d := nodeDetailData{baseAdminData: h.base(r, "Node detail")}
	db := h.DB()
	if db == nil || id == 0 {
		h.render(w, "node_detail", d)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	var lastSeen sql.NullTime
	err := db.QueryRowContext(ctx,
		`SELECT n.id, n.name, n.api_url, n.public_hostname, COALESCE(n.public_ip,''),
		        ng.name, n.health_status, n.is_enabled, n.approved_at IS NOT NULL,
		        n.last_seen_at, n.max_routes, n.current_routes, n.last_rtt_ms,
		        COALESCE(n.tunnel_enabled,0),
		        n.fwd_mtu, n.tunnel_wstunnel_healthy,
		        n.fwd_ip_forward_enabled, n.fwd_policy_drop_detected,
		        n.fwd_docker_rules_installed,
		        n.fwd_firewall_backend, n.fwd_last_setup_error,
		        COALESCE(DATE_FORMAT(n.fwd_reported_at,'%Y-%m-%d %H:%i'),''),
		        COALESCE(CASE WHEN n.modules_probed_at IS NOT NULL THEN n.has_waf        END, ?),
		        COALESCE(CASE WHEN n.modules_probed_at IS NOT NULL THEN n.has_l4         END, ?),
		        COALESCE(CASE WHEN n.modules_probed_at IS NOT NULL THEN n.has_dns_module END, ?),
		        COALESCE(CASE WHEN n.modules_probed_at IS NOT NULL THEN n.has_rate_limit END, ?),
		        COALESCE(CASE WHEN n.modules_probed_at IS NOT NULL THEN n.has_geoip      END, ?), COALESCE(n.caddy_version,'')
		 FROM caddy_nodes n JOIN node_groups ng ON ng.id = n.node_group_id
		 WHERE n.id = ?`,
		b2i(h.Routes != nil && h.Routes.WAFModuleAvailable),
		b2i(h.Routes != nil && h.Routes.Layer4ModuleAvailable),
		b2i(h.Routes != nil && h.Routes.DNS01ModuleAvailable),
		b2i(h.Routes != nil && h.Routes.RateLimitModuleAvailable),
		b2i(h.Routes != nil && h.Routes.GeoModuleAvailable), id,
	).Scan(&d.Node.ID, &d.Node.Name, &d.Node.APIURL, &d.Node.PublicHost, &d.Node.PublicIP,
		&d.Node.GroupName, &d.Node.Health, &d.Node.Enabled, &d.Node.Approved,
		&lastSeen, &d.Node.MaxRoutes, &d.Node.CurrentRoutes, &d.Node.LastRTTMs,
		&d.Node.TunnelEnabled,
		&d.Node.TunnelMTU, &d.Node.WstunnelHealthy,
		&d.Node.FwdIPForward, &d.Node.FwdPolicyDrop,
		&d.Node.FwdDockerRules,
		&d.Node.FwdFirewallBackend, &d.Node.FwdLastSetupError,
		&d.Node.FwdReportedAt,
		&d.Node.HasWAF, &d.Node.HasL4, &d.Node.HasDNSModule,
		&d.Node.HasRateLimit, &d.Node.HasGeoIP, &d.Node.CaddyVersion)
	if err != nil {
		d.Error = "node not found"
		h.render(w, "node_detail", d)
		return
	}
	d.Node.WGKeepalive = 25
	if lastSeen.Valid {
		d.Node.LastSeen = lastSeen.Time.Format("2006-01-02 15:04:05 MST")
	}

	_ = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM routes WHERE caddy_node_id=?", id).Scan(&d.RouteCount)
	_ = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM routes WHERE caddy_node_id=? AND status='active'", id).Scan(&d.ActiveRoutes)
	_ = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM routes WHERE caddy_node_id=? AND status='failed'", id).Scan(&d.FailedRoutes)

	rrows, err := db.QueryContext(ctx,
		`SELECT r.id, r.domain, r.path_prefix, r.upstream_port, r.status, COALESCE(r.last_error,''),
		        r.ssl_enabled, r.websocket, r.force_https, r.kind, COALESCE(r.tag,''), r.updated_at,
		        s.id, s.name, COALESCE(NULLIF(r.backend_ip_override,''), s.backend_ip), c.id, u.email, p.name, p.kind,
		        n.id, n.name, n.public_hostname
		 FROM routes r
		 JOIN services s ON s.id = r.service_id
		 JOIN clients c ON c.id = s.client_id
		 JOIN users u ON u.id = c.user_id
		 JOIN plans p ON p.id = s.plan_id
		 JOIN caddy_nodes n ON n.id = r.caddy_node_id
		 WHERE r.caddy_node_id = ?
		 ORDER BY r.updated_at DESC LIMIT 25`, id)
	if err == nil {
		defer rrows.Close()
		for rrows.Next() {
			var hr hostRow
			if e := rrows.Scan(
				&hr.RouteID, &hr.Domain, &hr.PathPrefix, &hr.UpstreamPort,
				&hr.Status, &hr.LastError,
				&hr.SSL, &hr.WebSocket, &hr.ForceHTTPS, &hr.Kind, &hr.Tag, &hr.UpdatedAt,
				&hr.ServiceID, &hr.ServiceName, &hr.BackendIP,
				&hr.ClientID, &hr.ClientEmail,
				&hr.PlanName, &hr.PlanKind,
				&hr.NodeID, &hr.NodeName, &hr.NodeHostname,
			); e == nil {
				d.RecentRoutes = append(d.RecentRoutes, hr)
			}
		}
	}

	arows, err := db.QueryContext(ctx,
		`SELECT al.created_at, al.action, COALESCE(u.email,''), COALESCE(al.meta,'')
		 FROM audit_log al LEFT JOIN users u ON u.id = al.user_id
		 WHERE al.entity = 'node' AND al.entity_id = ?
		 ORDER BY al.id DESC LIMIT 20`, strconv.FormatInt(id, 10))
	if err == nil {
		defer arows.Close()
		for arows.Next() {
			var line nodeAuditLine
			var t time.Time
			if e := arows.Scan(&t, &line.Action, &line.Email, &line.Meta); e == nil {
				line.When = t.Format("2006-01-02 15:04:05")
				d.RecentAudit = append(d.RecentAudit, line)
			}
		}
	}

	// Recent alerts for this node via labels_json; skip on unsupported JSON_EXTRACT.
	alCtx, alCancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer alCancel()
	alrows, alErr := db.QueryContext(alCtx,
		`SELECT rule_id, severity, title, DATE_FORMAT(fired_at, '%Y-%m-%d %H:%i')
		 FROM alert_log
		 WHERE JSON_UNQUOTE(JSON_EXTRACT(labels_json, '$.node_id')) = ?
		 ORDER BY id DESC LIMIT 10`, strconv.FormatInt(id, 10))
	if alErr == nil {
		defer alrows.Close()
		for alrows.Next() {
			var al nodeAlertRow
			if e := alrows.Scan(&al.RuleID, &al.Severity, &al.Title, &al.FiredAt); e == nil {
				d.NodeAlerts = append(d.NodeAlerts, al)
			}
		}
	}

	// Load global GeoIP DB status so the template can show it next to the badge.
	d.GeoIPMeta = h.loadGeoIPView(ctx, db)
	d.PSK = h.loadNodePSK(ctx, db, id)

	// 24h total bandwidth + request count for all routes on this node (from rollups).
	_ = db.QueryRowContext(ctx,
		`SELECT COALESCE(SUM(lr.bytes_resp),0), COALESCE(SUM(lr.requests),0)
		 FROM log_rollups lr
		 JOIN routes r ON r.id = lr.route_id
		 WHERE r.caddy_node_id = ? AND lr.bucket_start >= `+store.DateSub(24, "HOUR")+``, id,
	).Scan(&d.NodeBandwidth24h, &d.NodeRequests24h)

	// Top 5 routes by 24h bandwidth on this node (from rollups).
	bwrows, err := db.QueryContext(ctx,
		`SELECT lr.route_id, r.domain, COALESCE(SUM(lr.bytes_resp),0), COALESCE(SUM(lr.requests),0)
		 FROM log_rollups lr
		 JOIN routes r ON r.id = lr.route_id
		 WHERE r.caddy_node_id = ? AND lr.bucket_start >= `+store.DateSub(24, "HOUR")+`
		 GROUP BY lr.route_id, r.domain
		 ORDER BY SUM(lr.bytes_resp) DESC LIMIT 5`, id)
	if err == nil {
		defer bwrows.Close()
		for bwrows.Next() {
			var bw nodeBWRoute
			if e := bwrows.Scan(&bw.RouteID, &bw.Domain, &bw.BytesResp, &bw.Requests); e == nil {
				d.TopRoutesBW = append(d.TopRoutesBW, bw)
			}
		}
	}

	// Preflight: routes that need a Caddy module the node doesn't have. Effective
	// capability = per-node declared flag if set, else fleet-wide env flag (mirrors
	// probedOr); COALESCE the env value in so unprobed nodes don't false-warn.
	envWAF := h.Routes != nil && h.Routes.WAFModuleAvailable
	envGeo := h.Routes != nil && h.Routes.GeoModuleAvailable
	envRate := h.Routes != nil && h.Routes.RateLimitModuleAvailable
	mmRows, mmErr := db.QueryContext(ctx, `
		SELECT r.id, r.domain, CASE
		  WHEN r.waf_enabled=1     AND COALESCE(CASE WHEN n.modules_probed_at IS NOT NULL THEN n.has_waf        END, ?)=0 THEN 'WAF'
		  WHEN r.geo_mode!='off'   AND COALESCE(CASE WHEN n.modules_probed_at IS NOT NULL THEN n.has_geoip      END, ?)=0 THEN 'GeoIP'
		  WHEN r.rate_enabled=1    AND COALESCE(CASE WHEN n.modules_probed_at IS NOT NULL THEN n.has_rate_limit END, ?)=0 THEN 'rate_limit'
		  WHEN r.geo_mode!='off'   AND n.geoip_db_present=0 THEN 'GeoIP DB'
		END AS missing
		FROM routes r
		JOIN caddy_nodes n ON n.id = r.caddy_node_id
		WHERE r.caddy_node_id = ? AND r.status != 'disabled'
		  AND (
		        (r.waf_enabled=1     AND COALESCE(CASE WHEN n.modules_probed_at IS NOT NULL THEN n.has_waf        END, ?)=0)
		     OR (r.geo_mode!='off'   AND COALESCE(CASE WHEN n.modules_probed_at IS NOT NULL THEN n.has_geoip      END, ?)=0)
		     OR (r.rate_enabled=1    AND COALESCE(CASE WHEN n.modules_probed_at IS NOT NULL THEN n.has_rate_limit END, ?)=0)
		     OR (r.geo_mode!='off'   AND n.geoip_db_present=0)
		  )
		ORDER BY r.domain LIMIT 50`,
		b2i(envWAF), b2i(envGeo), b2i(envRate), id, b2i(envWAF), b2i(envGeo), b2i(envRate))
	if mmErr == nil {
		defer mmRows.Close()
		for mmRows.Next() {
			var mm nodeMismatch
			if e := mmRows.Scan(&mm.RouteID, &mm.Domain, &mm.Missing); e == nil {
				d.ModuleMismatches = append(d.ModuleMismatches, mm)
			}
		}
	}

	h.render(w, "node_detail", d)
}

// NodeRTTJSON handles GET /admin/nodes/{id}/rtt.json. Returns {labels,
// values} (rtt_ms_avg per 5-min bucket, last 24h) for the node_detail
// Chart.js sparkline - same shape/mechanism as TunnelsBandwidthJSON.
func (h *AdminHandlers) NodeRTTJSON(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chiURLParamHosts(r, "id"), 10, 64)
	db := h.DB()
	if db == nil || id == 0 {
		apiJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid node id"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	rows, err := db.QueryContext(ctx,
		`SELECT DATE_FORMAT(bucket_start,'%m-%d %H:%i'), rtt_ms_avg
		 FROM node_rtt_samples
		 WHERE node_id = ? AND bucket_start >= `+store.DateSub(24, "HOUR")+`
		 ORDER BY bucket_start`, id)
	if err != nil {
		apiJSON(w, http.StatusInternalServerError, map[string]any{"error": "query failed"})
		return
	}
	defer rows.Close()

	labels := []string{}
	values := []int{}
	for rows.Next() {
		var label string
		var avg int
		if err := rows.Scan(&label, &avg); err == nil {
			labels = append(labels, label)
			values = append(values, avg)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"labels": labels,
		"values": values,
	})
}
