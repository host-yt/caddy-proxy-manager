package aitools

import (
	"context"
	"database/sql"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/host-yt/caddy-proxy-manager/internal/geoip"
)

// builtins returns the read-only tool set. Each tool selects only non-sensitive
// operational columns - the secret columns deliberately excluded per table are
// noted at each query. SELECT only; no statement mutates state.
func (r *Registry) builtins() []Tool {
	return []Tool{
		{
			Name:        "list_nodes",
			Description: "List Caddy edge nodes with health, enabled flag, public IP and route counts.",
			Schema:      limitSchema(50),
			Exec:        r.listNodes,
		},
		{
			Name:           "list_routes",
			Description:    "List proxy routes (domain, status, node, ssl) optionally filtered by status.",
			Schema:         listRoutesSchema,
			Exec:           r.listRoutes,
			clientRelevant: true,
			scopedExec:     r.listRoutesScoped,
		},
		{
			Name:           "list_clients",
			Description:    "List clients with display name, email and their service/route counts.",
			Schema:         limitSchema(50),
			Exec:           r.listClients,
			clientRelevant: true,
			scopedExec:     r.listClientsScoped,
		},
		{
			Name:           "list_services",
			Description:    "List services with name, status, plan and owning client.",
			Schema:         limitSchema(50),
			Exec:           r.listServices,
			clientRelevant: true,
			scopedExec:     r.listServicesScoped,
		},
		{
			Name:           "get_traffic_stats",
			Description:    "Traffic summary over the last N hours: total requests, errors, top hosts, top visitor countries (ISO2, '??' = unresolved), and top client IPs.",
			Schema:         trafficSchema,
			Exec:           r.trafficStats,
			clientRelevant: true,
			scopedExec:     r.trafficStatsScoped,
		},
		{
			Name:        "get_system_summary",
			Description: "Single-call system overview: node counts, route counts, active clients, open alerts, WAF blocks last 24h, storage used by backups. Use as a first call to orient before drilling into specifics.",
			Schema:      emptyObjectSchema,
			Exec:        r.systemSummary,
		},
		{
			Name:        "node_health",
			Description: "Summary of node health statuses (counts per status, total enabled/disabled).",
			Schema:      emptyObjectSchema,
			Exec:        r.nodeHealth,
		},
		{
			Name:        "get_recent_alerts",
			Description: "Return the most recent fired alerts (node offline, cert expiry, etc.) from the alert log.",
			Schema:      limitSchema(20),
			Exec:        r.recentAlerts,
		},
		{
			Name:        "get_waf_summary",
			Description: "WAF events summary over the last N hours: counts by severity and action, top attacking IPs, top targeted hosts.",
			Schema:      trafficSchema,
			Exec:        r.wafSummary,
		},
		{
			Name:        "search_routes",
			Description: "Search proxy routes by domain name substring (case-insensitive). Returns domain, status, SSL, node.",
			Schema:      searchRoutesSchema,
			Exec:        r.searchRoutes,
		},
		{
			Name:           "get_route_logs",
			Description:    "Return the most recent access log entries for a specific domain (or route ID). Useful for debugging 4xx/5xx errors on a specific site.",
			Schema:         routeLogsSchema,
			Exec:           r.routeLogs,
			clientRelevant: true,
			scopedExec:     r.routeLogsScoped,
		},
		{
			Name:           "get_audit_log",
			Description:    "Return recent audit log entries. Filter by actor email, action name (e.g. 'route.create'), or entity type. Scoped callers see only their own events.",
			Schema:         json.RawMessage(`{"type":"object","properties":{"actor":{"type":"string","description":"filter by actor email (partial match)"},"action":{"type":"string","description":"filter by action string (partial match), e.g. 'route.create'"},"entity":{"type":"string","description":"filter by entity type, e.g. 'route', 'client', 'user'"},"limit":{"type":"integer","minimum":1,"maximum":100}},"additionalProperties":false}`),
			Exec:           r.auditLog,
			clientRelevant: true,
			scopedExec:     r.auditLogScoped,
		},
		{
			Name:           "list_wg_peers",
			Description:    "List WireGuard tunnel peers: name, status, assigned IP, last handshake age. Private keys never exposed. Scoped callers see only their own peers.",
			Schema:         json.RawMessage(`{"type":"object","properties":{"status":{"type":"string","description":"filter by status: active, revoked, pending"},"limit":{"type":"integer","minimum":1,"maximum":200}},"additionalProperties":false}`),
			Exec:           r.listWGPeers,
			clientRelevant: true,
			scopedExec:     r.listWGPeersScoped,
		},
		{
			Name:        "get_backup_status",
			Description: "Return recent backup job history (last N jobs): destination name, kind, status, size, duration, error. Encrypted credential columns are never selected.",
			Schema:      json.RawMessage(`{"type":"object","properties":{"limit":{"type":"integer","minimum":1,"maximum":50}},"additionalProperties":false}`),
			Exec:        r.backupStatus,
		},
		{
			Name:           "get_waf_events",
			Description:    "Return recent WAF block/detect events. Filter by domain, severity (critical/high/medium/low), or action (block/detect). Useful for investigating attacks or false positives.",
			Schema:         wafEventsSchema,
			Exec:           r.wafEvents,
			clientRelevant: true,
			scopedExec:     r.wafEventsScoped,
		},
		{
			Name:        "get_client_detail",
			Description: "Look up a single client by email address or numeric client ID. Returns display name, email, active status, registration date, service count, route count and WireGuard peer count.",
			Schema:      identifierSchema,
			Exec:        r.clientDetail,
		},
		{
			Name:        "get_node_detail",
			Description: "Look up a single Caddy edge node by name or numeric node ID. Returns health, enabled flag, public IP, route counts, priority and last-seen time.",
			Schema:      identifierSchema,
			Exec:        r.nodeDetail,
		},
		{
			Name:        "list_node_groups",
			Description: "List node groups with mode (single/active_active/failover), node count, and plan count. Useful for understanding routing topology.",
			Schema:      emptyObjectSchema,
			Exec:        r.listNodeGroups,
		},
		{
			Name:        "list_plans",
			Description: "List service plans: name, max_domains, max_ports, ssl/websocket/path-routing flags, rate_limit_rpm, node_group. Useful for capacity planning or answering 'what plan allows X?'",
			Schema:      limitSchema(50),
			Exec:        r.listPlans,
		},
		{
			Name:           "get_service_detail",
			Description:    "Look up a service by name or numeric ID. Returns status, plan name, route count, 30d bandwidth and created date. Admin sees backend IP; scoped callers see only their own services.",
			Schema:         identifierSchema,
			Exec:           r.serviceDetail,
			clientRelevant: true,
			scopedExec:     r.serviceDetailScoped,
		},
		{
			Name:        "list_active_alerts",
			Description: "List alerts fired in the last N hours (default 24, max 720). Filter by severity (info/warning/critical). Returns rule_id, severity, title, fired_at. Useful for system health checks.",
			Schema:      listActiveAlertsSchema,
			Exec:        r.listActiveAlerts,
		},
		{
			Name:        "list_ssl_certs",
			Description: "List manual SSL certificates sorted by expiry (soonest first). Returns name, common_name, SANs, not_after, days_left (negative = already expired).",
			Schema:      limitSchema(50),
			Exec:        r.listSSLCerts,
		},
	}
}

// limitArgs is the common {limit} parameter.
type limitArgs struct {
	Limit int `json:"limit"`
}

func limitSchema(def int) json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{"limit":{"type":"integer","description":"max rows (default ` +
		itoa(def) + `)","minimum":1,"maximum":200}},"additionalProperties":false}`)
}

var listRoutesSchema = json.RawMessage(`{"type":"object","properties":{` +
	`"limit":{"type":"integer","minimum":1,"maximum":200},` +
	`"status":{"type":"string","description":"filter by route status e.g. active, failed, pending_dns"}},` +
	`"additionalProperties":false}`)

var trafficSchema = json.RawMessage(`{"type":"object","properties":{` +
	`"hours":{"type":"integer","description":"window size in hours (default 24, max 720)","minimum":1,"maximum":720},` +
	`"top":{"type":"integer","description":"top-N hosts/IPs (default 5, max 20)","minimum":1,"maximum":20}},` +
	`"additionalProperties":false}`)

var searchRoutesSchema = json.RawMessage(`{"type":"object","required":["query"],"properties":{` +
	`"query":{"type":"string","description":"domain substring to search for","minLength":1,"maxLength":253},` +
	`"limit":{"type":"integer","minimum":1,"maximum":100}},` +
	`"additionalProperties":false}`)

var routeLogsSchema = json.RawMessage(`{"type":"object","properties":{` +
	`"domain":{"type":"string","description":"exact or partial domain to look up; if omitted, route_id must be set"},` +
	`"route_id":{"type":"integer","description":"route ID (alternative to domain)"},` +
	`"limit":{"type":"integer","minimum":1,"maximum":100},` +
	`"errors_only":{"type":"boolean","description":"when true, only return status >= 400"}},` +
	`"additionalProperties":false}`)

var wafEventsSchema = json.RawMessage(`{"type":"object","properties":{` +
	`"domain":{"type":"string","description":"filter to a specific domain (partial match)"},` +
	`"severity":{"type":"string","description":"filter by severity: critical, high, medium, or low"},` +
	`"action":{"type":"string","description":"filter by action: block or detect"},` +
	`"hours":{"type":"integer","description":"look-back window in hours (default 24, max 720)","minimum":1,"maximum":720},` +
	`"limit":{"type":"integer","minimum":1,"maximum":100}},` +
	`"additionalProperties":false}`)

var identifierSchema = json.RawMessage(`{"type":"object","properties":{"identifier":{"type":"string","description":"email address or numeric ID"}},"required":["identifier"],"additionalProperties":false}`)

var listActiveAlertsSchema = json.RawMessage(`{"type":"object","properties":{` +
	`"hours":{"type":"integer","description":"lookback window in hours (default 24, max 720)","minimum":1,"maximum":720},` +
	`"severity":{"type":"string","description":"filter by severity: info, warning, critical"},` +
	`"limit":{"type":"integer","description":"max rows (default 50)","minimum":1,"maximum":200}},` +
	`"additionalProperties":false}`)

// systemSummary gathers top-level counts in a single round-trip set.
func (r *Registry) systemSummary(ctx context.Context, _ json.RawMessage) (string, error) {
	type result struct {
		NodesTotal      int64 `json:"nodes_total"`
		NodesHealthy    int64 `json:"nodes_healthy"`
		RoutesTotal     int64 `json:"routes_total"`
		RoutesActive    int64 `json:"routes_active"`
		ClientsTotal    int64 `json:"clients_total"`
		OpenAlerts      int64 `json:"open_alerts"`
		WAFBlocks24h    int64 `json:"waf_blocks_24h"`
		BackupBytes     int64 `json:"backup_storage_bytes"`
	}
	var s result
	type scanPair struct {
		q    string
		dest *int64
	}
	pairs := []scanPair{
		{`SELECT COUNT(*) FROM caddy_nodes WHERE deleted_at IS NULL`, &s.NodesTotal},
		{`SELECT COUNT(*) FROM caddy_nodes WHERE deleted_at IS NULL AND status='healthy'`, &s.NodesHealthy},
		{`SELECT COUNT(*) FROM routes WHERE deleted_at IS NULL`, &s.RoutesTotal},
		{`SELECT COUNT(*) FROM routes WHERE deleted_at IS NULL AND status='active'`, &s.RoutesActive},
		{`SELECT COUNT(*) FROM clients WHERE deleted_at IS NULL`, &s.ClientsTotal},
		{`SELECT COUNT(*) FROM alert_log WHERE resolved_at IS NULL`, &s.OpenAlerts},
		{`SELECT COUNT(*) FROM waf_events WHERE action='blocked' AND ts >= NOW() - INTERVAL 24 HOUR`, &s.WAFBlocks24h},
		{`SELECT COALESCE(SUM(size_bytes),0) FROM backup_jobs WHERE status='success'`, &s.BackupBytes},
	}
	for _, p := range pairs {
		_ = r.db.QueryRowContext(ctx, p.q).Scan(p.dest)
	}
	return toJSON(s)
}

// list_nodes: caddy_nodes carries no secret columns; agent_token_hash and WG
// private keys live in other tables and are never selected here.
func (r *Registry) listNodes(ctx context.Context, raw json.RawMessage) (string, error) {
	var a limitArgs
	_ = json.Unmarshal(raw, &a)
	limit := clampLimit(a.Limit, 50, 200)
	const q = `SELECT name, health_status, is_enabled, COALESCE(public_ip,''),
	                  current_routes, max_routes
	           FROM caddy_nodes ORDER BY name ASC LIMIT ?`
	rows, err := r.db.QueryContext(ctx, q, limit)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	type node struct {
		Name          string `json:"name"`
		Health        string `json:"health"`
		Enabled       bool   `json:"enabled"`
		PublicIP      string `json:"public_ip"`
		CurrentRoutes int    `json:"current_routes"`
		MaxRoutes     int    `json:"max_routes"`
	}
	out := make([]node, 0, limit)
	for rows.Next() {
		var n node
		if err := rows.Scan(&n.Name, &n.Health, &n.Enabled, &n.PublicIP, &n.CurrentRoutes, &n.MaxRoutes); err != nil {
			return "", err
		}
		out = append(out, n)
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	return toJSON(map[string]any{"nodes": out, "count": len(out)})
}

type routesArgs struct {
	Limit  int    `json:"limit"`
	Status string `json:"status"`
}

// list_routes: routes has no secrets; last_error is omitted (can be verbose).
func (r *Registry) listRoutes(ctx context.Context, raw json.RawMessage) (string, error) {
	var a routesArgs
	_ = json.Unmarshal(raw, &a)
	limit := clampLimit(a.Limit, 50, 200)
	q := `SELECT rt.domain, rt.path_prefix, rt.status, rt.ssl_enabled, cn.name
	      FROM routes rt JOIN caddy_nodes cn ON cn.id = rt.caddy_node_id`
	args := []any{}
	if a.Status != "" {
		q += " WHERE rt.status = ?"
		args = append(args, a.Status)
	}
	q += " ORDER BY rt.domain ASC LIMIT ?"
	args = append(args, limit)
	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	type route struct {
		Domain string `json:"domain"`
		Path   string `json:"path,omitempty"`
		Status string `json:"status"`
		SSL    bool   `json:"ssl"`
		Node   string `json:"node"`
	}
	out := make([]route, 0, limit)
	for rows.Next() {
		var rt route
		if err := rows.Scan(&rt.Domain, &rt.Path, &rt.Status, &rt.SSL, &rt.Node); err != nil {
			return "", err
		}
		out = append(out, rt)
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	return toJSON(map[string]any{"routes": out, "count": len(out)})
}

// list_clients: joins users for email only; password_hash/totp_secret/oidc_*
// are deliberately NOT selected.
func (r *Registry) listClients(ctx context.Context, raw json.RawMessage) (string, error) {
	var a limitArgs
	_ = json.Unmarshal(raw, &a)
	limit := clampLimit(a.Limit, 50, 200)
	const q = `SELECT COALESCE(c.display_name,''), COALESCE(u.email,''),
	                  (SELECT COUNT(*) FROM services s WHERE s.client_id = c.id) AS service_count
	           FROM clients c JOIN users u ON u.id = c.user_id
	           ORDER BY c.id ASC LIMIT ?`
	rows, err := r.db.QueryContext(ctx, q, limit)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	type client struct {
		Name     string `json:"name"`
		Email    string `json:"email"`
		Services int    `json:"services"`
	}
	out := make([]client, 0, limit)
	for rows.Next() {
		var c client
		if err := rows.Scan(&c.Name, &c.Email, &c.Services); err != nil {
			return "", err
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	return toJSON(map[string]any{"clients": out, "count": len(out)})
}

// list_services: backend_ip and port ranges are admin-only operational secrets
// in spirit; we expose name/status/plan/client only, NOT backend_ip.
func (r *Registry) listServices(ctx context.Context, raw json.RawMessage) (string, error) {
	var a limitArgs
	_ = json.Unmarshal(raw, &a)
	limit := clampLimit(a.Limit, 50, 200)
	const q = `SELECT s.name, s.status, COALESCE(p.name,''), COALESCE(c.display_name,'')
	           FROM services s
	           JOIN plans p ON p.id = s.plan_id
	           JOIN clients c ON c.id = s.client_id
	           ORDER BY s.id ASC LIMIT ?`
	rows, err := r.db.QueryContext(ctx, q, limit)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	type service struct {
		Name   string `json:"name"`
		Status string `json:"status"`
		Plan   string `json:"plan"`
		Client string `json:"client"`
	}
	out := make([]service, 0, limit)
	for rows.Next() {
		var s service
		if err := rows.Scan(&s.Name, &s.Status, &s.Plan, &s.Client); err != nil {
			return "", err
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	return toJSON(map[string]any{"services": out, "count": len(out)})
}

type trafficArgs struct {
	Hours int `json:"hours"`
	Top   int `json:"top"`
}

// get_traffic_stats: aggregates over host_access_log (no secret columns). Top
// hosts come from joining route_id->routes.domain; top IPs from remote_ip.
func (r *Registry) trafficStats(ctx context.Context, raw json.RawMessage) (string, error) {
	var a trafficArgs
	_ = json.Unmarshal(raw, &a)
	hours := clampLimit(a.Hours, 24, 720)
	top := clampLimit(a.Top, 5, 20)
	since := time.Now().UTC().Add(-time.Duration(hours) * time.Hour)

	var total int64
	var errors4xx, errors5xx sql.NullInt64
	row := r.db.QueryRowContext(ctx,
		`SELECT COUNT(*),
		        SUM(CASE WHEN status BETWEEN 400 AND 499 THEN 1 ELSE 0 END),
		        SUM(CASE WHEN status BETWEEN 500 AND 599 THEN 1 ELSE 0 END)
		 FROM host_access_log WHERE ts >= ?`, since)
	if err := row.Scan(&total, &errors4xx, &errors5xx); err != nil {
		return "", err
	}

	topHosts, err := r.topHosts(ctx, since, top)
	if err != nil {
		return "", err
	}
	topIPs, err := r.topIPs(ctx, since, top)
	if err != nil {
		return "", err
	}
	topCountries, err := r.topCountries(ctx, since, top)
	if err != nil {
		return "", err
	}
	return toJSON(map[string]any{
		"window_hours":   hours,
		"requests":       total,
		"errors_4xx":     errors4xx.Int64,
		"errors_5xx":     errors5xx.Int64,
		"top_hosts":      topHosts,
		"top_countries":  topCountries,
		"top_client_ips": topIPs,
	})
}

// trafficCountryIPCap bounds how many distinct visitor IPs we resolve to a
// country per call (matches the traffic map cap) so a wide window stays cheap.
const trafficCountryIPCap = 5000

// topCountries resolves visitor remote_ip to ISO2 via the shared geoip resolver
// (same source as the traffic map) and returns the busiest countries. Unresolved
// or private IPs bucket as "??". Empty when no geoip db is configured.
func (r *Registry) topCountries(ctx context.Context, since time.Time, limit int) ([]countHit, error) {
	const q = `SELECT remote_ip, COUNT(*) c
	           FROM host_access_log
	           WHERE ts >= ? AND remote_ip <> ''
	           GROUP BY remote_ip ORDER BY c DESC, remote_ip ASC LIMIT ?`
	rows, err := r.db.QueryContext(ctx, q, since, trafficCountryIPCap)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	resolver := geoip.Global()
	byCC := map[string]int64{}
	for rows.Next() {
		var ip string
		var c int64
		if err := rows.Scan(&ip, &c); err != nil {
			return nil, err
		}
		cc := resolver.LookupISO2(ip)
		if cc == "" {
			cc = "??"
		}
		byCC[cc] += c
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]countHit, 0, len(byCC))
	for cc, n := range byCC {
		out = append(out, countHit{Value: cc, Count: n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Value < out[j].Value
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

type countHit struct {
	Value string `json:"value"`
	Count int64  `json:"count"`
}

func (r *Registry) topHosts(ctx context.Context, since time.Time, limit int) ([]countHit, error) {
	const q = `SELECT rt.domain, COUNT(*) c
	           FROM host_access_log hal JOIN routes rt ON rt.id = hal.route_id
	           WHERE hal.ts >= ?
	           GROUP BY rt.domain ORDER BY c DESC, rt.domain ASC LIMIT ?`
	return scanCountHits(ctx, r.db, q, since, limit)
}

func (r *Registry) topIPs(ctx context.Context, since time.Time, limit int) ([]countHit, error) {
	const q = `SELECT remote_ip, COUNT(*) c
	           FROM host_access_log
	           WHERE ts >= ? AND remote_ip <> ''
	           GROUP BY remote_ip ORDER BY c DESC, remote_ip ASC LIMIT ?`
	return scanCountHits(ctx, r.db, q, since, limit)
}

func scanCountHits(ctx context.Context, db *sql.DB, q string, since time.Time, limit int) ([]countHit, error) {
	rows, err := db.QueryContext(ctx, q, since, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]countHit, 0, limit)
	for rows.Next() {
		var h countHit
		if err := rows.Scan(&h.Value, &h.Count); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// node_health: count of nodes per health_status plus enabled/disabled totals.
func (r *Registry) nodeHealth(ctx context.Context, _ json.RawMessage) (string, error) {
	const q = `SELECT health_status, COUNT(*),
	                  SUM(CASE WHEN is_enabled = 1 THEN 1 ELSE 0 END)
	           FROM caddy_nodes GROUP BY health_status`
	rows, err := r.db.QueryContext(ctx, q)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	byStatus := map[string]int64{}
	var totalEnabled, total int64
	for rows.Next() {
		var status string
		var count int64
		var enabled sql.NullInt64
		if err := rows.Scan(&status, &count, &enabled); err != nil {
			return "", err
		}
		byStatus[status] = count
		total += count
		totalEnabled += enabled.Int64
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	return toJSON(map[string]any{
		"by_status": byStatus,
		"total":     total,
		"enabled":   totalEnabled,
		"disabled":  total - totalEnabled,
	})
}

// recentAlerts: reads alert_log, safe non-secret columns only.
func (r *Registry) recentAlerts(ctx context.Context, raw json.RawMessage) (string, error) {
	var a limitArgs
	_ = json.Unmarshal(raw, &a)
	limit := clampLimit(a.Limit, 20, 100)
	const q = `SELECT rule_id, severity, title, COALESCE(detail,''), fired_at
	           FROM alert_log ORDER BY fired_at DESC LIMIT ?`
	rows, err := r.db.QueryContext(ctx, q, limit)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	type alert struct {
		RuleID   string `json:"rule_id"`
		Severity string `json:"severity"`
		Title    string `json:"title"`
		Detail   string `json:"detail,omitempty"`
		FiredAt  string `json:"fired_at"`
	}
	out := make([]alert, 0, limit)
	for rows.Next() {
		var a alert
		var firedAt time.Time
		if err := rows.Scan(&a.RuleID, &a.Severity, &a.Title, &a.Detail, &firedAt); err != nil {
			return "", err
		}
		a.FiredAt = firedAt.UTC().Format(time.RFC3339)
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	return toJSON(map[string]any{"alerts": out, "count": len(out)})
}

// wafSummary: counts + top attackers + top targets from waf_events.
func (r *Registry) wafSummary(ctx context.Context, raw json.RawMessage) (string, error) {
	var a trafficArgs
	_ = json.Unmarshal(raw, &a)
	hours := clampLimit(a.Hours, 24, 720)
	top := clampLimit(a.Top, 5, 20)
	since := time.Now().UTC().Add(-time.Duration(hours) * time.Hour)

	// Counts by severity.
	bySeverity := map[string]int64{}
	rows, err := r.db.QueryContext(ctx,
		`SELECT severity, COUNT(*) FROM waf_events WHERE ts >= ? GROUP BY severity`, since)
	if err != nil {
		return "", err
	}
	for rows.Next() {
		var sev string
		var cnt int64
		if err := rows.Scan(&sev, &cnt); err != nil {
			rows.Close()
			return "", err
		}
		bySeverity[sev] = cnt
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return "", err
	}

	// Counts by action.
	byAction := map[string]int64{}
	rows, err = r.db.QueryContext(ctx,
		`SELECT action, COUNT(*) FROM waf_events WHERE ts >= ? GROUP BY action`, since)
	if err != nil {
		return "", err
	}
	for rows.Next() {
		var act string
		var cnt int64
		if err := rows.Scan(&act, &cnt); err != nil {
			rows.Close()
			return "", err
		}
		byAction[act] = cnt
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return "", err
	}

	// Top attacking IPs.
	topIPs, err := scanCountHits(ctx, r.db,
		`SELECT remote_ip, COUNT(*) c FROM waf_events WHERE ts >= ? AND remote_ip <> '' GROUP BY remote_ip ORDER BY c DESC, remote_ip ASC LIMIT ?`,
		since, top)
	if err != nil {
		return "", err
	}

	// Top targeted hosts.
	topHosts, err := scanCountHits(ctx, r.db,
		`SELECT host, COUNT(*) c FROM waf_events WHERE ts >= ? AND host <> '' GROUP BY host ORDER BY c DESC, host ASC LIMIT ?`,
		since, top)
	if err != nil {
		return "", err
	}

	return toJSON(map[string]any{
		"window_hours": hours,
		"by_severity":  bySeverity,
		"by_action":    byAction,
		"top_ips":      topIPs,
		"top_hosts":    topHosts,
	})
}

// searchRoutes: case-insensitive domain LIKE search.
func (r *Registry) searchRoutes(ctx context.Context, raw json.RawMessage) (string, error) {
	var a struct {
		Query string `json:"query"`
		Limit int    `json:"limit"`
	}
	_ = json.Unmarshal(raw, &a)
	if a.Query == "" {
		return toJSON(map[string]any{"routes": []any{}, "count": 0})
	}
	limit := clampLimit(a.Limit, 20, 100)
	pattern := "%" + strings.ReplaceAll(a.Query, "%", `\%`) + "%"
	const q = `SELECT rt.domain, rt.path_prefix, rt.status, rt.ssl_enabled, cn.name
	           FROM routes rt JOIN caddy_nodes cn ON cn.id = rt.caddy_node_id
	           WHERE rt.domain LIKE ? ESCAPE '\\' ORDER BY rt.domain ASC LIMIT ?`
	rows, err := r.db.QueryContext(ctx, q, pattern, limit)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	type route struct {
		Domain string `json:"domain"`
		Path   string `json:"path,omitempty"`
		Status string `json:"status"`
		SSL    bool   `json:"ssl"`
		Node   string `json:"node"`
	}
	out := make([]route, 0, limit)
	for rows.Next() {
		var rt route
		if err := rows.Scan(&rt.Domain, &rt.Path, &rt.Status, &rt.SSL, &rt.Node); err != nil {
			return "", err
		}
		out = append(out, rt)
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	return toJSON(map[string]any{"routes": out, "count": len(out)})
}

// routeLogs returns recent access log entries for a specific route.
func (r *Registry) routeLogs(ctx context.Context, raw json.RawMessage) (string, error) {
	var a struct {
		Domain     string `json:"domain"`
		RouteID    int64  `json:"route_id"`
		Limit      int    `json:"limit"`
		ErrorsOnly bool   `json:"errors_only"`
	}
	_ = json.Unmarshal(raw, &a)
	limit := clampLimit(a.Limit, 30, 100)

	var routeID int64
	if a.RouteID > 0 {
		routeID = a.RouteID
	} else if a.Domain != "" {
		pattern := "%" + strings.ReplaceAll(a.Domain, "%", `\%`) + "%"
		_ = r.db.QueryRowContext(ctx,
			`SELECT id FROM routes WHERE domain LIKE ? ESCAPE '\\' ORDER BY id LIMIT 1`, pattern,
		).Scan(&routeID)
	}
	if routeID == 0 {
		return toJSON(map[string]any{"error": "route not found", "entries": []any{}})
	}

	cond := "route_id = ?"
	args := []any{routeID}
	if a.ErrorsOnly {
		cond += " AND status >= 400"
	}
	qFull := `SELECT ts, method, uri, status, latency_ms, remote_ip, bytes_resp
	           FROM host_access_log WHERE ` + cond + ` ORDER BY ts DESC, id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := r.db.QueryContext(ctx, qFull, args...)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	type entry struct {
		TS        string `json:"ts"`
		Method    string `json:"method"`
		URI       string `json:"uri"`
		Status    int    `json:"status"`
		LatencyMS int64  `json:"latency_ms"`
		RemoteIP  string `json:"remote_ip"`
		BytesResp int64  `json:"bytes_resp"`
	}
	out := make([]entry, 0, limit)
	for rows.Next() {
		var e entry
		if err := rows.Scan(&e.TS, &e.Method, &e.URI, &e.Status, &e.LatencyMS, &e.RemoteIP, &e.BytesResp); err != nil {
			return "", err
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	return toJSON(map[string]any{"route_id": routeID, "count": len(out), "entries": out})
}

// auditLog returns recent audit log entries. Never exposes meta JSON that could
// contain secrets; only the scalar columns (actor email, action, entity, IP) are selected.
func (r *Registry) auditLog(ctx context.Context, raw json.RawMessage) (string, error) {
	var a struct {
		Actor  string `json:"actor"`
		Action string `json:"action"`
		Entity string `json:"entity"`
		Limit  int    `json:"limit"`
	}
	_ = json.Unmarshal(raw, &a)
	limit := clampLimit(a.Limit, 30, 100)

	q := `SELECT DATE_FORMAT(al.created_at,'%Y-%m-%dT%H:%i:%sZ'),
	             COALESCE(u.email,'system'),
	             al.action, COALESCE(al.entity,''), COALESCE(al.entity_id,''),
	             COALESCE(al.ip,'')
	      FROM audit_log al
	      LEFT JOIN users u ON u.id = al.user_id
	      WHERE 1=1`
	args := []any{}
	if a.Actor != "" {
		q += " AND u.email LIKE ? ESCAPE '\\'"
		args = append(args, "%"+strings.ReplaceAll(a.Actor, "%", `\%`)+"%")
	}
	if a.Action != "" {
		q += " AND al.action LIKE ? ESCAPE '\\'"
		args = append(args, "%"+strings.ReplaceAll(a.Action, "%", `\%`)+"%")
	}
	if a.Entity != "" {
		q += " AND al.entity = ?"
		args = append(args, a.Entity)
	}
	q += " ORDER BY al.created_at DESC LIMIT ?"
	args = append(args, limit)

	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	type entry struct {
		At       string `json:"at"`
		Actor    string `json:"actor"`
		Action   string `json:"action"`
		Entity   string `json:"entity,omitempty"`
		EntityID string `json:"entity_id,omitempty"`
		IP       string `json:"ip,omitempty"`
	}
	out := make([]entry, 0, limit)
	for rows.Next() {
		var e entry
		if err := rows.Scan(&e.At, &e.Actor, &e.Action, &e.Entity, &e.EntityID, &e.IP); err != nil {
			return "", err
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	return toJSON(map[string]any{"count": len(out), "entries": out})
}

// listWGPeers returns WireGuard peer status. Private/server keys never selected.
func (r *Registry) listWGPeers(ctx context.Context, raw json.RawMessage) (string, error) {
	var a struct {
		Status string `json:"status"`
		Limit  int    `json:"limit"`
	}
	_ = json.Unmarshal(raw, &a)
	limit := clampLimit(a.Limit, 50, 200)

	q := `SELECT p.name, p.status, p.assigned_ip,
	             COALESCE(DATE_FORMAT(p.last_handshake_at,'%Y-%m-%dT%H:%i:%sZ'),''),
	             TIMESTAMPDIFF(SECOND, p.last_handshake_at, NOW()),
	             p.rx_bytes, p.tx_bytes,
	             COALESCE(u.email,''), n.name
	      FROM customer_wg_peer p
	      JOIN clients c ON c.id = p.client_id
	      JOIN users u ON u.id = c.user_id
	      LEFT JOIN caddy_nodes n ON n.id = p.node_id`
	args := []any{}
	if a.Status != "" {
		q += " WHERE p.status = ?"
		args = append(args, a.Status)
	}
	q += " ORDER BY p.last_handshake_at DESC, p.id DESC LIMIT ?"
	args = append(args, limit)

	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	type peer struct {
		Name           string `json:"name"`
		Status         string `json:"status"`
		AssignedIP     string `json:"assigned_ip"`
		LastHandshake  string `json:"last_handshake,omitempty"`
		HandshakeAgeSec int64 `json:"handshake_age_sec,omitempty"`
		RxBytes        int64  `json:"rx_bytes"`
		TxBytes        int64  `json:"tx_bytes"`
		ClientEmail    string `json:"client_email"`
		NodeName       string `json:"node,omitempty"`
	}
	out := make([]peer, 0, limit)
	for rows.Next() {
		var p peer
		var ageSec sql.NullInt64
		if err := rows.Scan(&p.Name, &p.Status, &p.AssignedIP, &p.LastHandshake, &ageSec, &p.RxBytes, &p.TxBytes, &p.ClientEmail, &p.NodeName); err != nil {
			return "", err
		}
		if ageSec.Valid {
			p.HandshakeAgeSec = ageSec.Int64
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	return toJSON(map[string]any{"count": len(out), "peers": out})
}

// backupStatus returns recent backup job history. Encrypted credential columns never selected.
func (r *Registry) backupStatus(ctx context.Context, raw json.RawMessage) (string, error) {
	var a limitArgs
	_ = json.Unmarshal(raw, &a)
	limit := clampLimit(a.Limit, 20, 50)
	rows, err := r.db.QueryContext(ctx,
		`SELECT d.name, d.kind,
		        j.kind, j.status,
		        j.size_bytes,
		        TIMESTAMPDIFF(SECOND, j.started_at, COALESCE(j.finished_at, NOW())),
		        COALESCE(DATE_FORMAT(j.created_at,'%Y-%m-%dT%H:%i:%sZ'),''),
		        COALESCE(LEFT(j.error_text,200),'')
		 FROM backup_jobs j
		 JOIN backup_destinations d ON d.id = j.destination_id
		 ORDER BY j.created_at DESC LIMIT ?`, limit)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	type job struct {
		Destination string `json:"destination"`
		DestKind    string `json:"dest_kind"`
		Kind        string `json:"kind"`
		Status      string `json:"status"`
		SizeBytes   int64  `json:"size_bytes"`
		DurationSec int64  `json:"duration_sec"`
		CreatedAt   string `json:"created_at"`
		Error       string `json:"error,omitempty"`
	}
	out := make([]job, 0, limit)
	for rows.Next() {
		var j job
		if err := rows.Scan(&j.Destination, &j.DestKind, &j.Kind, &j.Status, &j.SizeBytes, &j.DurationSec, &j.CreatedAt, &j.Error); err != nil {
			return "", err
		}
		out = append(out, j)
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	return toJSON(map[string]any{"count": len(out), "jobs": out})
}

// wafEvents returns recent WAF events with per-event detail.
func (r *Registry) wafEvents(ctx context.Context, raw json.RawMessage) (string, error) {
	var a struct {
		Domain   string `json:"domain"`
		Severity string `json:"severity"`
		Action   string `json:"action"`
		Hours    int    `json:"hours"`
		Limit    int    `json:"limit"`
	}
	_ = json.Unmarshal(raw, &a)
	hours := clampLimit(a.Hours, 24, 720)
	limit := clampLimit(a.Limit, 30, 100)
	since := time.Now().UTC().Add(-time.Duration(hours) * time.Hour)

	q := `SELECT DATE_FORMAT(ts,'%Y-%m-%dT%H:%i:%sZ'), severity, rule_id, action, remote_ip, host, uri, message
	      FROM waf_events WHERE ts >= ?`
	args := []any{since}
	if a.Severity != "" {
		q += " AND severity = ?"
		args = append(args, a.Severity)
	}
	if a.Action != "" {
		q += " AND action = ?"
		args = append(args, a.Action)
	}
	if a.Domain != "" {
		pattern := "%" + strings.ReplaceAll(a.Domain, "%", `\%`) + "%"
		q += " AND host LIKE ? ESCAPE '\\'"
		args = append(args, pattern)
	}
	q += " ORDER BY ts DESC, id DESC LIMIT ?"
	args = append(args, limit)

	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	type event struct {
		TS       string `json:"ts"`
		Severity string `json:"severity"`
		RuleID   string `json:"rule_id"`
		Action   string `json:"action"`
		RemoteIP string `json:"remote_ip"`
		Host     string `json:"host"`
		URI      string `json:"uri"`
		Message  string `json:"message"`
	}
	out := make([]event, 0, limit)
	for rows.Next() {
		var e event
		if err := rows.Scan(&e.TS, &e.Severity, &e.RuleID, &e.Action, &e.RemoteIP, &e.Host, &e.URI, &e.Message); err != nil {
			return "", err
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	return toJSON(map[string]any{"window_hours": hours, "count": len(out), "events": out})
}

// clientDetail looks up one client by email or numeric ID.
func (r *Registry) clientDetail(ctx context.Context, raw json.RawMessage) (string, error) {
	if r.db == nil {
		return `{"error":"database unavailable"}`, nil
	}
	var a struct {
		Identifier string `json:"identifier"`
	}
	_ = json.Unmarshal(raw, &a)
	numID, _ := strconv.ParseInt(a.Identifier, 10, 64)
	type result struct {
		ID           int64  `json:"id"`
		DisplayName  string `json:"display_name"`
		Email        string `json:"email"`
		IsActive     bool   `json:"is_active"`
		CreatedAt    string `json:"created_at"`
		ServiceCount int64  `json:"service_count"`
		RouteCount   int64  `json:"route_count"`
		WGPeerCount  int64  `json:"wg_peer_count"`
	}
	var res result
	err := r.db.QueryRowContext(ctx,
		`SELECT c.id, COALESCE(c.display_name,''), u.email, u.is_active, DATE(u.created_at),
		        (SELECT COUNT(*) FROM services WHERE client_id = c.id),
		        (SELECT COUNT(*) FROM services sv JOIN routes rt ON rt.service_id = sv.id WHERE sv.client_id = c.id),
		        (SELECT COUNT(*) FROM customer_wg_peer WHERE client_id = c.id)
		 FROM clients c JOIN users u ON u.id = c.user_id
		 WHERE c.id = ? OR u.email = ?`,
		numID, a.Identifier,
	).Scan(&res.ID, &res.DisplayName, &res.Email, &res.IsActive, &res.CreatedAt,
		&res.ServiceCount, &res.RouteCount, &res.WGPeerCount)
	if err == sql.ErrNoRows {
		return `{"error":"client not found"}`, nil
	}
	if err != nil {
		return "", err
	}
	return toJSON(res)
}

// nodeDetail looks up one Caddy node by name or numeric ID.
func (r *Registry) nodeDetail(ctx context.Context, raw json.RawMessage) (string, error) {
	if r.db == nil {
		return `{"error":"database unavailable"}`, nil
	}
	var a struct {
		Identifier string `json:"identifier"`
	}
	_ = json.Unmarshal(raw, &a)
	numID, _ := strconv.ParseInt(a.Identifier, 10, 64)
	type result struct {
		ID            int64  `json:"id"`
		Name          string `json:"name"`
		Health        string `json:"health"`
		PublicIP      string `json:"public_ip"`
		Enabled       bool   `json:"enabled"`
		MaxRoutes     int64  `json:"max_routes"`
		CurrentRoutes int64  `json:"current_routes"`
		Priority      int64  `json:"priority"`
		LastSeen      string `json:"last_seen"`
	}
	var res result
	err := r.db.QueryRowContext(ctx,
		`SELECT n.id, n.name, n.health_status, COALESCE(n.public_ip,''), n.is_enabled,
		        n.max_routes, n.current_routes, n.priority,
		        COALESCE(DATE_FORMAT(n.last_seen_at,'%Y-%m-%dT%H:%i:%SZ'),'never')
		 FROM caddy_nodes n
		 WHERE n.id = ? OR n.name = ?`,
		numID, a.Identifier,
	).Scan(&res.ID, &res.Name, &res.Health, &res.PublicIP, &res.Enabled,
		&res.MaxRoutes, &res.CurrentRoutes, &res.Priority, &res.LastSeen)
	if err == sql.ErrNoRows {
		return `{"error":"node not found"}`, nil
	}
	if err != nil {
		return "", err
	}
	return toJSON(res)
}

func (r *Registry) listNodeGroups(ctx context.Context, _ json.RawMessage) (string, error) {
	db := r.db
	if db == nil {
		return `{"error":"db unavailable"}`, nil
	}
	type group struct {
		ID        int64  `json:"id"`
		Name      string `json:"name"`
		Mode      string `json:"mode"`
		NodeCount int    `json:"node_count"`
		PlanCount int    `json:"plan_count"`
	}
	rows, err := db.QueryContext(ctx,
		`SELECT ng.id, ng.name, ng.mode,
		        COUNT(DISTINCT cn.id), COUNT(DISTINCT p.id)
		 FROM node_groups ng
		 LEFT JOIN caddy_nodes cn ON cn.node_group_id = ng.id
		 LEFT JOIN plans p ON p.node_group_id = ng.id
		 GROUP BY ng.id ORDER BY ng.name`)
	if err != nil {
		return `{"error":"query failed"}`, nil
	}
	defer rows.Close()
	out := make([]group, 0, 8)
	for rows.Next() {
		var g group
		if rows.Scan(&g.ID, &g.Name, &g.Mode, &g.NodeCount, &g.PlanCount) == nil {
			out = append(out, g)
		}
	}
	b, _ := json.Marshal(map[string]any{"node_groups": out, "total": len(out)})
	return string(b), nil
}

func (r *Registry) listPlans(ctx context.Context, raw json.RawMessage) (string, error) {
	var a limitArgs
	_ = json.Unmarshal(raw, &a)
	limit := clampLimit(a.Limit, 50, 200)
	db := r.db
	if db == nil {
		return `{"error":"db unavailable"}`, nil
	}
	type plan struct {
		ID               int64  `json:"id"`
		Name             string `json:"name"`
		MaxDomains       int    `json:"max_domains"`
		MaxPorts         int    `json:"max_ports"`
		SSL              bool   `json:"ssl_enabled"`
		Websocket        bool   `json:"websocket_enabled"`
		PathRouting      bool   `json:"path_routing_enabled"`
		Wildcard         bool   `json:"wildcard_enabled"`
		RateLimitRPM     int    `json:"rate_limit_rpm,omitempty"`
		NodeGroup        string `json:"node_group"`
	}
	rows, err := db.QueryContext(ctx,
		`SELECT p.id, p.name, p.max_domains, p.max_ports,
		        p.ssl_enabled, p.websocket_enabled, p.path_routing_enabled, p.wildcard_enabled,
		        COALESCE(p.rate_limit_rpm,0), ng.name
		 FROM plans p JOIN node_groups ng ON ng.id = p.node_group_id
		 ORDER BY p.name LIMIT ?`, limit)
	if err != nil {
		return `{"error":"query failed"}`, nil
	}
	defer rows.Close()
	out := make([]plan, 0, 16)
	for rows.Next() {
		var p plan
		if rows.Scan(&p.ID, &p.Name, &p.MaxDomains, &p.MaxPorts,
			&p.SSL, &p.Websocket, &p.PathRouting, &p.Wildcard,
			&p.RateLimitRPM, &p.NodeGroup) == nil {
			out = append(out, p)
		}
	}
	b, _ := json.Marshal(map[string]any{"plans": out, "total": len(out)})
	return string(b), nil
}

func (r *Registry) serviceDetail(ctx context.Context, raw json.RawMessage) (string, error) {
	var args struct {
		Identifier string `json:"identifier"`
	}
	_ = json.Unmarshal(raw, &args)
	id := strings.TrimSpace(args.Identifier)
	if id == "" {
		return `{"error":"identifier required"}`, nil
	}
	db := r.db
	if db == nil {
		return `{"error":"db unavailable"}`, nil
	}
	numID, _ := strconv.ParseInt(id, 10, 64)
	type res struct {
		ID          int64  `json:"id"`
		Name        string `json:"name"`
		Status      string `json:"status"`
		BackendIP   string `json:"backend_ip"`
		Plan        string `json:"plan"`
		NodeGroup   string `json:"node_group"`
		RouteCount  int    `json:"route_count"`
		Bandwidth30d int64 `json:"bandwidth_30d_bytes"`
		CreatedAt   string `json:"created_at"`
	}
	var r2 res
	err := db.QueryRowContext(ctx,
		`SELECT s.id, s.name, s.status, s.backend_ip,
		        p.name, ng.name,
		        COUNT(DISTINCT ro.id),
		        COALESCE(SUM(lr.bytes_resp+COALESCE(lr.bytes_req,0)),0),
		        DATE_FORMAT(s.created_at,'%Y-%m-%dT%H:%i:%sZ')
		 FROM services s
		 JOIN plans p ON p.id = s.plan_id
		 JOIN node_groups ng ON ng.id = s.node_group_id
		 LEFT JOIN routes ro ON ro.service_id = s.id
		 LEFT JOIN log_rollups lr ON lr.route_id = ro.id AND lr.bucket_start >= NOW() - INTERVAL 30 DAY
		 WHERE s.id = ? OR s.name = ?
		 GROUP BY s.id`, numID, id,
	).Scan(&r2.ID, &r2.Name, &r2.Status, &r2.BackendIP,
		&r2.Plan, &r2.NodeGroup, &r2.RouteCount, &r2.Bandwidth30d, &r2.CreatedAt)
	if err == sql.ErrNoRows {
		return `{"error":"service not found"}`, nil
	}
	if err != nil {
		return "", err
	}
	return toJSON(r2)
}

func (r *Registry) listActiveAlerts(ctx context.Context, raw json.RawMessage) (string, error) {
	var args struct {
		Hours    int    `json:"hours"`
		Severity string `json:"severity"`
		Limit    int    `json:"limit"`
	}
	_ = json.Unmarshal(raw, &args)
	if args.Hours <= 0 || args.Hours > 720 {
		args.Hours = 24
	}
	if args.Limit <= 0 || args.Limit > 200 {
		args.Limit = 50
	}
	db := r.db
	if db == nil {
		return `{"error":"db unavailable"}`, nil
	}
	type row struct {
		RuleID   string `json:"rule_id"`
		Severity string `json:"severity"`
		Title    string `json:"title"`
		FiredAt  string `json:"fired_at"`
	}
	var qargs []any
	q := `SELECT rule_id, severity, title, DATE_FORMAT(fired_at,'%Y-%m-%dT%H:%i:%sZ') FROM alert_log WHERE fired_at >= NOW() - INTERVAL ? HOUR`
	qargs = append(qargs, args.Hours)
	if args.Severity != "" {
		q += " AND severity = ?"
		qargs = append(qargs, args.Severity)
	}
	q += " ORDER BY fired_at DESC LIMIT ?"
	qargs = append(qargs, args.Limit)
	rows, err := db.QueryContext(ctx, q, qargs...)
	if err != nil {
		return `{"error":"query failed"}`, nil
	}
	defer rows.Close()
	var out []row
	for rows.Next() {
		var ro row
		if rows.Scan(&ro.RuleID, &ro.Severity, &ro.Title, &ro.FiredAt) == nil {
			out = append(out, ro)
		}
	}
	if out == nil {
		out = []row{}
	}
	b, _ := json.Marshal(map[string]any{"alerts": out, "hours": args.Hours, "total": len(out)})
	return string(b), nil
}

func (r *Registry) listSSLCerts(ctx context.Context, raw json.RawMessage) (string, error) {
	var args limitArgs
	_ = json.Unmarshal(raw, &args)
	if args.Limit <= 0 || args.Limit > 200 {
		args.Limit = 50
	}
	db := r.db
	if db == nil {
		return `{"error":"db unavailable"}`, nil
	}
	type row struct {
		ID         int64  `json:"id"`
		Name       string `json:"name"`
		CommonName string `json:"common_name"`
		Sans       string `json:"sans"`
		NotAfter   string `json:"not_after"`
		DaysLeft   int    `json:"days_left"`
	}
	rows, err := db.QueryContext(ctx,
		`SELECT id, name, common_name, sans,
		        DATE_FORMAT(not_after,'%Y-%m-%dT%H:%i:%sZ'),
		        TIMESTAMPDIFF(DAY, NOW(), not_after)
		 FROM manual_certs ORDER BY not_after ASC LIMIT ?`, args.Limit)
	if err != nil {
		return `{"error":"query failed"}`, nil
	}
	defer rows.Close()
	var out []row
	for rows.Next() {
		var ro row
		if rows.Scan(&ro.ID, &ro.Name, &ro.CommonName, &ro.Sans, &ro.NotAfter, &ro.DaysLeft) == nil {
			out = append(out, ro)
		}
	}
	if out == nil {
		out = []row{}
	}
	b, _ := json.Marshal(map[string]any{"certs": out, "total": len(out)})
	return string(b), nil
}

// itoa is a tiny helper; strconv is also used by clientDetail/nodeDetail.
func itoa(n int) string {
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
