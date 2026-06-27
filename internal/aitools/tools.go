package aitools

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"
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
			Name:        "list_routes",
			Description: "List proxy routes (domain, status, node, ssl) optionally filtered by status.",
			Schema:      listRoutesSchema,
			Exec:        r.listRoutes,
		},
		{
			Name:        "list_clients",
			Description: "List clients with display name, email and their service/route counts.",
			Schema:      limitSchema(50),
			Exec:        r.listClients,
		},
		{
			Name:        "list_services",
			Description: "List services with name, status, plan and owning client.",
			Schema:      limitSchema(50),
			Exec:        r.listServices,
		},
		{
			Name:        "get_traffic_stats",
			Description: "Traffic summary over the last N hours: total requests, errors, and top hosts/IPs.",
			Schema:      trafficSchema,
			Exec:        r.trafficStats,
		},
		{
			Name:        "node_health",
			Description: "Summary of node health statuses (counts per status, total enabled/disabled).",
			Schema:      emptyObjectSchema,
			Exec:        r.nodeHealth,
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
	return toJSON(map[string]any{
		"window_hours":   hours,
		"requests":       total,
		"errors_4xx":     errors4xx.Int64,
		"errors_5xx":     errors5xx.Int64,
		"top_hosts":      topHosts,
		"top_client_ips": topIPs,
	})
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

// itoa is a tiny strconv.Itoa to avoid an import only used in schema strings.
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
