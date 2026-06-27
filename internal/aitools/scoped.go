package aitools

import (
	"context"
	"database/sql"
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

// emptyResult is returned by scoped tools when the caller's scope resolves to no
// clients - we must never widen an empty ClientIDs to "all rows".
func emptyResult(key string) (string, error) {
	return toJSON(map[string]any{key: []any{}, "count": 0})
}

// inPlaceholders builds an "(?,?,...)" list and the matching args slice for a
// client-id IN filter. Callers MUST pass scope.ClientIDs (server-derived), never
// any id from the model. Returns ok=false for an empty list so the caller short
// -circuits to no rows instead of emitting "IN ()" (a SQL error / accidental all).
func inPlaceholders(ids []int64) (clause string, args []any, ok bool) {
	if len(ids) == 0 {
		return "", nil, false
	}
	ph := make([]string, len(ids))
	args = make([]any, len(ids))
	for i, id := range ids {
		ph[i] = "?"
		args[i] = id
	}
	return "(" + strings.Join(ph, ",") + ")", args, true
}

// listServicesScoped lists only services owned by scope.ClientIDs. The model's
// args carry no client_id - the filter comes solely from the scope.
func (r *Registry) listServicesScoped(ctx context.Context, scope Scope, raw json.RawMessage) (string, error) {
	var a limitArgs
	_ = json.Unmarshal(raw, &a)
	limit := clampLimit(a.Limit, 50, 200)
	in, args, ok := inPlaceholders(scope.ClientIDs)
	if !ok {
		return emptyResult("services")
	}
	q := `SELECT s.name, s.status, COALESCE(p.name,''), COALESCE(c.display_name,''),
	             COALESCE((SELECT COUNT(*) FROM routes r WHERE r.service_id=s.id),0)
	      FROM services s
	      JOIN plans p ON p.id = s.plan_id
	      JOIN clients c ON c.id = s.client_id
	      WHERE s.client_id IN ` + in + `
	      ORDER BY s.id ASC LIMIT ?`
	args = append(args, limit)
	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	type service struct {
		Name        string `json:"name"`
		Status      string `json:"status"`
		Plan        string `json:"plan"`
		Client      string `json:"client"`
		DomainCount int    `json:"domain_count"`
	}
	out := make([]service, 0, limit)
	for rows.Next() {
		var s service
		if err := rows.Scan(&s.Name, &s.Status, &s.Plan, &s.Client, &s.DomainCount); err != nil {
			return "", err
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	return toJSON(map[string]any{"services": out, "count": len(out)})
}

// listRoutesScoped lists only routes whose owning service belongs to
// scope.ClientIDs. Status filter from args is allowed (not a tenant boundary).
func (r *Registry) listRoutesScoped(ctx context.Context, scope Scope, raw json.RawMessage) (string, error) {
	var a routesArgs
	_ = json.Unmarshal(raw, &a)
	limit := clampLimit(a.Limit, 50, 200)
	in, args, ok := inPlaceholders(scope.ClientIDs)
	if !ok {
		return emptyResult("routes")
	}
	q := `SELECT rt.domain, COALESCE(rt.path_prefix,''), rt.upstream_port, rt.status, rt.ssl_enabled, s.name
	      FROM routes rt
	      JOIN services s ON s.id = rt.service_id
	      WHERE s.client_id IN ` + in
	if a.Status != "" {
		q += " AND rt.status = ?"
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
		Domain       string `json:"domain"`
		Path         string `json:"path,omitempty"`
		UpstreamPort int    `json:"upstream_port"`
		Status       string `json:"status"`
		SSL          bool   `json:"ssl"`
		Service      string `json:"service"`
	}
	out := make([]route, 0, limit)
	for rows.Next() {
		var rt route
		if err := rows.Scan(&rt.Domain, &rt.Path, &rt.UpstreamPort, &rt.Status, &rt.SSL, &rt.Service); err != nil {
			return "", err
		}
		out = append(out, rt)
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	return toJSON(map[string]any{"routes": out, "count": len(out)})
}

// listClientsScoped returns ONLY the caller's own client row(s). A scoped caller
// must never enumerate other tenants, so this is constrained to scope.ClientIDs.
func (r *Registry) listClientsScoped(ctx context.Context, scope Scope, raw json.RawMessage) (string, error) {
	var a limitArgs
	_ = json.Unmarshal(raw, &a)
	limit := clampLimit(a.Limit, 50, 200)
	in, args, ok := inPlaceholders(scope.ClientIDs)
	if !ok {
		return emptyResult("clients")
	}
	q := `SELECT COALESCE(c.display_name,''), COALESCE(u.email,''), c.status,
	             (SELECT COUNT(*) FROM services s WHERE s.client_id = c.id) AS service_count,
	             (SELECT COUNT(*) FROM routes r JOIN services s ON s.id = r.service_id WHERE s.client_id = c.id) AS route_count
	      FROM clients c JOIN users u ON u.id = c.user_id
	      WHERE c.id IN ` + in + `
	      ORDER BY c.id ASC LIMIT ?`
	args = append(args, limit)
	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	type client struct {
		Name     string `json:"name"`
		Email    string `json:"email"`
		Status   string `json:"status"`
		Services int    `json:"services"`
		Routes   int    `json:"routes"`
	}
	out := make([]client, 0, limit)
	for rows.Next() {
		var c client
		if err := rows.Scan(&c.Name, &c.Email, &c.Status, &c.Services, &c.Routes); err != nil {
			return "", err
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	return toJSON(map[string]any{"clients": out, "count": len(out)})
}

// trafficStatsScoped aggregates host_access_log limited to routes whose owning
// service belongs to scope.ClientIDs, so a client never sees cross-tenant
// traffic. All sub-selects carry the same client-id IN filter.
func (r *Registry) trafficStatsScoped(ctx context.Context, scope Scope, raw json.RawMessage) (string, error) {
	var a trafficArgs
	_ = json.Unmarshal(raw, &a)
	hours := clampLimit(a.Hours, 24, 720)
	top := clampLimit(a.Top, 5, 20)
	since := time.Now().UTC().Add(-time.Duration(hours) * time.Hour)

	in, idArgs, ok := inPlaceholders(scope.ClientIDs)
	if !ok {
		return toJSON(map[string]any{
			"window_hours": hours, "requests": 0, "errors_4xx": 0, "errors_5xx": 0, "bytes_resp": 0,
			"top_hosts": []any{}, "top_countries": []any{}, "top_client_ips": []any{},
		})
	}
	// route_id IN (routes owned by the caller's clients) is the tenant boundary.
	routeFilter := `route_id IN (SELECT r.id FROM routes r JOIN services s ON s.id = r.service_id WHERE s.client_id IN ` + in + `)`

	// Totals from rollups (pre-aggregated, avoids full access-log scan).
	var total, errors4xxRaw, errors5xxRaw, bytesResp int64
	totArgs := append([]any{since}, idArgs...)
	row := r.db.QueryRowContext(ctx,
		`SELECT COALESCE(SUM(requests),0),
		        COALESCE(SUM(errors_4xx),0),
		        COALESCE(SUM(errors_5xx),0),
		        COALESCE(SUM(bytes_resp),0)
		 FROM log_rollups WHERE bucket_start >= ? AND `+routeFilter, totArgs...)
	if err := row.Scan(&total, &errors4xxRaw, &errors5xxRaw, &bytesResp); err != nil {
		return "", err
	}
	errors4xx := sql.NullInt64{Int64: errors4xxRaw, Valid: true}
	errors5xx := sql.NullInt64{Int64: errors5xxRaw, Valid: true}

	topHosts, err := r.scopedTopHosts(ctx, since, top, in, idArgs)
	if err != nil {
		return "", err
	}
	topIPs, err := r.scopedTopIPs(ctx, since, top, routeFilter, idArgs)
	if err != nil {
		return "", err
	}
	topCC, err := r.scopedTopCountries(ctx, since, top, routeFilter, idArgs)
	if err != nil {
		return "", err
	}
	return toJSON(map[string]any{
		"window_hours":   hours,
		"requests":       total,
		"errors_4xx":     errors4xx.Int64,
		"errors_5xx":     errors5xx.Int64,
		"bytes_resp":     bytesResp,
		"top_hosts":      topHosts,
		"top_client_ips": topIPs,
		"top_countries":  topCC,
	})
}

func (r *Registry) scopedTopHosts(ctx context.Context, since time.Time, limit int, in string, idArgs []any) ([]hostHit, error) {
	q := `SELECT rt.domain, SUM(lr.requests), COALESCE(SUM(lr.bytes_resp),0)
	      FROM log_rollups lr
	      JOIN routes rt ON rt.id = lr.route_id
	      JOIN services s ON s.id = rt.service_id
	      WHERE lr.bucket_start >= ? AND s.client_id IN ` + in + `
	      GROUP BY rt.domain ORDER BY SUM(lr.requests) DESC, rt.domain ASC LIMIT ?`
	args := append(append([]any{since}, idArgs...), limit)
	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]hostHit, 0, limit)
	for rows.Next() {
		var h hostHit
		if err := rows.Scan(&h.Domain, &h.Requests, &h.BytesResp); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

func (r *Registry) scopedTopIPs(ctx context.Context, since time.Time, limit int, routeFilter string, idArgs []any) ([]countHit, error) {
	q := `SELECT remote_ip, COUNT(*) c
	      FROM host_access_log
	      WHERE ts >= ? AND remote_ip <> '' AND ` + routeFilter + `
	      GROUP BY remote_ip ORDER BY c DESC, remote_ip ASC LIMIT ?`
	args := append(append([]any{since}, idArgs...), limit)
	return scanCountHitsArgs(ctx, r.db, q, args)
}

// scopedTopCountries queries the stored country column in host_access_log
// filtered to the caller's routes. Rows with no country are omitted.
func (r *Registry) scopedTopCountries(ctx context.Context, since time.Time, limit int, routeFilter string, idArgs []any) ([]countHit, error) {
	q := `SELECT country, COUNT(*) c
	      FROM host_access_log
	      WHERE ts >= ? AND country <> '' AND ` + routeFilter + `
	      GROUP BY country ORDER BY c DESC, country ASC LIMIT ?`
	args := append(append([]any{since}, idArgs...), limit)
	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []countHit
	for rows.Next() {
		var h countHit
		if err := rows.Scan(&h.Value, &h.Count); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// routeLogsScoped returns recent access log entries scoped to the caller's routes.
func (r *Registry) routeLogsScoped(ctx context.Context, scope Scope, raw json.RawMessage) (string, error) {
	var a struct {
		Domain     string `json:"domain"`
		RouteID    int64  `json:"route_id"`
		Limit      int    `json:"limit"`
		ErrorsOnly bool   `json:"errors_only"`
	}
	_ = json.Unmarshal(raw, &a)
	limit := clampLimit(a.Limit, 30, 100)

	in, idArgs, ok := inPlaceholders(scope.ClientIDs)
	if !ok {
		return toJSON(map[string]any{"entries": []any{}, "count": 0})
	}

	var routeID int64
	if a.RouteID > 0 {
		// Verify route belongs to the scoped clients before accepting it.
		_ = r.db.QueryRowContext(ctx,
			`SELECT rt.id FROM routes rt JOIN services s ON s.id = rt.service_id
			 WHERE rt.id = ? AND s.client_id IN `+in,
			append([]any{a.RouteID}, idArgs...)...).Scan(&routeID)
	} else if a.Domain != "" {
		pattern := "%" + strings.ReplaceAll(a.Domain, "%", `\%`) + "%"
		args := append([]any{pattern}, idArgs...)
		_ = r.db.QueryRowContext(ctx,
			`SELECT rt.id FROM routes rt JOIN services s ON s.id = rt.service_id
			 WHERE rt.domain LIKE ? ESCAPE '\\' AND s.client_id IN `+in+` ORDER BY rt.id LIMIT 1`,
			args...).Scan(&routeID)
	}
	if routeID == 0 {
		return toJSON(map[string]any{"error": "route not found", "entries": []any{}})
	}

	cond := "route_id = ?"
	args := []any{routeID}
	if a.ErrorsOnly {
		cond += " AND status >= 400"
	}
	q := `SELECT DATE_FORMAT(ts,'%Y-%m-%dT%H:%i:%s.%fZ'), method, uri, status, latency_ms, remote_ip, bytes_resp, COALESCE(country,'')
	      FROM host_access_log WHERE ` + cond + ` ORDER BY ts DESC, id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := r.db.QueryContext(ctx, q, args...)
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
		Country   string `json:"country,omitempty"`
	}
	out := make([]entry, 0, limit)
	for rows.Next() {
		var e entry
		if err := rows.Scan(&e.TS, &e.Method, &e.URI, &e.Status, &e.LatencyMS, &e.RemoteIP, &e.BytesResp, &e.Country); err != nil {
			return "", err
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	return toJSON(map[string]any{"route_id": routeID, "count": len(out), "entries": out})
}

// wafEventsScoped returns WAF events limited to the caller's routes.
func (r *Registry) wafEventsScoped(ctx context.Context, scope Scope, raw json.RawMessage) (string, error) {
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

	in, idArgs, ok := inPlaceholders(scope.ClientIDs)
	if !ok {
		return toJSON(map[string]any{"window_hours": hours, "count": 0, "events": []any{}})
	}
	routeFilter := `route_id IN (SELECT r.id FROM routes r JOIN services s ON s.id = r.service_id WHERE s.client_id IN ` + in + `)`

	q := `SELECT DATE_FORMAT(ts,'%Y-%m-%dT%H:%i:%sZ'), severity, rule_id, action, remote_ip, host, uri, message
	      FROM waf_events WHERE ts >= ? AND ` + routeFilter
	args := append([]any{since}, idArgs...)
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

// serviceDetailScoped looks up one service by name or ID, enforcing client ownership.
// backend_ip is not returned - admin-only column.
func (r *Registry) serviceDetailScoped(ctx context.Context, scope Scope, raw json.RawMessage) (string, error) {
	var args struct {
		Identifier string `json:"identifier"`
	}
	_ = json.Unmarshal(raw, &args)
	id := strings.TrimSpace(args.Identifier)
	if id == "" {
		return `{"error":"identifier required"}`, nil
	}
	in, idArgs, ok := inPlaceholders(scope.ClientIDs)
	if !ok {
		return `{"error":"service not found"}`, nil
	}
	numID, _ := strconv.ParseInt(id, 10, 64)
	type res struct {
		ID           int64  `json:"id"`
		Name         string `json:"name"`
		Status       string `json:"status"`
		Plan         string `json:"plan"`
		NodeGroup    string `json:"node_group"`
		RouteCount   int    `json:"route_count"`
		Bandwidth30d int64  `json:"bandwidth_30d_bytes"`
		CreatedAt    string `json:"created_at"`
	}
	var r2 res
	q := `SELECT s.id, s.name, s.status,
	             p.name, ng.name,
	             COUNT(DISTINCT ro.id),
	             COALESCE(SUM(lr.bytes_resp+COALESCE(lr.bytes_req,0)),0),
	             DATE_FORMAT(s.created_at,'%Y-%m-%dT%H:%i:%sZ')
	      FROM services s
	      JOIN plans p ON p.id = s.plan_id
	      JOIN node_groups ng ON ng.id = s.node_group_id
	      LEFT JOIN routes ro ON ro.service_id = s.id
	      LEFT JOIN log_rollups lr ON lr.route_id = ro.id AND lr.bucket_start >= NOW() - INTERVAL 30 DAY
	      WHERE (s.id = ? OR s.name = ?) AND s.client_id IN ` + in + `
	      GROUP BY s.id`
	args2 := append([]any{numID, id}, idArgs...)
	err := r.db.QueryRowContext(ctx, q, args2...).Scan(
		&r2.ID, &r2.Name, &r2.Status, &r2.Plan, &r2.NodeGroup,
		&r2.RouteCount, &r2.Bandwidth30d, &r2.CreatedAt)
	if err == sql.ErrNoRows {
		return `{"error":"service not found"}`, nil
	}
	if err != nil {
		return "", err
	}
	return toJSON(r2)
}

// auditLogScoped returns audit events for the caller's own user account.
func (r *Registry) auditLogScoped(ctx context.Context, scope Scope, raw json.RawMessage) (string, error) {
	var a struct {
		Limit int `json:"limit"`
	}
	_ = json.Unmarshal(raw, &a)
	limit := clampLimit(a.Limit, 50, 200)
	in, idArgs, ok := inPlaceholders(scope.ClientIDs)
	if !ok {
		return emptyResult("entries")
	}
	q := `SELECT DATE_FORMAT(al.created_at,'%Y-%m-%dT%H:%i:%sZ'), al.action, al.entity, COALESCE(al.entity_id,''), COALESCE(al.ip,'')
	      FROM audit_log al
	      WHERE al.user_id IN (SELECT user_id FROM clients WHERE id IN ` + in + `)
	      ORDER BY al.created_at DESC LIMIT ?`
	args := append(idArgs, limit)
	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	type entry struct {
		At       string `json:"at"`
		Action   string `json:"action"`
		Entity   string `json:"entity"`
		EntityID string `json:"entity_id,omitempty"`
		IP       string `json:"ip,omitempty"`
	}
	out := make([]entry, 0, limit)
	for rows.Next() {
		var e entry
		if err := rows.Scan(&e.At, &e.Action, &e.Entity, &e.EntityID, &e.IP); err != nil {
			return "", err
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	return toJSON(map[string]any{"count": len(out), "entries": out})
}

// listWGPeersScoped returns WireGuard peers owned by the caller's client accounts.
func (r *Registry) listWGPeersScoped(ctx context.Context, scope Scope, raw json.RawMessage) (string, error) {
	var a struct {
		Status string `json:"status"`
		Limit  int    `json:"limit"`
	}
	_ = json.Unmarshal(raw, &a)
	limit := clampLimit(a.Limit, 50, 200)
	in, idArgs, ok := inPlaceholders(scope.ClientIDs)
	if !ok {
		return emptyResult("peers")
	}
	q := `SELECT p.name, p.status, p.assigned_ip,
	             COALESCE(DATE_FORMAT(p.last_handshake_at,'%Y-%m-%dT%H:%i:%sZ'),''),
	             TIMESTAMPDIFF(SECOND, p.last_handshake_at, NOW()),
	             p.rx_bytes, p.tx_bytes, COALESCE(n.name,'')
	      FROM customer_wg_peer p
	      LEFT JOIN caddy_nodes n ON n.id = p.node_id
	      WHERE p.client_id IN ` + in
	args := idArgs
	if a.Status != "" {
		q += " AND p.status = ?"
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
		Name            string `json:"name"`
		Status          string `json:"status"`
		AssignedIP      string `json:"assigned_ip"`
		LastHandshake   string `json:"last_handshake,omitempty"`
		HandshakeAgeSec int64  `json:"handshake_age_sec,omitempty"`
		RxBytes         int64  `json:"rx_bytes"`
		TxBytes         int64  `json:"tx_bytes"`
		NodeName        string `json:"node,omitempty"`
	}
	out := make([]peer, 0, limit)
	for rows.Next() {
		var p peer
		var ageSec sql.NullInt64
		if err := rows.Scan(&p.Name, &p.Status, &p.AssignedIP, &p.LastHandshake, &ageSec, &p.RxBytes, &p.TxBytes, &p.NodeName); err != nil {
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

// scanCountHitsArgs runs a value+count query with an arbitrary arg list.
func scanCountHitsArgs(ctx context.Context, db *sql.DB, q string, args []any) ([]countHit, error) {
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []countHit
	for rows.Next() {
		var h countHit
		if err := rows.Scan(&h.Value, &h.Count); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}
