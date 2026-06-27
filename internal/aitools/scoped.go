package aitools

import (
	"context"
	"database/sql"
	"encoding/json"
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
	q := `SELECT s.name, s.status, COALESCE(p.name,''), COALESCE(c.display_name,'')
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
	q := `SELECT rt.domain, COALESCE(rt.path_prefix,''), rt.status, rt.ssl_enabled, s.name
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
		Domain  string `json:"domain"`
		Path    string `json:"path,omitempty"`
		Status  string `json:"status"`
		SSL     bool   `json:"ssl"`
		Service string `json:"service"`
	}
	out := make([]route, 0, limit)
	for rows.Next() {
		var rt route
		if err := rows.Scan(&rt.Domain, &rt.Path, &rt.Status, &rt.SSL, &rt.Service); err != nil {
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
	q := `SELECT COALESCE(c.display_name,''), COALESCE(u.email,''),
	             (SELECT COUNT(*) FROM services s WHERE s.client_id = c.id) AS service_count
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
			"window_hours": hours, "requests": 0, "errors_4xx": 0, "errors_5xx": 0,
			"top_hosts": []any{}, "top_countries": []any{}, "top_client_ips": []any{},
		})
	}
	// route_id IN (routes owned by the caller's clients) is the tenant boundary.
	routeFilter := `route_id IN (SELECT r.id FROM routes r JOIN services s ON s.id = r.service_id WHERE s.client_id IN ` + in + `)`

	var total int64
	var errors4xx, errors5xx sql.NullInt64
	totArgs := append([]any{since}, idArgs...)
	row := r.db.QueryRowContext(ctx,
		`SELECT COUNT(*),
		        SUM(CASE WHEN status BETWEEN 400 AND 499 THEN 1 ELSE 0 END),
		        SUM(CASE WHEN status BETWEEN 500 AND 599 THEN 1 ELSE 0 END)
		 FROM host_access_log WHERE ts >= ? AND `+routeFilter, totArgs...)
	if err := row.Scan(&total, &errors4xx, &errors5xx); err != nil {
		return "", err
	}

	topHosts, err := r.scopedTopHosts(ctx, since, top, in, idArgs)
	if err != nil {
		return "", err
	}
	topIPs, err := r.scopedTopIPs(ctx, since, top, routeFilter, idArgs)
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

func (r *Registry) scopedTopHosts(ctx context.Context, since time.Time, limit int, in string, idArgs []any) ([]countHit, error) {
	q := `SELECT rt.domain, COUNT(*) c
	      FROM host_access_log hal
	      JOIN routes rt ON rt.id = hal.route_id
	      JOIN services s ON s.id = rt.service_id
	      WHERE hal.ts >= ? AND s.client_id IN ` + in + `
	      GROUP BY rt.domain ORDER BY c DESC, rt.domain ASC LIMIT ?`
	args := append(append([]any{since}, idArgs...), limit)
	return scanCountHitsArgs(ctx, r.db, q, args)
}

func (r *Registry) scopedTopIPs(ctx context.Context, since time.Time, limit int, routeFilter string, idArgs []any) ([]countHit, error) {
	q := `SELECT remote_ip, COUNT(*) c
	      FROM host_access_log
	      WHERE ts >= ? AND remote_ip <> '' AND ` + routeFilter + `
	      GROUP BY remote_ip ORDER BY c DESC, remote_ip ASC LIMIT ?`
	args := append(append([]any{since}, idArgs...), limit)
	return scanCountHitsArgs(ctx, r.db, q, args)
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
