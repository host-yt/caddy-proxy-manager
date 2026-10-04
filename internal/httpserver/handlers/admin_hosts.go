package handlers

import (
	"context"
	"database/sql"
	"encoding/csv"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/host-yt/caddy-proxy-manager/internal/audit"
	"github.com/host-yt/caddy-proxy-manager/internal/domain/routes"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
	"github.com/host-yt/caddy-proxy-manager/internal/store"
)

// admin_hosts.go implements the NPM-style flat "Hosts" view: every route
// in the system (across every client) joined with its service, owning
// user, plan, and assigned Caddy node. The dedicated screens that group
// by client/service still exist; this is the operator's quick-glance
// surface for daily work (find a domain, see who owns it, who's serving
// it, what state it's in).

type hostGroupOption struct {
	ID    int64
	Name  string
	Color string
}

type hostRow struct {
	RouteID      int64
	Domain       string
	PathPrefix   string
	UpstreamPort int
	BackendIP    string
	Status       string // pending_dns / dns_ok / pending_ssl / active / failed / disabled
	LastError    string
	SSL          bool
	WebSocket    bool
	ForceHTTPS   bool
	Kind         string // 'proxy' | 'redirect'
	Tag          string
	ServiceID    int64
	ServiceName  string
	ClientID     int64
	ClientEmail  string
	PlanName     string
	PlanKind     string
	NodeID       int64
	NodeName     string
	NodeHostname string
	UpdatedAt    time.Time

	// External upstream: when set, BackendDisplay shows this FQDN instead
	// of the internal backend IP.
	External     bool
	ExternalHost string
	IssuedAt     string // ssl_issued_at hint (issued, NOT expiry); empty if unset

	// SSOProviderURL non-empty = SSO gate active; drives the badge in the table.
	SSOProviderURL string
	SSOStrictMode  bool

	// MaintenanceMode shows the wrench badge in the list and drives the quick toggle.
	MaintenanceMode bool

	// mTLS fields for the list badge: cert enforcement + CA health.
	RequireClientCert bool
	MTLSCAActive      bool   // true only when CA status='active'
	MTLSCAName        string // CA display name for tooltip

	// GeoMode is the per-route geo filter setting (off/allow/deny).
	GeoMode string

	GroupID    sql.NullInt64
	GroupName  string
	GroupColor string

	// Req24h is total requests from log_rollups in the last 24 hours.
	Req24h int64
	// Err24h is total 4xx+5xx errors from log_rollups in the last 24 hours.
	Err24h int64

	// Derived view-model fields for the at-a-glance table (filled below).
	BackendDisplay string
	CertStatus     string // "active" | "pending" | "off"
	Health         string // route-status-derived health hint
	// CertDaysLeft is days until manual cert expiry; -1 = no manual cert.
	CertDaysLeft int

	// Compile-state badge: "" means never compiled since upgrade (unknown), NEVER defaults to "ok".
	CompileStatus string // "" | "ok" | "quarantined" | "denied" | "target_rejected" | "not_emitted"
	CompileReason string
	CompileAt     time.Time

	// Per-node apply state: what the serving nodes actually loaded, worst first.
	ApplyState   string // "" (no enabled node) | "applied" | "unknown" | "pending" | "failed"
	ApplyOK      int    // nodes whose last /load holds the current config
	ApplyTotal   int
	ApplyDetails string // per-node tooltip
}

type hostsData struct {
	baseAdminData
	Hosts           []hostRow
	Total           int // total rows matching filters, across all pages
	Q               string
	Status          string
	NodeIDFilter    int64
	TagFilter       string
	BackendIPFilter string
	Groups          []hostGroupOption
	GroupFilter     int64
	NodeOptions     []hostsNewNode
	StatusCounts    map[string]int // per-status route counts (excludes deleted)

	// Pagination. Page links must preserve active filters via FilterQS.
	Page       int
	PageSize   int
	TotalPages int
	HasPrev    bool
	HasNext    bool
	PrevPage   int
	NextPage   int
	FilterQS   string // pre-built "&q=...&status=..." suffix for page links
}

// hostsPageSize is the fixed rows-per-page for the flat Hosts list.
const hostsPageSize = 50

// HostsList, HostsNew, HostsCreate together replace the multi-step
// client→service→route flow for the operator's own use: type one form,
// get one row in /admin/hosts.

// internalAdminPlanName is the plan auto-provisioned for routes the
// super-admin adds directly (i.e. they have no logical "customer" yet).
// kind='npm', uncapped, lives in the default node group.
const internalAdminPlanName = "_admin-self"

// b2i maps a bool to MySQL TINYINT (1/0) for use as a bound query parameter.
func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// HostsList renders /admin/hosts: every route in the DB, NPM-style flat list.
// Optional query params: q (domain or client email substring),
// status (route status enum), node_id (assigned node).
func (h *AdminHandlers) HostsList(w http.ResponseWriter, r *http.Request) {
	d := hostsData{baseAdminData: h.base(r, "Hosts")}
	db := h.DB()
	if db == nil {
		h.render(w, "hosts", d)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	d.NodeOptions = h.loadNodeOptions(ctx)

	d.Q = strings.TrimSpace(r.URL.Query().Get("q"))
	d.Status = strings.TrimSpace(r.URL.Query().Get("status"))
	d.NodeIDFilter, _ = strconv.ParseInt(r.URL.Query().Get("node_id"), 10, 64)
	d.TagFilter = strings.TrimSpace(r.URL.Query().Get("tag"))
	d.BackendIPFilter = strings.TrimSpace(r.URL.Query().Get("backend_ip"))
	d.GroupFilter, _ = strconv.ParseInt(r.URL.Query().Get("group_id"), 10, 64)
	d.Groups = loadHostGroups(ctx, db)

	where := []string{"1=1"}
	args := []any{}
	if d.Q != "" {
		where = append(where, "(r.domain LIKE ? OR u.email LIKE ?)")
		args = append(args, "%"+d.Q+"%", "%"+d.Q+"%")
	}
	switch d.Status {
	case "active", "pending_dns", "dns_ok", "pending_ssl", "failed", "disabled":
		where = append(where, "r.status = ?")
		args = append(args, d.Status)
	}
	if d.NodeIDFilter > 0 {
		where = append(where, "r.caddy_node_id = ?")
		args = append(args, d.NodeIDFilter)
	}
	if d.TagFilter != "" {
		where = append(where, "r.tag = ?")
		args = append(args, d.TagFilter)
	}
	if d.BackendIPFilter != "" {
		// filter on effective backend: override or service IP
		where = append(where, "COALESCE(NULLIF(r.backend_ip_override,''), s.backend_ip) LIKE ?")
		args = append(args, "%"+d.BackendIPFilter+"%")
	}
	if d.GroupFilter > 0 {
		where = append(where, "r.group_id = ?")
		args = append(args, d.GroupFilter)
	}
	// Scope: non-super_admins see only routes owned by their assigned clients.
	if allowed, all, ok := h.adminClientScope(ctx, middleware.SessionFromContext(r.Context())); ok && !all {
		if len(allowed) == 0 {
			where = append(where, "1=0")
		} else {
			ids := make([]int64, 0, len(allowed))
			for id := range allowed {
				ids = append(ids, id)
			}
			where = append(where, "c.id IN ("+placeholders(len(ids))+")")
			for _, id := range ids {
				args = append(args, id)
			}
		}
	}
	whereSQL := strings.Join(where, " AND ")

	// Aggregate counts per status across ALL non-deleted routes (no filter).
	d.StatusCounts = make(map[string]int)
	scRows, err := db.QueryContext(ctx,
		`SELECT status, COUNT(*) FROM routes WHERE status NOT IN ('deleted') GROUP BY status`)
	if err == nil {
		for scRows.Next() {
			var st string
			var cnt int
			if scRows.Scan(&st, &cnt) == nil {
				d.StatusCounts[st] = cnt
			}
		}
		scRows.Close()
	}

	// Total row count under the SAME filters (drives pagination). Args are
	// reused below for the page query (LIMIT/OFFSET are appended separately).
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*)
		   FROM routes r
		   JOIN services s    ON s.id = r.service_id
		   JOIN clients c     ON c.id = s.client_id
		   JOIN users u       ON u.id = c.user_id
		   JOIN plans p       ON p.id = s.plan_id
		   JOIN caddy_nodes n ON n.id = r.caddy_node_id
		   WHERE `+whereSQL, args...).Scan(&d.Total); err != nil {
		h.Logger.Error("hosts list count", "err", err)
		d.Error = "Could not load the hosts list. Refresh to retry; if it persists, check the panel logs for 'hosts list count'."
		h.render(w, "hosts", d)
		return
	}

	d.PageSize = hostsPageSize
	d.Page, _ = strconv.Atoi(r.URL.Query().Get("page"))
	if d.Page < 1 {
		d.Page = 1
	}
	d.TotalPages = (d.Total + d.PageSize - 1) / d.PageSize
	if d.TotalPages < 1 {
		d.TotalPages = 1
	}
	if d.Page > d.TotalPages {
		d.Page = d.TotalPages
	}
	d.HasPrev = d.Page > 1
	d.HasNext = d.Page < d.TotalPages
	d.PrevPage = d.Page - 1
	if d.PrevPage < 1 {
		d.PrevPage = 1
	}
	d.NextPage = d.Page + 1
	if d.NextPage > d.TotalPages {
		d.NextPage = d.TotalPages
	}
	d.FilterQS = hostsFilterQuery(d.Q, d.Status, d.NodeIDFilter, d.TagFilter, d.BackendIPFilter, d.GroupFilter)

	q := `SELECT r.id, r.domain, r.path_prefix, r.upstream_port,
	             r.status, COALESCE(r.last_error,''),
	             r.ssl_enabled, r.websocket, r.force_https,
	             r.kind, COALESCE(r.tag,''), r.updated_at,
	             s.id, s.name, COALESCE(NULLIF(r.backend_ip_override,''), s.backend_ip),
	             c.id, u.email,
	             p.name, p.kind,
	             n.id, n.name, n.public_hostname,
	             COALESCE(r.upstream_external,0), COALESCE(r.upstream_host_header,''),
	             COALESCE(DATE_FORMAT(r.ssl_issued_at,'%Y-%m-%d %H:%i'),''),
	             COALESCE(r.sso_provider_url,''), COALESCE(r.sso_strict_mode,0),
	             COALESCE(DATEDIFF(mc.not_after, NOW()), -1),
	             COALESCE(r.maintenance_mode,0),
	             COALESCE(r.require_client_cert,0),
	             CASE WHEN r.mtls_ca_id IS NOT NULL AND mca.status='active' THEN 1 ELSE 0 END,
	             COALESCE(NULLIF(mca.name,''), mca.common_name, ''),
	             COALESCE(r.geo_mode,'off'),
	             COALESCE(lr.req24h, 0), COALESCE(lr.err24h, 0),
	             COALESCE(hg.id,0), COALESCE(hg.name,''), COALESCE(hg.color,'')
	      FROM routes r
	      JOIN services s    ON s.id = r.service_id
	      JOIN clients c     ON c.id = s.client_id
	      JOIN users u       ON u.id = c.user_id
	      JOIN plans p       ON p.id = s.plan_id
	      JOIN caddy_nodes n ON n.id = r.caddy_node_id
	      LEFT JOIN manual_certs mc ON mc.route_id = r.id
	      LEFT JOIN mtls_cas mca ON mca.id = r.mtls_ca_id
	      LEFT JOIN (
	        SELECT route_id, SUM(requests) AS req24h,
	               SUM(errors_4xx+errors_5xx) AS err24h
	        FROM log_rollups
	        WHERE bucket_start >= ` + store.DateSub(1, "DAY") + `
	        GROUP BY route_id
	      ) lr ON lr.route_id = r.id
	      LEFT JOIN host_groups hg ON hg.id = r.group_id
	      WHERE ` + whereSQL + `
	      ORDER BY r.updated_at DESC
	      LIMIT ? OFFSET ?`
	pageArgs := append(append([]any{}, args...), d.PageSize, (d.Page-1)*d.PageSize)
	rows, err := db.QueryContext(ctx, q, pageArgs...)
	if err != nil {
		h.Logger.Error("hosts list query", "err", err)
		d.Error = "Could not load the hosts list. Refresh to retry; if it persists, check the panel logs for 'hosts list query'."
		h.render(w, "hosts", d)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var hr hostRow
		// upstream_host_header reused as the external FQDN source; the FQDN
		// itself lives in backend_ip_override (already in BackendIP).
		var extHostHeader string
		var groupIDRaw int64
		if err := rows.Scan(
			&hr.RouteID, &hr.Domain, &hr.PathPrefix, &hr.UpstreamPort,
			&hr.Status, &hr.LastError,
			&hr.SSL, &hr.WebSocket, &hr.ForceHTTPS,
			&hr.Kind, &hr.Tag, &hr.UpdatedAt,
			&hr.ServiceID, &hr.ServiceName, &hr.BackendIP,
			&hr.ClientID, &hr.ClientEmail,
			&hr.PlanName, &hr.PlanKind,
			&hr.NodeID, &hr.NodeName, &hr.NodeHostname,
			&hr.External, &extHostHeader, &hr.IssuedAt,
			&hr.SSOProviderURL, &hr.SSOStrictMode,
			&hr.CertDaysLeft, &hr.MaintenanceMode,
			&hr.RequireClientCert, &hr.MTLSCAActive, &hr.MTLSCAName, &hr.GeoMode,
			&hr.Req24h, &hr.Err24h,
			&groupIDRaw, &hr.GroupName, &hr.GroupColor,
		); err == nil {
			if groupIDRaw > 0 {
				hr.GroupID = sql.NullInt64{Int64: groupIDRaw, Valid: true}
			}
			hr.ExternalHost = extHostHeader
			hr.BackendDisplay = hostBackendDisplay(hr)
			hr.CertStatus = hostCertStatus(hr.SSL, hr.Status)
			hr.Health = hr.Status // cheap per-row hint; no extra probes
			d.Hosts = append(d.Hosts, hr)
		}
	}

	// CompileStatus stays "" (unknown) for any route absent from the map or on error - never defaults to "ok".
	if h.Routes != nil && len(d.Hosts) > 0 {
		ids := make([]int64, len(d.Hosts))
		for i, hr := range d.Hosts {
			ids[i] = hr.RouteID
		}
		results, err := h.Routes.CompileResults(ctx, ids)
		if err != nil {
			h.Logger.Error("hosts list compile results", "err", err)
		} else {
			for i := range d.Hosts {
				if cr, ok := results[d.Hosts[i].RouteID]; ok {
					d.Hosts[i].CompileStatus = cr.Status
					d.Hosts[i].CompileReason = cr.Reason
					d.Hosts[i].CompileAt = cr.At
				}
			}
		}
	}

	if h.Routes != nil && len(d.Hosts) > 0 {
		ids := make([]int64, len(d.Hosts))
		for i, hr := range d.Hosts {
			ids[i] = hr.RouteID
		}
		states, err := h.Routes.NodeApplyStates(ctx, ids)
		if err != nil {
			h.Logger.Error("hosts list node apply states", "err", err)
		}
		for i := range d.Hosts {
			fillApplyState(&d.Hosts[i], states[d.Hosts[i].RouteID])
		}
	}

	h.render(w, "hosts", d)
}

// applyRank orders per-node states so the row shows the worst one.
var applyRank = map[string]int{routes.ApplyApplied: 1, routes.ApplyUnknown: 2, routes.ApplyPending: 3, routes.ApplyFailed: 4}

// fillApplyState folds per-node apply states into the row's badge fields.
func fillApplyState(hr *hostRow, nodes []routes.NodeApply) {
	parts := make([]string, 0, len(nodes))
	for _, n := range nodes {
		hr.ApplyTotal++
		if n.State == routes.ApplyApplied {
			hr.ApplyOK++
		}
		if applyRank[n.State] > applyRank[hr.ApplyState] {
			hr.ApplyState = n.State
		}
		p := n.NodeName + ": " + n.State
		if n.Error != "" {
			p += " (" + n.Error + ")"
		}
		if n.Attempts > 0 {
			p += fmt.Sprintf(" [retry %d]", n.Attempts)
		}
		parts = append(parts, p)
	}
	hr.ApplyDetails = strings.Join(parts, "; ")
}

// HostsExport streams GET /admin/hosts/export.csv: all routes matching filters as CSV.
func (h *AdminHandlers) HostsExport(w http.ResponseWriter, r *http.Request) {
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	ctx := r.Context()
	sess := middleware.SessionFromContext(ctx)

	if !checkLogsExportRateLimit(logsExportLimiterKey(r, sess), time.Now()) {
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	q := strings.TrimSpace(r.URL.Query().Get("q"))
	status := strings.TrimSpace(r.URL.Query().Get("status"))
	nodeID, _ := strconv.ParseInt(r.URL.Query().Get("node_id"), 10, 64)
	tag := strings.TrimSpace(r.URL.Query().Get("tag"))
	backendIP := strings.TrimSpace(r.URL.Query().Get("backend_ip"))

	where := []string{"1=1"}
	args := []any{}
	if q != "" {
		where = append(where, "(r.domain LIKE ? OR u.email LIKE ?)")
		args = append(args, "%"+q+"%", "%"+q+"%")
	}
	switch status {
	case "active", "pending_dns", "dns_ok", "pending_ssl", "failed", "disabled":
		where = append(where, "r.status = ?")
		args = append(args, status)
	}
	if nodeID > 0 {
		where = append(where, "r.caddy_node_id = ?")
		args = append(args, nodeID)
	}
	if tag != "" {
		where = append(where, "r.tag = ?")
		args = append(args, tag)
	}
	if backendIP != "" {
		// filter on effective backend: override or service IP
		where = append(where, "COALESCE(NULLIF(r.backend_ip_override,''), s.backend_ip) LIKE ?")
		args = append(args, "%"+backendIP+"%")
	}
	// Scope: a non-super_admin exports only routes of its assigned clients (twin
	// of the HostsList filter). Without this a scoped admin could CSV-dump every
	// tenant's routes.
	if allowed, all, ok := h.adminClientScope(ctx, sess); ok && !all {
		if len(allowed) == 0 {
			where = append(where, "1=0")
		} else {
			ids := make([]int64, 0, len(allowed))
			for id := range allowed {
				ids = append(ids, id)
			}
			where = append(where, "c.id IN ("+placeholders(len(ids))+")")
			for _, id := range ids {
				args = append(args, id)
			}
		}
	}
	whereSQL := strings.Join(where, " AND ")

	rows, err := db.QueryContext(ctx,
		`SELECT r.id, r.domain, COALESCE(r.path_prefix,''), r.upstream_port,
		        r.status, r.ssl_enabled, r.kind,
		        s.name, COALESCE(NULLIF(c.display_name,''), u.email),
		        n.name, COALESCE(r.tag,''),
		        DATE_FORMAT(r.updated_at,'%Y-%m-%d %H:%i')
		 FROM routes r
		 JOIN services s    ON s.id = r.service_id
		 JOIN clients c     ON c.id = s.client_id
		 JOIN users u       ON u.id = c.user_id
		 JOIN caddy_nodes n ON n.id = r.caddy_node_id
		 WHERE `+whereSQL+`
		 ORDER BY r.id DESC LIMIT 10000`, args...)
	if err != nil {
		h.Logger.Error("hosts export query", "err", err)
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="hpg-routes.csv"`)
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"id", "domain", "path_prefix", "upstream_port", "status", "ssl", "kind", "service", "client", "node", "tag", "updated_at"})

	count := 0
	for rows.Next() {
		var (
			id, port       int64
			domain, prefix string
			st, svc        string
			ssl            bool
			kind, client   string
			node, rtag, ts string
		)
		if err := rows.Scan(&id, &domain, &prefix, &port, &st, &ssl, &kind, &svc, &client, &node, &rtag, &ts); err != nil {
			continue
		}
		sslStr := "0"
		if ssl {
			sslStr = "1"
		}
		_ = cw.Write(csvSafeRow([]string{
			strconv.FormatInt(id, 10),
			domain,
			prefix,
			strconv.FormatInt(port, 10),
			st,
			sslStr,
			kind,
			svc,
			client,
			node,
			rtag,
			ts,
		}))
		count++
		if count%100 == 0 {
			cw.Flush()
		}
	}
	cw.Flush()

	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "admin.hosts.export", Entity: "route",
		Meta: map[string]any{"count": count, "q": q, "status": status, "tag": tag},
	})
}

// hostsFilterQuery builds the "&key=val" suffix appended to page links so
// the active filters survive pagination. The leading "page=" is added by
// the template; everything here is already URL-escaped.
func hostsFilterQuery(q, status string, nodeID int64, tag, backendIP string, groupID int64) string {
	v := url.Values{}
	if q != "" {
		v.Set("q", q)
	}
	if status != "" {
		v.Set("status", status)
	}
	if nodeID > 0 {
		v.Set("node_id", strconv.FormatInt(nodeID, 10))
	}
	if tag != "" {
		v.Set("tag", tag)
	}
	if backendIP != "" {
		v.Set("backend_ip", backendIP)
	}
	if groupID > 0 {
		v.Set("group_id", strconv.FormatInt(groupID, 10))
	}
	if len(v) == 0 {
		return ""
	}
	return "&" + v.Encode()
}

// loadHostGroups returns all host groups ordered by name.
func loadHostGroups(ctx context.Context, db *sql.DB) []hostGroupOption {
	rows, err := db.QueryContext(ctx, "SELECT id, name, color FROM host_groups ORDER BY name")
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []hostGroupOption
	for rows.Next() {
		var g hostGroupOption
		if rows.Scan(&g.ID, &g.Name, &g.Color) == nil {
			out = append(out, g)
		}
	}
	return out
}

// hostBackendDisplay returns the effective upstream as "host:port". External
// routes show their public FQDN; everything else reuses the resolved backend
// (COALESCE override/service IP). Redirects have no backend.
func hostBackendDisplay(hr hostRow) string {
	if hr.Kind == "redirect" {
		return "-"
	}
	host := hr.BackendIP
	if hr.External && hr.ExternalHost != "" {
		host = hr.ExternalHost
	}
	if hr.UpstreamPort > 0 {
		return host + ":" + strconv.Itoa(hr.UpstreamPort)
	}
	return host
}

// hostCertStatus maps ssl_enabled + route status into a compact label. No
// expiry is stored, so we never fabricate one (issued hint lives separately).
func hostCertStatus(ssl bool, status string) string {
	if !ssl {
		return "off"
	}
	if status == "active" {
		return "active"
	}
	return "pending"
}
