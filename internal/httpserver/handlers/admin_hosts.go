package handlers

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"golang.org/x/crypto/bcrypt"

	"github.com/host-yt/caddy-proxy-manager/internal/audit"
	"github.com/host-yt/caddy-proxy-manager/internal/caddyapi"
	"github.com/host-yt/caddy-proxy-manager/internal/customfields"
	"github.com/host-yt/caddy-proxy-manager/internal/domain/routes"
	"github.com/host-yt/caddy-proxy-manager/internal/geoip"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
	"github.com/host-yt/caddy-proxy-manager/internal/security"
	"github.com/host-yt/caddy-proxy-manager/internal/store"
)

// bcryptHash returns a bcrypt hash of pw with the default cost (Caddy's
// http_basic provider accepts bcrypt natively; cost 10 is standard).
func bcryptHash(pw []byte) ([]byte, error) {
	return bcrypt.GenerateFromPassword(pw, bcrypt.DefaultCost)
}

// genProxySecret returns a random URL-safe inbound bearer for an external
// upstream route. Shown to the operator once; stored encrypted at rest.
func genProxySecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "hpgx_" + base64.RawURLEncoding.EncodeToString(b), nil
}

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
		d.Error = "query failed"
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
	        WHERE bucket_start >= DATE_SUB(NOW(), INTERVAL 1 DAY)
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
		d.Error = "query failed"
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
	h.render(w, "hosts", d)
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

type hostsNewData struct {
	baseAdminData
	Nodes   []hostsNewNode
	Groups  []hostGroupOption
	Form    hostsNewForm
	CFViews []customfields.View
}

type hostsNewNode struct {
	ID       int64
	Name     string
	Hostname string
	Group    string
}

type hostsNewForm struct {
	Domain         string
	BackendIP      string
	Port           string
	UpstreamScheme string
	NodeID         string
	SSL            bool
	WebSocket      bool
	Kind           string
	RedirectURL    string
	RedirectCode   string
	Tag            string
	// External-HTTPS-upstream route: proxy to an allowlisted public FQDN.
	External           bool
	ExternalHost       string
	UpstreamHostHeader string
	// Wildcard DNS-01: domain served by a *.zone cert (gated by DNS01_AVAILABLE).
	WildcardEnabled bool
	WildcardZone    string
	GroupID         int64
}

// HostsNew renders /admin/hosts/new (GET).
func (h *AdminHandlers) HostsNew(w http.ResponseWriter, r *http.Request) {
	d := hostsNewData{
		baseAdminData: h.base(r, "Add host"),
		Form:          hostsNewForm{SSL: true, WebSocket: true, Kind: "proxy", RedirectCode: "308", UpstreamScheme: "http"},
	}
	d.Nodes = h.loadNodeOptions(r.Context())
	db := h.DB()
	if db != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		d.Groups = loadHostGroups(ctx, db)
		if defs, err := customfields.LoadDefs(ctx, db, "host"); err == nil {
			d.CFViews = customfields.Merge(defs, nil)
		}
	}
	h.render(w, "hosts_new", d)
}

// HostsCreate handles /admin/hosts/new (POST). It atomically:
//  1. Ensures the super-admin has a clients row (1:1 with their user).
//  2. Ensures the "_admin-self" plan exists (kind=npm, uncapped).
//  3. Finds or creates a services row for (admin client, backend_ip).
//     Range is 1-65535 so the admin can map any port without re-editing
//     the service.
//  4. Calls Routes.Create which performs the placement, INSERT, and
//     Caddy push in one transaction.
func (h *AdminHandlers) HostsCreate(w http.ResponseWriter, r *http.Request) {
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	if h.Routes == nil {
		http.Error(w, "routes service not wired", http.StatusInternalServerError)
		return
	}
	sess := middleware.SessionFromContext(r.Context())
	if sess == nil {
		http.Error(w, "no session", http.StatusUnauthorized)
		return
	}
	_ = r.ParseForm()
	form := hostsNewForm{
		Domain:         strings.TrimSpace(strings.ToLower(r.FormValue("domain"))),
		BackendIP:      strings.TrimSpace(r.FormValue("backend_ip")),
		Port:           strings.TrimSpace(r.FormValue("port")),
		UpstreamScheme: strings.TrimSpace(r.FormValue("upstream_scheme")),
		NodeID:         strings.TrimSpace(r.FormValue("node_id")),
		SSL:            r.FormValue("ssl") == "1",
		WebSocket:      r.FormValue("websocket") == "1",
		Kind:           strings.TrimSpace(r.FormValue("kind")),
		RedirectURL:    strings.TrimSpace(r.FormValue("redirect_url")),
		RedirectCode:   strings.TrimSpace(r.FormValue("redirect_code")),
		Tag:            strings.TrimSpace(r.FormValue("tag")),

		External:           r.FormValue("upstream_external") == "1",
		ExternalHost:       strings.ToLower(strings.TrimSpace(r.FormValue("external_host"))),
		UpstreamHostHeader: strings.TrimSpace(r.FormValue("upstream_host_header")),
		WildcardEnabled:    r.FormValue("wildcard_enabled") == "1",
		WildcardZone:       strings.ToLower(strings.TrimSpace(r.FormValue("wildcard_zone"))),
	}
	if form.UpstreamScheme != "https" {
		form.UpstreamScheme = "http"
	}
	if form.Kind != "redirect" {
		form.Kind = "proxy"
	}
	if form.External {
		// External routes are always an https proxy; the customer port range
		// and backend-IP field do not apply.
		form.Kind = "proxy"
		form.UpstreamScheme = "https"
	}
	port, _ := strconv.Atoi(form.Port)
	redirectCode, _ := strconv.Atoi(form.RedirectCode)
	nodeID, _ := strconv.ParseInt(form.NodeID, 10, 64)
	groupID, _ := strconv.ParseInt(r.FormValue("group_id"), 10, 64)

	if form.Domain == "" || nodeID == 0 {
		h.renderHostsNewErr(w, r, form, "domain and node are required")
		return
	}
	if form.External {
		// External upstream: validate the FQDN (allowlist is enforced in
		// Create). Default the port to 443. Service bookkeeping is keyed on
		// backend_ip, so reuse the external host there.
		if form.ExternalHost == "" || !isValidUpstreamHost(form.ExternalHost) {
			h.renderHostsNewErr(w, r, form, "external host must be a valid FQDN")
			return
		}
		if port == 0 {
			port = 443
		}
		form.BackendIP = form.ExternalHost
	} else if form.Kind == "proxy" {
		if form.BackendIP == "" || port <= 0 || port > 65535 {
			h.renderHostsNewErr(w, r, form, "backend IP and port are required for proxy routes")
			return
		}
		if !isValidUpstreamHost(form.BackendIP) {
			h.renderHostsNewErr(w, r, form, "backend must be a valid IP or hostname")
			return
		}
	} else {
		// Redirect: backend isn't called, but admin service is keyed on
		// (client, backend_ip). Use a stable sentinel so all redirect
		// routes share one bookkeeping service per admin.
		form.BackendIP = "0.0.0.0"
		port = 0
		if form.RedirectURL == "" {
			h.renderHostsNewErr(w, r, form, "redirect URL is required for redirect routes")
			return
		}
		switch redirectCode {
		case 0:
			redirectCode = 308
		case 301, 302, 307, 308:
		default:
			h.renderHostsNewErr(w, r, form, "redirect code must be 301/302/307/308")
			return
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Resolve node's group so the plan + service line up.
	var nodeGroupID int64
	if err := db.QueryRowContext(ctx,
		"SELECT node_group_id FROM caddy_nodes WHERE id = ? AND approved_at IS NOT NULL AND is_enabled = 1",
		nodeID).Scan(&nodeGroupID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			h.renderHostsNewErr(w, r, form, "node not found or not approved")
			return
		}
		h.Logger.Error("admin hosts: node lookup", "err", err)
		h.renderHostsNewErr(w, r, form, "node lookup failed")
		return
	}

	clientID, err := ensureAdminClient(ctx, db, sess.UserID)
	if err != nil {
		h.Logger.Error("admin hosts: ensure client", "err", err)
		h.renderHostsNewErr(w, r, form, "could not provision admin client")
		return
	}
	planID, err := ensureAdminPlan(ctx, db, nodeGroupID)
	if err != nil {
		h.Logger.Error("admin hosts: ensure plan", "err", err)
		h.renderHostsNewErr(w, r, form, "could not provision admin plan")
		return
	}
	serviceID, err := ensureAdminService(ctx, db, clientID, form.BackendIP, planID, nodeGroupID)
	if err != nil {
		h.Logger.Error("admin hosts: ensure service", "err", err)
		h.renderHostsNewErr(w, r, form, "could not provision admin service")
		return
	}

	// Validate mTLS CA when client-cert enforcement is requested.
	requireClientCert := r.FormValue("require_client_cert") == "1"
	mtlsCAID, _ := strconv.ParseInt(r.FormValue("mtls_ca_id"), 10, 64)
	if requireClientCert && mtlsCAID <= 0 {
		h.renderHostsNewErr(w, r, form, "require_client_cert needs an mTLS CA assigned")
		return
	}
	if requireClientCert && mtlsCAID > 0 {
		// Reject if CA has no uploaded certificate or is not active.
		var caCount int
		_ = db.QueryRowContext(ctx,
			"SELECT COUNT(*) FROM mtls_cas WHERE id=? AND status='active' AND cert_pem IS NOT NULL AND cert_pem != ''",
			mtlsCAID).Scan(&caCount)
		if caCount == 0 {
			h.renderHostsNewErr(w, r, form, "selected mTLS CA is not active - upload a certificate first")
			return
		}
	}

	// Generate the one-time inbound bearer for external routes (Create
	// encrypts it at rest; we show the plaintext once below).
	var proxySecret string
	if form.External {
		s, gerr := genProxySecret()
		if gerr != nil {
			h.renderHostsNewErr(w, r, form, "could not generate proxy secret")
			return
		}
		proxySecret = s
	}

	// Load host custom field defs and encode submitted values before create.
	cfDefs, cfDefsErr := customfields.LoadDefs(ctx, db, "host")
	if cfDefsErr != nil {
		h.Logger.Warn("admin hosts: load cf defs", "err", cfDefsErr)
	}
	cfJSON, cfErr := customfields.EncodeFromForm(cfDefs, r.Form)
	if cfErr != nil {
		h.renderHostsNewErr(w, r, form, cfErr.Error())
		return
	}

	routeID, err := h.Routes.Create(ctx, 0, routes.CreateInput{
		ServiceID:      serviceID,
		UpstreamPort:   port,
		UpstreamScheme: form.UpstreamScheme,
		Domain:         form.Domain,
		SSL:            form.SSL,
		WebSocket:      form.WebSocket,
		ForceHTTPS:     form.SSL,
		Kind:           form.Kind,
		RedirectURL:    form.RedirectURL,
		RedirectCode:   redirectCode,
		Tag:            form.Tag,

		External:           form.External,
		ExternalHost:       form.ExternalHost,
		UpstreamHostHeader: form.UpstreamHostHeader,
		ProxySecretPlain:   proxySecret,
		WildcardEnabled:    form.WildcardEnabled,
		WildcardZone:       form.WildcardZone,
		// Persisted in the same INSERT so host metadata is atomic with the route.
		GroupID:      groupID,
		CustomFields: cfJSON,
	})
	if err != nil {
		h.Logger.Warn("admin hosts: route create", "err", err)
		h.renderHostsNewErr(w, r, form, "create failed: "+sanitizeErr(err))
		return
	}

	// Never log the secret in the audit meta.
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "admin.host.create", Entity: "route",
		EntityID: itoa64(routeID),
		Meta: map[string]any{
			"domain": form.Domain, "backend_ip": form.BackendIP, "port": port,
			"node_id": nodeID, "kind": form.Kind, "redirect_url": form.RedirectURL,
			"external": form.External, "external_host": form.ExternalHost,
		},
	})
	if form.External && proxySecret != "" {
		// Never splice the plaintext bearer into the redirect URL - it would
		// land in browser history / Referer / front-proxy logs. It's
		// recoverable on demand via the edit page's audited Reveal button.
		edit := "/admin/hosts/" + itoa64(routeID) + "/edit"
		redirectWithFlash(w, r, edit,
			"External host added: "+form.Domain+". Click Reveal to copy the inbound bearer.", "")
		return
	}
	redirectWithFlash(w, r, "/admin/hosts", "Host added: "+form.Domain, "")
}

func (h *AdminHandlers) renderHostsNewErr(w http.ResponseWriter, r *http.Request, form hostsNewForm, msg string) {
	d := hostsNewData{baseAdminData: h.base(r, "Add host"), Form: form}
	d.Error = msg
	d.Nodes = h.loadNodeOptions(r.Context())
	db := h.DB()
	if db != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		d.Groups = loadHostGroups(ctx, db)
		if defs, err := customfields.LoadDefs(ctx, db, "host"); err == nil {
			// Preserve submitted values on re-render after validation error.
			_ = r.ParseForm()
			vals, _ := customfields.EncodeFromForm(defs, r.Form)
			d.CFViews = customfields.Merge(defs, customfields.Decode(vals))
		}
	}
	h.render(w, "hosts_new", d)
}

func (h *AdminHandlers) loadNodeOptions(ctx context.Context) []hostsNewNode {
	db := h.DB()
	if db == nil {
		return nil
	}
	c, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	rows, err := db.QueryContext(c,
		`SELECT n.id, n.name, n.public_hostname, ng.name
		 FROM caddy_nodes n JOIN node_groups ng ON ng.id = n.node_group_id
		 WHERE n.approved_at IS NOT NULL AND n.is_enabled = 1
		 ORDER BY ng.name, n.name`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []hostsNewNode
	for rows.Next() {
		var n hostsNewNode
		if err := rows.Scan(&n.ID, &n.Name, &n.Hostname, &n.Group); err == nil {
			out = append(out, n)
		}
	}
	return out
}

// HostsDelete: POST /admin/hosts/{id}/delete. Removes the route + tells
// the assigned Caddy node to re-load its config (handled by Routes.Delete).
func (h *AdminHandlers) HostsDelete(w http.ResponseWriter, r *http.Request) {
	if h.Routes == nil || h.DB() == nil {
		http.Error(w, "not ready", http.StatusServiceUnavailable)
		return
	}
	sess := middleware.SessionFromContext(r.Context())
	id, _ := strconv.ParseInt(chiURLParamHosts(r, "id"), 10, 64)
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	var domain string
	_ = h.DB().QueryRowContext(ctx, "SELECT domain FROM routes WHERE id = ?", id).Scan(&domain)
	if err := h.Routes.Delete(ctx, 0, id); err != nil {
		h.Logger.Warn("admin hosts delete", "id", id, "err", err)
		redirectWithFlash(w, r, "/admin/hosts", "", "delete failed: "+sanitizeErr(err))
		return
	}
	audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "admin.host.delete", Entity: "route",
		EntityID: itoa64(id), Meta: map[string]any{"domain": domain},
	})
	// htmx: the row was hx-swap'd, so reply with an empty 200 (the target row
	// is replaced by nothing = removed). No-JS clients get the redirect.
	if isHTMXRequest(r) {
		w.WriteHeader(http.StatusOK)
		return
	}
	redirectWithFlash(w, r, "/admin/hosts", "Host removed", "")
}

// isHTMXRequest reports whether the request came from htmx (so the handler can
// return an HTML fragment / empty body instead of a full-page redirect).
func isHTMXRequest(r *http.Request) bool {
	return r.Header.Get("HX-Request") == "true"
}

// HostsToggle flips a route between active and disabled. Disabled
// routes are excluded from buildRoutesForNode, so the next push (kicked
// off here) removes them from Caddy without deleting the DB row.
func (h *AdminHandlers) HostsToggle(w http.ResponseWriter, r *http.Request) {
	if h.Routes == nil || h.DB() == nil {
		http.Error(w, "not ready", http.StatusServiceUnavailable)
		return
	}
	sess := middleware.SessionFromContext(r.Context())
	id, _ := strconv.ParseInt(chiURLParamHosts(r, "id"), 10, 64)
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	var (
		status string
		nodeID int64
	)
	if err := h.DB().QueryRowContext(ctx,
		"SELECT status, caddy_node_id FROM routes WHERE id = ?", id,
	).Scan(&status, &nodeID); err != nil {
		redirectWithFlash(w, r, "/admin/hosts", "", "route not found")
		return
	}
	next := "disabled"
	if status == "disabled" {
		// Re-enabling: reset to pending_dns so the reconciler verifies
		// DNS still resolves before pushing back to Caddy.
		next = "pending_dns"
	}
	if _, err := h.DB().ExecContext(ctx,
		"UPDATE routes SET status = ?, updated_at = NOW() WHERE id = ?", next, id); err != nil {
		redirectWithFlash(w, r, "/admin/hosts", "", "update failed")
		return
	}
	go func() {
		defer recoverBg(h.Logger, "resync")
		ctx, cancel := context.WithTimeout(h.Routes.BackgroundCtx(), 30*time.Second)
		defer cancel()
		_ = h.Routes.Resync(ctx, nodeID)
	}()
	audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "admin.host.toggle", Entity: "route",
		EntityID: itoa64(id), Meta: map[string]any{"from": status, "to": next},
	})
	redirectWithFlash(w, r, "/admin/hosts", "Host "+next, "")
}

func chiURLParamHosts(r *http.Request, key string) string { return chi.URLParam(r, key) }

// HostsClone copies an existing route row into a new inactive clone.
// Uses information_schema to build a dynamic INSERT so future column additions don't require handler changes.
func (h *AdminHandlers) HostsClone(w http.ResponseWriter, r *http.Request) {
	if h.DB() == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	sess := middleware.SessionFromContext(r.Context())
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	db := h.DB()
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Verify route exists and fetch its domain for the audit entry.
	var domain string
	if err := db.QueryRowContext(ctx, "SELECT domain FROM routes WHERE id=?", id).Scan(&domain); err != nil {
		http.NotFound(w, r)
		return
	}

	// Discover columns at runtime so the clone stays correct after migrations.
	colRows, err := db.QueryContext(ctx,
		`SELECT COLUMN_NAME FROM information_schema.COLUMNS
		 WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes'
		 ORDER BY ORDINAL_POSITION`)
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	defer colRows.Close()
	var allCols []string
	for colRows.Next() {
		var c string
		_ = colRows.Scan(&c)
		allCols = append(allCols, c)
	}

	// Columns excluded from the copy (auto-generated or intentionally reset).
	skip := map[string]bool{
		"id": true, "created_at": true, "updated_at": true,
		"last_error": true, "last_push_at": true, "proxy_secret_hash": true,
	}
	// Columns where the cloned value differs from the source.
	override := map[string]string{
		"domain":           `CONCAT('clone-of-', domain)`,
		"status":           `'inactive'`,
		"maintenance_mode": `0`,
	}
	var insertCols, selectExprs []string
	for _, c := range allCols {
		if skip[c] {
			continue
		}
		insertCols = append(insertCols, c)
		if expr, ok := override[c]; ok {
			selectExprs = append(selectExprs, expr)
		} else {
			selectExprs = append(selectExprs, c)
		}
	}
	cloneSQL := "INSERT INTO routes (" + strings.Join(insertCols, ",") + ") SELECT " +
		strings.Join(selectExprs, ",") + " FROM routes WHERE id=?"
	res, err := db.ExecContext(ctx, cloneSQL, id)
	if err != nil {
		redirectWithFlash(w, r, "/admin/hosts", "", "clone failed: "+sanitizeErr(err))
		return
	}
	newID, _ := res.LastInsertId()
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "admin.host.clone", Entity: "route",
		EntityID: itoa64(newID),
		Meta:     map[string]any{"source_id": id, "domain": "clone-of-" + domain},
	})
	redirectWithFlash(w, r, fmt.Sprintf("/admin/hosts/%d/edit", newID), "Route cloned - update domain + activate.", "")
}

// HostsToggleMaintenance flips maintenance_mode for a single route and resyncs Caddy.
func (h *AdminHandlers) HostsToggleMaintenance(w http.ResponseWriter, r *http.Request) {
	if h.Routes == nil || h.DB() == nil {
		http.Error(w, "not ready", http.StatusServiceUnavailable)
		return
	}
	sess := middleware.SessionFromContext(r.Context())
	id, _ := strconv.ParseInt(chiURLParamHosts(r, "id"), 10, 64)
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	var current int
	var nodeID int64
	if err := h.DB().QueryRowContext(ctx,
		"SELECT COALESCE(maintenance_mode,0), caddy_node_id FROM routes WHERE id = ?", id,
	).Scan(&current, &nodeID); err != nil {
		redirectWithFlash(w, r, "/admin/hosts", "", "route not found")
		return
	}
	newMode := 1 - current
	if _, err := h.DB().ExecContext(ctx,
		"UPDATE routes SET maintenance_mode = ?, updated_at = NOW() WHERE id = ?", newMode, id,
	); err != nil {
		redirectWithFlash(w, r, "/admin/hosts", "", "update failed")
		return
	}
	go func() {
		defer recoverBg(h.Logger, "maint-resync")
		h.Routes.SchedulePush(nodeID)
	}()
	onOff := "disabled"
	if newMode == 1 {
		onOff = "enabled"
	}
	audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "admin.host.maintenance.toggle", Entity: "route",
		EntityID: itoa64(id), Meta: map[string]any{"maintenance_mode": newMode},
	})
	redirectWithFlash(w, r, "/admin/hosts", "Maintenance mode "+onOff, "")
}

// HostsPurgeCache flushes the Souin origin cache on the node that
// serves this route. Useful after the operator points the route at a
// new backend or invalidates content out-of-band. POST only.
//
// Node-wide flush (not per-route) - Souin's per-key purge requires the
// exact internal cache key, which we don't track in the panel. The
// extra blast radius is acceptable: the cache rebuilds on the next
// request and TTLs are short by default.
func (h *AdminHandlers) HostsPurgeCache(w http.ResponseWriter, r *http.Request) {
	if h.DB() == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	id, _ := strconv.ParseInt(chiURLParamHosts(r, "id"), 10, 64)
	if id == 0 {
		http.Redirect(w, r, "/admin/hosts", http.StatusSeeOther)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	var apiURL, domain string
	if err := h.DB().QueryRowContext(ctx,
		`SELECT n.api_url, r.domain
		 FROM routes r JOIN caddy_nodes n ON n.id = r.caddy_node_id
		 WHERE r.id = ?`, id).Scan(&apiURL, &domain); err != nil {
		redirectWithFlash(w, r, "/admin/hosts", "", "route not found")
		return
	}

	client := caddyapi.New(apiURL)
	if err := client.PurgeCache(ctx); err != nil {
		h.Metrics.CacheOp("purge", "fail")
		if errors.Is(err, caddyapi.ErrNotFound) {
			// 404 on every Souin path. Distinguish "panel never pushed
			// apps.cache" from "panel pushed it but Caddy build lacks
			// cache-handler module" by introspecting the live config.
			loaded, lerr := client.CacheAppLoaded(ctx)
			msg := ""
			switch {
			case lerr != nil:
				msg = "cache purge failed: 404, and config introspection failed: " + sanitizeErr(lerr)
			case !loaded:
				msg = "cache purge failed: node has no apps.cache in running config. CACHE_HANDLER_AVAILABLE may be off, or last Resync failed (check /admin/nodes logs)."
			default:
				msg = "cache purge failed: apps.cache loaded but neither the Souin admin endpoint nor the re-provision fallback worked. Restart the Caddy container as a last resort."
			}
			h.Logger.Warn("cache purge 404", "id", id, "node", apiURL, "loaded", loaded, "introspect_err", lerr)
			redirectWithFlash(w, r, "/admin/hosts/"+strconv.FormatInt(id, 10)+"/edit", "", msg)
			return
		}
		h.Logger.Warn("cache purge", "id", id, "err", err)
		redirectWithFlash(w, r, "/admin/hosts/"+strconv.FormatInt(id, 10)+"/edit", "",
			"cache purge failed: "+sanitizeErr(err))
		return
	}

	h.Metrics.CacheOp("purge", "success")
	sess := middleware.SessionFromContext(r.Context())
	audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "admin.host.cache.purge", Entity: "route",
		EntityID: itoa64(id), Meta: map[string]any{"domain": domain},
	})
	redirectWithFlash(w, r, "/admin/hosts/"+strconv.FormatInt(id, 10)+"/edit",
		"Cache flushed on the node serving "+domain, "")
}

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
		        n.last_seen_at, n.max_routes, n.current_routes,
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
		&lastSeen, &d.Node.MaxRoutes, &d.Node.CurrentRoutes,
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

	// 24h total bandwidth + request count for all routes on this node (from rollups).
	_ = db.QueryRowContext(ctx,
		`SELECT COALESCE(SUM(lr.bytes_resp),0), COALESCE(SUM(lr.requests),0)
		 FROM log_rollups lr
		 JOIN routes r ON r.id = lr.route_id
		 WHERE r.caddy_node_id = ? AND lr.bucket_start >= NOW() - INTERVAL 24 HOUR`, id,
	).Scan(&d.NodeBandwidth24h, &d.NodeRequests24h)

	// Top 5 routes by 24h bandwidth on this node (from rollups).
	bwrows, err := db.QueryContext(ctx,
		`SELECT lr.route_id, r.domain, COALESCE(SUM(lr.bytes_resp),0), COALESCE(SUM(lr.requests),0)
		 FROM log_rollups lr
		 JOIN routes r ON r.id = lr.route_id
		 WHERE r.caddy_node_id = ? AND lr.bucket_start >= NOW() - INTERVAL 24 HOUR
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
		END AS missing
		FROM routes r
		JOIN caddy_nodes n ON n.id = r.caddy_node_id
		WHERE r.caddy_node_id = ? AND r.status != 'disabled'
		  AND (
		        (r.waf_enabled=1     AND COALESCE(CASE WHEN n.modules_probed_at IS NOT NULL THEN n.has_waf        END, ?)=0)
		     OR (r.geo_mode!='off'   AND COALESCE(CASE WHEN n.modules_probed_at IS NOT NULL THEN n.has_geoip      END, ?)=0)
		     OR (r.rate_enabled=1    AND COALESCE(CASE WHEN n.modules_probed_at IS NOT NULL THEN n.has_rate_limit END, ?)=0)
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

// HostsCheckDNS is the JSON endpoint behind the "Check DNS" button on
// the /admin/hosts/new form. It does a fast A-record lookup for the
// supplied domain and compares the resolved IPs against the chosen
// node's public IP, returning a small JSON payload the form's inline
// JS renders next to the domain field. This is a UX hint only - the
// real DNS gate still runs server-side in routes.Service.Create.
func (h *AdminHandlers) HostsCheckDNS(w http.ResponseWriter, r *http.Request) {
	domain := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("domain")))
	nodeID, _ := strconv.ParseInt(r.URL.Query().Get("node_id"), 10, 64)
	resp := map[string]any{"domain": domain}
	if domain == "" || nodeID == 0 {
		resp["error"] = "domain and node_id required"
		apiJSON(w, http.StatusBadRequest, resp)
		return
	}
	db := h.DB()
	if db == nil {
		resp["error"] = "db unavailable"
		apiJSON(w, http.StatusServiceUnavailable, resp)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
	defer cancel()
	var expectedIP, hostname string
	if err := db.QueryRowContext(ctx,
		"SELECT COALESCE(public_ip,''), public_hostname FROM caddy_nodes WHERE id = ?", nodeID,
	).Scan(&expectedIP, &hostname); err != nil {
		resp["error"] = "node not found"
		apiJSON(w, http.StatusNotFound, resp)
		return
	}
	resp["expected_ip"] = expectedIP
	resp["node_hostname"] = hostname

	resolver := &net.Resolver{}
	addrs, err := resolver.LookupHost(ctx, domain)
	if err != nil {
		resp["resolved"] = []string{}
		resp["match"] = false
		resp["error"] = "lookup failed: " + err.Error()
		apiJSON(w, http.StatusOK, resp)
		return
	}
	resp["resolved"] = addrs
	match := false
	if expectedIP != "" {
		for _, a := range addrs {
			if a == expectedIP {
				match = true
				break
			}
		}
	}
	resp["match"] = match
	apiJSON(w, http.StatusOK, resp)
}

// HostsDNSTest performs a real DNS lookup through the resolver configured for
// a route (dns_resolver_ip or the WG peer's assigned_ip) and returns latency +
// resolved addresses. Used by the "Test resolver" button on the DNS tab.
func (h *AdminHandlers) HostsDNSTest(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, _ := strconv.ParseInt(idStr, 10, 64)
	resp := map[string]any{"route_id": id}
	if id == 0 {
		apiJSON(w, http.StatusBadRequest, map[string]any{"error": "bad route id"})
		return
	}
	db := h.DB()
	if db == nil {
		apiJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "db unavailable"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	var resolverIP, resolverPeerIP, upstreamHost, addressFamily string
	err := db.QueryRowContext(ctx,
		`SELECT COALESCE(r.dns_resolver_ip,''), COALESCE(dns_peer.assigned_ip,''),
		        COALESCE(NULLIF(r.backend_ip_override,''), s.backend_ip),
		        COALESCE(r.dns_address_family,'any')
		   FROM routes r
		   JOIN services s ON s.id = r.service_id
		   LEFT JOIN customer_wg_peer dns_peer
		     ON dns_peer.id = r.dns_resolver_via_wg_peer_id AND dns_peer.status <> 'revoked'
		  WHERE r.id = ?`, id,
	).Scan(&resolverIP, &resolverPeerIP, &upstreamHost, &addressFamily)
	if err != nil {
		apiJSON(w, http.StatusNotFound, map[string]any{"error": "route not found"})
		return
	}
	// Pick effective resolver: direct IP wins over peer IP.
	effectiveResolver := resolverIP
	if effectiveResolver == "" {
		effectiveResolver = resolverPeerIP
	}
	resp["resolver"] = effectiveResolver
	resp["host"] = upstreamHost
	resp["address_family"] = addressFamily
	// When upstream is already a bare IP, there is nothing to resolve.
	if net.ParseIP(upstreamHost) != nil {
		resp["resolved"] = []string{upstreamHost}
		resp["latency_ms"] = 0
		resp["ok"] = true
		resp["note"] = "upstream is a bare IP, no DNS lookup needed"
		apiJSON(w, http.StatusOK, resp)
		return
	}
	// Build a resolver pointed at the configured DNS server.
	resolver := net.DefaultResolver
	if effectiveResolver != "" {
		// Refuse loopback/link-local/unspecified resolvers (SSRF guard, also
		// covers legacy rows saved before save-time validation existed).
		if ip := net.ParseIP(effectiveResolver); ip == nil || security.IsDangerousProxyBackend(ip) {
			resp["ok"] = false
			resp["error"] = "resolver address not allowed"
			apiJSON(w, http.StatusOK, resp)
			return
		}
		dialAddr := net.JoinHostPort(effectiveResolver, "53")
		resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				d := net.Dialer{}
				return d.DialContext(ctx, "udp", dialAddr)
			},
		}
	}
	start := time.Now()
	network := "ip4"
	if addressFamily == "ipv6" {
		network = "ip6"
	}
	addrs, lookupErr := resolver.LookupNetIP(ctx, network, upstreamHost)
	latencyMs := time.Since(start).Milliseconds()
	resp["latency_ms"] = latencyMs
	if lookupErr != nil {
		if h.Logger != nil {
			h.Logger.Warn("dns resolver test failed", "route_id", id, "host", upstreamHost,
				"resolver", effectiveResolver, "err", lookupErr)
		}
		resp["ok"] = false
		// Return a sanitized category, not the raw resolver error (which can
		// leak internal addresses/ports); full detail goes to the log above.
		resp["error"] = dnsTestErrorCategory(lookupErr)
		resp["resolved"] = []string{}
		apiJSON(w, http.StatusOK, resp)
		return
	}
	strs := make([]string, 0, len(addrs))
	for _, a := range addrs {
		strs = append(strs, a.String())
	}
	resp["resolved"] = strs
	resp["ok"] = len(strs) > 0
	apiJSON(w, http.StatusOK, resp)
}

// dnsTestErrorCategory maps a resolver error to a coarse, non-leaky label so
// the test endpoint never echoes raw internal addresses or ports to the admin.
func dnsTestErrorCategory(err error) string {
	if err == nil {
		return ""
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		switch {
		case dnsErr.IsTimeout:
			return "resolver timed out"
		case dnsErr.IsNotFound:
			return "name not found (NXDOMAIN)"
		}
		return "resolver query failed"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "resolver timed out"
	}
	return "DNS lookup failed"
}

// HostsTestBackend makes a TCP dial to the route's upstream backend and returns
// reachability + latency. Useful for operators debugging why a route isn't
// forwarding — confirms the panel host can reach the backend before Caddy is
// even involved. RFC1918 is allowed (WG mesh peers live there); loopback and
// link-local are blocked via IsDangerousProxyBackend.
func (h *AdminHandlers) HostsTestBackend(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chiURLParamHosts(r, "id"), 10, 64)
	if id == 0 {
		apiJSON(w, http.StatusBadRequest, map[string]any{"error": "bad route id"})
		return
	}
	db := h.DB()
	if db == nil {
		apiJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "db unavailable"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	var backendHost string
	var upstreamPort int
	err := db.QueryRowContext(ctx,
		`SELECT COALESCE(NULLIF(r.backend_ip_override,''), s.backend_ip), r.upstream_port
		   FROM routes r JOIN services s ON s.id = r.service_id WHERE r.id = ?`, id,
	).Scan(&backendHost, &upstreamPort)
	if err != nil {
		apiJSON(w, http.StatusNotFound, map[string]any{"error": "route not found"})
		return
	}
	// Resolve hostname if needed, then SSRF-check the resulting IP.
	ip := net.ParseIP(backendHost)
	if ip == nil {
		// hostname — resolve first so the SSRF check sees the real IP
		addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", backendHost)
		if err != nil || len(addrs) == 0 {
			apiJSON(w, http.StatusOK, map[string]any{
				"reachable": false,
				"error":     "hostname resolution failed",
				"host":      backendHost,
				"port":      upstreamPort,
			})
			return
		}
		ip = addrs[0].AsSlice()
	}
	if security.IsDangerousProxyBackend(ip) {
		apiJSON(w, http.StatusForbidden, map[string]any{"error": "backend address not allowed"})
		return
	}
	addr := net.JoinHostPort(backendHost, strconv.Itoa(upstreamPort))
	dialCtx, dialCancel := context.WithTimeout(ctx, 5*time.Second)
	defer dialCancel()
	start := time.Now()
	conn, dialErr := (&net.Dialer{}).DialContext(dialCtx, "tcp", addr)
	latencyMs := time.Since(start).Milliseconds()
	if dialErr != nil {
		apiJSON(w, http.StatusOK, map[string]any{
			"reachable":  false,
			"latency_ms": latencyMs,
			"error":      "connection refused or timed out",
			"host":       backendHost,
			"port":       upstreamPort,
		})
		return
	}
	_ = conn.Close()
	apiJSON(w, http.StatusOK, map[string]any{
		"reachable":  true,
		"latency_ms": latencyMs,
		"host":       backendHost,
		"port":       upstreamPort,
	})
}

// HostsRetry re-runs the DNS check on a single route and re-pushes the
// node config. Surfaces "force a renewal" semantically - Caddy's on-
// demand TLS issues / renews certs as part of evaluating the pushed
// config, so a clean re-push is the right unblock when ACME has been
// failing for known-DNS-already-correct hosts.
func (h *AdminHandlers) HostsRetry(w http.ResponseWriter, r *http.Request) {
	if h.Routes == nil || h.DB() == nil {
		http.Error(w, "not ready", http.StatusServiceUnavailable)
		return
	}
	sess := middleware.SessionFromContext(r.Context())
	id, _ := strconv.ParseInt(chiURLParamHosts(r, "id"), 10, 64)
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	if err := h.Routes.VerifyDNS(ctx, 0, id); err != nil {
		redirectWithFlash(w, r, "/admin/hosts", "", "retry failed: "+sanitizeErr(err))
		return
	}
	audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "admin.host.retry", Entity: "route", EntityID: itoa64(id),
	})
	redirectWithFlash(w, r, "/admin/hosts", "Retry triggered", "")
}

// HostsBulk applies one action (enable / disable / delete) to many
// routes at once. Failures are aggregated into the flash so the
// operator sees a partial-success summary instead of bailing on the
// first error.
func (h *AdminHandlers) HostsBulk(w http.ResponseWriter, r *http.Request) {
	if h.Routes == nil || h.DB() == nil {
		http.Error(w, "not ready", http.StatusServiceUnavailable)
		return
	}
	sess := middleware.SessionFromContext(r.Context())
	_ = r.ParseForm()
	action := r.FormValue("action")
	ids := r.Form["ids"]
	destNodeID, _ := strconv.ParseInt(strings.TrimSpace(r.FormValue("node_id")), 10, 64)
	if action == "" || len(ids) == 0 {
		redirectWithFlash(w, r, "/admin/hosts", "", "select rows and an action")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	ok, fail := 0, 0
	touchedNodes := map[int64]struct{}{}
	for _, s := range ids {
		id, err := strconv.ParseInt(s, 10, 64)
		if err != nil || id == 0 {
			fail++
			continue
		}
		var nodeID int64
		_ = h.DB().QueryRowContext(ctx,
			"SELECT caddy_node_id FROM routes WHERE id = ?", id).Scan(&nodeID)
		switch action {
		case "delete":
			if derr := h.Routes.Delete(ctx, 0, id); derr != nil {
				fail++
				continue
			}
		case "disable":
			if _, derr := h.DB().ExecContext(ctx,
				"UPDATE routes SET status='disabled', updated_at=NOW() WHERE id=?", id); derr != nil {
				fail++
				continue
			}
			touchedNodes[nodeID] = struct{}{}
		case "enable":
			if _, derr := h.DB().ExecContext(ctx,
				"UPDATE routes SET status='pending_dns', last_error=NULL, updated_at=NOW() WHERE id=?", id); derr != nil {
				fail++
				continue
			}
			touchedNodes[nodeID] = struct{}{}
		case "set_tag":
			tag := strings.TrimSpace(r.FormValue("tag"))
			if len(tag) > 64 {
				tag = tag[:64]
			}
			if tag == "" {
				fail++
				continue
			}
			if _, derr := h.DB().ExecContext(ctx,
				"UPDATE routes SET tag=?, updated_at=NOW() WHERE id=?", tag, id); derr != nil {
				fail++
				continue
			}
		case "clear_tag":
			if _, derr := h.DB().ExecContext(ctx,
				"UPDATE routes SET tag=NULL, updated_at=NOW() WHERE id=?", id); derr != nil {
				fail++
				continue
			}
		case "move_node":
			if destNodeID <= 0 {
				fail++
				continue
			}
			// capture old node for resync
			var oldNodeID int64
			_ = h.DB().QueryRowContext(ctx, "SELECT caddy_node_id FROM routes WHERE id=?", id).Scan(&oldNodeID)
			if _, derr := h.DB().ExecContext(ctx,
				"UPDATE routes SET caddy_node_id=?, updated_at=NOW() WHERE id=?", destNodeID, id); derr != nil {
				fail++
				continue
			}
			touchedNodes[oldNodeID] = struct{}{}
			touchedNodes[destNodeID] = struct{}{}
		case "maintenance_on":
			if _, derr := h.DB().ExecContext(ctx,
				"UPDATE routes SET maintenance_mode=1, updated_at=NOW() WHERE id=?", id); derr != nil {
				fail++
				continue
			}
			touchedNodes[nodeID] = struct{}{}
		case "maintenance_off":
			if _, derr := h.DB().ExecContext(ctx,
				"UPDATE routes SET maintenance_mode=0, updated_at=NOW() WHERE id=?", id); derr != nil {
				fail++
				continue
			}
			touchedNodes[nodeID] = struct{}{}
		case "retry_ssl":
			// Only resets routes with ssl_enabled to trigger cert re-issue.
			if _, derr := h.DB().ExecContext(ctx,
				"UPDATE routes SET status=?, last_error=NULL, updated_at=NOW() WHERE id=? AND ssl_enabled=1",
				"pending_ssl", id); derr != nil {
				fail++
				continue
			}
			touchedNodes[nodeID] = struct{}{}
		case "resync":
			// Queue node for immediate resync without changing route status.
			touchedNodes[nodeID] = struct{}{}
		default:
			fail++
			continue
		}
		ok++
	}
	// Single resync per affected node, not per row.
	for nodeID := range touchedNodes {
		nid := nodeID
		go func() {
			defer recoverBg(h.Logger, "resync")
			ctx, cancel := context.WithTimeout(h.Routes.BackgroundCtx(), 30*time.Second)
			defer cancel()
			_ = h.Routes.Resync(ctx, nid)
		}()
	}
	audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "admin.host.bulk", Entity: "route",
		Meta: map[string]any{"action": action, "ok": ok, "fail": fail, "count": len(ids)},
	})
	msg := strconv.Itoa(ok) + " host(s) " + action + "d"
	if fail > 0 {
		msg += "; " + strconv.Itoa(fail) + " failed"
	}
	redirectWithFlash(w, r, "/admin/hosts", msg, "")
}

// ensureAdminClient returns the clients.id for the admin user, creating
// it on first call. Each user has at most one clients row (uq_clients_user).
func ensureAdminClient(ctx context.Context, db *sql.DB, userID int64) (int64, error) {
	var id int64
	err := db.QueryRowContext(ctx, "SELECT id FROM clients WHERE user_id = ?", userID).Scan(&id)
	if err == nil {
		return id, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	res, err := db.ExecContext(ctx,
		"INSERT INTO clients (user_id, display_name) VALUES (?, ?)",
		userID, "admin (self)")
	if err != nil {
		return 0, err
	}
	id, _ = res.LastInsertId()
	return id, nil
}

// ensureAdminPlan returns the id of the "_admin-self" plan, creating it
// in the supplied node_group on first call. The plan is kind=npm with
// no caps so admin hosts never trip plan limits.
func ensureAdminPlan(ctx context.Context, db *sql.DB, nodeGroupID int64) (int64, error) {
	// Plans are keyed by (name, node_group_id). Without the group filter,
	// the first call wins and subsequent groups silently inherit the wrong
	// node_group - services then get placed against routes the wrong
	// caddy node owns and the resync loop fights itself.
	var id int64
	err := db.QueryRowContext(ctx,
		"SELECT id FROM plans WHERE name = ? AND node_group_id = ? LIMIT 1",
		internalAdminPlanName, nodeGroupID).Scan(&id)
	if err == nil {
		return id, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	res, err := db.ExecContext(ctx,
		`INSERT INTO plans (name, kind, max_domains, max_ports, ssl_enabled,
		   path_routing_enabled, wildcard_enabled, websocket_enabled, node_group_id)
		 VALUES (?, 'npm', 1000000, 1000000, 1, 1, 1, 1, ?)`,
		internalAdminPlanName, nodeGroupID)
	if err != nil {
		return 0, err
	}
	id, _ = res.LastInsertId()
	return id, nil
}

// ensureAdminService finds or creates a services row keyed on
// (client_id, backend_ip). The port range is the full 1..65535 so a
// single service can carry many admin-added routes. New backends get
// new services on demand; deleting the last route does not GC the
// service (cheap, lets the admin reuse it later).
func ensureAdminService(ctx context.Context, db *sql.DB, clientID int64, backendIP string, planID, nodeGroupID int64) (int64, error) {
	var id int64
	err := db.QueryRowContext(ctx,
		`SELECT id FROM services WHERE client_id = ? AND backend_ip = ? LIMIT 1`,
		clientID, backendIP).Scan(&id)
	if err == nil {
		return id, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	res, err := db.ExecContext(ctx,
		`INSERT INTO services (client_id, name, backend_ip, allowed_port_start, allowed_port_end,
		   plan_id, node_group_id, status)
		 VALUES (?, ?, ?, 1, 65535, ?, ?, 'active')`,
		clientID, "admin "+backendIP, backendIP, planID, nodeGroupID)
	if err != nil {
		return 0, err
	}
	id, _ = res.LastInsertId()
	return id, nil
}

// ---- Certs (per-route SSL cockpit) -------------------------------------

type certRow struct {
	RouteID     int64
	Domain      string
	Status      string // route status
	SSLEnabled  bool
	IssuedAt    string
	ClientEmail string
	NodeName    string
	NodeHost    string
	LastError   string
}

type certsData struct {
	baseAdminData
	Certs []certRow
	Total int
}

// CertsList renders /admin/certs: SSL-focused per-route view. Reuses the
// retry / toggle endpoints under /admin/hosts/{id}/*, so renewal is a
// single button click that triggers a DNS re-check + Caddy re-push (and
// thereby reissues on-demand TLS).
func (h *AdminHandlers) CertsList(w http.ResponseWriter, r *http.Request) {
	d := certsData{baseAdminData: h.base(r, "Certificates")}
	db := h.DB()
	if db == nil {
		h.render(w, "certs", d)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	rows, err := db.QueryContext(ctx,
		`SELECT r.id, r.domain, r.status, r.ssl_enabled,
		        COALESCE(DATE_FORMAT(r.ssl_issued_at,'%Y-%m-%d %H:%i'),''),
		        u.email, n.name, n.public_hostname, COALESCE(r.last_error,'')
		 FROM routes r
		 JOIN services s    ON s.id = r.service_id
		 JOIN clients c     ON c.id = s.client_id
		 JOIN users u       ON u.id = c.user_id
		 JOIN caddy_nodes n ON n.id = r.caddy_node_id
		 WHERE r.kind = 'proxy' OR r.kind IS NULL
		 ORDER BY r.ssl_enabled DESC, r.status, r.domain
		 LIMIT 500`)
	if err != nil {
		h.Logger.Error("certs list", "err", err)
		d.Error = "query failed"
		h.render(w, "certs", d)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var c certRow
		if err := rows.Scan(&c.RouteID, &c.Domain, &c.Status, &c.SSLEnabled,
			&c.IssuedAt, &c.ClientEmail, &c.NodeName, &c.NodeHost, &c.LastError); err == nil {
			d.Certs = append(d.Certs, c)
		}
	}
	d.Total = len(d.Certs)
	h.render(w, "certs", d)
}

// ---- Host edit (per-row advanced settings) -----------------------------

// upstreamRow is one additional backend in the host-edit "Load balancing" tab.
type upstreamRow struct {
	Host        string
	Port        int
	Weight      int
	MaxRequests int  // Caddy upstream max concurrent requests (0 = unlimited)
	Enabled     bool // soft-disable without removing from pool
	// No per-upstream passive health fields: stock Caddy cannot honor them
	// (unknown key fails the whole /load); passive health stays pool-level.
}

type locationRuleRow struct {
	Path           string
	Action         string
	UpstreamScheme string
	UpstreamHost   string
	UpstreamPort   int
	RedirectURL    string
	RedirectCode   int
	RewriteURI     string
}

type basicAuthUserRow struct {
	Username string
}

type hostEditData struct {
	baseAdminData
	RouteID               int64
	Domain                string
	Aliases               string // comma-separated additional hostnames
	PathPrefix            string
	BackendIP             string
	Port                  int
	UpstreamScheme        string
	UpstreamSkipTLSVerify bool
	NodeName              string
	NodeHost              string
	Status                string

	Kind          string
	RedirectURL   string
	RedirectCode  int
	SSL           bool
	ForceHTTPS    bool
	WebSocket     bool
	HTTP2         bool
	HTTP3         bool
	CacheEnabled  bool
	CacheTTLSecs  int
	CustomHeaders string // textarea - one "Name: value" per line
	Tag           string

	MaintenanceMode    bool
	MaintenanceMessage string

	// Per-route error/maintenance page override.
	ErrorOverride bool
	ErrorHTML     string
	ErrorLogoURL  string
	ErrorBrand    string
	ErrorBgColor  string

	CacheVary string // comma-separated header list, e.g. "Accept-Encoding,Accept-Language"

	AccessAllow      string // newline- or comma-separated CIDR list, IPv4 + IPv6
	AccessDeny       string
	AccessBlockAll   bool   // true = deny everyone by default, only Allow IPs pass
	MaintenanceAllow string // CIDR list of IPs that bypass the maintenance page

	CustomConfig string // raw JSON array of Caddy handler objects

	CompressDisabled bool // true = opt out of stock encode (gzip/zstd)

	// Load balancing + health checks (A2). Upstreams are ADDITIONAL backends;
	// empty = single-dial. WeightedLBAvail gates the weighted policy in the UI.
	Upstreams               []upstreamRow
	LocationRules           []locationRuleRow
	LBPolicy                string
	LBHeaderField           string // header name for "header" policy
	LBCookieName            string // cookie name for "cookie" policy
	LBCookieSecret          string // HMAC secret for "cookie" policy
	WeightedLBAvail         bool
	LBTryDurationMs         int // total retry budget in ms (0 = default 5000)
	LBTryIntervalMs         int // delay between retries in ms (0 = no delay)
	DialTimeoutMs           int // per-route dial timeout override (0 = default 10s)
	ResponseHeaderTimeoutMs int // per-route response header timeout (0 = no limit)
	HealthURI               string
	HealthInterval          int
	HealthTimeout           int
	HealthStatus            int
	HealthFails             int
	HealthPassive           bool
	HealthFailDur           int
	HealthMaxFails          int

	// Rate limiting (A3, gated). ModuleAvailable warns when the node lacks it.
	RateLimitEnabled         bool
	RateLimitWindow          string
	RateLimitMaxEvents       int
	RateLimitKey             string
	RateLimitModuleAvailable bool
	// WAF (A4, gated). Blocking false = detection-only.
	WAFEnabled         bool
	WAFBlocking        bool
	WAFDirectives      string
	WAFModuleAvailable bool
	// Geo blocking (gated). Mode off/allow/deny; countries = CSV ISO alpha-2.
	GeoMode            string
	GeoCountries       string
	GeoModuleAvailable bool
	GeoResponseCode    int
	GeoFailClosed      bool
	GeoAllowCIDRs      string
	GeoContinents      string
	GeoBlockCIDRs      string
	// Per-node capability flags from caddy_nodes.has_* columns.
	// Warn in UI when a module is enabled on a node that lacks it.
	NodeHasWAF       bool
	NodeHasL4        bool
	NodeHasGeoIP     bool
	NodeHasRateLimit bool
	// GeoIPAvailable reflects whether the runtime GeoIP database is loaded.
	GeoIPAvailable bool

	// Wildcard DNS-01 (B1, gated). WildcardZones = datalist of dns_providers.
	WildcardEnabled bool
	WildcardZone    string
	WildcardZones   []string

	// ViaWGPeerID == 0 means "no tunnel". When non-zero, build resolves
	// backend host to that peer's tunnel IP at push time.
	ViaWGPeerID   int64
	ClientTunnels []tunnelOption

	// Basic Auth gate (NPM-style). User+password popup before any
	// upstream request. HasPassword tells the UI whether to default
	// 'keep current password' or force a new one.
	BasicAuthUser        string
	BasicAuthHasPassword bool
	// BasicAuthUsers lists accounts from route_basic_auth_users for the multi-user table.
	BasicAuthUsers []basicAuthUserRow

	// SSO forward-auth (Authentik / Authelia / generic).
	SSOProviderURL    string
	SSOCopyHeaders    string // textarea, one header per line
	SSOTrustedProxies string // comma/space-separated
	// SSO scope. Empty = gate the whole route. Non-empty narrows to
	// specific paths / hosts (matched together as AND).
	SSOPaths string
	SSOHosts string
	// SSOViaWGPeerID binds the SSO provider call to a WG tunnel peer.
	SSOViaWGPeerID int64
	SSOStrictMode  bool

	// Built-in forward-auth portal: per-host toggle + selectable groups.
	PortalProtect bool
	PortalGroups  []portalGroupOption

	// External HTTPS upstream (admin-only). When External, BackendIP holds the
	// upstream FQDN (= backend_ip_override). HasProxySecret is whether an
	// inbound bearer is set (never the plaintext). ExternalAllowlist feeds a
	// datalist of permitted hosts.
	External           bool
	ExternalHost       string
	UpstreamHostHeader string
	HasProxySecret     bool
	ExternalAllowlist  []string

	// Outbound/egress IP. Mode "fixed"/"random" bind the upstream connection.
	OutboundIPMode    string
	OutboundIP        string
	NodeOutboundIPs   []string // inventory from caddy_nodes.outbound_ips; feeds datalist
	PlanAllowEgressIP bool     // whether the host's plan permits non-default egress

	// DNS controls per host. ResolverIP takes priority over ResolverViaWGPeerID.
	DNSResolverIP      string
	DNSResolverViaWGID int64  // WG peer whose assigned_ip is used as resolver
	DNSAddressFamily   string // "any" | "ipv4" | "ipv6"

	// mTLS client-cert enforcement. RequireClientCert gates the Caddy TLS
	// connection policy; MTLSCAID selects the trust-anchor CA. MTLSCAs feeds
	// the dropdown (id + label). MTLSCAActive reflects saved CA health.
	RequireClientCert bool
	MTLSCAID          int64
	MTLSCAActive      bool // true when the saved CA status='active'
	MTLSCAs           []mtlsCAOption
	// MTLSPathRules lists RBAC path rules for this route.
	MTLSPathRules []mtlsPathRuleRow
	// MTLSCARoles lists available roles for the selected CA (feeds rule add dropdown).
	MTLSCARoles []mtlsRoleRow

	Groups  []hostGroupOption
	GroupID sql.NullInt64

	CFViews []customfields.View
}

// mtlsCAOption is one selectable trust-anchor CA in the host editor dropdown.
type mtlsCAOption struct {
	ID    int64
	Label string
}

// tunnelOption is the dropdown entry the host-edit form renders.
type tunnelOption struct {
	ID         int64
	Name       string
	AssignedIP string
}

// HostsEdit renders /admin/hosts/{id}/edit (GET).
func (h *AdminHandlers) HostsEdit(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chiURLParamHosts(r, "id"), 10, 64)
	d := hostEditData{baseAdminData: h.base(r, "Edit host"), RouteID: id}
	db := h.DB()
	if db == nil || id == 0 {
		h.render(w, "hosts_edit", d)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	// Scoped admins must not view hosts outside their client scope (edit form leaks node IP inventory).
	sess := middleware.SessionFromContext(r.Context())
	if !h.scopeCheckRoute(ctx, sess, id) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	var (
		headersJSON  sql.NullString
		redirectURL  sql.NullString
		redirectCode sql.NullInt32
		tag          sql.NullString
	)
	var maintMsg sql.NullString
	var cacheVary sql.NullString
	var accessAllow, accessDeny, customCfg, aliases sql.NullString
	var maintAllow sql.NullString
	var accessBlockAll bool
	var viaPeerID sql.NullInt64
	var clientID int64
	var baUser, baHash sql.NullString
	var ssoURL, ssoCopy, ssoTrusted, ssoPaths, ssoHosts sql.NullString
	var ssoViaPeer sql.NullInt64
	var ssoStrictMode bool
	var extFlag bool
	var extHostHeader, secretEnc sql.NullString
	err := db.QueryRowContext(ctx,
		`SELECT r.domain, COALESCE(r.aliases,''), r.path_prefix, COALESCE(NULLIF(r.backend_ip_override,''), s.backend_ip), r.upstream_port, r.upstream_scheme, r.upstream_skip_tls_verify, r.status,
		        r.kind, r.redirect_url, r.redirect_code, r.ssl_enabled,
		        r.force_https, r.websocket, r.http2_enabled, r.http3_enabled,
		        r.cache_enabled, r.cache_ttl_secs, r.custom_headers, r.tag,
		        r.maintenance_mode, r.maintenance_message, r.cache_vary,
		        r.access_allow, r.access_deny,
		        COALESCE(r.access_block_all, 0), COALESCE(r.maintenance_allow,''),
		        r.custom_config,
		        r.via_wg_peer_id, s.client_id,
		        n.name, n.public_hostname,
		        r.basic_auth_user, r.basic_auth_bcrypt,
		        r.sso_provider_url, r.sso_copy_headers, r.sso_trusted_proxies,
		        COALESCE(r.sso_paths,''), COALESCE(r.sso_hosts,''),
		        r.sso_via_wg_peer_id,
		        COALESCE(r.sso_strict_mode,0),
		        COALESCE(r.upstream_external,0), COALESCE(r.upstream_host_header,''), COALESCE(r.proxy_secret_enc,''),
		        COALESCE(r.compress_disabled,0),
		        COALESCE(r.lb_policy,''),
		        COALESCE(r.lb_header_field,''), COALESCE(r.lb_cookie_name,''), COALESCE(r.lb_cookie_secret,''),
		        COALESCE(r.health_active_uri,''), COALESCE(r.health_active_interval,10), COALESCE(r.health_active_timeout,5),
		        COALESCE(r.health_active_status,0), COALESCE(r.health_active_fails,3),
		        COALESCE(r.health_passive_enabled,0), COALESCE(r.health_passive_fail_dur,30), COALESCE(r.health_passive_max_fail,3),
		        COALESCE(r.lb_try_duration_ms,5000), COALESCE(r.lb_try_interval_ms,250),
		        COALESCE(r.rate_enabled,0), COALESCE(r.rate_window,''), COALESCE(r.rate_max_events,0), COALESCE(r.rate_key,''),
		        COALESCE(r.waf_enabled,0), COALESCE(r.waf_blocking,0), COALESCE(r.waf_directives,''),
		        COALESCE(r.geo_mode,'off'), COALESCE(r.geo_countries,''),
		        COALESCE(r.geo_response_code,403), COALESCE(r.geo_fail_closed,0), COALESCE(r.geo_allow_cidrs,''),
		        COALESCE(r.geo_continents,''), COALESCE(r.geo_block_cidrs,''),
		        COALESCE(r.wildcard_enabled,0), COALESCE(r.wildcard_zone,''),
		        COALESCE(r.error_override,0), COALESCE(r.error_html,''), COALESCE(r.error_logo_url,''),
		        COALESCE(r.error_brand,''), COALESCE(r.error_bg_color,''),
		        COALESCE(r.outbound_ip_mode,'default'), COALESCE(r.outbound_ip,''),
	        COALESCE(r.dns_resolver_ip,''), COALESCE(r.dns_resolver_via_wg_peer_id,0),
	        COALESCE(r.dns_address_family,'any'),
	        COALESCE(r.require_client_cert,0), COALESCE(r.mtls_ca_id,0),
		        COALESCE(CASE WHEN n.modules_probed_at IS NOT NULL THEN n.has_waf        END, ?), COALESCE(n.has_l4,0),
		        COALESCE(CASE WHEN n.modules_probed_at IS NOT NULL THEN n.has_geoip      END, ?),
		        COALESCE(CASE WHEN n.modules_probed_at IS NOT NULL THEN n.has_rate_limit END, ?),
		        COALESCE(r.dial_timeout_ms,0), COALESCE(r.response_header_timeout_ms,0),
		        COALESCE(r.group_id,0)
		 FROM routes r
		 JOIN services s ON s.id = r.service_id
		 JOIN caddy_nodes n ON n.id = r.caddy_node_id
		 WHERE r.id = ?`,
		b2i(h.Routes != nil && h.Routes.WAFModuleAvailable),
		b2i(h.Routes != nil && h.Routes.GeoModuleAvailable),
		b2i(h.Routes != nil && h.Routes.RateLimitModuleAvailable), id,
	).Scan(&d.Domain, &aliases, &d.PathPrefix, &d.BackendIP, &d.Port, &d.UpstreamScheme, &d.UpstreamSkipTLSVerify, &d.Status,
		&d.Kind, &redirectURL, &redirectCode, &d.SSL,
		&d.ForceHTTPS, &d.WebSocket, &d.HTTP2, &d.HTTP3,
		&d.CacheEnabled, &d.CacheTTLSecs, &headersJSON, &tag,
		&d.MaintenanceMode, &maintMsg, &cacheVary,
		&accessAllow, &accessDeny,
		&accessBlockAll, &maintAllow,
		&customCfg,
		&viaPeerID, &clientID,
		&d.NodeName, &d.NodeHost,
		&baUser, &baHash,
		&ssoURL, &ssoCopy, &ssoTrusted,
		&ssoPaths, &ssoHosts,
		&ssoViaPeer,
		&ssoStrictMode,
		&extFlag, &extHostHeader, &secretEnc,
		&d.CompressDisabled,
		&d.LBPolicy,
		&d.LBHeaderField, &d.LBCookieName, &d.LBCookieSecret,
		&d.HealthURI, &d.HealthInterval, &d.HealthTimeout, &d.HealthStatus, &d.HealthFails,
		&d.HealthPassive, &d.HealthFailDur, &d.HealthMaxFails,
		&d.LBTryDurationMs, &d.LBTryIntervalMs,
		&d.RateLimitEnabled, &d.RateLimitWindow, &d.RateLimitMaxEvents, &d.RateLimitKey,
		&d.WAFEnabled, &d.WAFBlocking, &d.WAFDirectives,
		&d.GeoMode, &d.GeoCountries,
		&d.GeoResponseCode, &d.GeoFailClosed, &d.GeoAllowCIDRs,
		&d.GeoContinents, &d.GeoBlockCIDRs,
		&d.WildcardEnabled, &d.WildcardZone,
		&d.ErrorOverride, &d.ErrorHTML, &d.ErrorLogoURL, &d.ErrorBrand, &d.ErrorBgColor,
		&d.OutboundIPMode, &d.OutboundIP,
		&d.DNSResolverIP, &d.DNSResolverViaWGID, &d.DNSAddressFamily,
		&d.RequireClientCert, &d.MTLSCAID,
		&d.NodeHasWAF, &d.NodeHasL4, &d.NodeHasGeoIP, &d.NodeHasRateLimit,
		&d.DialTimeoutMs, &d.ResponseHeaderTimeoutMs,
		&d.GroupID.Int64)
	if d.GroupID.Int64 > 0 {
		d.GroupID.Valid = true
	}
	if err != nil {
		d.Error = "host not found"
		h.render(w, "hosts_edit", d)
		return
	}
	// mTLS CA dropdown: active CAs only, newest first (best-effort).
	if car, cerr := db.QueryContext(ctx,
		`SELECT id, COALESCE(NULLIF(name,''), common_name) FROM mtls_cas WHERE status='active' ORDER BY id DESC`); cerr == nil {
		for car.Next() {
			var o mtlsCAOption
			if car.Scan(&o.ID, &o.Label) == nil {
				d.MTLSCAs = append(d.MTLSCAs, o)
			}
		}
		car.Close()
	}
	// Check whether the saved CA is currently active (drives status pill).
	if d.MTLSCAID > 0 {
		var caStatus string
		_ = db.QueryRowContext(ctx, `SELECT status FROM mtls_cas WHERE id=?`, d.MTLSCAID).Scan(&caStatus)
		d.MTLSCAActive = caStatus == "active"

		// Load available roles for the selected CA (feeds path-rule add dropdown).
		if rr, rerr := db.QueryContext(ctx,
			`SELECT id, name FROM mtls_roles WHERE ca_id=? ORDER BY name ASC`, d.MTLSCAID); rerr == nil {
			for rr.Next() {
				var ro mtlsRoleRow
				if rr.Scan(&ro.ID, &ro.Name) == nil {
					d.MTLSCARoles = append(d.MTLSCARoles, ro)
				}
			}
			rr.Close()
		}

		// Load path rules for this route.
		if pr, prerr := db.QueryContext(ctx, `
			SELECT pr.id, pr.path_pattern, ro.name
			  FROM mtls_path_rules pr
			  JOIN mtls_roles ro ON ro.id = pr.required_role_id
			 WHERE pr.route_id = ?
			 ORDER BY pr.id ASC`, id); prerr == nil {
			for pr.Next() {
				var rule mtlsPathRuleRow
				if pr.Scan(&rule.ID, &rule.PathPattern, &rule.RequiredRole) == nil {
					d.MTLSPathRules = append(d.MTLSPathRules, rule)
				}
			}
			pr.Close()
		}
	}
	d.Groups = loadHostGroups(ctx, db)
	d.WeightedLBAvail = h.Routes.WeightedLBAvailable
	d.RateLimitModuleAvailable = h.Routes.RateLimitModuleAvailable
	d.WAFModuleAvailable = h.Routes.WAFModuleAvailable
	d.GeoModuleAvailable = h.Routes.GeoModuleAvailable
	d.GeoIPAvailable = geoip.Global().Available()
	// Wildcard zones datalist (best-effort).
	if zr, zerr := db.QueryContext(ctx, "SELECT name FROM dns_providers ORDER BY name ASC"); zerr == nil {
		for zr.Next() {
			var z string
			if zr.Scan(&z) == nil {
				d.WildcardZones = append(d.WildcardZones, z)
			}
		}
		zr.Close()
	}
	// Additional backends for the Load balancing tab (best-effort).
	if urows, uerr := db.QueryContext(ctx,
		`SELECT host, port, weight, COALESCE(max_requests,0), COALESCE(enabled,1)
		   FROM route_upstreams WHERE route_id = ? ORDER BY sort_order ASC, id ASC`, id); uerr == nil {
		for urows.Next() {
			var ur upstreamRow
			if urows.Scan(&ur.Host, &ur.Port, &ur.Weight, &ur.MaxRequests, &ur.Enabled) == nil {
				d.Upstreams = append(d.Upstreams, ur)
			}
		}
		urows.Close()
	}
	if lrows, lerr := db.QueryContext(ctx,
		`SELECT path_glob, action, upstream_scheme, COALESCE(upstream_host,''), COALESCE(upstream_port,0),
		        COALESCE(redirect_url,''), COALESCE(redirect_code,308), COALESCE(rewrite_uri,'')
		   FROM route_location_rules
		  WHERE route_id = ?
		  ORDER BY sort_order ASC, id ASC`, id); lerr == nil {
		for lrows.Next() {
			var lr locationRuleRow
			if lrows.Scan(&lr.Path, &lr.Action, &lr.UpstreamScheme, &lr.UpstreamHost, &lr.UpstreamPort,
				&lr.RedirectURL, &lr.RedirectCode, &lr.RewriteURI) == nil {
				d.LocationRules = append(d.LocationRules, lr)
			}
		}
		lrows.Close()
	}
	if redirectURL.Valid {
		d.RedirectURL = redirectURL.String
	}
	if redirectCode.Valid {
		d.RedirectCode = int(redirectCode.Int32)
	}
	if tag.Valid {
		d.Tag = tag.String
	}
	if maintMsg.Valid {
		d.MaintenanceMessage = maintMsg.String
	}
	if cacheVary.Valid {
		d.CacheVary = cacheVary.String
	}
	if accessAllow.Valid {
		d.AccessAllow = accessAllow.String
	}
	d.AccessBlockAll = accessBlockAll
	if maintAllow.Valid {
		d.MaintenanceAllow = maintAllow.String
	}
	if accessDeny.Valid {
		d.AccessDeny = accessDeny.String
	}
	if customCfg.Valid {
		d.CustomConfig = customCfg.String
	}
	if aliases.Valid {
		d.Aliases = aliases.String
	}
	if viaPeerID.Valid {
		d.ViaWGPeerID = viaPeerID.Int64
	}
	d.External = extFlag
	if d.External {
		d.ExternalHost = d.BackendIP // override column was coalesced into BackendIP
		if extHostHeader.Valid {
			d.UpstreamHostHeader = extHostHeader.String
		}
	}
	d.HasProxySecret = secretEnc.Valid && secretEnc.String != ""
	if h.Routes != nil {
		d.ExternalAllowlist = h.Routes.ExternalAllowlistAll()
	}
	if baUser.Valid {
		d.BasicAuthUser = baUser.String
	}
	d.BasicAuthHasPassword = baHash.Valid && baHash.String != ""
	// Load multi-user basic auth accounts (best-effort; falls back to single-user if table missing).
	if burows, buerr := db.QueryContext(ctx,
		`SELECT username FROM route_basic_auth_users WHERE route_id = ? ORDER BY username ASC`, id); buerr == nil {
		for burows.Next() {
			var u basicAuthUserRow
			if burows.Scan(&u.Username) == nil {
				d.BasicAuthUsers = append(d.BasicAuthUsers, u)
			}
		}
		burows.Close()
	}
	if ssoURL.Valid {
		d.SSOProviderURL = ssoURL.String
	}
	if ssoCopy.Valid {
		d.SSOCopyHeaders = ssoCopy.String
	}
	if ssoTrusted.Valid {
		d.SSOTrustedProxies = ssoTrusted.String
	}
	if ssoPaths.Valid {
		d.SSOPaths = ssoPaths.String
	}
	if ssoHosts.Valid {
		d.SSOHosts = ssoHosts.String
	}
	if ssoViaPeer.Valid {
		d.SSOViaWGPeerID = ssoViaPeer.Int64
	}
	d.SSOStrictMode = ssoStrictMode
	// Built-in portal: toggle + grantable groups for this host (additive
	// query so the large route SELECT above stays untouched).
	_ = db.QueryRowContext(ctx, `SELECT COALESCE(portal_protect,0) FROM routes WHERE id = ?`, id).Scan(&d.PortalProtect)
	d.PortalGroups = h.portalGroupsForRoute(ctx, sess, id, clientID)
	d.ClientTunnels = loadClientTunnels(ctx, db, clientID)
	// Fetch node's outbound IP inventory and plan egress flag for the egress tab.
	var nodeOutboundIPsJSON sql.NullString
	var planAllowEgress bool
	_ = db.QueryRowContext(ctx,
		`SELECT n.outbound_ips, COALESCE(p.allow_egress_ip,0)
		   FROM routes r
		   JOIN caddy_nodes n ON n.id = r.caddy_node_id
		   JOIN services s ON s.id = r.service_id
		   JOIN plans p ON p.id = s.plan_id
		  WHERE r.id = ?`, id,
	).Scan(&nodeOutboundIPsJSON, &planAllowEgress)
	d.PlanAllowEgressIP = planAllowEgress
	if nodeOutboundIPsJSON.Valid && nodeOutboundIPsJSON.String != "" {
		var ips []string
		if json.Unmarshal([]byte(nodeOutboundIPsJSON.String), &ips) == nil {
			d.NodeOutboundIPs = ips
		}
	}
	if headersJSON.Valid && headersJSON.String != "" {
		var m map[string]string
		if json.Unmarshal([]byte(headersJSON.String), &m) == nil {
			lines := make([]string, 0, len(m))
			for k, v := range m {
				lines = append(lines, k+": "+v)
			}
			d.CustomHeaders = strings.Join(lines, "\n")
		}
	}
	// Load host custom field defs + decode stored values for the edit form.
	if cfDefs, cfErr := customfields.LoadDefs(ctx, db, "host"); cfErr == nil && len(cfDefs) > 0 {
		var cfRaw sql.NullString
		_ = db.QueryRowContext(ctx, "SELECT COALESCE(custom_fields,'') FROM routes WHERE id = ?", id).Scan(&cfRaw)
		d.CFViews = customfields.Merge(cfDefs, customfields.Decode(cfRaw.String))
	}
	h.render(w, "hosts_edit", d)
}

// HostsUpdate handles POST /admin/hosts/{id}/edit.
func (h *AdminHandlers) HostsUpdate(w http.ResponseWriter, r *http.Request) {
	if h.Routes == nil || h.DB() == nil {
		http.Error(w, "not ready", http.StatusServiceUnavailable)
		return
	}
	id, _ := strconv.ParseInt(chiURLParamHosts(r, "id"), 10, 64)
	if id == 0 {
		http.Redirect(w, r, "/admin/hosts", http.StatusSeeOther)
		return
	}
	sess := middleware.SessionFromContext(r.Context())
	// Scoped admins must not update hosts outside their client scope.
	if !h.scopeCheckRoute(r.Context(), sess, id) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	_ = r.ParseForm()
	domain := strings.TrimSpace(strings.ToLower(r.FormValue("domain")))
	pathPrefix := strings.TrimSpace(r.FormValue("path_prefix"))
	backendIP := strings.TrimSpace(r.FormValue("backend_ip"))
	port, _ := strconv.Atoi(r.FormValue("port"))
	kind := strings.TrimSpace(r.FormValue("kind"))
	if kind != "redirect" {
		kind = "proxy"
	}
	// External HTTPS upstream (admin-only). Parsed early so the customer-backend
	// port/host validation below is skipped; full validation + force-shape +
	// mutual exclusion happens once via_wg_peer_id is parsed.
	external := r.FormValue("upstream_external") == "1"
	externalHost := strings.ToLower(strings.TrimSpace(r.FormValue("external_host")))
	extHostHeader := strings.TrimSpace(r.FormValue("upstream_host_header"))
	if external {
		kind = "proxy"
	}
	redirectURL := strings.TrimSpace(r.FormValue("redirect_url"))
	redirectCode, _ := strconv.Atoi(r.FormValue("redirect_code"))
	ssl := r.FormValue("ssl") == "1"
	forceHTTPS := r.FormValue("force_https") == "1"
	websocket := r.FormValue("websocket") == "1"
	http2 := r.FormValue("http2") == "1"
	http3 := r.FormValue("http3") == "1"
	cacheEnabled := r.FormValue("cache_enabled") == "1"
	compressDisabled := r.FormValue("compress_disabled") == "1"

	// Load balancing + health checks (A2). Policy is allowlisted; weighted is
	// rejected unless the module gate is on so stock nodes never break.
	lbPolicy := r.FormValue("lb_policy")
	switch lbPolicy {
	case "", "round_robin", "least_conn", "ip_hash", "uri_hash", "header", "cookie":
	case "weighted_round_robin":
		if !h.Routes.WeightedLBAvailable {
			lbPolicy = "round_robin"
		}
	default:
		lbPolicy = ""
	}
	lbHeaderField := strings.TrimSpace(r.FormValue("lb_header_field"))
	lbCookieName := strings.TrimSpace(r.FormValue("lb_cookie_name"))
	lbCookieSecret := strings.TrimSpace(r.FormValue("lb_cookie_secret"))
	healthURI := strings.TrimSpace(r.FormValue("health_uri"))
	if healthURI != "" && !strings.HasPrefix(healthURI, "/") {
		healthURI = "/" + healthURI
	}
	healthInterval := clampInt(atoiDefault(r.FormValue("health_interval"), 10), 1, 300)
	healthTimeout := clampInt(atoiDefault(r.FormValue("health_timeout"), 5), 1, 60)
	healthStatus := atoiDefault(r.FormValue("health_expect_status"), 0)
	if healthStatus != 0 && (healthStatus < 100 || healthStatus > 599) {
		healthStatus = 0
	}
	healthFails := clampInt(atoiDefault(r.FormValue("health_fails"), 3), 1, 10)
	healthPassive := r.FormValue("health_passive") == "1"
	healthFailDur := clampInt(atoiDefault(r.FormValue("health_fail_dur"), 30), 1, 600)
	healthMaxFails := clampInt(atoiDefault(r.FormValue("health_max_fails"), 3), 1, 10)
	// Retry timing: total budget (0 = default 5000ms) and per-attempt delay
	// (0 = no inter-attempt delay). Clamped: duration 100-300000ms, interval 0-60000ms.
	lbTryDurationMs := clampInt(atoiDefault(r.FormValue("lb_try_duration_ms"), 5000), 100, 300000)
	lbTryIntervalMs := clampInt(atoiDefault(r.FormValue("lb_try_interval_ms"), 250), 0, 60000)
	dialTimeoutMs := clampInt(atoiDefault(r.FormValue("dial_timeout_ms"), 0), 0, 300000)
	responseHeaderTimeoutMs := clampInt(atoiDefault(r.FormValue("response_header_timeout_ms"), 0), 0, 300000)
	// Additional backends arrive as parallel arrays. Admin-only internal
	// targets (same trust level as backend_ip) so the host validator suffices.
	upHosts := r.Form["upstream_host[]"]
	upPorts := r.Form["upstream_port[]"]
	upWeights := r.Form["upstream_weight[]"]
	upMaxReqs := r.Form["upstream_max_requests[]"]
	upEnabled := r.Form["upstream_enabled[]"] // checkbox: present = enabled
	var newUpstreams []upstreamRow
	for i := range upHosts {
		host := strings.TrimSpace(upHosts[i])
		if host == "" {
			continue
		}
		port := 0
		if i < len(upPorts) {
			port = atoiDefault(upPorts[i], 0)
		}
		if !isValidUpstreamHost(host) || port < 1 || port > 65535 {
			continue
		}
		weight := 1
		if i < len(upWeights) {
			weight = clampInt(atoiDefault(upWeights[i], 1), 1, 100)
		}
		maxReq := 0
		if i < len(upMaxReqs) {
			maxReq = clampInt(atoiDefault(upMaxReqs[i], 0), 0, 100000)
		}
		// Checkboxes only submit when ticked; presence of index in enabled slice signals enabled.
		enabled := true
		if i < len(upEnabled) {
			enabled = upEnabled[i] == "1"
		}
		newUpstreams = append(newUpstreams, upstreamRow{
			Host: host, Port: port, Weight: weight, MaxRequests: maxReq, Enabled: enabled,
		})
	}
	newLocationRules, locErr := sanitizeLocationRules(r.Form)
	if locErr != nil {
		redirectWithFlash(w, r, "/admin/hosts/"+strconv.FormatInt(id, 10)+"/edit#tab=locations", "", "routing rule: "+sanitizeErr(locErr))
		return
	}

	// Rate limiting (A3). Window must be a valid Go duration when enabled.
	rateEnabled := r.FormValue("rate_enabled") == "1"
	rateWindow := strings.TrimSpace(r.FormValue("rate_window"))
	if rateWindow == "" {
		rateWindow = "1m"
	}
	rateMaxEvents := atoiDefault(r.FormValue("rate_max_events"), 100)
	if rateMaxEvents <= 0 {
		rateMaxEvents = 100
	}
	rateKey := strings.TrimSpace(r.FormValue("rate_key"))
	if rateKey == "custom" {
		rateKey = strings.TrimSpace(r.FormValue("rate_key_custom"))
	}
	if rateKey == "" {
		rateKey = "{http.request.remote.host}"
	}
	if rateEnabled {
		if _, derr := time.ParseDuration(rateWindow); derr != nil {
			redirectWithFlash(w, r, "/admin/hosts/"+strconv.FormatInt(id, 10)+"/edit", "", "rate limit: invalid window (e.g. 1m, 30s)")
			return
		}
		if rateMaxEvents < 1 || rateMaxEvents > 1000000 {
			redirectWithFlash(w, r, "/admin/hosts/"+strconv.FormatInt(id, 10)+"/edit", "", "rate limit: max events must be 1-1000000")
			return
		}
	}
	// WAF (A4). Detection-only unless blocking is also ticked.
	wafEnabled := r.FormValue("waf_enabled") == "1"
	wafBlocking := r.FormValue("waf_blocking") == "1"
	wafDirectives := strings.TrimSpace(r.FormValue("waf_directives"))
	if len(wafDirectives) > 16384 {
		redirectWithFlash(w, r, "/admin/hosts/"+strconv.FormatInt(id, 10)+"/edit", "", "WAF: custom directives too long (16 KiB max)")
		return
	}
	// Geo blocking. Normalize codes (uppercase, dedupe, drop junk); off when no mode.
	geoMode := strings.ToLower(strings.TrimSpace(r.FormValue("geo_mode")))
	if geoMode != "allow" && geoMode != "deny" {
		geoMode = "off"
	}
	geoCountries := geoip.NormalizeCountries(r.FormValue("geo_countries"))
	geoResponseCodeRaw, _ := strconv.Atoi(r.FormValue("geo_response_code"))
	if geoResponseCodeRaw == 0 {
		geoResponseCodeRaw = 403
	}
	geoFailClosed := r.FormValue("geo_fail_closed") == "1"
	// Validate + normalize to a comma list: a bad entry must surface to the
	// operator, not silently vanish (block-list drops would fail open) or reach
	// Caddy as a newline blob that rejects the whole /load.
	geoAllowCIDRs, errGA := sanitizeCIDRList(r.FormValue("geo_allow_cidrs"))
	if errGA != nil {
		redirectWithFlash(w, r, "/admin/hosts/"+strconv.FormatInt(id, 10)+"/edit", "", "geo allow list: "+sanitizeErr(errGA))
		return
	}
	geoContinents := geoip.NormalizeCountries(r.FormValue("geo_continents"))
	geoBlockCIDRs, errGB := sanitizeCIDRList(r.FormValue("geo_block_cidrs"))
	if errGB != nil {
		redirectWithFlash(w, r, "/admin/hosts/"+strconv.FormatInt(id, 10)+"/edit", "", "geo block list: "+sanitizeErr(errGB))
		return
	}
	// mTLS client-cert enforcement. require_client_cert needs a valid CA; an
	// enforced host with no CA would brick the handshake, so reject early.
	requireClientCert := r.FormValue("require_client_cert") == "1"
	mtlsCAID, _ := strconv.ParseInt(r.FormValue("mtls_ca_id"), 10, 64)
	if requireClientCert && mtlsCAID <= 0 {
		redirectWithFlash(w, r, "/admin/hosts/"+strconv.FormatInt(id, 10)+"/edit", "", "require_client_cert needs an mTLS CA assigned")
		return
	}
	if requireClientCert && mtlsCAID > 0 {
		// Reject if CA has no uploaded certificate or is not active.
		var caCount int
		_ = h.DB().QueryRowContext(r.Context(),
			"SELECT COUNT(*) FROM mtls_cas WHERE id=? AND status='active' AND cert_pem IS NOT NULL AND cert_pem != ''",
			mtlsCAID).Scan(&caCount)
		if caCount == 0 {
			redirectWithFlash(w, r, "/admin/hosts/"+strconv.FormatInt(id, 10)+"/edit", "", "selected mTLS CA is not active - upload a certificate first")
			return
		}
	}
	if !requireClientCert {
		mtlsCAID = 0 // clear the anchor when enforcement is off
	}
	// Wildcard DNS-01 (B1). Zone must cover the route domain when enabled.
	wildcardEnabled := r.FormValue("wildcard_enabled") == "1"
	wildcardZone := strings.ToLower(strings.TrimSpace(r.FormValue("wildcard_zone")))
	if wildcardEnabled {
		d := strings.ToLower(domain)
		if wildcardZone == "" || (d != wildcardZone && !strings.HasSuffix(d, "."+wildcardZone)) {
			redirectWithFlash(w, r, "/admin/hosts/"+strconv.FormatInt(id, 10)+"/edit", "", "wildcard: zone must cover the domain (e.g. zone customer.com for app.customer.com)")
			return
		}
	}

	// Outbound/egress IP. Only proxy routes need it; ignored for redirect/maintenance.
	outboundIPMode := r.FormValue("outbound_ip_mode")
	switch outboundIPMode {
	case "fixed", "random":
	default:
		outboundIPMode = "default"
	}
	outboundIP := strings.TrimSpace(r.FormValue("outbound_ip"))
	// Plan gate: check whether the plan allows non-default egress.
	editPath := "/admin/hosts/" + strconv.FormatInt(id, 10) + "/edit"
	// Hard block: reject save when a module-gated feature is on but the node lacks
	// the Caddy module. Effective capability = the per-node operator-declared flag
	// if the node was declared (modules_probed_at set), else the fleet-wide env
	// flag. Mirrors probedOr() in routes.Service.buildNodePush so the gate matches
	// what actually gets emitted.
	{
		var probedWAF, probedGeo, probedRate sql.NullBool
		_ = h.DB().QueryRowContext(r.Context(),
			`SELECT CASE WHEN n.modules_probed_at IS NOT NULL THEN n.has_waf        END,
			        CASE WHEN n.modules_probed_at IS NOT NULL THEN n.has_geoip      END,
			        CASE WHEN n.modules_probed_at IS NOT NULL THEN n.has_rate_limit END
			   FROM routes r JOIN caddy_nodes n ON n.id = r.caddy_node_id WHERE r.id = ?`, id,
		).Scan(&probedWAF, &probedGeo, &probedRate)
		// Default true (don't block) when env flags are unknown; emission still
		// gates via probedOr, so a false env never breaks the node here.
		effWAF, effGeo, effRate := true, true, true
		if h.Routes != nil {
			effWAF = h.Routes.WAFModuleAvailable
			effGeo = h.Routes.GeoModuleAvailable
			effRate = h.Routes.RateLimitModuleAvailable
		}
		if probedWAF.Valid {
			effWAF = probedWAF.Bool
		}
		if probedGeo.Valid {
			effGeo = probedGeo.Bool
		}
		if probedRate.Valid {
			effRate = probedRate.Bool
		}
		if wafEnabled && !effWAF {
			redirectWithFlash(w, r, editPath, "", "WAF requires the coraza-caddy/v2 module. Enable WAF_MODULE_AVAILABLE, or tick WAF (Coraza) under Module capabilities on the node edit page once Caddy is built with it.")
			return
		}
		if geoMode != "off" && !effGeo {
			redirectWithFlash(w, r, editPath, "", "GeoIP filtering requires the caddy-maxmind-geolocation module. Enable GEOIP_AVAILABLE, or tick GeoIP under Module capabilities on the node edit page once Caddy is built with it.")
			return
		}
		if rateEnabled && !effRate {
			redirectWithFlash(w, r, editPath, "", "Rate limiting requires the caddy-ratelimit module. Enable RATE_LIMIT_AVAILABLE, or tick Rate limit under Module capabilities on the node edit page once Caddy is built with it.")
			return
		}
	}
	if outboundIPMode != "default" {
		var planAllowEgress bool
		_ = h.DB().QueryRowContext(r.Context(),
			`SELECT COALESCE(p.allow_egress_ip,0)
			   FROM routes r
			   JOIN services s ON s.id = r.service_id
			   JOIN plans p ON p.id = s.plan_id
			  WHERE r.id = ?`, id,
		).Scan(&planAllowEgress)
		if !planAllowEgress {
			redirectWithFlash(w, r, editPath, "", "egress: plan does not allow custom egress IP")
			return
		}
	}
	if outboundIPMode == "fixed" && outboundIP == "" {
		redirectWithFlash(w, r, editPath, "", "egress: IP required when mode is fixed")
		return
	}
	if outboundIP != "" && net.ParseIP(outboundIP) == nil {
		redirectWithFlash(w, r, editPath, "", "egress: invalid IP address")
		return
	}
	// Reject fixed IP that is not in the node's inventory (prevents source-IP spoof).
	// If the inventory is absent/empty, skip the membership check for backward compat.
	if outboundIPMode == "fixed" && outboundIP != "" {
		var nodeIPsJSON sql.NullString
		_ = h.DB().QueryRowContext(r.Context(),
			`SELECT n.outbound_ips FROM routes r JOIN caddy_nodes n ON n.id = r.caddy_node_id WHERE r.id = ?`, id,
		).Scan(&nodeIPsJSON)
		if nodeIPsJSON.Valid && nodeIPsJSON.String != "" && nodeIPsJSON.String != "[]" {
			var nodeIPs []string
			if err2 := json.Unmarshal([]byte(nodeIPsJSON.String), &nodeIPs); err2 != nil || len(nodeIPs) == 0 {
				// Corrupt or empty JSON with non-empty string - treat as non-empty inventory with no match.
				redirectWithFlash(w, r, editPath, "", "egress: IP not in node's outbound_ips inventory")
				return
			}
			found := false
			for _, nip := range nodeIPs {
				if nip == outboundIP {
					found = true
					break
				}
			}
			if !found {
				redirectWithFlash(w, r, editPath, "", "egress: IP not in node's outbound_ips inventory")
				return
			}
		}
	}
	// random mode: clear outbound_ip (resolved at build time from node inventory).
	if outboundIPMode == "random" {
		outboundIP = ""
	} else if outboundIPMode != "fixed" {
		outboundIP = ""
	}

	// DNS controls: optional custom resolver IP or WG peer, plus address-family.
	dnsResolverIP := strings.TrimSpace(r.FormValue("dns_resolver_ip"))
	if dnsResolverIP != "" {
		ip := net.ParseIP(dnsResolverIP)
		if ip == nil {
			redirectWithFlash(w, r, editPath, "", "DNS resolver: must be a valid IP address (IPv4 or IPv6)")
			return
		}
		// Block loopback/link-local/unspecified to limit SSRF via the test
		// endpoint; RFC1918 stays allowed (resolvers live on the WG mesh).
		if security.IsDangerousProxyBackend(ip) {
			redirectWithFlash(w, r, editPath, "", "DNS resolver: loopback, link-local and unspecified addresses are not allowed")
			return
		}
	}
	dnsResolverViaWGID, _ := strconv.ParseInt(r.FormValue("dns_resolver_via_wg_peer_id"), 10, 64)
	// Mutual exclusion: direct IP beats peer; clear peer when IP is set.
	if dnsResolverIP != "" {
		dnsResolverViaWGID = 0
	}
	dnsAddressFamily := r.FormValue("dns_address_family")
	switch dnsAddressFamily {
	case "ipv4", "ipv6":
	default:
		dnsAddressFamily = "any"
	}

	groupID, _ := strconv.ParseInt(r.FormValue("group_id"), 10, 64)

	cacheTTL, _ := strconv.Atoi(r.FormValue("cache_ttl_secs"))
	if cacheTTL <= 0 {
		cacheTTL = 60
	}
	tag := strings.TrimSpace(r.FormValue("tag"))
	if len(tag) > 64 {
		tag = tag[:64]
	}
	headersRaw := r.FormValue("custom_headers")
	maintenanceMode := r.FormValue("maintenance_mode") == "1"
	maintenanceMsg := strings.TrimSpace(r.FormValue("maintenance_message"))
	if len(maintenanceMsg) > 500 {
		maintenanceMsg = maintenanceMsg[:500]
	}
	// Per-route error/maintenance page override (admin-only). HTML capped at
	// 100 KB and stored verbatim (rendered as static_response body, not templated).
	errOverride := r.FormValue("error_override") == "1"
	errHTML := r.FormValue("error_html")
	if len(errHTML) > 100*1024 {
		errHTML = errHTML[:100*1024]
	}
	errLogoURL := strings.TrimSpace(r.FormValue("error_logo_url"))
	errBrand := strings.TrimSpace(r.FormValue("error_brand"))
	if len(errBrand) > 128 {
		errBrand = errBrand[:128]
	}
	errBgColor := strings.TrimSpace(r.FormValue("error_bg_color"))
	if len(errBgColor) > 32 {
		errBgColor = errBgColor[:32]
	}
	// Same validation the node-wide branding path enforces (admin_branding.go):
	// error_logo_url lands in <img src> and error_bg_color is spliced into an
	// inline <style> block on the Caddy error page, so reject non-http(s) URLs
	// and unsafe CSS colours instead of only length-capping.
	if errLogoURL != "" && !isHTTPURL(errLogoURL) {
		redirectWithFlash(w, r, "/admin/hosts/"+strconv.FormatInt(id, 10)+"/edit", "", "error logo URL must be http(s)://")
		return
	}
	if errBgColor != "" && !isSafeCSSColor(errBgColor) {
		redirectWithFlash(w, r, "/admin/hosts/"+strconv.FormatInt(id, 10)+"/edit", "", "error background must be #RGB / #RRGGBB / #RRGGBBAA or rgb()/rgba()")
		return
	}
	cacheVary := sanitizeHeaderList(r.FormValue("cache_vary"))
	accessAllow, err1 := sanitizeCIDRList(r.FormValue("access_allow"))
	if err1 != nil {
		redirectWithFlash(w, r, "/admin/hosts/"+strconv.FormatInt(id, 10)+"/edit", "", "allow list: "+sanitizeErr(err1))
		return
	}
	accessDeny, err2 := sanitizeCIDRList(r.FormValue("access_deny"))
	if err2 != nil {
		redirectWithFlash(w, r, "/admin/hosts/"+strconv.FormatInt(id, 10)+"/edit", "", "deny list: "+sanitizeErr(err2))
		return
	}
	accessBlockAll := r.FormValue("access_block_all") == "1"
	maintenanceAllow, errMA := sanitizeCIDRList(r.FormValue("maintenance_allow"))
	if errMA != nil {
		redirectWithFlash(w, r, "/admin/hosts/"+strconv.FormatInt(id, 10)+"/edit", "", "maintenance allow: "+sanitizeErr(errMA))
		return
	}
	ssoPaths := sanitizePathList(r.FormValue("sso_paths"))
	ssoHosts := sanitizeHostList(r.FormValue("sso_hosts"))
	ssoViaPeerID, _ := strconv.ParseInt(r.FormValue("sso_via_wg_peer_id"), 10, 64)
	ssoStrictMode := r.FormValue("sso_strict_mode") == "1"
	// Built-in portal toggle + selected group IDs.
	portalProtect := r.FormValue("portal_protect") == "1"
	var portalGroupIDs []int64
	for _, v := range r.Form["portal_group_ids"] {
		if gid, perr := strconv.ParseInt(v, 10, 64); perr == nil && gid > 0 {
			portalGroupIDs = append(portalGroupIDs, gid)
		}
	}
	customCfg, err3 := sanitizeCustomConfig(r.FormValue("custom_config"))
	if err3 != nil {
		redirectWithFlash(w, r, "/admin/hosts/"+strconv.FormatInt(id, 10)+"/edit", "", "custom config: "+sanitizeErr(err3))
		return
	}
	aliases, errAli := sanitizeAliases(r.FormValue("aliases"), domain)
	if errAli != nil {
		redirectWithFlash(w, r, "/admin/hosts/"+strconv.FormatInt(id, 10)+"/edit", "", "aliases: "+sanitizeErr(errAli))
		return
	}
	// Basic auth: empty user/pass disables the gate; non-empty user + new
	// password triggers fresh bcrypt + base64 (Caddy http_basic format).
	// User can change just the username (keep password) by leaving the
	// password field empty + ticking 'Keep current password'.
	ssoProviderURL := strings.TrimSpace(r.FormValue("sso_provider_url"))
	ssoCopyHeaders := strings.TrimSpace(r.FormValue("sso_copy_headers"))
	ssoTrustedProxies := strings.TrimSpace(r.FormValue("sso_trusted_proxies"))
	// trusted_proxies feeds Caddy forward_auth; a malformed entry fails the
	// whole /load and wedges the node's resync. Validate as IPs or CIDRs.
	if ssoTrustedProxies != "" {
		for _, p := range strings.Fields(strings.ReplaceAll(ssoTrustedProxies, ",", " ")) {
			if _, _, errCIDR := net.ParseCIDR(p); errCIDR != nil && net.ParseIP(p) == nil {
				redirectWithFlash(w, r, "/admin/hosts/"+strconv.FormatInt(id, 10)+"/edit", "", "sso trusted proxies must be IPs or CIDRs")
				return
			}
		}
	}
	var ssoProviderURLVal, ssoCopyHeadersVal, ssoTrustedProxiesVal sql.NullString
	if ssoProviderURL != "" {
		ssoProviderURLVal = sql.NullString{String: ssoProviderURL, Valid: true}
	}
	if ssoCopyHeaders != "" {
		ssoCopyHeadersVal = sql.NullString{String: ssoCopyHeaders, Valid: true}
	}
	if ssoTrustedProxies != "" {
		ssoTrustedProxiesVal = sql.NullString{String: ssoTrustedProxies, Valid: true}
	}
	basicUser := strings.TrimSpace(r.FormValue("basic_auth_user"))
	basicPass := r.FormValue("basic_auth_pass")
	keepPass := r.FormValue("basic_auth_keep") == "1"
	var basicHashUpdate sql.NullString
	var basicUserUpdate sql.NullString
	if len(basicUser) > 64 {
		basicUser = basicUser[:64]
	}
	if basicUser == "" {
		// Clearing user clears the whole gate.
		basicUserUpdate = sql.NullString{}
		basicHashUpdate = sql.NullString{}
	} else {
		basicUserUpdate = sql.NullString{String: basicUser, Valid: true}
		if !keepPass && basicPass != "" {
			hashBytes, herr := bcryptHash([]byte(basicPass))
			if herr != nil {
				redirectWithFlash(w, r, "/admin/hosts/"+strconv.FormatInt(id, 10)+"/edit", "", "basic auth hash: "+sanitizeErr(herr))
				return
			}
			b64 := base64.StdEncoding.EncodeToString(hashBytes)
			basicHashUpdate = sql.NullString{String: b64, Valid: true}
		} else if !keepPass && basicPass == "" {
			// User typed name but no password - refuse (otherwise we'd
			// silently wipe the existing hash and lock the operator out
			// of an unauthenticated route).
			redirectWithFlash(w, r, "/admin/hosts/"+strconv.FormatInt(id, 10)+"/edit", "", "basic auth: password required (or tick 'keep current')")
			return
		} else {
			// keepPass==true: leave hash column alone - handled via separate
			// UPDATE branch below.
		}
	}

	if domain == "" {
		redirectWithFlash(w, r, "/admin/hosts/"+strconv.FormatInt(id, 10)+"/edit", "", "domain required")
		return
	}
	if kind == "proxy" && !external && (port <= 0 || port > 65535) {
		redirectWithFlash(w, r, "/admin/hosts/"+strconv.FormatInt(id, 10)+"/edit", "", "port invalid for proxy route")
		return
	}
	if kind == "proxy" && !external && backendIP != "" && !isValidUpstreamHost(backendIP) {
		redirectWithFlash(w, r, "/admin/hosts/"+strconv.FormatInt(id, 10)+"/edit", "", "backend must be a valid IP or hostname")
		return
	}
	// Tunnel + hostname auto-coerce: instead of rejecting the whole save
	// (which would also drop scheme/header/SSO changes the admin made in
	// the same form), silently clear the hostname → backend_ip_override
	// stays NULL → build path falls back to peer IP. Defence-in-depth in
	// routes/service.go already does the same at push time; doing it here
	// too keeps the UI honest about what got persisted.
	viaPeerPreview, _ := strconv.ParseInt(r.FormValue("via_wg_peer_id"), 10, 64)
	if kind == "proxy" && backendIP != "" && viaPeerPreview > 0 && net.ParseIP(backendIP) == nil {
		h.Logger.Info("host save: dropping hostname backend with tunnel set (peer IP will be used)",
			"route_id", id, "dropped", backendIP)
		backendIP = ""
	}
	upstreamScheme := strings.TrimSpace(r.FormValue("upstream_scheme"))
	if upstreamScheme != "https" {
		upstreamScheme = "http"
	}
	upstreamSkipTLS := r.FormValue("upstream_skip_tls_verify") == "1"
	viaPeerID, _ := strconv.ParseInt(r.FormValue("via_wg_peer_id"), 10, 64)
	if external {
		editPath := "/admin/hosts/" + strconv.FormatInt(id, 10) + "/edit"
		// MUTUAL EXCLUSION: an external route must NOT be bound to a WG peer -
		// binding one would NULL backend_ip_override (the FQDN) and break it.
		if viaPeerID > 0 {
			redirectWithFlash(w, r, editPath, "", "external upstream cannot also use a WG tunnel - clear 'Backend via'")
			return
		}
		// Allowlist check (Service + build path re-check; defense in depth).
		if !h.Routes.ExternalHostAllowed(externalHost) {
			redirectWithFlash(w, r, editPath, "", "external host must be in EXTERNAL_UPSTREAM_ALLOWLIST")
			return
		}
		// Force the route shape (mirrors Create).
		upstreamScheme = "https"
		ssl = true
		if port == 0 {
			port = 443
		}
		if extHostHeader == "" {
			extHostHeader = externalHost
		}
	}
	// Cross-tenant + node-topology guard: tunnel must belong to the same
	// client that owns the route's service AND live on the same Caddy
	// node as the route. The second check matters because wg-tun0 only
	// exists on the tunnel's home node - pointing a route on node A at a
	// peer on node B would yield 502s once Caddy tries to dial the
	// tunnel IP through a nonexistent interface.
	if viaPeerID > 0 {
		gctx, gcancel := context.WithTimeout(r.Context(), 2*time.Second)
		var owns int
		_ = h.DB().QueryRowContext(gctx,
			`SELECT COUNT(*) FROM customer_wg_peer p
			   JOIN routes r ON r.id = ?
			   JOIN services s ON s.id = r.service_id
			  WHERE p.id = ?
			    AND p.client_id = s.client_id
			    AND p.node_id   = r.caddy_node_id
			    AND p.status <> 'revoked'`,
			id, viaPeerID).Scan(&owns)
		gcancel()
		if owns == 0 {
			redirectWithFlash(w, r, "/admin/hosts/"+strconv.FormatInt(id, 10)+"/edit", "", "selected tunnel must belong to this route's client AND its assigned Caddy node")
			return
		}
	}
	if ssoViaPeerID > 0 {
		gctx, gcancel := context.WithTimeout(r.Context(), 2*time.Second)
		var owns int
		_ = h.DB().QueryRowContext(gctx,
			`SELECT COUNT(*) FROM customer_wg_peer p
			   JOIN routes r ON r.id = ?
			   JOIN services s ON s.id = r.service_id
			  WHERE p.id = ?
			    AND p.client_id = s.client_id
			    AND p.node_id   = r.caddy_node_id
			    AND p.status <> 'revoked'`,
			id, ssoViaPeerID).Scan(&owns)
		gcancel()
		if owns == 0 {
			redirectWithFlash(w, r, "/admin/hosts/"+strconv.FormatInt(id, 10)+"/edit", "", "selected SSO tunnel must belong to this route's client AND its assigned Caddy node")
			return
		}
	}
	// IDOR guard: DNS resolver peer must belong to the same client/node as this route.
	if dnsResolverViaWGID > 0 {
		gctx, gcancel := context.WithTimeout(r.Context(), 2*time.Second)
		var owns int
		_ = h.DB().QueryRowContext(gctx,
			`SELECT COUNT(*) FROM customer_wg_peer p
			   JOIN routes r ON r.id = ?
			   JOIN services s ON s.id = r.service_id
			  WHERE p.id = ?
			    AND p.client_id = s.client_id
			    AND p.node_id   = r.caddy_node_id
			    AND p.status <> 'revoked'`,
			id, dnsResolverViaWGID).Scan(&owns)
		gcancel()
		if owns == 0 {
			redirectWithFlash(w, r, "/admin/hosts/"+strconv.FormatInt(id, 10)+"/edit", "", "selected DNS tunnel must belong to this route's client AND its assigned Caddy node")
			return
		}
	}
	if kind == "redirect" && redirectURL == "" {
		redirectWithFlash(w, r, "/admin/hosts/"+strconv.FormatInt(id, 10)+"/edit", "", "redirect URL required for redirect route")
		return
	}
	if kind == "redirect" {
		if redirectCode == 0 {
			redirectCode = 308
		}
		switch redirectCode {
		case 301, 302, 307, 308:
		default:
			redirectWithFlash(w, r, "/admin/hosts/"+strconv.FormatInt(id, 10)+"/edit", "", "redirect_code must be 301/302/307/308")
			return
		}
	}

	headersJSON := parseHeaderLines(headersRaw)

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	var nodeID, serviceID int64
	var currentBackendIP string
	var prevOverride sql.NullString
	var prevRequireClientCert bool
	if err := h.DB().QueryRowContext(ctx,
		`SELECT r.caddy_node_id, r.service_id, s.backend_ip, r.backend_ip_override,
		        COALESCE(r.require_client_cert, 0)
		 FROM routes r JOIN services s ON s.id = r.service_id
		 WHERE r.id = ?`, id,
	).Scan(&nodeID, &serviceID, &currentBackendIP, &prevOverride, &prevRequireClientCert); err != nil {
		redirectWithFlash(w, r, "/admin/hosts", "", "route not found")
		return
	}

	// Backend edits are PER-ROUTE via routes.backend_ip_override so editing
	// one route does NOT cascade to siblings sharing the same service.
	// Always write the override on save (not gated by diff vs current view
	// value) so clearing the field reliably resets to NULL. Redirect-kind
	// routes never need an override - clear it so a future kind flip
	// doesn't restore stale data.
	var newOverride sql.NullString
	switch {
	case external:
		// External route: the override column carries the upstream FQDN.
		newOverride = sql.NullString{String: externalHost, Valid: true}
	case kind == "proxy" && backendIP != "":
		newOverride = sql.NullString{String: backendIP, Valid: true}
	}
	if _, err := h.DB().ExecContext(ctx,
		"UPDATE routes SET backend_ip_override = ? WHERE id = ?", newOverride, id); err != nil {
		h.Logger.Warn("host update: route backend_ip_override", "route_id", id, "err", err)
		redirectWithFlash(w, r, "/admin/hosts/"+strconv.FormatInt(id, 10)+"/edit", "", "backend IP update failed")
		return
	}
	// Audit on EFFECTIVE-backend change. Prev = prior override if set else
	// service backend. New = new override if set else service backend.
	// This catches override clears (override→null falls back to service)
	// and audits stale-override drops on kind=redirect, which the simple
	// `backendIP != currentBackendIP` gate would silently miss.
	prevEffective := currentBackendIP
	if prevOverride.Valid && prevOverride.String != "" {
		prevEffective = prevOverride.String
	}
	newEffective := currentBackendIP
	if newOverride.Valid && newOverride.String != "" {
		newEffective = newOverride.String
	}
	if prevEffective != newEffective {
		audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
			UserID: actorUserID(sess), Action: "admin.route.backend_ip.change", Entity: "route",
			EntityID: itoa64(id),
			Meta:     map[string]any{"old": prevEffective, "new": newEffective},
		})
	}
	_ = serviceID

	var tagVal sql.NullString
	if tag != "" {
		tagVal = sql.NullString{String: tag, Valid: true}
	}
	var redirURLVal sql.NullString
	if redirectURL != "" {
		redirURLVal = sql.NullString{String: redirectURL, Valid: true}
	}
	var redirCodeVal sql.NullInt32
	if kind == "redirect" {
		redirCodeVal = sql.NullInt32{Int32: int32(redirectCode), Valid: true}
	}
	var headersVal sql.NullString
	if headersJSON != "" {
		headersVal = sql.NullString{String: headersJSON, Valid: true}
	}
	var maintMsgVal sql.NullString
	if maintenanceMsg != "" {
		maintMsgVal = sql.NullString{String: maintenanceMsg, Valid: true}
	}
	var cacheVaryVal sql.NullString
	if cacheVary != "" {
		cacheVaryVal = sql.NullString{String: cacheVary, Valid: true}
	}
	var accessAllowVal, accessDenyVal, customCfgVal, aliasesVal sql.NullString
	var maintAllowVal, ssoPathsVal, ssoHostsVal sql.NullString
	if accessAllow != "" {
		accessAllowVal = sql.NullString{String: accessAllow, Valid: true}
	}
	if accessDeny != "" {
		accessDenyVal = sql.NullString{String: accessDeny, Valid: true}
	}
	if customCfg != "" {
		customCfgVal = sql.NullString{String: customCfg, Valid: true}
	}
	if aliases != "" {
		aliasesVal = sql.NullString{String: aliases, Valid: true}
	}
	if maintenanceAllow != "" {
		maintAllowVal = sql.NullString{String: maintenanceAllow, Valid: true}
	}
	if ssoPaths != "" {
		ssoPathsVal = sql.NullString{String: ssoPaths, Valid: true}
	}
	if ssoHosts != "" {
		ssoHostsVal = sql.NullString{String: ssoHosts, Valid: true}
	}

	// External upstream columns. proxy_secret_enc is NEVER written here (only
	// Create or the regenerate endpoint set it), so a normal edit can't wipe
	// the bearer. When not external, host_header is cleared to NULL.
	var extHostHeaderVal sql.NullString
	if external && extHostHeader != "" {
		extHostHeaderVal = sql.NullString{String: extHostHeader, Valid: true}
	}

	// Load host custom field defs and encode submitted values for this update.
	cfDefs, _ := customfields.LoadDefs(ctx, h.DB(), "host")
	cfJSON, cfErr := customfields.EncodeFromForm(cfDefs, r.Form)
	if cfErr != nil {
		redirectWithFlash(w, r, "/admin/hosts/"+strconv.FormatInt(id, 10)+"/edit", "", cfErr.Error())
		return
	}
	var cfVal sql.NullString
	if cfJSON != "" {
		cfVal = sql.NullString{String: cfJSON, Valid: true}
	}

	// Two UPDATE branches: when 'keep current password' is ticked we
	// must NOT touch basic_auth_bcrypt. Cleanest split is two queries.
	var err error
	if basicUser != "" && keepPass {
		_, err = h.DB().ExecContext(ctx,
			`UPDATE routes SET
			   domain = ?, aliases = ?, path_prefix = ?, upstream_port = ?, upstream_scheme = ?, upstream_skip_tls_verify = ?,
			   upstream_external = ?, upstream_host_header = ?,
			   via_wg_peer_id = ?,
			   kind = ?, redirect_url = ?, redirect_code = ?,
			   ssl_enabled = ?, force_https = ?, websocket = ?,
			   http2_enabled = ?, http3_enabled = ?,
			   cache_enabled = ?, cache_ttl_secs = ?,
			   compress_disabled = ?,
			   lb_policy = ?, lb_header_field = ?, lb_cookie_name = ?, lb_cookie_secret = ?,
			   health_active_uri = ?, health_active_interval = ?, health_active_timeout = ?,
			   health_active_status = ?, health_active_fails = ?,
			   health_passive_enabled = ?, health_passive_fail_dur = ?, health_passive_max_fail = ?,
			   lb_try_duration_ms = ?, lb_try_interval_ms = ?,
			   dial_timeout_ms = ?, response_header_timeout_ms = ?,
			   rate_enabled = ?, rate_window = ?, rate_max_events = ?, rate_key = ?,
			   waf_enabled = ?, waf_blocking = ?, waf_directives = ?,
			   geo_mode = ?, geo_countries = ?,
			   geo_response_code = ?, geo_fail_closed = ?, geo_allow_cidrs = ?,
			   geo_continents = ?, geo_block_cidrs = ?,
			   require_client_cert = ?, mtls_ca_id = ?,
			   wildcard_enabled = ?, wildcard_zone = ?,
			   custom_headers = ?, tag = ?,
			   maintenance_mode = ?, maintenance_message = ?,
			   error_override = ?, error_html = ?, error_logo_url = ?, error_brand = ?, error_bg_color = ?,
			   cache_vary = ?,
			   access_allow = ?, access_deny = ?,
			   access_block_all = ?, maintenance_allow = ?,
			   custom_config = ?,
			   basic_auth_user = ?,
			   sso_provider_url = ?, sso_copy_headers = ?, sso_trusted_proxies = ?,
			   sso_paths = ?, sso_hosts = ?, sso_via_wg_peer_id = ?, sso_strict_mode = ?,
			   outbound_ip_mode = ?, outbound_ip = ?,
			   dns_resolver_ip = ?, dns_resolver_via_wg_peer_id = ?, dns_address_family = ?,
			   group_id = NULLIF(?, 0),
			   custom_fields = ?,
			   updated_at = NOW()
			 WHERE id = ?`,
			domain, aliasesVal, pathPrefix, port, upstreamScheme, upstreamSkipTLS,
			external, extHostHeaderVal,
			nullableInt64(viaPeerID),
			kind, redirURLVal, redirCodeVal,
			ssl, forceHTTPS, websocket,
			http2, http3,
			cacheEnabled, cacheTTL,
			compressDisabled,
			lbPolicy, lbHeaderField, lbCookieName, lbCookieSecret,
			healthURI, healthInterval, healthTimeout,
			healthStatus, healthFails,
			healthPassive, healthFailDur, healthMaxFails,
			lbTryDurationMs, lbTryIntervalMs,
			dialTimeoutMs, responseHeaderTimeoutMs,
			rateEnabled, rateWindow, rateMaxEvents, rateKey,
			wafEnabled, wafBlocking, wafDirectives,
			geoMode, geoCountries,
			geoResponseCodeRaw, geoFailClosed, geoAllowCIDRs,
			geoContinents, geoBlockCIDRs,
			requireClientCert, nullableInt64(mtlsCAID),
			wildcardEnabled, wildcardZone,
			headersVal, tagVal,
			maintenanceMode, maintMsgVal,
			errOverride, errHTML, errLogoURL, errBrand, errBgColor,
			cacheVaryVal,
			accessAllowVal, accessDenyVal,
			accessBlockAll, maintAllowVal,
			customCfgVal,
			basicUserUpdate,
			ssoProviderURLVal, ssoCopyHeadersVal, ssoTrustedProxiesVal,
			ssoPathsVal, ssoHostsVal, nullableInt64(ssoViaPeerID), ssoStrictMode,
			outboundIPMode, nullableString(outboundIP),
			nullableString(dnsResolverIP), nullableInt64(dnsResolverViaWGID), dnsAddressFamily,
			groupID,
			cfVal,
			id)
	} else {
		_, err = h.DB().ExecContext(ctx,
			`UPDATE routes SET
			   domain = ?, aliases = ?, path_prefix = ?, upstream_port = ?, upstream_scheme = ?, upstream_skip_tls_verify = ?,
			   upstream_external = ?, upstream_host_header = ?,
			   via_wg_peer_id = ?,
			   kind = ?, redirect_url = ?, redirect_code = ?,
			   ssl_enabled = ?, force_https = ?, websocket = ?,
			   http2_enabled = ?, http3_enabled = ?,
			   cache_enabled = ?, cache_ttl_secs = ?,
			   compress_disabled = ?,
			   lb_policy = ?, lb_header_field = ?, lb_cookie_name = ?, lb_cookie_secret = ?,
			   health_active_uri = ?, health_active_interval = ?, health_active_timeout = ?,
			   health_active_status = ?, health_active_fails = ?,
			   health_passive_enabled = ?, health_passive_fail_dur = ?, health_passive_max_fail = ?,
			   lb_try_duration_ms = ?, lb_try_interval_ms = ?,
			   dial_timeout_ms = ?, response_header_timeout_ms = ?,
			   rate_enabled = ?, rate_window = ?, rate_max_events = ?, rate_key = ?,
			   waf_enabled = ?, waf_blocking = ?, waf_directives = ?,
			   geo_mode = ?, geo_countries = ?,
			   geo_response_code = ?, geo_fail_closed = ?, geo_allow_cidrs = ?,
			   geo_continents = ?, geo_block_cidrs = ?,
			   require_client_cert = ?, mtls_ca_id = ?,
			   wildcard_enabled = ?, wildcard_zone = ?,
			   custom_headers = ?, tag = ?,
			   maintenance_mode = ?, maintenance_message = ?,
			   error_override = ?, error_html = ?, error_logo_url = ?, error_brand = ?, error_bg_color = ?,
			   cache_vary = ?,
			   access_allow = ?, access_deny = ?,
			   access_block_all = ?, maintenance_allow = ?,
			   custom_config = ?,
			   basic_auth_user = ?, basic_auth_bcrypt = ?,
			   sso_provider_url = ?, sso_copy_headers = ?, sso_trusted_proxies = ?,
			   sso_paths = ?, sso_hosts = ?, sso_via_wg_peer_id = ?, sso_strict_mode = ?,
			   outbound_ip_mode = ?, outbound_ip = ?,
			   dns_resolver_ip = ?, dns_resolver_via_wg_peer_id = ?, dns_address_family = ?,
			   group_id = NULLIF(?, 0),
			   custom_fields = ?,
			   updated_at = NOW()
			 WHERE id = ?`,
			domain, aliasesVal, pathPrefix, port, upstreamScheme, upstreamSkipTLS,
			external, extHostHeaderVal,
			nullableInt64(viaPeerID),
			kind, redirURLVal, redirCodeVal,
			ssl, forceHTTPS, websocket,
			http2, http3,
			cacheEnabled, cacheTTL,
			compressDisabled,
			lbPolicy, lbHeaderField, lbCookieName, lbCookieSecret,
			healthURI, healthInterval, healthTimeout,
			healthStatus, healthFails,
			healthPassive, healthFailDur, healthMaxFails,
			lbTryDurationMs, lbTryIntervalMs,
			dialTimeoutMs, responseHeaderTimeoutMs,
			rateEnabled, rateWindow, rateMaxEvents, rateKey,
			wafEnabled, wafBlocking, wafDirectives,
			geoMode, geoCountries,
			geoResponseCodeRaw, geoFailClosed, geoAllowCIDRs,
			geoContinents, geoBlockCIDRs,
			requireClientCert, nullableInt64(mtlsCAID),
			wildcardEnabled, wildcardZone,
			headersVal, tagVal,
			maintenanceMode, maintMsgVal,
			errOverride, errHTML, errLogoURL, errBrand, errBgColor,
			cacheVaryVal,
			accessAllowVal, accessDenyVal,
			accessBlockAll, maintAllowVal,
			customCfgVal,
			basicUserUpdate, basicHashUpdate,
			ssoProviderURLVal, ssoCopyHeadersVal, ssoTrustedProxiesVal,
			ssoPathsVal, ssoHostsVal, nullableInt64(ssoViaPeerID), ssoStrictMode,
			outboundIPMode, nullableString(outboundIP),
			nullableString(dnsResolverIP), nullableInt64(dnsResolverViaWGID), dnsAddressFamily,
			groupID,
			cfVal,
			id)
	}
	if err != nil {
		if strings.Contains(err.Error(), "Duplicate entry") {
			redirectWithFlash(w, r, "/admin/hosts/"+strconv.FormatInt(id, 10)+"/edit", "", "another route already owns this domain+path")
			return
		}
		h.Logger.Warn("host update", "id", id, "err", err)
		redirectWithFlash(w, r, "/admin/hosts/"+strconv.FormatInt(id, 10)+"/edit", "", "update failed")
		return
	}
	// Audit mTLS enforcement toggle when require_client_cert changed.
	if prevRequireClientCert != requireClientCert {
		audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
			UserID: actorUserID(sess), Action: "host.mtls_enforcement_changed", Entity: "route",
			EntityID: itoa64(id),
			Meta:     map[string]any{"enabled": requireClientCert},
		})
	}
	// Rewrite child collections atomically (DELETE+INSERT in a tx) so a partial
	// failure can't leave an empty upstream pool or half-applied location rules.
	if tx, txErr := h.DB().BeginTx(ctx, nil); txErr == nil {
		_, e1 := tx.ExecContext(ctx, `DELETE FROM route_upstreams WHERE route_id = ?`, id)
		var e2 error
		for i, u := range newUpstreams {
			enInt := 0
			if u.Enabled {
				enInt = 1
			}
			// Per-upstream passive health columns are left at their defaults:
			// stock Caddy cannot honor them, so the UI no longer sets them.
			if _, e2 = tx.ExecContext(ctx,
				`INSERT INTO route_upstreams
				 (route_id, host, port, weight, max_requests, enabled, sort_order)
				 VALUES (?, ?, ?, ?, ?, ?, ?)`,
				id, u.Host, u.Port, u.Weight, u.MaxRequests, enInt, i); e2 != nil {
				break
			}
		}
		_, e3 := tx.ExecContext(ctx, `DELETE FROM route_location_rules WHERE route_id = ?`, id)
		var e4 error
		for i, rule := range newLocationRules {
			if _, e4 = tx.ExecContext(ctx,
				`INSERT INTO route_location_rules
				 (route_id, sort_order, path_glob, action, upstream_scheme, upstream_host, upstream_port, redirect_url, redirect_code, rewrite_uri)
				 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				id, i, rule.Path, rule.Action, rule.UpstreamScheme, nullableString(rule.UpstreamHost), nullableInt(rule.UpstreamPort),
				nullableString(rule.RedirectURL), rule.RedirectCode, nullableString(rule.RewriteURI)); e4 != nil {
				break
			}
		}
		if e1 != nil || e2 != nil || e3 != nil || e4 != nil {
			_ = tx.Rollback()
			h.Logger.Warn("host child rules rewrite failed", "id", id, "err", firstErr(e1, e2, e3, e4))
		} else {
			_ = tx.Commit()
		}
	}
	// Built-in portal: persist the toggle + replace grants. Scope-safe -
	// SetRouteGrants only writes group IDs the caller is allowed to reference
	// (groups owned by the route's client, plus globals for super_admin), so a
	// scoped admin cannot grant another tenant's group via a forged form post.
	if h.Portal != nil {
		if _, perr := h.DB().ExecContext(ctx,
			`UPDATE routes SET portal_protect = ? WHERE id = ?`, portalProtect, id); perr != nil {
			h.Logger.Warn("portal_protect update", "id", id, "err", perr)
		}
		var portalClientID int64
		_ = h.DB().QueryRowContext(ctx, `SELECT client_id FROM services WHERE id = ?`, serviceID).Scan(&portalClientID)
		includeGlobal := sess != nil && sess.Role == "super_admin"
		visible := map[int64]bool{}
		if grps, gerr := h.Portal.GroupsForGrant(ctx, portalClientID, includeGlobal); gerr == nil {
			for _, g := range grps {
				visible[g.ID] = true
			}
		}
		if gerr := h.Portal.SetRouteGrants(ctx, id, portalGroupIDs, visible, false); gerr != nil {
			h.Logger.Warn("portal grants update", "id", id, "err", gerr)
		}
		audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
			UserID: actorUserID(sess), Action: "portal.route.grants", Entity: "route", EntityID: itoa64(id),
			Meta: map[string]any{"protect": portalProtect, "groups": portalGroupIDs},
		})
	}

	go func() {
		defer recoverBg(h.Logger, "resync")
		ctx, cancel := context.WithTimeout(h.Routes.BackgroundCtx(), 30*time.Second)
		defer cancel()
		_ = h.Routes.Resync(ctx, nodeID)
	}()

	audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "admin.host.update", Entity: "route",
		EntityID: itoa64(id),
		Meta: map[string]any{
			"domain": domain, "kind": kind, "tag": tag,
			"ssl": ssl, "force_https": forceHTTPS, "websocket": websocket,
			"cache_enabled":    cacheEnabled,
			"maintenance_mode": maintenanceMode,
			"location_rules":   len(newLocationRules),
		},
	})
	// Stay on the edit page (preserving the active tab via #fragment so the
	// admin doesn't lose context after every save).
	dest := "/admin/hosts/" + strconv.FormatInt(id, 10) + "/edit"
	if tab := strings.TrimSpace(r.FormValue("active_tab")); isTabSlug(tab) {
		dest += "#tab=" + tab
	}
	redirectWithFlash(w, r, dest, "Host updated", "")
}

// HostsRegenerateSecret rotates the inbound bearer for an external-upstream
// route. Only the AES-GCM ciphertext is stored and it is never logged
// (secret never logged); the new plaintext is recoverable via the audited
// Reveal button, never spliced into a redirect URL.
func (h *AdminHandlers) HostsRegenerateSecret(w http.ResponseWriter, r *http.Request) {
	if h.Routes == nil || h.DB() == nil {
		http.Error(w, "not ready", http.StatusServiceUnavailable)
		return
	}
	sess := middleware.SessionFromContext(r.Context())
	id, _ := strconv.ParseInt(chiURLParamHosts(r, "id"), 10, 64)
	edit := "/admin/hosts/" + strconv.FormatInt(id, 10) + "/edit"
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	var external bool
	var nodeID int64
	if err := h.DB().QueryRowContext(ctx,
		"SELECT COALESCE(upstream_external,0), caddy_node_id FROM routes WHERE id = ?", id,
	).Scan(&external, &nodeID); err != nil {
		redirectWithFlash(w, r, "/admin/hosts", "", "route not found")
		return
	}
	if !external {
		redirectWithFlash(w, r, edit, "", "not an external route")
		return
	}
	if h.Routes.EncryptSecret == nil {
		redirectWithFlash(w, r, edit, "", "secret encryption not configured")
		return
	}
	plain, err := genProxySecret()
	if err != nil {
		redirectWithFlash(w, r, edit, "", "secret generation failed")
		return
	}
	enc, err := h.Routes.EncryptSecret(plain)
	if err != nil {
		redirectWithFlash(w, r, edit, "", "secret encrypt failed")
		return
	}
	if _, err := h.DB().ExecContext(ctx,
		"UPDATE routes SET proxy_secret_enc = ?, updated_at = NOW() WHERE id = ?", enc, id); err != nil {
		redirectWithFlash(w, r, edit, "", "secret update failed")
		return
	}
	// Re-push so the node enforces the new bearer immediately.
	go func() {
		defer recoverBg(h.Logger, "resync")
		c, cn := context.WithTimeout(h.Routes.BackgroundCtx(), 30*time.Second)
		defer cn()
		_ = h.Routes.Resync(c, nodeID)
	}()
	audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "admin.host.regenerate_secret", Entity: "route",
		EntityID: itoa64(id), // never log the plaintext
	})
	redirectWithFlash(w, r, edit, "Bearer rotated. Click Reveal to copy the new inbound token.", "")
}

// HostsRevealSecret returns the current inbound bearer plaintext for an
// external-upstream route so the operator can copy it into their caller.
// Admin-only + CSRF + audited; decrypted from the AES-GCM ciphertext and never
// logged. Deliberate owner-only reveal of a recoverable (not hashed) secret.
func (h *AdminHandlers) HostsRevealSecret(w http.ResponseWriter, r *http.Request) {
	if h.Routes == nil || h.DB() == nil {
		http.Error(w, "not ready", http.StatusServiceUnavailable)
		return
	}
	sess := middleware.SessionFromContext(r.Context())
	id, _ := strconv.ParseInt(chiURLParamHosts(r, "id"), 10, 64)
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	var external bool
	var enc string
	if err := h.DB().QueryRowContext(ctx,
		"SELECT COALESCE(upstream_external,0), COALESCE(proxy_secret_enc,'') FROM routes WHERE id = ?", id,
	).Scan(&external, &enc); err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if !external || enc == "" {
		http.Error(w, "no bearer set", http.StatusNotFound)
		return
	}
	if h.Routes.DecryptSecret == nil {
		http.Error(w, "secret decryption not configured", http.StatusServiceUnavailable)
		return
	}
	plain, err := h.Routes.DecryptSecret(enc)
	if err != nil {
		http.Error(w, "decrypt failed", http.StatusInternalServerError)
		return
	}
	audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "admin.host.reveal_secret", Entity: "route",
		EntityID: itoa64(id), // never log the plaintext
	})
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]string{"secret": plain})
}

// loadClientTunnels returns the active WG peers for a single client,
// used to populate the "Backend via" dropdown on host edit.
func loadClientTunnels(ctx context.Context, db *sql.DB, clientID int64) []tunnelOption {
	if db == nil || clientID == 0 {
		return nil
	}
	rows, err := db.QueryContext(ctx,
		`SELECT id, name, assigned_ip
		 FROM customer_wg_peer
		 WHERE client_id = ? AND status <> 'revoked'
		 ORDER BY id DESC LIMIT 50`, clientID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []tunnelOption
	for rows.Next() {
		var t tunnelOption
		if err := rows.Scan(&t.ID, &t.Name, &t.AssignedIP); err == nil {
			out = append(out, t)
		}
	}
	return out
}

// nullableInt64 returns a sql.NullInt64 (0 → NULL) so the UPDATE
// statement sets via_wg_peer_id back to NULL when the operator clears
// the dropdown.
func nullableInt64(v int64) sql.NullInt64 {
	if v == 0 {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: v, Valid: true}
}

func nullableString(v string) sql.NullString {
	if v == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: v, Valid: true}
}

func nullableInt(v int) sql.NullInt64 {
	if v == 0 {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: int64(v), Valid: true}
}

func sanitizeLocationRules(form url.Values) ([]locationRuleRow, error) {
	paths := form["loc_path[]"]
	actions := form["loc_action[]"]
	schemes := form["loc_upstream_scheme[]"]
	hosts := form["loc_upstream_host[]"]
	ports := form["loc_upstream_port[]"]
	redirects := form["loc_redirect_url[]"]
	codes := form["loc_redirect_code[]"]
	rewrites := form["loc_rewrite_uri[]"]
	if len(paths) > 50 {
		return nil, fmt.Errorf("max 50 rules")
	}
	out := make([]locationRuleRow, 0, len(paths))
	for i, rawPath := range paths {
		path, err := sanitizeLocationPath(rawPath)
		if err != nil {
			return nil, err
		}
		if path == "" {
			continue
		}
		action := fieldAt(actions, i)
		switch action {
		case "", "proxy":
			action = "proxy"
		case "redirect", "block", "rewrite":
		default:
			return nil, fmt.Errorf("invalid action for %s", path)
		}
		scheme := fieldAt(schemes, i)
		if scheme != "https" {
			scheme = "http"
		}
		rule := locationRuleRow{
			Path:           path,
			Action:         action,
			UpstreamScheme: scheme,
			RedirectCode:   308,
		}
		switch action {
		case "proxy":
			rule.UpstreamHost = strings.TrimSpace(fieldAt(hosts, i))
			rule.UpstreamPort = atoiDefault(fieldAt(ports, i), 0)
			if !isValidUpstreamHost(rule.UpstreamHost) || rule.UpstreamPort < 1 || rule.UpstreamPort > 65535 {
				return nil, fmt.Errorf("%s proxy requires a valid host and port", path)
			}
		case "redirect":
			rule.RedirectURL = strings.TrimSpace(fieldAt(redirects, i))
			if rule.RedirectURL == "" {
				return nil, fmt.Errorf("%s redirect requires a destination", path)
			}
			if !(strings.HasPrefix(rule.RedirectURL, "http://") || strings.HasPrefix(rule.RedirectURL, "https://") || strings.HasPrefix(rule.RedirectURL, "/")) {
				return nil, fmt.Errorf("%s redirect destination must be http(s):// or /relative", path)
			}
			rule.RedirectCode = atoiDefault(fieldAt(codes, i), 308)
			switch rule.RedirectCode {
			case 301, 302, 307, 308:
			default:
				return nil, fmt.Errorf("%s redirect code must be 301/302/307/308", path)
			}
		case "rewrite":
			rule.RewriteURI = strings.TrimSpace(fieldAt(rewrites, i))
			if !strings.HasPrefix(rule.RewriteURI, "/") {
				return nil, fmt.Errorf("%s rewrite URI must start with /", path)
			}
			if len(rule.RewriteURI) > 1024 {
				return nil, fmt.Errorf("%s rewrite URI too long", path)
			}
		}
		out = append(out, rule)
	}
	return out, nil
}

func sanitizeLocationPath(raw string) (string, error) {
	path := strings.TrimSpace(raw)
	if path == "" {
		return "", nil
	}
	if strings.Contains(path, "://") || strings.ContainsAny(path, "?#") || strings.Contains(path, "..") {
		return "", fmt.Errorf("invalid path %q", raw)
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if len(path) > 255 {
		return "", fmt.Errorf("path too long")
	}
	if strings.Contains(path, "*") {
		if path != "/*" && !strings.HasSuffix(path, "/*") {
			return "", fmt.Errorf("wildcard must be a trailing /* in %q", raw)
		}
		if strings.Count(path, "*") > 1 {
			return "", fmt.Errorf("only one wildcard is supported in %q", raw)
		}
		return path, nil
	}
	if path != "/" {
		path += "/*"
	}
	return path, nil
}

func fieldAt(values []string, i int) string {
	if i < 0 || i >= len(values) {
		return ""
	}
	return strings.TrimSpace(values[i])
}

// sanitizeAliases parses the operator-supplied alias textarea (comma /
// whitespace / semicolon separated), lowercases, dedupes, and validates
// each as a DNS hostname. Rejects entries equal to the primary domain so
// /ask lookups stay unambiguous.
func sanitizeAliases(raw, primary string) (string, error) {
	if strings.TrimSpace(raw) == "" {
		return "", nil
	}
	splitter := func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == ';'
	}
	out := make([]string, 0, 4)
	seen := map[string]bool{}
	for _, p := range strings.FieldsFunc(raw, splitter) {
		d := strings.ToLower(strings.TrimSpace(p))
		if d == "" || d == primary || seen[d] {
			continue
		}
		// Lightweight RFC1035 check: len 1..253, dot somewhere, no `..`,
		// only [a-z0-9.-], no leading/trailing dots or hyphens. Anything
		// stricter than this should be done in domain/routes/validDomain.
		if len(d) > 253 || !strings.Contains(d, ".") || strings.Contains(d, "..") {
			return "", fmt.Errorf("invalid alias %q", p)
		}
		for _, c := range d {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '-') {
				return "", fmt.Errorf("invalid alias %q", p)
			}
		}
		seen[d] = true
		out = append(out, d)
	}
	return strings.Join(out, ","), nil
}

// sanitizeHeaderList accepts an operator-supplied comma- or whitespace-
// separated header name list (e.g. "Accept-Encoding, Accept-Language")
// and returns a canonical comma-joined form with invalid chars stripped.
// Used by the cache_vary form field - Souin reads this list as the
// Vary-like cache-key contribution.
func sanitizeHeaderList(raw string) string {
	if strings.TrimSpace(raw) == "" {
		return ""
	}
	// Split on both commas and whitespace so admins can paste either form.
	splitter := func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	}
	out := make([]string, 0, 4)
	seen := map[string]bool{}
	for _, p := range strings.FieldsFunc(raw, splitter) {
		// Header names: tokens per RFC 7230 - letters, digits, and
		// !#$%&'*+-.^_`|~ . Reject anything else conservatively so this
		// can't smuggle weird characters into Caddy config.
		ok := true
		for _, c := range p {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' ||
				c >= '0' && c <= '9' || c == '-' || c == '_') {
				ok = false
				break
			}
		}
		if !ok || len(p) > 64 {
			continue
		}
		k := strings.ToLower(p)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, p)
	}
	if len(out) == 0 {
		return ""
	}
	joined := strings.Join(out, ",")
	if len(joined) > 255 {
		joined = joined[:255]
	}
	return joined
}

// sanitizePathList accepts newline- / comma- / space-separated paths
// (e.g. "/dashboard/*", "/api/admin") and returns a comma-joined,
// deduped form. Each token must start with "/" and stay under 200
// chars. Used by per-route SSO scope.
func sanitizePathList(raw string) string {
	if strings.TrimSpace(raw) == "" {
		return ""
	}
	splitter := func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	}
	seen := map[string]bool{}
	out := make([]string, 0, 8)
	for _, p := range strings.FieldsFunc(raw, splitter) {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		if len(p) > 200 || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return strings.Join(out, ",")
}

// sanitizeHostList accepts comma/space/newline-separated host names.
// Lower-cased + deduped; per-token <=253 chars. Used by per-route SSO
// scope so the operator can gate just one alias.
func sanitizeHostList(raw string) string {
	if strings.TrimSpace(raw) == "" {
		return ""
	}
	splitter := func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == ';'
	}
	seen := map[string]bool{}
	out := make([]string, 0, 4)
	for _, h := range strings.FieldsFunc(raw, splitter) {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" || len(h) > 253 || seen[h] {
			continue
		}
		seen[h] = true
		out = append(out, h)
	}
	return strings.Join(out, ",")
}

// sanitizeCIDRList parses an operator-supplied CIDR list (newline-,
// comma-, or space-separated) and returns a normalised comma-joined
// form. Each token must be a valid IP or CIDR; otherwise the whole
// list is rejected (caller flashes the error). Caps the result at
// 4 KiB to keep TEXT columns honest.
func sanitizeCIDRList(raw string) (string, error) {
	if strings.TrimSpace(raw) == "" {
		return "", nil
	}
	splitter := func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	}
	out := make([]string, 0, 8)
	seen := map[string]bool{}
	for _, p := range strings.FieldsFunc(raw, splitter) {
		// Accept either a bare IP or a CIDR; expand bare IPs to /32 (v4)
		// or /128 (v6) so Caddy's remote_ip matcher gets consistent input.
		token := p
		if !strings.Contains(token, "/") {
			if ip := net.ParseIP(token); ip != nil {
				if ip.To4() != nil {
					token += "/32"
				} else {
					token += "/128"
				}
			}
		}
		if _, _, err := net.ParseCIDR(token); err != nil {
			return "", fmt.Errorf("invalid CIDR: %q", p)
		}
		if seen[token] {
			continue
		}
		seen[token] = true
		out = append(out, token)
	}
	joined := strings.Join(out, ",")
	if len(joined) > 4096 {
		return "", fmt.Errorf("list too long (max 4 KiB)")
	}
	return joined, nil
}

// isValidUpstreamHost accepts an IP literal or a DNS hostname.
// atoiDefault parses s as int, returning def on any error.
func atoiDefault(s string, def int) int {
	if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
		return n
	}
	return def
}

// firstErr returns the first non-nil error.
func firstErr(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}

// recoverBg logs and swallows a panic in a fire-and-forget handler goroutine.
// These have no Recoverer middleware (that only wraps the request goroutine),
// so one panic in a detached push would otherwise crash the whole process.
func recoverBg(logger *slog.Logger, name string) {
	if r := recover(); r != nil && logger != nil {
		logger.Error("background goroutine panicked", "task", name, "panic", r, "stack", string(debug.Stack()))
	}
}

// isTabSlug accepts only a short [a-z0-9-] tab id, so an attacker-supplied
// active_tab can never inject CRLF/markup into the redirect Location header.
func isTabSlug(s string) bool {
	if s == "" || len(s) > 24 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}

// clampInt bounds n to [lo, hi].
func clampInt(n, lo, hi int) int {
	if n < lo {
		return lo
	}
	if n > hi {
		return hi
	}
	return n
}

func isValidUpstreamHost(h string) bool {
	h = strings.TrimSpace(h)
	if h == "" || len(h) > 253 {
		return false
	}
	if net.ParseIP(h) != nil {
		return true
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for i, c := range label {
			ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
				(c >= '0' && c <= '9') || c == '-'
			if !ok || (c == '-' && (i == 0 || i == len(label)-1)) {
				return false
			}
		}
	}
	return true
}

// sanitizeCustomConfig validates and re-marshals an admin-supplied JSON
// array of Caddy handler objects. Rejects anything that isn't a valid
// JSON array, or whose elements aren't objects (Caddy expects `{...}` per
// handler, not bare strings/numbers). 16 KiB hard cap. Empty input is OK.
func sanitizeCustomConfig(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	if len(raw) > 16384 {
		return "", fmt.Errorf("too large (16 KiB max)")
	}
	var arr []map[string]any
	if err := json.Unmarshal([]byte(raw), &arr); err != nil {
		return "", fmt.Errorf("must be a JSON array of objects: %v", err)
	}
	for i, h := range arr {
		if _, ok := h["handler"]; !ok {
			return "", fmt.Errorf("entry #%d missing required `handler` key", i)
		}
	}
	// Re-marshal so we store a normalised form (and reject sneaky
	// whitespace-only or BOM-prefixed inputs).
	out, err := json.Marshal(arr)
	if err != nil {
		return "", fmt.Errorf("re-marshal failed: %v", err)
	}
	return string(out), nil
}

// parseHeaderLines turns textarea content ("Name: value\nOther: x")
// into a compact JSON object the routes.custom_headers column stores.
// Empty lines and lines without ":" are skipped silently. Returns "" if
// no valid lines so we keep a NULL column instead of an empty {}.
func parseHeaderLines(raw string) string {
	out := map[string]string{}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		i := strings.IndexByte(line, ':')
		if i <= 0 || i == len(line)-1 {
			continue
		}
		name := strings.TrimSpace(line[:i])
		value := strings.TrimSpace(line[i+1:])
		if name == "" || value == "" {
			continue
		}
		out[name] = value
	}
	if len(out) == 0 {
		return ""
	}
	b, _ := json.Marshal(out)
	return string(b)
}

func (h *AdminHandlers) HostGroupCreate(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.FormValue("name"))
	color := strings.TrimSpace(r.FormValue("color"))
	if name == "" {
		redirectWithFlash(w, r, "/admin/hosts", "", "group name required")
		return
	}
	if color == "" || len(color) != 7 || color[0] != '#' {
		color = "#6366f1"
	}
	db := h.DB()
	if db == nil {
		redirectWithFlash(w, r, "/admin/hosts", "", "db unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	_, err := db.ExecContext(ctx, "INSERT INTO host_groups (name, color) VALUES (?, ?)", name, color)
	if err != nil {
		redirectWithFlash(w, r, "/admin/hosts", "", "create failed: "+sanitizeErr(err))
		return
	}
	redirectWithFlash(w, r, "/admin/hosts", "Group created", "")
}

func (h *AdminHandlers) HostGroupUpdate(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		redirectWithFlash(w, r, "/admin/hosts", "", "invalid id")
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	color := strings.TrimSpace(r.FormValue("color"))
	if name == "" {
		redirectWithFlash(w, r, "/admin/hosts", "", "group name required")
		return
	}
	if color == "" || len(color) != 7 || color[0] != '#' {
		color = "#6366f1"
	}
	db := h.DB()
	if db == nil {
		redirectWithFlash(w, r, "/admin/hosts", "", "db unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	_, err = db.ExecContext(ctx, "UPDATE host_groups SET name=?, color=? WHERE id=?", name, color, id)
	if err != nil {
		redirectWithFlash(w, r, "/admin/hosts", "", "update failed: "+sanitizeErr(err))
		return
	}
	redirectWithFlash(w, r, "/admin/hosts", "Group updated", "")
}

func (h *AdminHandlers) HostGroupDelete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		redirectWithFlash(w, r, "/admin/hosts", "", "invalid id")
		return
	}
	db := h.DB()
	if db == nil {
		redirectWithFlash(w, r, "/admin/hosts", "", "db unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	// ON DELETE SET NULL clears routes.group_id automatically.
	_, err = db.ExecContext(ctx, "DELETE FROM host_groups WHERE id=?", id)
	if err != nil {
		redirectWithFlash(w, r, "/admin/hosts", "", "delete failed: "+sanitizeErr(err))
		return
	}
	redirectWithFlash(w, r, "/admin/hosts", "Group deleted", "")
}

// BasicAuthAddUser handles POST /admin/hosts/{id}/basic-auth.
// Adds or updates a basic auth account for the route.
func (h *AdminHandlers) BasicAuthAddUser(w http.ResponseWriter, r *http.Request) {
	if h.DB() == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	routeID, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || routeID <= 0 {
		http.Redirect(w, r, "/admin/hosts", http.StatusSeeOther)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	sess := middleware.SessionFromContext(r.Context())
	if !h.scopeCheckRoute(ctx, sess, routeID) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	editURL := fmt.Sprintf("/admin/hosts/%d/edit", routeID)
	_ = r.ParseForm()
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	if username == "" {
		redirectWithFlash(w, r, editURL, "", "username is required")
		return
	}
	if len(password) < 8 {
		redirectWithFlash(w, r, editURL, "", "password must be at least 8 characters")
		return
	}
	hash, herr := bcryptHash([]byte(password))
	if herr != nil {
		redirectWithFlash(w, r, editURL, "", "hash error: "+sanitizeErr(herr))
		return
	}
	var basicAuthQ string
	if store.Driver() == "sqlite3" {
		basicAuthQ = `INSERT INTO route_basic_auth_users (route_id, username, bcrypt_hash) VALUES (?, ?, ?) ON CONFLICT(route_id, username) DO UPDATE SET bcrypt_hash=excluded.bcrypt_hash`
	} else {
		basicAuthQ = `INSERT INTO route_basic_auth_users (route_id, username, bcrypt_hash) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE bcrypt_hash=VALUES(bcrypt_hash)`
	}
	_, dbErr := h.DB().ExecContext(ctx, basicAuthQ, routeID, username, string(hash))
	if dbErr != nil {
		redirectWithFlash(w, r, editURL, "", "save failed: "+sanitizeErr(dbErr))
		return
	}
	if h.Routes != nil {
		var nodeID int64
		_ = h.DB().QueryRowContext(ctx, "SELECT caddy_node_id FROM routes WHERE id=?", routeID).Scan(&nodeID)
		if nodeID > 0 {
			h.Routes.SchedulePush(nodeID)
		}
	}
	redirectWithFlash(w, r, editURL, "User added", "")
}

// BasicAuthRemoveUser handles POST /admin/hosts/{id}/basic-auth/{username}/delete.
// Removes one basic auth account from the route.
func (h *AdminHandlers) BasicAuthRemoveUser(w http.ResponseWriter, r *http.Request) {
	if h.DB() == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	routeID, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || routeID <= 0 {
		http.Redirect(w, r, "/admin/hosts", http.StatusSeeOther)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	sess := middleware.SessionFromContext(r.Context())
	if !h.scopeCheckRoute(ctx, sess, routeID) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	editURL := fmt.Sprintf("/admin/hosts/%d/edit", routeID)
	username := chi.URLParam(r, "username")
	if username == "" {
		redirectWithFlash(w, r, editURL, "", "username missing")
		return
	}
	_, dbErr := h.DB().ExecContext(ctx,
		"DELETE FROM route_basic_auth_users WHERE route_id = ? AND username = ?",
		routeID, username)
	if dbErr != nil {
		redirectWithFlash(w, r, editURL, "", "delete failed: "+sanitizeErr(dbErr))
		return
	}
	if h.Routes != nil {
		var nodeID int64
		_ = h.DB().QueryRowContext(ctx, "SELECT caddy_node_id FROM routes WHERE id=?", routeID).Scan(&nodeID)
		if nodeID > 0 {
			h.Routes.SchedulePush(nodeID)
		}
	}
	redirectWithFlash(w, r, editURL, "User removed", "")
}
