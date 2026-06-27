package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"time"

	"github.com/host-yt/caddy-proxy-manager/internal/accesslog"
)

type nodeStatRow struct {
	Name              string
	Health            string
	CurrentRoutes     int
	MaxRoutes         int
	RequestsHour      uint64
	ErrorsHour        uint64
	BytesOutHour      uint64
	BytesOutHourHuman string
	ActiveConns       uint32
}

type topClientRow struct {
	Name             string
	Services         int
	Routes           int
	Active           int
	Bandwidth7d      int64
	Bandwidth7dHuman string
}

type recentRouteRow struct {
	Domain     string
	PathPrefix string
	Port       int
	NodeName   string
	Status     string
	CreatedAt  string
}

type planUsageRow struct {
	PlanName     string
	ClientCount  int
	ServiceCount int
	RouteCount   int
	ActiveRoutes int
}

// planViolationRow represents a client exceeding their plan limits.
type planViolationRow struct {
	ClientID    int64
	ClientEmail string
	PlanName    string
	Reason      string // e.g. "routes (12) exceeds max_domains (10)"
}

// nodeTrafficRow holds per-node 7d bandwidth + route count for the stats table.
type nodeTrafficRow struct {
	NodeID       int64
	NodeName     string
	Bytes7d      int64
	Bytes7dHuman string
	Requests7d   int64
	RouteCount   int
}

// moduleMismatchRow is a route that requires a Caddy module the assigned node lacks.
type moduleMismatchRow struct {
	RouteID  int64
	Domain   string
	NodeName string
	Feature  string // "WAF", "GeoIP", "Rate limit"
}

// wafTopRouteRow holds per-route WAF event counts for the stats top-10 table.
type wafTopRouteRow struct {
	RouteID    int64
	Domain     string
	EventCount int64
	Blocked    int64 // action="block" count
}

type statsData struct {
	baseAdminData

	NodeCount    int
	NodeHealthy  int
	NodeDown     int
	RouteActive  int
	RoutePending int
	RouteFailed  int
	ClientCount  int
	ServiceCount int
	Requests24h  string
	Errors24h    string

	NodeStats      []nodeStatRow
	TopClients     []topClientRow
	RecentRoutes   []recentRouteRow
	PlanUsage      []planUsageRow
	NodeTraffic      []nodeTrafficRow
	PlanViolations   []planViolationRow
	ModuleMismatches []moduleMismatchRow
	WAFTopRoutes     []wafTopRouteRow

	Cache    cacheSummary
	Security securitySummary
	Ops      opsSummary

	// Access-log analytics: protocol breakdown and byte totals over 24h.
	ProtoBreakdown  []accesslog.ProtoHit
	BytesTotal24h   int64
	BytesTotalHuman string

	// Pre-serialised JSON for Chart.js (avoids template-side escaping woes).
	RouteStatusLabels jsonRaw
	RouteStatusValues jsonRaw
	TrafficLabels     jsonRaw
	TrafficValues     jsonRaw
	ActivityLabels    jsonRaw
	ActivityValues    jsonRaw
}

// jsonRaw is rendered without HTML escaping (numbers/strings only - never user input).
type jsonRaw = template.JS

// cacheSummary surfaces enough about the Souin origin cache for the
// admin to know whether the feature is live and what's leaning on it.
// Real hit/miss counters need a Prometheus scrape of each node's
// Caddy /metrics endpoint, which we don't yet do; this gives the
// admin the next-best thing without adding a scraper dependency.
type cacheSummary struct {
	ModuleEnabled   bool // CACHE_HANDLER_AVAILABLE env (mirrors routes.CacheModuleAvailable)
	RoutesWithCache int  // count of routes where cache_enabled=1
	RoutesWithVary  int  // subset of above that also set cache_vary
	TopCachedHosts  []cachedHostRow
}

type cachedHostRow struct {
	Domain     string
	PathPrefix string
	TTLSecs    int
	Vary       string
	NodeName   string
}

// securitySummary aggregates auth + 2FA + passkey activity over the last
// 24h. Pulled from audit_log so it survives panel restarts and doesn't
// need a Prom scrape - though the same numbers also feed Prometheus via
// internal/obs metric helpers wired in handlers.
type securitySummary struct {
	LoginSuccess  int
	LoginFail     int
	LoginViaPass  int
	LoginViaOIDC  int
	LoginViaPassk int
	LoginViaSSOJ  int
	MFATOTP       int
	MFASMS        int
	MFAEmail      int
	MFAPasskey    int
	MFANone       int
	PasskeyAdds   int
	PasskeyDels   int
	OTPFails      int
	BFLockouts    int
	UsersWithTOTP int
	UsersWithSMS  int
	UsersWithMail int
	UsersWithPK   int
	ActiveAdmins  int
	ActiveClient  int
}

// opsSummary aggregates control-plane activity over the last 24h.
type opsSummary struct {
	CaddyPushes    int
	CaddyPushFails int
	CacheFlushes   int
	RoutesCreated  int
	RoutesDeleted  int
	BackupsRun     int
	BackupsFailed  int
	WebhookSent    int
	WebhookFailed  int
	SSOJumpSuccess int
	SSOJumpDenied  int
	APIKeysCreated int
	APIKeysRevoked int
}

// Stats renders /admin/stats.
func (h *AdminHandlers) Stats(w http.ResponseWriter, r *http.Request) {
	d := statsData{baseAdminData: h.base(r, "Statistics")}
	db := h.DB()
	if db == nil {
		h.render(w, "stats", d)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// --- KPI counters --------------------------------------------------
	_ = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM caddy_nodes").Scan(&d.NodeCount)
	_ = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM caddy_nodes WHERE health_status='healthy'").Scan(&d.NodeHealthy)
	_ = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM caddy_nodes WHERE health_status='down'").Scan(&d.NodeDown)
	_ = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM routes WHERE status='active'").Scan(&d.RouteActive)
	_ = db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM routes WHERE status IN ('pending_dns','dns_ok','pending_ssl')").Scan(&d.RoutePending)
	_ = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM routes WHERE status='failed'").Scan(&d.RouteFailed)
	_ = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM clients").Scan(&d.ClientCount)
	_ = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM services").Scan(&d.ServiceCount)

	// --- Requests / errors in last 24h (counter delta) -----------------
	req24, err24 := h.requestsErrorsLast24h(ctx, db)
	d.Requests24h = humanInt(req24)
	d.Errors24h = humanInt(err24)

	// --- Per-node traffic table ---------------------------------------
	d.NodeStats = h.perNodeStats(ctx, db)

	// --- Top clients (ordered by 7d bandwidth desc) -------------------
	crows, _ := db.QueryContext(ctx,
		`SELECT COALESCE(NULLIF(c.display_name,""), u.email),
		        (SELECT COUNT(*) FROM services s WHERE s.client_id = c.id),
		        (SELECT COUNT(*) FROM routes r JOIN services s ON s.id=r.service_id WHERE s.client_id=c.id),
		        (SELECT COUNT(*) FROM routes r JOIN services s ON s.id=r.service_id WHERE s.client_id=c.id AND r.status="active"),
		        COALESCE((SELECT SUM(lr.bytes_resp) FROM log_rollups lr
		                  JOIN routes r ON r.id=lr.route_id
		                  JOIN services s ON s.id=r.service_id
		                  WHERE s.client_id=c.id
		                  AND lr.bucket_start >= (NOW() - INTERVAL 7 DAY)), 0)
		 FROM clients c JOIN users u ON u.id=c.user_id
		 ORDER BY 5 DESC, 3 DESC LIMIT 10`)
	if crows != nil {
		for crows.Next() {
			var row topClientRow
			if err := crows.Scan(&row.Name, &row.Services, &row.Routes, &row.Active, &row.Bandwidth7d); err == nil {
				row.Bandwidth7dHuman = humanBytes(uint64(row.Bandwidth7d))
				d.TopClients = append(d.TopClients, row)
			}
		}
		crows.Close()
	}

	// --- Plan usage breakdown (clients/services/routes per plan) ------
	prows, _ := db.QueryContext(ctx,
		`SELECT p.name,
		        COUNT(DISTINCT c.id),
		        COUNT(DISTINCT s.id),
		        COUNT(r.id),
		        SUM(CASE WHEN r.status="active" THEN 1 ELSE 0 END)
		 FROM plans p
		 LEFT JOIN clients c ON c.plan_id=p.id
		 LEFT JOIN services s ON s.client_id=c.id
		 LEFT JOIN routes r ON r.service_id=s.id
		 GROUP BY p.id, p.name
		 ORDER BY COUNT(DISTINCT c.id) DESC`)
	if prows != nil {
		for prows.Next() {
			var row planUsageRow
			var active sql.NullInt64
			if err := prows.Scan(&row.PlanName, &row.ClientCount, &row.ServiceCount, &row.RouteCount, &active); err == nil {
				if active.Valid {
					row.ActiveRoutes = int(active.Int64)
				}
				d.PlanUsage = append(d.PlanUsage, row)
			}
		}
		prows.Close()
	}

	// --- Node traffic breakdown (7d bandwidth + route count per node) ----
	ntrRows, _ := db.QueryContext(ctx,
		`SELECT n.id, n.name,
		        COALESCE(SUM(lr.bytes_resp),0),
		        COALESCE(SUM(lr.requests),0),
		        COUNT(DISTINCT r.id)
		 FROM caddy_nodes n
		 LEFT JOIN routes r ON r.caddy_node_id=n.id
		 LEFT JOIN log_rollups lr ON lr.route_id=r.id AND lr.bucket_start >= (NOW() - INTERVAL 7 DAY)
		 GROUP BY n.id, n.name
		 ORDER BY 3 DESC LIMIT 10`)
	if ntrRows != nil {
		for ntrRows.Next() {
			var row nodeTrafficRow
			if err := ntrRows.Scan(&row.NodeID, &row.NodeName, &row.Bytes7d, &row.Requests7d, &row.RouteCount); err == nil {
				row.Bytes7dHuman = humanBytes(uint64(row.Bytes7d))
				d.NodeTraffic = append(d.NodeTraffic, row)
			}
		}
		ntrRows.Close()
	}

	// --- Module mismatches (routes needing modules the node lacks) ----
	mmCtx, mmCancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer mmCancel()
	mmRows, _ := db.QueryContext(mmCtx,
		`SELECT r.id, r.domain, n.name,
		        CASE
		          WHEN COALESCE(r.waf_enabled,0)=1 AND COALESCE(n.has_waf,0)=0 THEN "WAF"
		          WHEN COALESCE(r.geo_mode,"off")!="off" AND COALESCE(n.has_geoip,0)=0 THEN "GeoIP"
		          WHEN COALESCE(r.rate_limit_rpm,0)>0 AND COALESCE(n.has_rate_limit,0)=0 THEN "Rate limit"
		        END AS feature
		 FROM routes r
		 JOIN caddy_nodes n ON n.id = r.caddy_node_id
		 WHERE r.status NOT IN ("disabled","deleted")
		   AND (
		     (COALESCE(r.waf_enabled,0)=1 AND COALESCE(n.has_waf,0)=0)
		     OR (COALESCE(r.geo_mode,"off")!="off" AND COALESCE(n.has_geoip,0)=0)
		     OR (COALESCE(r.rate_limit_rpm,0)>0 AND COALESCE(n.has_rate_limit,0)=0)
		   )
		 LIMIT 50`)
	if mmRows != nil {
		for mmRows.Next() {
			var row moduleMismatchRow
			if err := mmRows.Scan(&row.RouteID, &row.Domain, &row.NodeName, &row.Feature); err == nil {
				d.ModuleMismatches = append(d.ModuleMismatches, row)
			}
		}
		mmRows.Close()
	}

	// --- Top WAF-blocked routes (7d) - skip gracefully if table missing ----
	wafRows, wafErr := db.QueryContext(ctx,
		`SELECT we.route_id, COALESCE(r.domain,'(deleted)'),
		        COUNT(*) as cnt,
		        SUM(we.action='block') as blocked
		 FROM waf_events we
		 LEFT JOIN routes r ON r.id = we.route_id
		 WHERE we.created_at >= NOW() - INTERVAL 7 DAY
		 GROUP BY we.route_id, r.domain
		 ORDER BY cnt DESC LIMIT 10`)
	if wafErr == nil {
		for wafRows.Next() {
			var row wafTopRouteRow
			if err := wafRows.Scan(&row.RouteID, &row.Domain, &row.EventCount, &row.Blocked); err == nil {
				d.WAFTopRoutes = append(d.WAFTopRoutes, row)
			}
		}
		wafRows.Close()
	}

	// --- Plan violations (clients exceeding limits, max 20, dedup by client) ----
	d.PlanViolations = h.planViolationsFor(ctx, db)

	// --- Recent routes ------------------------------------------------
	rrows, _ := db.QueryContext(ctx,
		`SELECT r.domain, COALESCE(r.path_prefix,''), r.upstream_port, n.name, r.status,
		        DATE_FORMAT(r.created_at, '%Y-%m-%d %H:%i')
		 FROM routes r JOIN caddy_nodes n ON n.id=r.caddy_node_id
		 ORDER BY r.id DESC LIMIT 10`)
	if rrows != nil {
		for rrows.Next() {
			var row recentRouteRow
			if err := rrows.Scan(&row.Domain, &row.PathPrefix, &row.Port, &row.NodeName, &row.Status, &row.CreatedAt); err == nil {
				d.RecentRoutes = append(d.RecentRoutes, row)
			}
		}
		rrows.Close()
	}

	// --- Cache summary -------------------------------------------------
	d.Cache = h.cacheSummaryFor(ctx, db)

	// --- Security + ops (24h) -----------------------------------------
	d.Security = h.securitySummaryFor(ctx, db)
	d.Ops = h.opsSummaryFor(ctx, db)

	// --- Access-log analytics (bytes + protocol, global, 24h) ---------
	if h.AccessLogs != nil {
		protos, _ := h.AccessLogs.ProtoBreakdown(ctx, accesslog.AnalyticsFilter{})
		d.ProtoBreakdown = protos
		bytesSummary, _ := h.AccessLogs.BytesSummary(ctx, accesslog.AnalyticsFilter{})
		d.BytesTotal24h = bytesSummary.TotalBytes
		if bytesSummary.TotalBytes > 0 {
			d.BytesTotalHuman = humanBytes(uint64(bytesSummary.TotalBytes))
		}
	}

	// --- Chart data ---------------------------------------------------
	d.RouteStatusLabels = jsonRaw(mustJSON([]string{"active", "pending", "failed", "disabled"}))
	var disabled int
	_ = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM routes WHERE status='disabled'").Scan(&disabled)
	d.RouteStatusValues = jsonRaw(mustJSON([]int{d.RouteActive, d.RoutePending, d.RouteFailed, disabled}))

	tl, tv := h.trafficTimeseries(ctx, db)
	d.TrafficLabels = jsonRaw(mustJSON(tl))
	d.TrafficValues = jsonRaw(mustJSON(tv))

	al, av := h.activityTimeseries(ctx, db)
	d.ActivityLabels = jsonRaw(mustJSON(al))
	d.ActivityValues = jsonRaw(mustJSON(av))

	h.render(w, "stats", d)
}

// cacheSummaryFor fills the cache panel: module availability flag,
// counts of routes opting into cache + Vary, and a short list of the
// hottest cached hosts (highest TTL = longest-lived in the store, so
// most likely to be carrying real traffic).
func (h *AdminHandlers) cacheSummaryFor(ctx context.Context, db *sql.DB) cacheSummary {
	out := cacheSummary{ModuleEnabled: h.Routes != nil && h.Routes.CacheModuleAvailable}
	if db == nil {
		return out
	}
	_ = db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM routes WHERE cache_enabled = 1").Scan(&out.RoutesWithCache)
	_ = db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM routes WHERE cache_enabled = 1 AND cache_vary IS NOT NULL AND cache_vary <> ''").Scan(&out.RoutesWithVary)
	rows, err := db.QueryContext(ctx,
		`SELECT r.domain, COALESCE(r.path_prefix,''), r.cache_ttl_secs,
		        COALESCE(r.cache_vary,''), n.name
		 FROM routes r JOIN caddy_nodes n ON n.id = r.caddy_node_id
		 WHERE r.cache_enabled = 1
		 ORDER BY r.cache_ttl_secs DESC, r.id DESC
		 LIMIT 8`)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var row cachedHostRow
		if err := rows.Scan(&row.Domain, &row.PathPrefix, &row.TTLSecs, &row.Vary, &row.NodeName); err == nil {
			out.TopCachedHosts = append(out.TopCachedHosts, row)
		}
	}
	return out
}

// planViolationsFor returns up to 20 clients exceeding plan limits (deduped by client).
func (h *AdminHandlers) planViolationsFor(ctx context.Context, db *sql.DB) []planViolationRow {
	if db == nil {
		return nil
	}
	seen := map[int64]struct{}{}
	var out []planViolationRow

	// Check 1: active routes > max_domains.
	r1, err := db.QueryContext(ctx,
		`SELECT c.id, COALESCE(NULLIF(c.display_name,''), u.email), p.name, COUNT(r.id), p.max_domains
		 FROM clients c
		 JOIN users u ON u.id=c.user_id
		 JOIN plans p ON p.id=c.plan_id
		 JOIN services s ON s.client_id=c.id
		 JOIN routes r ON r.service_id=s.id
		 WHERE r.status IN ('active','pending_dns','dns_ok','pending_ssl')
		 GROUP BY c.id, c.display_name, u.email, p.name, p.max_domains
		 HAVING COUNT(r.id) > p.max_domains AND p.max_domains > 0`)
	if err == nil {
		defer r1.Close()
		for r1.Next() {
			var v planViolationRow
			var count, max int
			if err := r1.Scan(&v.ClientID, &v.ClientEmail, &v.PlanName, &count, &max); err != nil {
				continue
			}
			if _, dup := seen[v.ClientID]; dup {
				continue
			}
			seen[v.ClientID] = struct{}{}
			v.Reason = fmt.Sprintf("routes (%d) exceeds max_domains (%d)", count, max)
			out = append(out, v)
			if len(out) >= 20 {
				return out
			}
		}
	}

	// Check 2: WebSocket routes used without plan.websocket.
	r2, err := db.QueryContext(ctx,
		`SELECT c.id, COALESCE(NULLIF(c.display_name,''), u.email), p.name
		 FROM clients c
		 JOIN users u ON u.id=c.user_id
		 JOIN plans p ON p.id=c.plan_id
		 JOIN services s ON s.client_id=c.id
		 JOIN routes r ON r.service_id=s.id
		 WHERE r.websocket=1 AND p.websocket=0 AND r.status NOT IN ('disabled','deleted')
		 GROUP BY c.id, c.display_name, u.email, p.name`)
	if err == nil {
		defer r2.Close()
		for r2.Next() {
			var v planViolationRow
			if err := r2.Scan(&v.ClientID, &v.ClientEmail, &v.PlanName); err != nil {
				continue
			}
			if _, dup := seen[v.ClientID]; dup {
				continue
			}
			seen[v.ClientID] = struct{}{}
			v.Reason = "WebSocket routes not allowed in plan"
			out = append(out, v)
			if len(out) >= 20 {
				return out
			}
		}
	}

	return out
}

// requestsErrorsLast24h sums (latest - 24h-ago) across all nodes.
func (h *AdminHandlers) requestsErrorsLast24h(ctx context.Context, db *sql.DB) (uint64, uint64) {
	rows, err := db.QueryContext(ctx,
		`SELECT node_id,
		        MAX(requests_total) - MIN(requests_total) AS req_delta,
		        MAX(errors_total)   - MIN(errors_total)   AS err_delta
		 FROM node_traffic_samples
		 WHERE sampled_at > NOW() - INTERVAL 1 DAY
		 GROUP BY node_id`)
	if err != nil {
		return 0, 0
	}
	defer rows.Close()
	var req, errs uint64
	for rows.Next() {
		var nid int64
		var r, e sql.NullInt64
		if err := rows.Scan(&nid, &r, &e); err != nil {
			continue
		}
		if r.Valid && r.Int64 > 0 {
			req += uint64(r.Int64)
		}
		if e.Valid && e.Int64 > 0 {
			errs += uint64(e.Int64)
		}
	}
	return req, errs
}

func (h *AdminHandlers) perNodeStats(ctx context.Context, db *sql.DB) []nodeStatRow {
	rows, err := db.QueryContext(ctx,
		`SELECT n.id, n.name, n.health_status, n.current_routes, n.max_routes
		 FROM caddy_nodes n ORDER BY n.priority DESC, n.id`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	type tmp struct {
		id  int64
		row nodeStatRow
	}
	var nodes []tmp
	for rows.Next() {
		var t tmp
		if err := rows.Scan(&t.id, &t.row.Name, &t.row.Health, &t.row.CurrentRoutes, &t.row.MaxRoutes); err == nil {
			nodes = append(nodes, t)
		}
	}
	for i := range nodes {
		var maxR, minR, maxE, minE, maxB, minB sql.NullInt64
		var ac sql.NullInt64
		_ = db.QueryRowContext(ctx,
			`SELECT MAX(requests_total), MIN(requests_total),
			        MAX(errors_total),   MIN(errors_total),
			        MAX(bytes_out_total),MIN(bytes_out_total),
			        (SELECT active_conns FROM node_traffic_samples
			           WHERE node_id = ? ORDER BY sampled_at DESC LIMIT 1)
			 FROM node_traffic_samples
			 WHERE node_id = ? AND sampled_at > NOW() - INTERVAL 1 HOUR`,
			nodes[i].id, nodes[i].id,
		).Scan(&maxR, &minR, &maxE, &minE, &maxB, &minB, &ac)
		nodes[i].row.RequestsHour = uintDelta(maxR, minR)
		nodes[i].row.ErrorsHour = uintDelta(maxE, minE)
		nodes[i].row.BytesOutHour = uintDelta(maxB, minB)
		nodes[i].row.BytesOutHourHuman = humanBytes(nodes[i].row.BytesOutHour)
		if ac.Valid {
			nodes[i].row.ActiveConns = uint32(ac.Int64)
		}
	}
	out := make([]nodeStatRow, len(nodes))
	for i, n := range nodes {
		out[i] = n.row
	}
	return out
}

// trafficTimeseries returns 24h of HTTP requests per hour across all
// nodes. requests_total in node_traffic_samples is a monotonic Caddy
// counter, so per-hour activity = max(counter)-min(counter) inside the
// bucket, summed over nodes. Old impl SUM(requests_total) leaked the
// cumulative counter into the chart and produced a monotonically rising
// line that looked like traffic but was really uptime.
func (h *AdminHandlers) trafficTimeseries(ctx context.Context, db *sql.DB) ([]string, []uint64) {
	buckets := map[int64]uint64{}
	rows, err := db.QueryContext(ctx,
		`SELECT FLOOR(UNIX_TIMESTAMP(sampled_at)/3600)*3600 AS hr,
		        node_id,
		        MAX(requests_total) - MIN(requests_total) AS delta
		 FROM node_traffic_samples
		 WHERE sampled_at > NOW() - INTERVAL 1 DAY
		 GROUP BY hr, node_id`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var hr int64
			var nodeID int64
			var v uint64
			if err := rows.Scan(&hr, &nodeID, &v); err == nil {
				buckets[hr] += v
			}
		}
	}
	labels := make([]string, 0, 24)
	values := make([]uint64, 0, 24)
	now := time.Now().UTC().Truncate(time.Hour)
	for i := 23; i >= 0; i-- {
		t := now.Add(-time.Duration(i) * time.Hour)
		labels = append(labels, t.Local().Format("15:00"))
		values = append(values, buckets[t.Unix()])
	}
	return labels, values
}

// activityTimeseries returns 24h of audit-log entries grouped per hour
// with a zero-filled 24-bucket grid. Buckets keyed by UNIX hour so the
// DB session TZ doesn't have to match the Go runtime TZ.
func (h *AdminHandlers) activityTimeseries(ctx context.Context, db *sql.DB) ([]string, []int) {
	counts := map[int64]int{}
	rows, err := db.QueryContext(ctx,
		`SELECT FLOOR(UNIX_TIMESTAMP(created_at)/3600)*3600 AS hr, COUNT(*)
		 FROM audit_log
		 WHERE created_at > NOW() - INTERVAL 1 DAY
		 GROUP BY hr`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var hr int64
			var c int
			if err := rows.Scan(&hr, &c); err == nil {
				counts[hr] = c
			}
		}
	}
	labels := make([]string, 0, 24)
	values := make([]int, 0, 24)
	now := time.Now().UTC().Truncate(time.Hour)
	for i := 23; i >= 0; i-- {
		t := now.Add(-time.Duration(i) * time.Hour)
		labels = append(labels, t.Local().Format("15:00"))
		values = append(values, counts[t.Unix()])
	}
	return labels, values
}

// ---- helpers -----------------------------------------------------------

func uintDelta(maxV, minV sql.NullInt64) uint64 {
	if !maxV.Valid || !minV.Valid {
		return 0
	}
	d := maxV.Int64 - minV.Int64
	if d < 0 {
		return 0
	}
	return uint64(d)
}

func humanInt(n uint64) string {
	switch {
	case n < 1000:
		return fmt.Sprintf("%d", n)
	case n < 1_000_000:
		return fmt.Sprintf("%.1fK", float64(n)/1000)
	case n < 1_000_000_000:
		return fmt.Sprintf("%.1fM", float64(n)/1_000_000)
	default:
		return fmt.Sprintf("%.1fB", float64(n)/1_000_000_000)
	}
}

func humanBytes(n uint64) string {
	switch {
	case n < 1024:
		return fmt.Sprintf("%d B", n)
	case n < 1024*1024:
		return fmt.Sprintf("%.1f KB", float64(n)/1024)
	case n < 1024*1024*1024:
		return fmt.Sprintf("%.1f MB", float64(n)/(1024*1024))
	default:
		return fmt.Sprintf("%.1f GB", float64(n)/(1024*1024*1024))
	}
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "[]"
	}
	return string(b)
}

// securitySummaryFor aggregates auth + 2FA + passkey activity over the
// last 24h. All queries are best-effort; any single row count failure
// leaves the field at zero rather than aborting the page render.
func (h *AdminHandlers) securitySummaryFor(ctx context.Context, db *sql.DB) securitySummary {
	var s securitySummary
	if db == nil {
		return s
	}
	_ = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM audit_log WHERE action='login.success' AND created_at > NOW() - INTERVAL 24 HOUR").Scan(&s.LoginSuccess)
	_ = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM audit_log WHERE action='login.fail' AND created_at > NOW() - INTERVAL 24 HOUR").Scan(&s.LoginFail)

	// Login entry-point + MFA factor breakdown. JSON_EXTRACT works on
	// the meta column we already stamp from finalizeLogin (via, mfa).
	_ = db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM audit_log WHERE action='login.success' AND created_at > NOW() - INTERVAL 24 HOUR
		   AND JSON_EXTRACT(meta, '$.via') = 'password'`).Scan(&s.LoginViaPass)
	_ = db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM audit_log WHERE action='login.success' AND created_at > NOW() - INTERVAL 24 HOUR
		   AND JSON_EXTRACT(meta, '$.via') = 'oidc'`).Scan(&s.LoginViaOIDC)
	_ = db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM audit_log WHERE action='login.success' AND created_at > NOW() - INTERVAL 24 HOUR
		   AND JSON_EXTRACT(meta, '$.via') = 'passkey'`).Scan(&s.LoginViaPassk)
	_ = db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM audit_log WHERE action='sso_jump.success' AND created_at > NOW() - INTERVAL 24 HOUR`).Scan(&s.LoginViaSSOJ)

	_ = db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM audit_log WHERE action='login.success' AND created_at > NOW() - INTERVAL 24 HOUR
		   AND JSON_EXTRACT(meta, '$.mfa') = 'totp'`).Scan(&s.MFATOTP)
	_ = db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM audit_log WHERE action='login.success' AND created_at > NOW() - INTERVAL 24 HOUR
		   AND JSON_EXTRACT(meta, '$.mfa') = 'sms'`).Scan(&s.MFASMS)
	_ = db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM audit_log WHERE action='login.success' AND created_at > NOW() - INTERVAL 24 HOUR
		   AND JSON_EXTRACT(meta, '$.mfa') = 'email'`).Scan(&s.MFAEmail)
	_ = db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM audit_log WHERE action='login.success' AND created_at > NOW() - INTERVAL 24 HOUR
		   AND JSON_EXTRACT(meta, '$.mfa') = 'passkey'`).Scan(&s.MFAPasskey)
	_ = db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM audit_log WHERE action='login.success' AND created_at > NOW() - INTERVAL 24 HOUR
		   AND JSON_EXTRACT(meta, '$.mfa') = 'none'`).Scan(&s.MFANone)

	_ = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM audit_log WHERE action='passkey.register' AND created_at > NOW() - INTERVAL 24 HOUR").Scan(&s.PasskeyAdds)
	_ = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM audit_log WHERE action='passkey.delete' AND created_at > NOW() - INTERVAL 24 HOUR").Scan(&s.PasskeyDels)
	_ = db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM audit_log
		  WHERE action IN ('2fa.fail','2fa.sms.fail','2fa.email.fail')
		    AND created_at > NOW() - INTERVAL 24 HOUR`).Scan(&s.OTPFails)
	_ = db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM audit_log
		  WHERE action='login.fail'
		    AND JSON_EXTRACT(meta, '$.reason') = 'rate_limited'
		    AND created_at > NOW() - INTERVAL 24 HOUR`).Scan(&s.BFLockouts)

	// Enrollment posture - useful even without traffic.
	_ = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM users WHERE totp_enabled = 1").Scan(&s.UsersWithTOTP)
	_ = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM users WHERE sms_otp_enabled = 1").Scan(&s.UsersWithSMS)
	_ = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM users WHERE email_otp_enabled = 1").Scan(&s.UsersWithMail)
	// has_passkey is on users; missing column degrades gracefully to 0.
	_ = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM users WHERE has_passkey = 1").Scan(&s.UsersWithPK)

	_ = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM users WHERE role IN ('admin','super_admin') AND is_active = 1").Scan(&s.ActiveAdmins)
	_ = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM users WHERE role = 'client' AND is_active = 1").Scan(&s.ActiveClient)
	return s
}

// opsSummaryFor aggregates control-plane activity over the last 24h.
func (h *AdminHandlers) opsSummaryFor(ctx context.Context, db *sql.DB) opsSummary {
	var o opsSummary
	if db == nil {
		return o
	}
	_ = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM audit_log WHERE action='caddy.push.ok' AND created_at > NOW() - INTERVAL 24 HOUR").Scan(&o.CaddyPushes)
	_ = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM audit_log WHERE action='caddy.push.fail' AND created_at > NOW() - INTERVAL 24 HOUR").Scan(&o.CaddyPushFails)
	_ = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM audit_log WHERE action='admin.host.cache.purge' AND created_at > NOW() - INTERVAL 24 HOUR").Scan(&o.CacheFlushes)
	_ = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM audit_log WHERE action='route.create' AND created_at > NOW() - INTERVAL 24 HOUR").Scan(&o.RoutesCreated)
	_ = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM audit_log WHERE action='route.delete' AND created_at > NOW() - INTERVAL 24 HOUR").Scan(&o.RoutesDeleted)
	_ = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM audit_log WHERE action='backup.run.ok' AND created_at > NOW() - INTERVAL 24 HOUR").Scan(&o.BackupsRun)
	_ = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM audit_log WHERE action='backup.run.fail' AND created_at > NOW() - INTERVAL 24 HOUR").Scan(&o.BackupsFailed)
	_ = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM audit_log WHERE action='webhook.delivery.ok' AND created_at > NOW() - INTERVAL 24 HOUR").Scan(&o.WebhookSent)
	_ = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM audit_log WHERE action='webhook.delivery.fail' AND created_at > NOW() - INTERVAL 24 HOUR").Scan(&o.WebhookFailed)
	_ = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM audit_log WHERE action='sso_jump.success' AND created_at > NOW() - INTERVAL 24 HOUR").Scan(&o.SSOJumpSuccess)
	_ = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM audit_log WHERE action='sso_jump.denied' AND created_at > NOW() - INTERVAL 24 HOUR").Scan(&o.SSOJumpDenied)
	_ = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM audit_log WHERE action LIKE 'api_key.create%' AND created_at > NOW() - INTERVAL 24 HOUR").Scan(&o.APIKeysCreated)
	_ = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM audit_log WHERE action LIKE 'api_key.revoke%' AND created_at > NOW() - INTERVAL 24 HOUR").Scan(&o.APIKeysRevoked)
	return o
}
