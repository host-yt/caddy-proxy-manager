package handlers

import (
	"bytes"
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/csv"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/host-yt/caddy-proxy-manager/internal/accesslog"
	"github.com/host-yt/caddy-proxy-manager/internal/audit"
	"github.com/host-yt/caddy-proxy-manager/internal/auth"
	"github.com/host-yt/caddy-proxy-manager/internal/deployment"
	"github.com/host-yt/caddy-proxy-manager/internal/domain/routes"
	"github.com/host-yt/caddy-proxy-manager/internal/domain/wgpeer"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
	"github.com/host-yt/caddy-proxy-manager/internal/i18n"
	"github.com/host-yt/caddy-proxy-manager/internal/installstate"
	"github.com/host-yt/caddy-proxy-manager/internal/mail"
	"github.com/host-yt/caddy-proxy-manager/internal/security"
	"github.com/host-yt/caddy-proxy-manager/internal/store"
	"github.com/host-yt/caddy-proxy-manager/internal/view"
)

type ClientHandlers struct {
	DB        func() *sql.DB
	Sessions  *auth.Manager
	Templates *view.AppTemplates
	Routes    *routes.Service
	Logger    *slog.Logger
	State     *installstate.Manager // for TOTP secret encryption at rest
	// WGPeers (optional) drives /app/tunnels self-service flow.
	WGPeers *wgpeer.Service
	// SMS (optional) used for SMS OTP enrollment flow.
	SMS interface {
		Send(ctx context.Context, to, body string) error
	}
	// Mailer (optional) used for Email OTP enrollment + login challenges.
	Mailer *mail.Mailer
	// AccessLogs (optional) reads stored per-route access log entries.
	AccessLogs *accesslog.Store
}

type baseAppData struct {
	Title             string
	Email             string
	Role              string
	CSRF              string
	Flash             string
	Error             string
	CSPNonce          string
	Lang              string
	Theme             string
	ImpersonatorEmail string // non-empty when an admin is viewing as this client
	Brand             Branding
	// Features gates client nav items by install profile (e.g. tunnels, api_tokens).
	Features deployment.Features
	// SystemBanner is shown site-wide; empty means no banner.
	SystemBanner          string
	SystemBannerType      string // "info" | "warning" | "error"
	SystemBannerLink      string // optional CTA URL
	SystemBannerLinkLabel string // optional CTA label; defaults to "Learn more"
}

func (h *ClientHandlers) base(r *http.Request, title string) baseAppData {
	sess := middleware.SessionFromContext(r.Context())
	d := baseAppData{
		Title:    title,
		CSPNonce: middleware.CSPNonce(r.Context()),
		Lang:     i18n.LangFromRequest(r),
		Theme:    themeFromRequest(r),
		Brand:    LoadBranding(r.Context(), h.DB()),
	}
	if sess != nil {
		d.Email = sess.Email
		d.Role = sess.Role
		d.CSRF = sess.CSRFToken
		d.ImpersonatorEmail = sess.ImpersonatorEmail
		// Reseller overlay: a client owned by a reseller sees that reseller's
		// brand (name/logo) over the global one. clients.reseller_id, not
		// users.reseller_id (the latter marks reseller-admins).
		if db := h.DB(); db != nil {
			ctxB, canB := context.WithTimeout(r.Context(), 500*time.Millisecond)
			var rid sql.NullInt64
			db.QueryRowContext(ctxB, "SELECT reseller_id FROM clients WHERE user_id=?", sess.UserID).Scan(&rid)
			canB()
			if rid.Valid && rid.Int64 > 0 {
				d.Brand = LoadBrandingFor(r.Context(), db, rid.Int64)
			}
		}
	}
	if msg := r.URL.Query().Get("flash"); msg != "" {
		d.Flash = msg
	}
	if msg := r.URL.Query().Get("err"); msg != "" {
		d.Error = msg
	}
	prof := deployment.Default
	if h.State != nil {
		prof = deployment.Parse(h.State.Get().Profile)
	}
	d.Features = prof.Features()
	// Load system announcement banner from DB.
	if db := h.DB(); db != nil {
		var text, btype, link, linkLabel string
		ctx2, can := context.WithTimeout(r.Context(), 500*time.Millisecond)
		defer can()
		db.QueryRowContext(ctx2, "SELECT value FROM settings WHERE `key`=?", "system.banner_text").Scan(&text)
		db.QueryRowContext(ctx2, "SELECT value FROM settings WHERE `key`=?", "system.banner_type").Scan(&btype)
		db.QueryRowContext(ctx2, "SELECT value FROM settings WHERE `key`=?", "system.banner_link").Scan(&link)
		db.QueryRowContext(ctx2, "SELECT value FROM settings WHERE `key`=?", "system.banner_link_label").Scan(&linkLabel)
		if strings.TrimSpace(text) != "" {
			d.SystemBanner = strings.TrimSpace(text)
			d.SystemBannerType = btype
			if d.SystemBannerType == "" {
				d.SystemBannerType = "info"
			}
			d.SystemBannerLink = strings.TrimSpace(link)
			d.SystemBannerLinkLabel = strings.TrimSpace(linkLabel)
		}
	}
	return d
}

func (h *ClientHandlers) render(w http.ResponseWriter, page string, data any) {
	var buf bytes.Buffer
	if err := h.Templates.Render(&buf, page, data); err != nil {
		h.Logger.Error("client render", "page", page, "err", err)
		http.Error(w, "render failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(buf.Bytes())
}

func clientIDFor(ctx context.Context, db *sql.DB, userID int64) (int64, error) {
	var id int64
	err := db.QueryRowContext(ctx, "SELECT id FROM clients WHERE user_id = ?", userID).Scan(&id)
	return id, err
}

// ---- Dashboard ----------------------------------------------------------

type clientDashboardData struct {
	baseAppData
	ServiceCount      int
	ActiveRoutes      int
	PendingRoutes     int
	FailedRoutes      int
	TotalBandwidth7d  string // formatted bytes for last 7 days
	Requests24h       int64  // total requests in last 24h across all client routes
	Errors24h         int64  // 4xx+5xx in last 24h
	Bandwidth30dDays  []accesslog.BandwidthDayBucket // 30-day daily totals
	Bandwidth30dTotal int64                           // sum across Bandwidth30dDays
	MaxDay30dBytes    int64                           // max bucket for bar scaling
}

func (h *ClientHandlers) Dashboard(w http.ResponseWriter, r *http.Request) {
	d := clientDashboardData{baseAppData: h.base(r, "Dashboard")}
	sess := middleware.SessionFromContext(r.Context())
	db := h.DB()
	if db == nil || sess == nil {
		h.render(w, "dashboard", d)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3_000_000_000)
	defer cancel()
	clientID, err := clientIDFor(ctx, db, sess.UserID)
	if err != nil {
		h.render(w, "dashboard", d)
		return
	}
	_ = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM services WHERE client_id = ?", clientID).Scan(&d.ServiceCount)
	_ = db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM routes r JOIN services s ON s.id=r.service_id
		 WHERE s.client_id = ? AND r.status='active'`, clientID).Scan(&d.ActiveRoutes)
	_ = db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM routes r JOIN services s ON s.id=r.service_id
		 WHERE s.client_id = ? AND r.status IN ('pending_dns','dns_ok','pending_ssl')`, clientID).Scan(&d.PendingRoutes)
	_ = db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM routes r JOIN services s ON s.id=r.service_id
		 WHERE s.client_id = ? AND r.status='failed'`, clientID).Scan(&d.FailedRoutes)
	var bw7d int64
	_ = db.QueryRowContext(ctx,
		`SELECT COALESCE(SUM(lr.bytes_resp),0)
		 FROM log_rollups lr
		 JOIN routes r ON r.id=lr.route_id
		 JOIN services s ON s.id=r.service_id
		 WHERE s.client_id=? AND lr.bucket_start >= NOW()-INTERVAL 7 DAY`, clientID).Scan(&bw7d)
	d.TotalBandwidth7d = formatBytes(bw7d)
	// 24h request + error counts from rollups.
	_ = db.QueryRowContext(ctx,
		`SELECT COALESCE(SUM(lr.requests),0),
		        COALESCE(SUM(lr.errors_4xx + lr.errors_5xx),0)
		 FROM log_rollups lr
		 JOIN routes r ON r.id = lr.route_id
		 JOIN services s ON s.id = r.service_id
		 WHERE s.client_id = ? AND lr.bucket_start >= NOW() - INTERVAL 24 HOUR`, clientID,
	).Scan(&d.Requests24h, &d.Errors24h)
	// 30-day per-day bandwidth from pre-aggregated rollups (hourly buckets).
	// Avoids a full scan of raw host_access_log on large installations.
	rows, err2 := db.QueryContext(ctx,
		`SELECT DATE(lr.bucket_start) AS day, COALESCE(SUM(lr.bytes_resp),0)
		 FROM log_rollups lr
		 JOIN routes r ON r.id = lr.route_id
		 JOIN services s ON s.id = r.service_id
		 WHERE s.client_id = ? AND lr.bucket_start >= DATE_SUB(NOW(), INTERVAL 30 DAY)
		 GROUP BY DATE(lr.bucket_start)
		 ORDER BY day ASC`, clientID)
	if err2 == nil {
		for rows.Next() {
			var day string
			var bytes int64
			if rows.Scan(&day, &bytes) == nil {
				t, terr := time.Parse("2006-01-02", day)
				if terr != nil {
					continue
				}
				d.Bandwidth30dDays = append(d.Bandwidth30dDays, accesslog.BandwidthDayBucket{
					Label:      t.Format("Mon 02"),
					ShortLabel: t.Format("Mon"),
					Bytes:      bytes,
				})
				d.Bandwidth30dTotal += bytes
				if bytes > d.MaxDay30dBytes {
					d.MaxDay30dBytes = bytes
				}
			}
		}
		_ = rows.Close()
	}
	h.render(w, "dashboard", d)
}

// ---- Services (read-only customer view) --------------------------------

type clientServiceRow struct {
	ID               int64
	Name             string
	BackendIP        string
	PortStart        int
	PortEnd          int
	PlanName         string
	PlanKind         string // 'restricted' | 'npm' - controls whether the client may edit BackendIP / port range
	Status           string
	RouteCount       int
	MaxDomains       int
	SSLEnabled       bool
	WebsocketEnabled bool
	RateLimitRPM     int // 0 = unlimited
	PathRouting      bool
	RouteCountPct    int // 0-100 for quota bar
	Notes            string
}

type clientServicesData struct {
	baseAppData
	Services []clientServiceRow
}

func (h *ClientHandlers) Services(w http.ResponseWriter, r *http.Request) {
	d := clientServicesData{baseAppData: h.base(r, "My VPS")}
	sess := middleware.SessionFromContext(r.Context())
	db := h.DB()
	if db == nil || sess == nil {
		h.render(w, "services", d)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3_000_000_000)
	defer cancel()
	clientID, err := clientIDFor(ctx, db, sess.UserID)
	if err != nil {
		h.render(w, "services", d)
		return
	}
	rows, err := db.QueryContext(ctx,
		`SELECT s.id, s.name, s.backend_ip, s.allowed_port_start, s.allowed_port_end, p.name, p.kind, s.status,
		        (SELECT COUNT(*) FROM routes r WHERE r.service_id = s.id),
		        p.max_domains, p.ssl_enabled, p.websocket_enabled, COALESCE(p.rate_limit_rpm,0), p.path_routing_enabled,
		        COALESCE(s.notes,"")
		 FROM services s JOIN plans p ON p.id = s.plan_id
		 WHERE s.client_id = ? ORDER BY s.id DESC`, clientID)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var s clientServiceRow
			if err := rows.Scan(
				&s.ID, &s.Name, &s.BackendIP, &s.PortStart, &s.PortEnd,
				&s.PlanName, &s.PlanKind, &s.Status, &s.RouteCount,
				&s.MaxDomains, &s.SSLEnabled, &s.WebsocketEnabled, &s.RateLimitRPM, &s.PathRouting,
				&s.Notes,
			); err == nil {
				// compute route quota percentage for progress bar
				if s.MaxDomains > 0 {
					pct := s.RouteCount * 100 / s.MaxDomains
					if pct > 100 {
						pct = 100
					}
					s.RouteCountPct = pct
				}
				d.Services = append(d.Services, s)
			}
		}
	}
	h.render(w, "services", d)
}

// ---- Service detail (read-only) ----------------------------------------

type clientServiceDetailRouteRow struct {
	RouteID    int64
	Domain     string
	PathPrefix string
	Port       int
	Status     string
	SSL        bool
}

type clientServiceDetailData struct {
	baseAppData
	ServiceID    int64
	Name         string
	Status       string
	PlanName     string
	Notes        string // admin-set notes (shown if non-empty)
	BackendIP    string
	RouteCount   int
	ActiveRoutes int
	Routes       []clientServiceDetailRouteRow
	Bandwidth7d  int64
	Bandwidth7dH string // human-formatted bandwidth
}

// ServiceDetail handles GET /app/services/{id}.
func (h *ClientHandlers) ServiceDetail(w http.ResponseWriter, r *http.Request) {
	sess := middleware.SessionFromContext(r.Context())
	db := h.DB()
	if db == nil || sess == nil {
		http.Redirect(w, r, "/app/services", http.StatusSeeOther)
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	clientID, err := clientIDFor(ctx, db, sess.UserID)
	if err != nil {
		http.Redirect(w, r, "/app/services", http.StatusSeeOther)
		return
	}
	d := clientServiceDetailData{baseAppData: h.base(r, "Service detail"), ServiceID: id}
	if err := db.QueryRowContext(ctx,
		`SELECT s.name, s.status, p.name, COALESCE(s.notes,''), s.backend_ip
		 FROM services s JOIN plans p ON p.id = s.plan_id
		 WHERE s.id = ? AND s.client_id = ?`, id, clientID,
	).Scan(&d.Name, &d.Status, &d.PlanName, &d.Notes, &d.BackendIP); err != nil {
		http.NotFound(w, r)
		return
	}
	rows, err := db.QueryContext(ctx,
		`SELECT id, domain, COALESCE(path_prefix,''), upstream_port, status, COALESCE(ssl_enabled,0)
		 FROM routes WHERE service_id = ? ORDER BY status, domain`, id)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var rr clientServiceDetailRouteRow
			var ssl int
			if err := rows.Scan(&rr.RouteID, &rr.Domain, &rr.PathPrefix, &rr.Port, &rr.Status, &ssl); err == nil {
				rr.SSL = ssl == 1
				d.Routes = append(d.Routes, rr)
				d.RouteCount++
				if rr.Status == "active" {
					d.ActiveRoutes++
				}
			}
		}
	}
	_ = db.QueryRowContext(ctx,
		`SELECT COALESCE(SUM(lr.bytes_resp),0)
		 FROM log_rollups lr JOIN routes r ON r.id = lr.route_id
		 WHERE r.service_id = ? AND lr.bucket_start >= (NOW() - INTERVAL 7 DAY)`, id,
	).Scan(&d.Bandwidth7d)
	d.Bandwidth7dH = formatBytes(d.Bandwidth7d)
	h.render(w, "service_detail", d)
}

// ServiceEdit (POST /app/services/{id}/edit) - only valid when the
// owning plan.kind = 'npm'. Restricted plans enforce hard rule #1:
// backend_ip / port range are admin-only.
func (h *ClientHandlers) ServiceEdit(w http.ResponseWriter, r *http.Request) {
	sess := middleware.SessionFromContext(r.Context())
	db := h.DB()
	if db == nil || sess == nil {
		http.Redirect(w, r, "/app/services", http.StatusSeeOther)
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	clientID, err := clientIDFor(ctx, db, sess.UserID)
	if err != nil {
		http.Redirect(w, r, "/app/services", http.StatusSeeOther)
		return
	}
	var (
		ownerID  int64
		planKind string
	)
	if err := db.QueryRowContext(ctx,
		`SELECT s.client_id, p.kind FROM services s JOIN plans p ON p.id = s.plan_id WHERE s.id = ?`, id,
	).Scan(&ownerID, &planKind); err != nil {
		redirectWithFlash(w, r, "/app/services", "", "service not found")
		return
	}
	if ownerID != clientID {
		redirectWithFlash(w, r, "/app/services", "", "not your service")
		return
	}
	if planKind != "npm" {
		redirectWithFlash(w, r, "/app/services", "", "your plan is admin-managed")
		return
	}
	_ = r.ParseForm()
	backendIP := strings.TrimSpace(r.FormValue("backend_ip"))
	ip := net.ParseIP(backendIP)
	if ip == nil {
		redirectWithFlash(w, r, "/app/services", "", "backend IP invalid")
		return
	}
	// Even on self-service npm plans, never let a client point the node at
	// loopback or link-local/cloud-metadata - that would proxy to node-local
	// services or leak the node's cloud credentials.
	if security.IsDangerousProxyBackend(ip) {
		redirectWithFlash(w, r, "/app/services", "", "backend IP not allowed (loopback / link-local / metadata)")
		return
	}
	// Hard rule #2: the allowed port range is the security boundary, NOT
	// client data. A client must never widen it (routes.Create validates the
	// chosen port against this range, so widening it to 1..65535 would let the
	// client proxy to any backend port). Only backend_ip is self-service here;
	// the admin-assigned range is left untouched.
	if _, err := db.ExecContext(ctx,
		"UPDATE services SET backend_ip = ?, updated_at = NOW() WHERE id = ?",
		backendIP, id); err != nil {
		h.Logger.Warn("client service edit", "id", id, "err", err)
		redirectWithFlash(w, r, "/app/services", "", "update failed")
		return
	}
	uid := sess.UserID
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: &uid, Action: "service.update.client", Entity: "service",
		EntityID: strconv.FormatInt(id, 10),
		Meta:     map[string]any{"backend_ip": backendIP, "plan_kind": planKind},
	})
	// Re-push affected nodes now so the new backend_ip takes effect within
	// seconds instead of waiting up to ~5 min for ReconcileDrift. Backgrounded
	// on the service's own context so the client response isn't blocked.
	if h.Routes != nil {
		go func(serviceID int64) {
			defer recoverBg(h.Logger, "client-service-edit-resync")
			bg, cancel := context.WithTimeout(h.Routes.BackgroundCtx(), 30*time.Second)
			defer cancel()
			rows, err := db.QueryContext(bg,
				`SELECT DISTINCT caddy_node_id FROM routes WHERE service_id = ? AND caddy_node_id IS NOT NULL`, serviceID)
			if err != nil {
				return
			}
			defer rows.Close()
			var nodeIDs []int64
			for rows.Next() {
				var nid int64
				if rows.Scan(&nid) == nil {
					nodeIDs = append(nodeIDs, nid)
				}
			}
			if rows.Err() != nil {
				return
			}
			for _, nid := range nodeIDs {
				h.Routes.SchedulePush(nid)
			}
		}(id)
	}
	redirectWithFlash(w, r, "/app/services", "Service updated", "")
}

// ---- Routes -------------------------------------------------------------

type clientRouteRow struct {
	ID              int64
	Domain          string
	PathPrefix      string
	UpstreamPort    int
	ServiceName     string
	Status          string
	LastError       string
	MaintenanceMode bool
	SvcStatus       string // parent service status
	CertDaysLeft    int    // -1 = no manual cert, 0+ = days until expiry
	DomainVerified  bool   // false => needs the _hpg-verify TXT proof before serving/cert
	VerifyToken     string // TXT value the owner must publish at _hpg-verify.<domain>
}

type clientRoutesData struct {
	baseAppData
	Routes              []clientRouteRow
	HasSuspendedService bool   // true if any route's service is suspended
	Q                   string // current search query
}

func (h *ClientHandlers) RoutesList(w http.ResponseWriter, r *http.Request) {
	d := clientRoutesData{baseAppData: h.base(r, "Domains")}
	sess := middleware.SessionFromContext(r.Context())
	db := h.DB()
	if db == nil || sess == nil {
		h.render(w, "routes_list", d)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3_000_000_000)
	defer cancel()
	clientID, err := clientIDFor(ctx, db, sess.UserID)
	if err != nil {
		h.render(w, "routes_list", d)
		return
	}
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	d.Q = q

	// build WHERE clause dynamically to support optional search filter
	query := `SELECT r.id, r.domain, COALESCE(r.path_prefix,''), r.upstream_port, s.name, r.status, COALESCE(r.last_error,''), COALESCE(r.maintenance_mode,0), s.status,
		        COALESCE(DATEDIFF(mc.not_after, NOW()), -1),
		        COALESCE(r.domain_verified,0), COALESCE(r.verify_token,'')
		 FROM routes r JOIN services s ON s.id = r.service_id
		 LEFT JOIN manual_certs mc ON mc.route_id = r.id
		 WHERE s.client_id = ?`
	args := []any{clientID}
	if q != "" {
		like := likeContains(q)
		query += ` AND (r.domain LIKE ? OR s.name LIKE ?)`
		args = append(args, like, like)
	}
	query += ` ORDER BY r.id DESC`

	rows, err := db.QueryContext(ctx, query, args...)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var rr clientRouteRow
			if err := rows.Scan(&rr.ID, &rr.Domain, &rr.PathPrefix, &rr.UpstreamPort, &rr.ServiceName, &rr.Status, &rr.LastError, &rr.MaintenanceMode, &rr.SvcStatus, &rr.CertDaysLeft, &rr.DomainVerified, &rr.VerifyToken); err == nil {
				if rr.SvcStatus == "suspended" {
					d.HasSuspendedService = true
				}
				d.Routes = append(d.Routes, rr)
			}
		}
	}
	h.render(w, "routes_list", d)
}

type clientRouteNewServiceOpt struct {
	ID        int64
	Name      string
	PortStart int
	PortEnd   int
}

type clientRouteNewForm struct {
	UpstreamPort int
	Domain       string
	PathPrefix   string
}

type clientRouteNewData struct {
	baseAppData
	Services          []clientRouteNewServiceOpt
	SelectedServiceID int64
	Form              clientRouteNewForm
	NodeHostname      string
	NodeIP            string
}

func (h *ClientHandlers) RouteNew(w http.ResponseWriter, r *http.Request) {
	d := clientRouteNewData{baseAppData: h.base(r, "New domain mapping")}
	sess := middleware.SessionFromContext(r.Context())
	db := h.DB()
	if db == nil || sess == nil {
		h.render(w, "route_new", d)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3_000_000_000)
	defer cancel()
	clientID, err := clientIDFor(ctx, db, sess.UserID)
	if err != nil {
		h.render(w, "route_new", d)
		return
	}
	rows, err := db.QueryContext(ctx,
		`SELECT id, name, allowed_port_start, allowed_port_end FROM services
		 WHERE client_id = ? AND status='active' ORDER BY id`, clientID)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var s clientRouteNewServiceOpt
			if err := rows.Scan(&s.ID, &s.Name, &s.PortStart, &s.PortEnd); err == nil {
				d.Services = append(d.Services, s)
			}
		}
	}
	if sid := r.URL.Query().Get("service_id"); sid != "" {
		if v, err := strconv.ParseInt(sid, 10, 64); err == nil {
			d.SelectedServiceID = v
		}
	}

	// Show DNS target = first node in the plan's node group.
	if len(d.Services) > 0 {
		nodeRow := db.QueryRowContext(ctx,
			`SELECT COALESCE(n.public_hostname,''), COALESCE(n.public_ip,'')
			 FROM services s
			 JOIN caddy_nodes n ON n.node_group_id = s.node_group_id
			 WHERE s.client_id = ? AND n.is_enabled = 1
			 ORDER BY n.priority DESC, n.id ASC LIMIT 1`, clientID)
		_ = nodeRow.Scan(&d.NodeHostname, &d.NodeIP)
	}

	h.render(w, "route_new", d)
}

func (h *ClientHandlers) RouteCreate(w http.ResponseWriter, r *http.Request) {
	sess := middleware.SessionFromContext(r.Context())
	if sess == nil {
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	_ = r.ParseForm()
	serviceID, _ := strconv.ParseInt(r.FormValue("service_id"), 10, 64)
	port, _ := strconv.Atoi(r.FormValue("upstream_port"))

	ctx, cancel := context.WithTimeout(r.Context(), 8_000_000_000)
	defer cancel()
	clientID, err := clientIDFor(ctx, db, sess.UserID)
	if err != nil {
		http.Error(w, "no client record", http.StatusForbidden)
		return
	}

	in := routes.CreateInput{
		ServiceID:    serviceID,
		UpstreamPort: port,
		Domain:       r.FormValue("domain"),
		PathPrefix:   r.FormValue("path_prefix"),
		SSL:          r.FormValue("ssl") == "1",
		WebSocket:    r.FormValue("websocket") == "1",
		ForceHTTPS:   r.FormValue("force_https") == "1",
	}
	routeID, err := h.Routes.Create(ctx, clientID, in)
	if err != nil {
		msg := mapRouteErr(err)
		redirectWithFlash(w, r, "/app/routes/new", "", msg)
		return
	}
	uid := sess.UserID
	audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
		UserID: &uid, Action: "route.create", Entity: "route",
		EntityID: fmt.Sprintf("%d", routeID),
		Meta: map[string]any{
			"service_id": in.ServiceID, "domain": strings.ToLower(strings.TrimSpace(in.Domain)),
			"path": in.PathPrefix, "port": in.UpstreamPort,
		},
	})
	redirectWithFlash(w, r, "/app/routes", "Domain mapping created. Update DNS and watch the status badge.", "")
}

func (h *ClientHandlers) RouteDelete(w http.ResponseWriter, r *http.Request) {
	sess := middleware.SessionFromContext(r.Context())
	if sess == nil {
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}
	db := h.DB()
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	ctx, cancel := context.WithTimeout(r.Context(), 8_000_000_000)
	defer cancel()
	clientID, err := clientIDFor(ctx, db, sess.UserID)
	if err != nil {
		http.Error(w, "no client", http.StatusForbidden)
		return
	}
	if err := h.Routes.Delete(ctx, clientID, id); err != nil {
		redirectWithFlash(w, r, "/app/routes", "", "delete failed: "+sanitizeErr(err))
		return
	}
	uid := sess.UserID
	audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
		UserID: &uid, Action: "route.delete", Entity: "route", EntityID: fmt.Sprintf("%d", id),
	})
	redirectWithFlash(w, r, "/app/routes", "Mapping deleted", "")
}

func (h *ClientHandlers) RouteVerifyDNS(w http.ResponseWriter, r *http.Request) {
	sess := middleware.SessionFromContext(r.Context())
	if sess == nil {
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}
	db := h.DB()
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	ctx, cancel := context.WithTimeout(r.Context(), 10_000_000_000)
	defer cancel()
	// AUTHZ-04: fail closed. On a missing clients row clientID would be 0, which
	// Routes.VerifyDNS treats as admin scope (skips the ownership check).
	clientID, err := clientIDFor(ctx, db, sess.UserID)
	if err != nil {
		http.Error(w, "no client", http.StatusForbidden)
		return
	}
	// Re-check first attempts DNS-TXT domain-ownership proof (clears the
	// domain_verified gate). If already verified it falls through to the normal
	// DNS A/CNAME re-check. Either way the route is re-advanced afterwards.
	if _, _, verr := h.Routes.VerifyDomainToken(ctx, clientID, id); verr != nil {
		if errors.Is(verr, routes.ErrVerifyTokenMissing) {
			redirectWithFlash(w, r, "/app/routes", "",
				"Domain not verified. Publish the _hpg-verify TXT record shown on the route, then re-check.")
			return
		}
		// Any error other than "already verified" is a real failure.
		if !errors.Is(verr, routes.ErrAlreadyVerified) {
			redirectWithFlash(w, r, "/app/routes", "", "re-check failed: "+sanitizeErr(verr))
			return
		}
	}
	if err := h.Routes.VerifyDNS(ctx, clientID, id); err != nil {
		redirectWithFlash(w, r, "/app/routes", "", "re-check failed: "+sanitizeErr(err))
		return
	}
	redirectWithFlash(w, r, "/app/routes", "DNS re-check queued", "")
}

func (h *ClientHandlers) RouteRetrySSL(w http.ResponseWriter, r *http.Request) {
	// MVP: re-checking DNS triggers a re-push too. SSL retry is the same path.
	h.RouteVerifyDNS(w, r)
}

// RouteMaintenance toggles maintenance_mode for a client-owned route.
func (h *ClientHandlers) RouteMaintenance(w http.ResponseWriter, r *http.Request) {
	sess := middleware.SessionFromContext(r.Context())
	if sess == nil {
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}
	db := h.DB()
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	clientID, err := clientIDFor(ctx, db, sess.UserID)
	if err != nil {
		http.Error(w, "no client", http.StatusForbidden)
		return
	}
	// Verify ownership.
	var ownerClientID int64
	if err := db.QueryRowContext(ctx,
		`SELECT s.client_id FROM routes r JOIN services s ON s.id = r.service_id WHERE r.id = ?`, id,
	).Scan(&ownerClientID); err != nil {
		redirectWithFlash(w, r, "/app/routes", "", "route not found")
		return
	}
	if ownerClientID != clientID {
		redirectWithFlash(w, r, "/app/routes", "", "not your route")
		return
	}
	// Read current state and toggle.
	var current int
	_ = db.QueryRowContext(ctx, "SELECT COALESCE(maintenance_mode,0) FROM routes WHERE id = ?", id).Scan(&current)
	next := 0
	msg := "Maintenance mode disabled"
	if current == 0 {
		next = 1
		msg = "Maintenance mode enabled"
	}
	if _, err := db.ExecContext(ctx, "UPDATE routes SET maintenance_mode = ?, updated_at = NOW() WHERE id = ?", next, id); err != nil {
		redirectWithFlash(w, r, "/app/routes", "", "update failed")
		return
	}
	uid := sess.UserID
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: &uid, Action: "route.maintenance.toggle", Entity: "route",
		EntityID: strconv.FormatInt(id, 10),
		Meta:     map[string]any{"maintenance_mode": next},
	})
	// Re-push affected node so Caddy picks up the change immediately.
	if h.Routes != nil {
		go func(routeID int64) {
			defer recoverBg(h.Logger, "client-maintenance-resync")
			bg, cancel := context.WithTimeout(h.Routes.BackgroundCtx(), 30*time.Second)
			defer cancel()
			var nid int64
			if err := db.QueryRowContext(bg,
				`SELECT caddy_node_id FROM routes WHERE id = ? AND caddy_node_id IS NOT NULL`, routeID,
			).Scan(&nid); err == nil {
				h.Routes.SchedulePush(nid)
			}
		}(id)
	}
	redirectWithFlash(w, r, "/app/routes", msg, "")
}

// RouteExport streams GET /app/routes/export.csv for the session client.
func (h *ClientHandlers) RouteExport(w http.ResponseWriter, r *http.Request) {
	sess := middleware.SessionFromContext(r.Context())
	db := h.DB()
	if db == nil || sess == nil {
		http.Error(w, "unavailable", 503)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	clientID, err := clientIDFor(ctx, db, sess.UserID)
	if err != nil {
		http.Error(w, "no client record", 403)
		return
	}
	rows, err := db.QueryContext(ctx,
		`SELECT r.domain, COALESCE(r.path_prefix,""), r.upstream_port, r.status,
		        r.ssl_enabled, COALESCE(r.maintenance_mode,0), s.name,
		        DATE_FORMAT(r.created_at,"%Y-%m-%d")
		 FROM routes r
		 JOIN services s ON s.id = r.service_id
		 WHERE s.client_id = ? ORDER BY r.id DESC`,
		clientID)
	if err != nil {
		http.Error(w, "query failed", 500)
		return
	}
	defer rows.Close()
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="my-routes.csv"`)
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"domain", "path_prefix", "upstream_port", "status", "ssl", "maintenance", "service", "created"})
	for rows.Next() {
		var domain, pathPfx, status, svcName, created string
		var port, ssl, maint int
		if err := rows.Scan(&domain, &pathPfx, &port, &status, &ssl, &maint, &svcName, &created); err != nil {
			continue
		}
		sslStr := "no"
		if ssl == 1 {
			sslStr = "yes"
		}
		maintStr := "no"
		if maint == 1 {
			maintStr = "yes"
		}
		_ = cw.Write([]string{domain, pathPfx, strconv.Itoa(port), status, sslStr, maintStr, svcName, created})
	}
	cw.Flush()
}

// ---- Route edit ---------------------------------------------------------

type clientRouteEditData struct {
	baseAppData
	RouteID      int64
	Domain       string
	PathPrefix   string
	UpstreamPort int
	WebSocket    bool
	ForceHTTPS   bool
	ServiceName  string
}

// RouteEdit renders the route edit form for the owning client.
func (h *ClientHandlers) RouteEdit(w http.ResponseWriter, r *http.Request) {
	sess := middleware.SessionFromContext(r.Context())
	if sess == nil {
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	clientID, err := clientIDFor(ctx, db, sess.UserID)
	if err != nil {
		http.Error(w, "no client record", http.StatusForbidden)
		return
	}
	d := clientRouteEditData{baseAppData: h.base(r, "Edit route"), RouteID: id}
	var ownerClientID int64
	if err := db.QueryRowContext(ctx,
		`SELECT s.client_id, r.domain, COALESCE(r.path_prefix,''), r.upstream_port,
		        COALESCE(r.websocket,0), COALESCE(r.force_https,0), s.name
		 FROM routes r JOIN services s ON s.id = r.service_id WHERE r.id = ?`, id,
	).Scan(&ownerClientID, &d.Domain, &d.PathPrefix, &d.UpstreamPort, &d.WebSocket, &d.ForceHTTPS, &d.ServiceName); err != nil {
		redirectWithFlash(w, r, "/app/routes", "", "route not found")
		return
	}
	if ownerClientID != clientID {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	h.render(w, "route_edit", d)
}

// RouteEditSave handles POST /app/routes/{id}/edit — validates and persists edits.
func (h *ClientHandlers) RouteEditSave(w http.ResponseWriter, r *http.Request) {
	sess := middleware.SessionFromContext(r.Context())
	if sess == nil {
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	_ = r.ParseForm()
	newDomain := strings.ToLower(strings.TrimSpace(r.FormValue("domain")))
	newPath := strings.TrimSpace(r.FormValue("path_prefix"))
	newPort, _ := strconv.Atoi(r.FormValue("upstream_port"))
	newWS := r.FormValue("websocket") == "1"
	newFH := r.FormValue("force_https") == "1"

	editURL := fmt.Sprintf("/app/routes/%d/edit", id)
	if newDomain == "" {
		redirectWithFlash(w, r, editURL, "", "domain is required")
		return
	}
	if newPort < 1 || newPort > 65535 {
		redirectWithFlash(w, r, editURL, "", "port must be 1-65535")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	clientID, err := clientIDFor(ctx, db, sess.UserID)
	if err != nil {
		http.Error(w, "no client record", http.StatusForbidden)
		return
	}

	// Load ownership + plan constraints + caddy node.
	var ownerClientID, portStart, portEnd int64
	var planWebSocket bool
	var caddyNodeID sql.NullInt64
	if err := db.QueryRowContext(ctx,
		`SELECT s.client_id, s.allowed_port_start, s.allowed_port_end, p.websocket_enabled, r.caddy_node_id
		 FROM routes r
		 JOIN services s ON s.id = r.service_id
		 JOIN plans p ON p.id = s.plan_id
		 WHERE r.id = ?`, id,
	).Scan(&ownerClientID, &portStart, &portEnd, &planWebSocket, &caddyNodeID); err != nil {
		redirectWithFlash(w, r, "/app/routes", "", "route not found")
		return
	}
	if ownerClientID != clientID {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if int64(newPort) < portStart || int64(newPort) > portEnd {
		redirectWithFlash(w, r, editURL, "", fmt.Sprintf("port must be in range %d-%d", portStart, portEnd))
		return
	}
	// Suppress WebSocket if plan does not permit it.
	if newWS && !planWebSocket {
		newWS = false
	}

	// Uniqueness check excluding self.
	var dup int
	_ = db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM routes WHERE domain = ? AND COALESCE(path_prefix,'') = ? AND id != ?`,
		newDomain, newPath, id,
	).Scan(&dup)
	if dup > 0 {
		redirectWithFlash(w, r, editURL, "", "domain + path already in use by another route")
		return
	}

	if _, err := db.ExecContext(ctx,
		`UPDATE routes SET domain=?, path_prefix=?, upstream_port=?, websocket=?, force_https=?, updated_at=NOW() WHERE id=?`,
		newDomain, newPath, newPort, newWS, newFH, id,
	); err != nil {
		redirectWithFlash(w, r, editURL, "", "update failed")
		return
	}

	// Re-push node so Caddy picks up changes quickly.
	if h.Routes != nil && caddyNodeID.Valid {
		nodeID := caddyNodeID.Int64
		go func() {
			defer recoverBg(h.Logger, "client-route-edit-resync")
			bg, cancel := context.WithTimeout(h.Routes.BackgroundCtx(), 30*time.Second)
			defer cancel()
			_ = bg
			h.Routes.SchedulePush(nodeID)
		}()
	}

	uid := sess.UserID
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: &uid, Action: "route.update", Entity: "route",
		EntityID: strconv.FormatInt(id, 10),
		Meta: map[string]any{
			"domain": newDomain, "path": newPath, "port": newPort,
			"websocket": newWS, "force_https": newFH,
		},
	})
	redirectWithFlash(w, r, "/app/routes", "Route updated.", "")
}

func mapRouteErr(err error) string {
	switch {
	case errors.Is(err, routes.ErrPortOutOfRange):
		return "Port is outside your allowed range."
	case errors.Is(err, routes.ErrInvalidDomain):
		return "Invalid domain."
	case errors.Is(err, routes.ErrDomainTaken):
		return "This domain (and path) is already mapped."
	case errors.Is(err, routes.ErrNoNodeFound):
		return "No proxy node has capacity for your plan. Contact support."
	case errors.Is(err, routes.ErrServiceNotYours):
		return "Service not found."
	case errors.Is(err, routes.ErrMaxDomains):
		return "Plan domain limit reached. Upgrade or remove an existing mapping."
	}
	if s := err.Error(); strings.Contains(s, "plan does not permit path routing") {
		return "Your plan does not allow path routing - leave path empty."
	}
	return "Create failed."
}

// ---- Client 2FA --------------------------------------------------------

type clientTwofaData struct {
	baseAppData
	Enabled         bool
	Enrolling       bool
	Secret          string
	QRBase64        string
	RecoveryCodes   []string
	SMSOTPEnabled   bool // user has SMS 2FA active
	SMSOTPAvailable bool // admin allowed SMS 2FA globally
	HasPhone        bool // user has phone_e164 set
	SMSOTPEnrolling bool // in-progress SMS enrollment (code sent, waiting confirm)
	// Email 2FA - always available as long as SMTP is wired (no admin gate).
	EmailOTPEnabled   bool
	EmailOTPEnrolling bool
	HasMailer         bool
}

func (h *ClientHandlers) TwoFAPage(w http.ResponseWriter, r *http.Request) {
	d := clientTwofaData{baseAppData: h.base(r, "Two-factor authentication")}
	d.HasMailer = h.Mailer != nil
	sess := middleware.SessionFromContext(r.Context())
	db := h.DB()
	if db != nil && sess != nil {
		ctx := r.Context()
		var smsOTPEnabled, emailOTPEnabled bool
		var phoneE164 sql.NullString
		_ = db.QueryRowContext(ctx,
			"SELECT totp_enabled, sms_otp_enabled, email_otp_enabled, phone_e164 FROM users WHERE id = ?",
			sess.UserID,
		).Scan(&d.Enabled, &smsOTPEnabled, &emailOTPEnabled, &phoneE164)
		d.SMSOTPEnabled = smsOTPEnabled
		d.EmailOTPEnabled = emailOTPEnabled
		d.HasPhone = phoneE164.Valid && phoneE164.String != ""
		var avail string
		_ = db.QueryRowContext(ctx,
			"SELECT value FROM settings WHERE `key` = 'sms_otp_available' LIMIT 1",
		).Scan(&avail)
		d.SMSOTPAvailable = avail == "1"
	}
	h.render(w, "twofa", d)
}

func (h *ClientHandlers) TwoFAStart(w http.ResponseWriter, r *http.Request) {
	sess := middleware.SessionFromContext(r.Context())
	db := h.DB()
	if sess == nil {
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}
	if db == nil {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}
	_, secret, qrPNG, err := auth.GenerateTOTP("Hostyt Proxy", sess.Email)
	if err != nil {
		http.Error(w, "totp gen failed", http.StatusInternalServerError)
		return
	}
	// Stash secret server-side; never round-trip it through the browser form.
	// Encrypt at rest to match totp_secret_enc; only the page render holds plaintext.
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	stash := secret
	if h.State != nil {
		if enc, eerr := h.State.Encrypt(secret); eerr == nil {
			stash = enc
		}
	}
	if _, err := db.ExecContext(ctx,
		"UPDATE users SET totp_pending_secret = ?, totp_pending_exp = "+store.DateAddMinutes(10)+", totp_pending_attempts = 0 WHERE id = ?",
		stash, sess.UserID,
	); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	d := clientTwofaData{
		baseAppData: h.base(r, "Set up 2FA"),
		Enrolling:   true,
		Secret:      secret, // displayed once for manual entry; NOT sent back in form
		QRBase64:    base64.StdEncoding.EncodeToString(qrPNG),
	}
	h.render(w, "twofa", d)
}

func (h *ClientHandlers) TwoFAConfirm(w http.ResponseWriter, r *http.Request) {
	sess := middleware.SessionFromContext(r.Context())
	db := h.DB()
	if sess == nil || db == nil {
		http.Error(w, "no db / no session", http.StatusServiceUnavailable)
		return
	}
	_ = r.ParseForm()
	code := strings.TrimSpace(r.FormValue("code"))
	ctx, cancel := context.WithTimeout(r.Context(), 8_000_000_000)
	defer cancel()
	// Read secret from DB stash written by TwoFAStart; never from the form body.
	var pendingSecret sql.NullString
	var pendingExp sql.NullTime
	var attempts int
	_ = db.QueryRowContext(ctx,
		"SELECT totp_pending_secret, totp_pending_exp, totp_pending_attempts FROM users WHERE id = ?", sess.UserID,
	).Scan(&pendingSecret, &pendingExp, &attempts)
	if !pendingSecret.Valid || pendingSecret.String == "" {
		redirectWithFlash(w, r, "/app/2fa", "", "setup session expired; restart 2FA setup")
		return
	}
	if !pendingExp.Valid || time.Now().After(pendingExp.Time) {
		// Expired stash: clear it so a stale secret can never be accepted later.
		_, _ = db.ExecContext(ctx,
			"UPDATE users SET totp_pending_secret = NULL, totp_pending_exp = NULL, totp_pending_attempts = 0 WHERE id = ?", sess.UserID)
		redirectWithFlash(w, r, "/app/2fa", "", "setup session expired; restart 2FA setup")
		return
	}
	// Decrypt stash; fall back to raw for any pre-encryption rows.
	secret := pendingSecret.String
	if h.State != nil {
		if dec, derr := h.State.Decrypt(pendingSecret.String); derr == nil {
			secret = dec
		}
	}
	if err := auth.ValidateTOTP(secret, code); err != nil {
		// Keep the stash so the user can retry within the window, but cap guesses.
		const maxTOTPEnrollAttempts = 5
		if attempts+1 >= maxTOTPEnrollAttempts {
			_, _ = db.ExecContext(ctx,
				"UPDATE users SET totp_pending_secret = NULL, totp_pending_exp = NULL, totp_pending_attempts = 0 WHERE id = ?", sess.UserID)
			redirectWithFlash(w, r, "/app/2fa", "", "too many attempts; restart 2FA setup")
			return
		}
		_, _ = db.ExecContext(ctx,
			"UPDATE users SET totp_pending_attempts = totp_pending_attempts + 1 WHERE id = ?", sess.UserID)
		redirectWithFlash(w, r, "/app/2fa", "", "invalid code; try again")
		return
	}
	// Correct code: consume the stash so it cannot be replayed.
	_, _ = db.ExecContext(ctx,
		"UPDATE users SET totp_pending_secret = NULL, totp_pending_exp = NULL, totp_pending_attempts = 0 WHERE id = ?", sess.UserID)
	codes, hashes, err := auth.GenerateRecoveryCodes(8)
	if err != nil {
		redirectWithFlash(w, r, "/app/2fa", "", "internal error")
		return
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		redirectWithFlash(w, r, "/app/2fa", "", "tx begin failed")
		return
	}
	defer tx.Rollback() //nolint:errcheck
	encSecret := secret
	useEnc := false
	if h.State != nil {
		if enc, eerr := h.State.Encrypt(secret); eerr == nil {
			encSecret = enc
			useEnc = true
		}
	}
	var totpErr error
	if useEnc {
		_, totpErr = tx.ExecContext(ctx,
			"UPDATE users SET totp_secret_enc = ?, totp_secret = NULL, totp_enabled = 1 WHERE id = ?",
			encSecret, sess.UserID)
	} else {
		_, totpErr = tx.ExecContext(ctx,
			"UPDATE users SET totp_secret = ?, totp_secret_enc = NULL, totp_enabled = 1 WHERE id = ?",
			secret, sess.UserID)
	}
	if totpErr != nil {
		redirectWithFlash(w, r, "/app/2fa", "", "internal error")
		return
	}
	_, _ = tx.ExecContext(ctx, "DELETE FROM recovery_codes WHERE user_id = ?", sess.UserID)
	for _, h := range hashes {
		if _, err := tx.ExecContext(ctx,
			"INSERT INTO recovery_codes (user_id, code_hash) VALUES (?, ?)", sess.UserID, h); err != nil {
			redirectWithFlash(w, r, "/app/2fa", "", "internal error")
			return
		}
	}
	if err := tx.Commit(); err != nil {
		redirectWithFlash(w, r, "/app/2fa", "", "internal error")
		return
	}
	uid := sess.UserID
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: &uid, Action: "2fa.enable", Entity: "user", EntityID: fmt.Sprintf("%d", uid),
	})
	d := clientTwofaData{
		baseAppData:   h.base(r, "Two-factor authentication"),
		Enabled:       true,
		RecoveryCodes: codes,
	}
	h.render(w, "twofa", d)
}

func (h *ClientHandlers) TwoFADisable(w http.ResponseWriter, r *http.Request) {
	sess := middleware.SessionFromContext(r.Context())
	db := h.DB()
	if sess == nil || db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5_000_000_000)
	defer cancel()
	_, _ = db.ExecContext(ctx, "UPDATE users SET totp_secret = NULL, totp_secret_enc = NULL, totp_enabled = 0 WHERE id = ?", sess.UserID)
	_, _ = db.ExecContext(ctx, "DELETE FROM recovery_codes WHERE user_id = ?", sess.UserID)
	uid := sess.UserID
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: &uid, Action: "2fa.disable", Entity: "user", EntityID: fmt.Sprintf("%d", uid),
	})
	redirectWithFlash(w, r, "/app/2fa", "2FA disabled", "")
}

// ---- SMS OTP enrollment (client) ----------------------------------------

// SMSOTPStart sends a verification code to the user's phone and stores the
// OTP ticket in Redis. The pending ticket is held in a separate cookie
// (not hpg_2fa_pending) so it doesn't interfere with normal login flow.
func (h *ClientHandlers) SMSOTPStart(w http.ResponseWriter, r *http.Request) {
	sess := middleware.SessionFromContext(r.Context())
	db := h.DB()
	if sess == nil || db == nil {
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()

	// Guard: admin must have enabled SMS OTP globally.
	var avail string
	_ = db.QueryRowContext(ctx,
		"SELECT value FROM settings WHERE `key` = 'sms_otp_available' LIMIT 1",
	).Scan(&avail)
	if avail != "1" {
		redirectWithFlash(w, r, "/app/2fa", "", "SMS 2FA is not available.")
		return
	}
	var phone sql.NullString
	_ = db.QueryRowContext(ctx, "SELECT phone_e164 FROM users WHERE id = ?", sess.UserID).Scan(&phone)
	if !phone.Valid || phone.String == "" {
		redirectWithFlash(w, r, "/app/2fa", "", "Set your phone in Account first.")
		return
	}
	if h.SMS == nil {
		redirectWithFlash(w, r, "/app/2fa", "", "SMS not configured.")
		return
	}
	// Generate and send code - need a redis.Client here; store ticket in session cookie.
	// We pass through the redirect back to twofa page with SMSOTPEnrolling=true.
	// Actual storage uses the auth.StoreSMSOTP helpers which need *redis.Client.
	// ClientHandlers doesn't hold RDB directly; store a short-lived Redis key via
	// the SMS field's Send - use a simple in-DB approach instead:
	// generate code → store SHA-256 hash in users.sms_otp_pending_hash + expiry.
	// This avoids injecting redis into ClientHandlers.
	code, err := auth.GenerateSMSOTP()
	if err != nil {
		redirectWithFlash(w, r, "/app/2fa", "", "Internal error.")
		return
	}
	// Store hash + expiry directly in DB (avoids redis dependency in ClientHandlers).
	hash := auth.SMSOTPHash(code)
	_, err = db.ExecContext(ctx,
		"UPDATE users SET sms_otp_pending_hash = ?, sms_otp_pending_exp = "+store.DateAddMinutes(5)+" WHERE id = ?",
		hash, sess.UserID)
	if err != nil {
		redirectWithFlash(w, r, "/app/2fa", "", "Internal error.")
		return
	}
	if err := h.SMS.Send(ctx, phone.String, fmt.Sprintf("Your Hostyt Proxy SMS 2FA setup code: %s", code)); err != nil {
		redirectWithFlash(w, r, "/app/2fa", "", "Failed to send SMS: "+sanitizeErr(err))
		return
	}
	uid := sess.UserID
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: &uid, Action: "2fa.sms.enroll.start", Entity: "user", EntityID: fmt.Sprintf("%d", uid),
	})
	// Show the confirm form.
	d := clientTwofaData{
		baseAppData:     h.base(r, "Two-factor authentication"),
		SMSOTPAvailable: true, HasPhone: true,
		SMSOTPEnrolling: true,
	}
	h.render(w, "twofa", d)
}

// SMSOTPConfirm verifies the enrollment code and sets sms_otp_enabled=1.
func (h *ClientHandlers) SMSOTPConfirm(w http.ResponseWriter, r *http.Request) {
	sess := middleware.SessionFromContext(r.Context())
	db := h.DB()
	if sess == nil || db == nil {
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}
	_ = r.ParseForm()
	code := strings.TrimSpace(r.FormValue("code"))
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	var storedHash sql.NullString
	var exp sql.NullTime
	_ = db.QueryRowContext(ctx,
		"SELECT sms_otp_pending_hash, sms_otp_pending_exp FROM users WHERE id = ?", sess.UserID,
	).Scan(&storedHash, &exp)

	if !storedHash.Valid || storedHash.String == "" {
		redirectWithFlash(w, r, "/app/2fa", "", "No pending SMS code. Start again.")
		return
	}
	if !exp.Valid || time.Now().After(exp.Time) {
		redirectWithFlash(w, r, "/app/2fa", "", "Code expired. Start again.")
		return
	}
	// Constant-time compare: avoid leaking match via response timing.
	if subtle.ConstantTimeCompare([]byte(auth.SMSOTPHash(code)), []byte(storedHash.String)) != 1 {
		redirectWithFlash(w, r, "/app/2fa", "", "Invalid code.")
		return
	}
	_, err := db.ExecContext(ctx,
		"UPDATE users SET sms_otp_enabled = 1, sms_otp_pending_hash = NULL, sms_otp_pending_exp = NULL WHERE id = ?",
		sess.UserID)
	if err != nil {
		redirectWithFlash(w, r, "/app/2fa", "", "Internal error.")
		return
	}
	uid := sess.UserID
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: &uid, Action: "2fa.sms.enroll.complete", Entity: "user", EntityID: fmt.Sprintf("%d", uid),
	})
	redirectWithFlash(w, r, "/app/2fa", "SMS 2FA enabled.", "")
}

// SMSOTPDisable turns off SMS OTP for the current user.
func (h *ClientHandlers) SMSOTPDisable(w http.ResponseWriter, r *http.Request) {
	sess := middleware.SessionFromContext(r.Context())
	db := h.DB()
	if sess == nil || db == nil {
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	_, _ = db.ExecContext(ctx,
		"UPDATE users SET sms_otp_enabled = 0, sms_otp_pending_hash = NULL, sms_otp_pending_exp = NULL WHERE id = ?",
		sess.UserID)
	uid := sess.UserID
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: &uid, Action: "2fa.sms.disable", Entity: "user", EntityID: fmt.Sprintf("%d", uid),
	})
	redirectWithFlash(w, r, "/app/2fa", "SMS 2FA disabled.", "")
}

// ---- Client API keys ----------------------------------------------------

type clientAPIKeyRow struct {
	ID         int64
	Name       string
	Prefix     string
	Scopes     string
	LastUsedAt string
	LastUsedIP string
	UseCount   int64
	CreatedAt  string
	ExpiresAt  string
	Revoked    bool
}

type clientAPIKeysData struct {
	baseAppData
	Keys     []clientAPIKeyRow
	NewPlain string
}

func (h *ClientHandlers) APIKeysPage(w http.ResponseWriter, r *http.Request) {
	d := clientAPIKeysData{baseAppData: h.base(r, "API tokens")}
	d.Keys = h.loadClientAPIKeys(r.Context())
	h.render(w, "api_keys", d)
}

func (h *ClientHandlers) APIKeysCreate(w http.ResponseWriter, r *http.Request) {
	sess := middleware.SessionFromContext(r.Context())
	db := h.DB()
	if db == nil || sess == nil {
		http.Error(w, "no db / no session", http.StatusServiceUnavailable)
		return
	}
	_ = r.ParseForm()
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		redirectWithFlash(w, r, "/app/api-keys", "", "name required")
		return
	}
	expiresDays, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("expires_days")))
	if expiresDays < 0 || expiresDays > 3650 {
		redirectWithFlash(w, r, "/app/api-keys", "", "expires_days must be 0..3650")
		return
	}
	// Build scopes from checkboxes; default both if neither is checked.
	var clientScopes []string
	if r.FormValue("scope_client_read") == "1" {
		clientScopes = append(clientScopes, "client:read")
	}
	if r.FormValue("scope_client_write") == "1" {
		clientScopes = append(clientScopes, "client:write")
	}
	scopes := strings.Join(clientScopes, ",")
	if scopes == "" {
		scopes = "client:read,client:write"
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	// Client-owned tokens are intentionally limited to the read+write
	// scopes the customer routes actually accept. The admin /v1/* scopes
	// are reserved for admin-issued keys.
	plain, id, prefix, err := auth.CreateAPIKey(ctx, db, sess.UserID, name, scopes)
	if err != nil {
		h.Logger.Error("client api key create", "err", err)
		redirectWithFlash(w, r, "/app/api-keys", "", "create failed")
		return
	}
	if expiresDays > 0 {
		_, _ = db.ExecContext(ctx,
			"UPDATE api_keys SET expires_at = ("+store.DateAddDaysParam()+") WHERE id = ?",
			expiresDays, id)
	}
	uid := sess.UserID
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: &uid, Action: "api_key.create.client", Entity: "api_key",
		EntityID: strconv.FormatInt(id, 10),
		Meta:     map[string]any{"name": name, "prefix": prefix},
	})
	d := clientAPIKeysData{baseAppData: h.base(r, "API tokens"), NewPlain: plain}
	d.Keys = h.loadClientAPIKeys(r.Context())
	h.render(w, "api_keys", d)
}

func (h *ClientHandlers) APIKeysRevoke(w http.ResponseWriter, r *http.Request) {
	sess := middleware.SessionFromContext(r.Context())
	db := h.DB()
	if db == nil || sess == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if _, err := db.ExecContext(ctx,
		"UPDATE api_keys SET revoked_at = NOW() WHERE id = ? AND user_id = ?", id, sess.UserID); err != nil {
		redirectWithFlash(w, r, "/app/api-keys", "", "revoke failed")
		return
	}
	uid := sess.UserID
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: &uid, Action: "api_key.revoke.client", Entity: "api_key",
		EntityID: strconv.FormatInt(id, 10),
	})
	redirectWithFlash(w, r, "/app/api-keys", "Token revoked", "")
}

func (h *ClientHandlers) loadClientAPIKeys(ctx context.Context) []clientAPIKeyRow {
	sess := middleware.SessionFromContext(ctx)
	db := h.DB()
	if db == nil || sess == nil {
		return nil
	}
	c, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	rows, err := db.QueryContext(c,
		`SELECT id, name, key_prefix, scopes,
		        COALESCE(DATE_FORMAT(last_used_at,'%Y-%m-%d %H:%i'),''),
		        last_used_ip,
		        use_count,
		        DATE_FORMAT(created_at,'%Y-%m-%d'),
		        COALESCE(DATE_FORMAT(expires_at,'%Y-%m-%d'),''),
		        revoked_at IS NOT NULL
		 FROM api_keys WHERE user_id = ? ORDER BY id DESC`, sess.UserID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []clientAPIKeyRow
	for rows.Next() {
		var k clientAPIKeyRow
		if err := rows.Scan(&k.ID, &k.Name, &k.Prefix, &k.Scopes, &k.LastUsedAt, &k.LastUsedIP, &k.UseCount, &k.CreatedAt, &k.ExpiresAt, &k.Revoked); err == nil {
			out = append(out, k)
		}
	}
	return out
}

// ---- Route logs (client view) ------------------------------------------

type clientRouteLogsData struct {
	baseAppData
	RouteID          int64
	Domain           string
	Error            string
	Entries          []accesslog.Entry
	AnalyticsTotal   int64
	StatusBuckets    []accesslog.StatusBucket
	ProtoBreakdown   []accesslog.ProtoHit
	BytesSummary     accesslog.BytesSummary
	TopPaths         []accesslog.PathHit
	TopCountries     []accesslog.CountryHit
	TopRemoteIPs     []accesslog.RemoteIPHit
	TopASNOrgs       []accesslog.ASNOrgHit
	BandwidthDays    []accesslog.BandwidthDayBucket // 7-day daily totals
	BandwidthTotal7d int64                          // sum across BandwidthDays
	MaxDayBytes      int64                          // max bucket for bar scaling
	Bandwidth30dDays  []accesslog.BandwidthDayBucket // 30-day daily totals
	Bandwidth30dTotal int64                          // sum across Bandwidth30dDays
	MaxDay30dBytes    int64                          // max bucket for 30-day bar scaling
}

// RouteLogs renders GET /app/routes/{id}/logs for the owning client.
func (h *ClientHandlers) RouteLogs(w http.ResponseWriter, r *http.Request) {
	sess := middleware.SessionFromContext(r.Context())
	db := h.DB()
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	d := clientRouteLogsData{baseAppData: h.base(r, "Route logs"), RouteID: id}
	if db == nil || sess == nil || id == 0 {
		h.render(w, "client_route_logs", d)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	clientID, err := clientIDFor(ctx, db, sess.UserID)
	if err != nil {
		http.Error(w, "no client record", http.StatusForbidden)
		return
	}

	// Verify the route belongs to this client.
	err = db.QueryRowContext(ctx,
		`SELECT r.domain FROM routes r
		 JOIN services s ON s.id = r.service_id
		 WHERE r.id = ? AND s.client_id = ?`, id, clientID,
	).Scan(&d.Domain)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	if h.AccessLogs != nil {
		entries, err := h.AccessLogs.Recent(ctx, id, 100)
		if err != nil {
			h.Logger.Warn("client route logs query", "id", id, "err", err)
		}
		d.Entries = entries

		now := time.Now().UTC()
		f := accesslog.AnalyticsFilter{
			RouteID: id,
			From:    now.Add(-24 * time.Hour),
			To:      now,
			Step:    time.Hour,
		}
		if buckets, err := h.AccessLogs.StatusBuckets(ctx, f); err == nil {
			d.StatusBuckets = buckets
			for _, b := range buckets {
				d.AnalyticsTotal += b.Count
			}
		}
		if proto, err := h.AccessLogs.ProtoBreakdown(ctx, f); err == nil {
			d.ProtoBreakdown = proto
		}
		if bsum, err := h.AccessLogs.BytesSummary(ctx, f); err == nil {
			d.BytesSummary = bsum
		}
		if paths, err := h.AccessLogs.TopPaths(ctx, f, 5); err == nil {
			d.TopPaths = paths
		}
		if countries, err := h.AccessLogs.TopCountries(ctx, f, 10); err == nil {
			d.TopCountries = countries
		}
		if ips, err := h.AccessLogs.TopRemoteIPs(ctx, f, 5); err == nil {
			d.TopRemoteIPs = ips
		}
		if asns, err := h.AccessLogs.TopASNOrgs(ctx, f, 5); err == nil {
			d.TopASNOrgs = asns
		}
		// 7-day daily bandwidth sparkline.
		bwFrom := now.Add(-7 * 24 * time.Hour)
		if days, err := h.AccessLogs.BandwidthDaySeries(ctx, id, bwFrom, now); err == nil {
			d.BandwidthDays = days
			for _, b := range days {
				d.BandwidthTotal7d += b.Bytes
				if b.Bytes > d.MaxDayBytes {
					d.MaxDayBytes = b.Bytes
				}
			}
		}
		// 30-day daily bandwidth chart.
		bw30From := now.Add(-30 * 24 * time.Hour)
		if days, err := h.AccessLogs.BandwidthDaySeries(ctx, id, bw30From, now); err == nil {
			d.Bandwidth30dDays = days
			for _, b := range days {
				d.Bandwidth30dTotal += b.Bytes
				if b.Bytes > d.MaxDay30dBytes {
					d.MaxDay30dBytes = b.Bytes
				}
			}
		}
	}
	h.render(w, "client_route_logs", d)
}

// routeCSVLimiter rate-limits CSV exports: 1 per routeID per 10 seconds.
var routeCSVLimiter sync.Map

// RouteLogsCSV serves GET /app/routes/{id}/logs/export.csv for the owning client.
func (h *ClientHandlers) RouteLogsCSV(w http.ResponseWriter, r *http.Request) {
	sess := middleware.SessionFromContext(r.Context())
	db := h.DB()
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if db == nil || sess == nil || id == 0 || h.AccessLogs == nil {
		http.Error(w, "not available", http.StatusServiceUnavailable)
		return
	}

	// Rate limit: 1 export per route per 10 s.
	key := strconv.FormatInt(id, 10)
	now := time.Now()
	if last, ok := routeCSVLimiter.Load(key); ok {
		if t, ok := last.(time.Time); ok && now.Sub(t) < 10*time.Second {
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
	}
	routeCSVLimiter.Store(key, now)

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	clientID, err := clientIDFor(ctx, db, sess.UserID)
	if err != nil {
		http.Error(w, "no client record", http.StatusForbidden)
		return
	}

	// Verify route belongs to this client.
	var domain string
	err = db.QueryRowContext(ctx,
		`SELECT r.domain FROM routes r
		 JOIN services s ON s.id = r.service_id
		 WHERE r.id = ? AND s.client_id = ?`, id, clientID,
	).Scan(&domain)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	f := parseLogsFilter(r)
	f.Limit = accesslog.MaxExportRows

	entries, err := h.AccessLogs.Filtered(ctx, id, f)
	if err != nil {
		h.Logger.Warn("client route logs csv export", "id", id, "err", err)
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}

	filename := fmt.Sprintf("route-%d-logs.csv", id)
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"timestamp", "method", "path", "status", "bytes_resp", "bytes_req", "duration_ms", "ip", "country"})
	for i, e := range entries {
		_ = cw.Write(csvSafeRow([]string{
			e.TS.UTC().Format(time.RFC3339),
			e.Method,
			e.URI,
			strconv.Itoa(e.Status),
			strconv.FormatInt(e.BytesResp, 10),
			strconv.FormatInt(e.BytesReq, 10),
			strconv.Itoa(e.LatencyMS),
			e.RemoteIP,
			e.Country,
		}))
		if (i+1)%100 == 0 {
			cw.Flush()
		}
	}
	cw.Flush()
}

