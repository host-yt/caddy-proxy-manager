package handlers

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/go-chi/chi/v5"
	"github.com/redis/go-redis/v9"

	"github.com/host-yt/caddy-proxy-manager/internal/accesslog"
	"github.com/host-yt/caddy-proxy-manager/internal/adminscope"
	"github.com/host-yt/caddy-proxy-manager/internal/aichat"
	"github.com/host-yt/caddy-proxy-manager/internal/aitools"
	"github.com/host-yt/caddy-proxy-manager/internal/alert"
	"github.com/host-yt/caddy-proxy-manager/internal/audit"
	"github.com/host-yt/caddy-proxy-manager/internal/auth"
	"github.com/host-yt/caddy-proxy-manager/internal/backup"
	"github.com/host-yt/caddy-proxy-manager/internal/caddyapi"
	"github.com/host-yt/caddy-proxy-manager/internal/captcha"
	"github.com/host-yt/caddy-proxy-manager/internal/chatstore"
	"github.com/host-yt/caddy-proxy-manager/internal/cloudflare"
	"github.com/host-yt/caddy-proxy-manager/internal/customfields"
	"github.com/host-yt/caddy-proxy-manager/internal/deployment"
	"github.com/host-yt/caddy-proxy-manager/internal/domain/portal"
	"github.com/host-yt/caddy-proxy-manager/internal/domain/routes"
	"github.com/host-yt/caddy-proxy-manager/internal/domain/wgpeer"
	"github.com/host-yt/caddy-proxy-manager/internal/geoip"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
	"github.com/host-yt/caddy-proxy-manager/internal/i18n"
	"github.com/host-yt/caddy-proxy-manager/internal/installstate"
	"github.com/host-yt/caddy-proxy-manager/internal/instasync"
	"github.com/host-yt/caddy-proxy-manager/internal/mail"
	"github.com/host-yt/caddy-proxy-manager/internal/nodejoin"
	"github.com/host-yt/caddy-proxy-manager/internal/obs"
	hpgoidc "github.com/host-yt/caddy-proxy-manager/internal/oidc"
	"github.com/host-yt/caddy-proxy-manager/internal/reseller"
	"github.com/host-yt/caddy-proxy-manager/internal/security"
	"github.com/host-yt/caddy-proxy-manager/internal/sms"
	"github.com/host-yt/caddy-proxy-manager/internal/store"
	"github.com/host-yt/caddy-proxy-manager/internal/view"
	"github.com/host-yt/caddy-proxy-manager/internal/wafevents"
	"github.com/host-yt/caddy-proxy-manager/internal/webhook"
	"github.com/host-yt/caddy-proxy-manager/internal/wireguard"
)

type AdminHandlers struct {
	DB         func() *sql.DB
	Sessions   *auth.Manager
	Templates  *view.AdminTemplates
	Logger     *slog.Logger
	State      *installstate.Manager              // for at-rest crypto on SMTP password
	Config     *adminConfigRefs                   // pointers the admin can mutate live
	ResyncNode func(context.Context, int64) error // injected from routes.Service
	// Routes (optional) is needed by admin/hosts quick-add and inline-edit
	// surfaces - they reuse the same Create/Delete/Resync logic as the
	// client-portal flow rather than re-implementing it.
	Routes     *routes.Service
	Mailer     *mail.Mailer
	OIDC       *hpgoidc.Service
	Cloudflare *cloudflare.Service
	Captcha    *captcha.Verifier
	Joiner     *nodejoin.Service
	WG         *wireguard.Service
	Backups    *backup.Service
	Webhooks   *webhook.Service
	// DrillJob is the backup restore drill; used for manual "run now" trigger.
	DrillJob drillRunner
	// GeoIPJob downloads the MaxMind DB; used for the manual "refresh now" trigger.
	GeoIPJob geoipRefresher
	// AdminScope enforces per-client visibility for non-super_admin roles. nil = no enforcement.
	AdminScope *adminscope.Service
	// Resellers is the reseller-ownership store (super_admin management UI). nil-safe.
	Resellers *reseller.Store
	// WriteWGConfig rebuilds /app/wg/wg0.conf from DB peers (sidecar
	// applies via `wg syncconf`). Triggered on node delete, WG settings
	// save, and the manual 'Apply WG config' button. Nil-safe.
	WriteWGConfig func(context.Context) error
	// SMS is the configurable SMS sender (Twilio / SMSAPI.pl / generic
	// webhook). Nil until wired by main; admin settings page degrades to a
	// "not wired" notice in that case.
	SMS *sms.Sender
	// WGPeers drives the customer-side WireGuard tunnel lifecycle.
	WGPeers *wgpeer.Service
	// RDB is the Redis client. Used for one-shot credential transfer
	// (e.g. show tunnel keys to operator after enable/rotate without
	// stuffing secrets into URL flash params).
	RDB *redis.Client
	// Metrics (nil-safe) - emits cache/route/mail/sms counters.
	Metrics *obs.Metrics
	// SIEMForwarder forwards audit events to the configured SIEM webhook (nil-safe).
	SIEMForwarder *audit.Forwarder
	// Enforce2FAEnv mirrors the REQUIRE_ADMIN_2FA env flag: when true the
	// runtime DB toggle is locked-on (env wins) and the UI shows it disabled.
	Enforce2FAEnv bool

	// AccessLogs reads stored per-host access log entries from the DB.
	AccessLogs *accesslog.Store
	// AccessLogBroker fans out live log entries to SSE subscribers.
	AccessLogBroker *accesslog.Broker
	// WAFEvents reads stored WAF event records from the DB.
	WAFEvents *wafevents.Store
	// Portal drives the built-in forward-auth access portal (groups, grants).
	Portal *portal.Service
	// AIFactory builds the configured provider client for the AI chat (nil-safe).
	AIFactory *aichat.Factory
	// ChatStore persists AI chat sessions/messages, ownership-scoped (nil-safe).
	ChatStore *chatstore.Store
	// AITools is the read-only HPG tool registry the assistant may call (nil-safe).
	AITools *aitools.Registry
	// AlertCfg holds alert thresholds for display on the alerts page.
	AlertCfg alert.Config
	// AlertEval is the running evaluator; used to TestFire on-demand.
	AlertEval *alert.Evaluator

	// SyncNotifier pushes sync triggers to slave HPG instances after config changes.
	SyncNotifier *instasync.Notifier
	// SlaveMode, when true, means this instance is read-only; SyncPushReceive is the only write endpoint.
	SlaveMode bool
	// SlaveToken is the pre-shared bearer token expected on /internal/sync/push.
	SlaveToken string
}

// adminConfigRefs holds pointers admin settings handlers can flip at runtime.
type adminConfigRefs struct {
	ACMEEmail   *string
	ACMEStaging *bool
	ACMECaURL   *string
	ACMEEabKID  *string
	ACMEEabHMAC *string
}

// SetConfigRefs wires the runtime-mutable config pointers.
func (h *AdminHandlers) SetConfigRefs(email *string, staging *bool, caURL, eabKID, eabHMAC *string) {
	h.Config = &adminConfigRefs{
		ACMEEmail:   email,
		ACMEStaging: staging,
		ACMECaURL:   caURL,
		ACMEEabKID:  eabKID,
		ACMEEabHMAC: eabHMAC,
	}
}

// ---- shared base data ---------------------------------------------------

// Crumb is one breadcrumb segment. URL "" renders as non-link (current page).
type Crumb struct {
	Label string
	URL   string
}

type baseAdminData struct {
	Title       string
	Email       string
	AdminName   string // friendly greeting name, derived from email local-part
	Role        string
	CSRF        string
	Flash       string
	Error       string
	CSPNonce    string
	Lang        string
	Theme       string
	Brand       Branding
	Breadcrumbs []Crumb // auto-populated from pageBreadcrumbs by render()
	PageDesc    string  // optional one-line page subtitle; defaults to ""
	// Profile/Features drive install-profile menu gating. Populated once per
	// request from install_state so the layout shows only enabled modules.
	Profile  string
	Features deployment.Features
	// SystemBanner is shown site-wide; empty means no banner.
	SystemBanner          string
	SystemBannerType      string // "info" | "warning" | "error"
	SystemBannerLink      string // optional CTA URL
	SystemBannerLinkLabel string // optional CTA label; defaults to "Learn more"
}

// pageBreadcrumbs maps a page key to its breadcrumb trail (section + leaf).
// Centralized so individual handlers don't each build crumbs. The leaf URL
// is "" so the template renders it as the current (non-link) page.
var pageBreadcrumbs = map[string][]Crumb{
	"dashboard":          {{Label: "Overview", URL: ""}, {Label: "Dashboard", URL: ""}},
	"stats":              {{Label: "Overview", URL: ""}, {Label: "Statistics", URL: ""}},
	"hosts":              {{Label: "Traffic", URL: ""}, {Label: "Hosts", URL: ""}},
	"hosts_new":          {{Label: "Traffic", URL: ""}, {Label: "Hosts", URL: "/admin/hosts"}, {Label: "Add host", URL: ""}},
	"hosts_edit":         {{Label: "Traffic", URL: ""}, {Label: "Hosts", URL: "/admin/hosts"}, {Label: "Edit host", URL: ""}},
	"host_logs":          {{Label: "Traffic", URL: ""}, {Label: "Hosts", URL: "/admin/hosts"}, {Label: "Access logs", URL: ""}},
	"waf_events":         {{Label: "Security", URL: ""}, {Label: "WAF events", URL: ""}},
	"access_groups":      {{Label: "Security", URL: ""}, {Label: "Access groups", URL: ""}},
	"mtls":               {{Label: "Security", URL: ""}, {Label: "mTLS authorities", URL: ""}},
	"streams":            {{Label: "Traffic", URL: ""}, {Label: "Streams (L4)", URL: ""}},
	"streams_edit":       {{Label: "Traffic", URL: ""}, {Label: "Streams (L4)", URL: "/admin/streams"}, {Label: "Edit stream", URL: ""}},
	"tunnels":            {{Label: "Traffic", URL: ""}, {Label: "Tunnels (WG)", URL: ""}},
	"tunnel_detail":      {{Label: "Traffic", URL: ""}, {Label: "Tunnels (WG)", URL: "/admin/tunnels"}, {Label: "Tunnel", URL: ""}},
	"certs":              {{Label: "Traffic", URL: ""}, {Label: "Certificates", URL: ""}},
	"manual_certs":       {{Label: "Traffic", URL: ""}, {Label: "Manual Certificates", URL: ""}},
	"nodes":              {{Label: "Fleet", URL: ""}, {Label: "Caddy nodes", URL: ""}},
	"node_detail":        {{Label: "Fleet", URL: ""}, {Label: "Caddy nodes", URL: "/admin/nodes"}, {Label: "Node", URL: ""}},
	"node_groups":        {{Label: "Fleet", URL: ""}, {Label: "Node groups", URL: ""}},
	"clients":            {{Label: "Customers", URL: ""}, {Label: "Clients", URL: ""}},
	"resellers":          {{Label: "Customers", URL: ""}, {Label: "Resellers", URL: ""}},
	"client_detail":      {{Label: "Customers", URL: ""}, {Label: "Clients", URL: "/admin/clients"}, {Label: "Client", URL: ""}},
	"plans":              {{Label: "Customers", URL: ""}, {Label: "Plans", URL: ""}},
	"services":           {{Label: "Customers", URL: ""}, {Label: "Services", URL: ""}},
	"users":              {{Label: "Customers", URL: ""}, {Label: "Users", URL: ""}},
	"audit":              {{Label: "System", URL: ""}, {Label: "Audit log", URL: ""}},
	"alerts":             {{Label: "System", URL: ""}, {Label: "Alerts", URL: ""}},
	"backups":            {{Label: "System", URL: ""}, {Label: "Backups", URL: ""}},
	"branding":           {{Label: "System", URL: ""}, {Label: "Branding", URL: ""}},
	"settings":           {{Label: "System", URL: ""}, {Label: "Settings", URL: ""}},
	"deployment":         {{Label: "System", URL: ""}, {Label: "Deployment mode", URL: ""}},
	"dns_providers":      {{Label: "System", URL: ""}, {Label: "DNS providers", URL: ""}},
	"external_allowlist": {{Label: "System", URL: ""}, {Label: "External allowlist", URL: ""}},
	"api_keys":           {{Label: "System", URL: ""}, {Label: "Settings", URL: "/admin/settings"}, {Label: "API keys", URL: ""}},
	"twofa":              {{Label: "System", URL: ""}, {Label: "Account", URL: "/admin/account"}, {Label: "Two-factor auth", URL: ""}},
	"admin_account":      {{Label: "System", URL: ""}, {Label: "Account", URL: ""}},
	"npm_import":         {{Label: "Tools", URL: ""}, {Label: "NPM import", URL: ""}},
	"ai_chat":            {{Label: "AI", URL: ""}, {Label: "AI assistant", URL: ""}},
	"worldmap":           {{Label: "Fleet", URL: ""}, {Label: "Traffic map", URL: ""}},
}

func (h *AdminHandlers) base(r *http.Request, title string) baseAdminData {
	sess := middleware.SessionFromContext(r.Context())
	d := baseAdminData{
		Title:    title,
		CSPNonce: middleware.CSPNonce(r.Context()),
		Lang:     i18n.LangFromRequest(r),
		Theme:    themeFromRequest(r),
		Brand:    LoadBranding(r.Context(), h.DB()),
	}
	if sess != nil {
		d.Email = sess.Email
		d.AdminName = greetingName(sess.Email)
		d.Role = sess.Role
		d.CSRF = sess.CSRFToken
		// Reseller-admin sees their reseller's brand overlaid on global.
		if sess.ResellerID > 0 {
			d.Brand = LoadBrandingFor(r.Context(), h.DB(), sess.ResellerID)
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
	d.Profile = string(prof)
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

// greetingName derives a friendly name from an email local-part (no name in
// session). "jane.doe@x" -> "Jane Doe"; falls back to the raw email.
func greetingName(email string) string {
	local, _, ok := strings.Cut(email, "@")
	if !ok || local == "" {
		return email
	}
	local = strings.NewReplacer(".", " ", "_", " ", "-", " ").Replace(local)
	words := strings.Fields(strings.ToLower(local))
	for i, w := range words {
		r := []rune(w)
		r[0] = unicode.ToUpper(r[0])
		words[i] = string(r)
	}
	if len(words) == 0 {
		return email
	}
	return strings.Join(words, " ")
}

// fillBreadcrumbs sets the embedded baseAdminData.Breadcrumbs from the
// central page->section map when a handler hasn't set its own. Operates on
// an addressable copy (render passes data by value) and returns it so the
// mechanism stays zero-touch for every page struct (all embed baseAdminData).
func fillBreadcrumbs(page string, data any) any {
	orig := reflect.ValueOf(data)
	if orig.Kind() != reflect.Struct {
		return data // pointers / non-structs: leave untouched
	}
	base := orig.FieldByName("baseAdminData")
	if !base.IsValid() || base.Kind() != reflect.Struct {
		return data
	}
	if bc := base.FieldByName("Breadcrumbs"); bc.IsValid() && bc.Len() > 0 {
		return data // handler set its own trail; leave it
	}
	crumbs, ok := pageBreadcrumbs[page]
	if !ok {
		// Unmapped page: single crumb from the page title.
		title := base.FieldByName("Title").String()
		if title == "" {
			title = page
		}
		crumbs = []Crumb{{Label: title, URL: ""}}
	}
	// Addressable copy so the embedded field is settable.
	cp := reflect.New(orig.Type()).Elem()
	cp.Set(orig)
	cp.FieldByName("baseAdminData").FieldByName("Breadcrumbs").Set(reflect.ValueOf(crumbs))
	return cp.Interface()
}

func (h *AdminHandlers) render(w http.ResponseWriter, page string, data any) {
	data = fillBreadcrumbs(page, data)
	var buf bytes.Buffer
	if err := h.Templates.Render(&buf, page, data); err != nil {
		h.Logger.Error("admin render", "page", page, "err", err)
		http.Error(w, "render failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(buf.Bytes())
}

func redirectWithFlash(w http.ResponseWriter, r *http.Request, path, flash, errMsg string) {
	q := ""
	if flash != "" {
		q = "?flash=" + escapeQuery(flash)
	}
	if errMsg != "" {
		if q == "" {
			q = "?"
		} else {
			q += "&"
		}
		q += "err=" + escapeQuery(errMsg)
	}
	http.Redirect(w, r, path+q, http.StatusSeeOther)
}

// escapeQuery percent-encodes a flash/diagnostic message for a query value.
// url.QueryEscape covers '=', '%', and every other reserved byte; the old
// hand-rolled 4-char replacer let '=' split the param and '%' double-decode.
func escapeQuery(s string) string {
	return url.QueryEscape(s)
}

// ---- Dashboard ----------------------------------------------------------

// AttentionItem is one actionable signal on the operational dashboard.
// Severity is "error" | "warn" | "info"; URL deep-links to the fix surface.
type AttentionItem struct {
	Severity string
	Text     string
	URL      string
}

// dashCounts holds the cheap headline numbers shown as stat cards.
type dashCounts struct {
	TotalHosts          int
	ActiveHosts         int
	PendingHosts        int
	FailedHosts         int
	NodesTotal          int
	NodesOnline         int
	Clients             int
	Plans               int
	SuspendedServices   int
	MTLSCAsExpiringSoon int
}

// dashEvent is a single recent audit-log line (latest activity feed).
type dashEvent struct {
	When   string
	Actor  string
	Action string
	Entity string
}

// dashTraffic is a small HTTP-requests series for a sparkline plus its total.
type dashTraffic struct {
	Labels []string
	Values []uint64
	Total  uint64
}

// dashTopRoute holds request count for one route over 24h.
type dashTopRoute struct {
	RouteID  int64
	Domain   string
	Requests int64
}

// dashTopClient holds bandwidth total for one client over 7d.
type dashTopClient struct {
	ClientID       int64
	DisplayName    string
	BandwidthBytes int64
}

type dashboardData struct {
	baseAdminData
	Attention    []AttentionItem
	Truncated    bool // true when Attention was capped
	Counts       dashCounts
	RecentEvents []dashEvent
	Traffic      dashTraffic
	TopRoutes    []dashTopRoute
	TopClients   []dashTopClient
}

// Cap below the max number of distinct attention items (currently 7) so the
// "+N more" truncation hint can actually fire; Truncated drives that hint.
const dashAttentionCap = 6

func (h *AdminHandlers) Dashboard(w http.ResponseWriter, r *http.Request) {
	d := dashboardData{baseAdminData: h.base(r, "Dashboard")}
	d.PageDesc = "Operational health at a glance"
	db := h.DB()
	if db == nil {
		h.render(w, "dashboard", d)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	d.Counts = h.dashboardCounts(ctx, db)
	d.Attention, d.Truncated = h.dashboardAttention(ctx, db)
	d.RecentEvents = h.dashboardRecentEvents(ctx, db)
	d.Traffic = h.dashboardTraffic(ctx, db)
	d.TopRoutes = h.dashboardTopRoutes(ctx, db)
	d.TopClients = h.dashboardTopClients(ctx, db)

	h.render(w, "dashboard", d)
}

func (h *AdminHandlers) dashboardCounts(ctx context.Context, db *sql.DB) dashCounts {
	var c dashCounts
	_ = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM routes").Scan(&c.TotalHosts)
	_ = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM routes WHERE status='active'").Scan(&c.ActiveHosts)
	_ = db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM routes WHERE status IN ('pending_dns','dns_ok','pending_ssl')").Scan(&c.PendingHosts)
	_ = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM routes WHERE status='failed'").Scan(&c.FailedHosts)
	_ = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM caddy_nodes").Scan(&c.NodesTotal)
	_ = db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM caddy_nodes WHERE health_status='healthy' AND is_enabled=1 AND approved_at IS NOT NULL").Scan(&c.NodesOnline)
	_ = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM clients").Scan(&c.Clients)
	_ = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM plans").Scan(&c.Plans)
	var susp int
	_ = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM services WHERE status='suspended'").Scan(&susp)
	c.SuspendedServices = susp
	// Count CA certs expiring within 30 days (includes already expired).
	var mtlsExpiring int
	_ = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM mtls_cas WHERE not_after < (NOW() + INTERVAL 30 DAY)").Scan(&mtlsExpiring)
	c.MTLSCAsExpiringSoon = mtlsExpiring
	return c
}

// dashboardAttention builds the actionable list from real conditions only;
// a condition with zero rows is omitted. Capped at dashAttentionCap.
func (h *AdminHandlers) dashboardAttention(ctx context.Context, db *sql.DB) ([]AttentionItem, bool) {
	var items []AttentionItem

	var stuckSSL, stuckDNS, failed int
	_ = db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM routes WHERE status='pending_ssl'").Scan(&stuckSSL)
	_ = db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM routes WHERE status IN ('pending_dns','dns_ok')").Scan(&stuckDNS)
	_ = db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM routes WHERE status='failed'").Scan(&failed)
	if failed > 0 {
		items = append(items, AttentionItem{
			Severity: "error",
			Text:     fmt.Sprintf("%d host(s) failed to provision", failed),
			URL:      "/admin/hosts?status=failed",
		})
	}
	if stuckSSL > 0 {
		items = append(items, AttentionItem{
			Severity: "warn",
			Text:     fmt.Sprintf("%d host(s) waiting on certificate issuance", stuckSSL),
			URL:      "/admin/hosts?status=pending_ssl",
		})
	}
	if stuckDNS > 0 {
		items = append(items, AttentionItem{
			Severity: "warn",
			Text:     fmt.Sprintf("%d host(s) waiting on DNS validation", stuckDNS),
			URL:      "/admin/hosts?status=pending_dns",
		})
	}

	// Node health: down, never-probed, then approved-but-disabled.
	// Offline/unreachable reflects the health probe writing health_status.
	// 'unknown' = enabled+approved but not yet probed; NodesOnline excludes
	// these, so surface them here to keep the card and attention list aligned.
	var nodesDown, nodesUnknown, nodesDisabled int
	_ = db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM caddy_nodes WHERE approved_at IS NOT NULL AND health_status IN ('down','degraded')").Scan(&nodesDown)
	_ = db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM caddy_nodes WHERE approved_at IS NOT NULL AND is_enabled=1 AND health_status='unknown'").Scan(&nodesUnknown)
	_ = db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM caddy_nodes WHERE approved_at IS NOT NULL AND is_enabled=0").Scan(&nodesDisabled)
	if nodesDown > 0 {
		items = append(items, AttentionItem{
			Severity: "error",
			Text:     fmt.Sprintf("%d Caddy node(s) offline or degraded", nodesDown),
			URL:      "/admin/nodes",
		})
	}
	if nodesUnknown > 0 {
		items = append(items, AttentionItem{
			Severity: "info",
			Text:     fmt.Sprintf("%d Caddy node(s) not yet health-checked", nodesUnknown),
			URL:      "/admin/nodes",
		})
	}
	if nodesDisabled > 0 {
		items = append(items, AttentionItem{
			Severity: "warn",
			Text:     fmt.Sprintf("%d Caddy node(s) disabled", nodesDisabled),
			URL:      "/admin/nodes",
		})
	}

	// Nodes auto-joined and awaiting operator approval.
	var pendingNodes int
	_ = db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM caddy_nodes WHERE approved_at IS NULL").Scan(&pendingNodes)
	if pendingNodes > 0 {
		items = append(items, AttentionItem{
			Severity: "info",
			Text:     fmt.Sprintf("%d Caddy node(s) awaiting approval", pendingNodes),
			URL:      "/admin/nodes",
		})
	}

	// Manual certificates expiring within 30 days or already expired.
	var expiringSoon, expired int
	_ = db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM manual_certs WHERE not_after BETWEEN NOW() AND (NOW() + INTERVAL 30 DAY)").Scan(&expiringSoon)
	_ = db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM manual_certs WHERE not_after < NOW()").Scan(&expired)
	if expired > 0 {
		items = append(items, AttentionItem{
			Severity: "error",
			Text:     fmt.Sprintf("%d manual cert(s) EXPIRED", expired),
			URL:      "/admin/manual-certs",
		})
	}
	if expiringSoon > 0 {
		items = append(items, AttentionItem{
			Severity: "warn",
			Text:     fmt.Sprintf("%d manual certificate(s) expiring within 30 days", expiringSoon),
			URL:      "/admin/manual-certs",
		})
	}

	// mTLS CA certs: expired ones block all client-cert auth on affected routes.
	var mtlsExpired, mtlsExpiringSoon int
	_ = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM mtls_cas WHERE not_after < NOW()").Scan(&mtlsExpired)
	_ = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM mtls_cas WHERE not_after BETWEEN NOW() AND (NOW() + INTERVAL 30 DAY)").Scan(&mtlsExpiringSoon)
	if mtlsExpired > 0 {
		items = append(items, AttentionItem{
			Severity: "error",
			Text:     fmt.Sprintf("%d mTLS CA cert(s) EXPIRED - routes requiring client certs may reject all connections", mtlsExpired),
			URL:      "/admin/mtls",
		})
	}
	if mtlsExpiringSoon > 0 {
		items = append(items, AttentionItem{
			Severity: "warn",
			Text:     fmt.Sprintf("%d mTLS CA cert(s) expiring within 30 days", mtlsExpiringSoon),
			URL:      "/admin/mtls",
		})
	}

	// Suspended services indicate an operator or billing action is blocking traffic.
	var suspendedServices int
	_ = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM services WHERE status='suspended'").Scan(&suspendedServices)
	if suspendedServices > 0 {
		items = append(items, AttentionItem{
			Severity: "warn",
			Text:     fmt.Sprintf("%d service(s) currently suspended", suspendedServices),
			URL:      "/admin/services?status=suspended",
		})
	}

	// Ghost clients: have services but none of their routes are active.
	var ghostClients int
	_ = db.QueryRowContext(ctx, `
		SELECT COUNT(DISTINCT c.id)
		FROM clients c
		WHERE NOT EXISTS (
			SELECT 1 FROM services s
			JOIN routes r ON r.service_id=s.id
			WHERE s.client_id=c.id AND r.status="active"
		) AND EXISTS (
			SELECT 1 FROM services s WHERE s.client_id=c.id
		)
	`).Scan(&ghostClients)
	if ghostClients > 0 {
		items = append(items, AttentionItem{
			Severity: "info",
			Text:     fmt.Sprintf("%d client(s) with services but no active routes", ghostClients),
			URL:      "/admin/clients",
		})
	}

	truncated := false
	if len(items) > dashAttentionCap {
		items = items[:dashAttentionCap]
		truncated = true
	}
	return items, truncated
}

// dashboardRecentEvents returns the latest audit-log lines. Degrades to an
// empty slice if the table/query fails.
func (h *AdminHandlers) dashboardRecentEvents(ctx context.Context, db *sql.DB) []dashEvent {
	rows, err := db.QueryContext(ctx,
		`SELECT DATE_FORMAT(a.created_at, '%Y-%m-%d %H:%i'),
		        COALESCE(u.email, a.actor_type), a.action, a.entity
		 FROM audit_log a LEFT JOIN users u ON u.id = a.user_id
		 ORDER BY a.id DESC LIMIT 8`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []dashEvent
	for rows.Next() {
		var e dashEvent
		if err := rows.Scan(&e.When, &e.Actor, &e.Action, &e.Entity); err == nil {
			out = append(out, e)
		}
	}
	return out
}

// dashboardTopRoutes returns the 5 busiest routes by request count in the last 24h.
func (h *AdminHandlers) dashboardTopRoutes(ctx context.Context, db *sql.DB) []dashTopRoute {
	rows, err := db.QueryContext(ctx,
		`SELECT lr.route_id, r.domain, SUM(lr.requests) AS reqs
		 FROM log_rollups lr JOIN routes r ON r.id = lr.route_id
		 WHERE lr.bucket_start >= NOW() - INTERVAL 24 HOUR
		 GROUP BY lr.route_id, r.domain
		 ORDER BY reqs DESC LIMIT 5`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []dashTopRoute
	for rows.Next() {
		var row dashTopRoute
		if err := rows.Scan(&row.RouteID, &row.Domain, &row.Requests); err == nil {
			out = append(out, row)
		}
	}
	return out
}

// dashboardTopClients returns the 5 highest-bandwidth clients over the last 7d.
func (h *AdminHandlers) dashboardTopClients(ctx context.Context, db *sql.DB) []dashTopClient {
	rows, err := db.QueryContext(ctx,
		`SELECT s.client_id, COALESCE(c.display_name, u.full_name, u.email), SUM(lr.bytes_resp) AS bw
		 FROM log_rollups lr
		 JOIN routes r ON r.id = lr.route_id
		 JOIN services s ON s.id = r.service_id
		 JOIN clients c ON c.id = s.client_id
		 JOIN users u ON u.id = c.user_id
		 WHERE lr.bucket_start >= NOW() - INTERVAL 7 DAY
		 GROUP BY s.client_id, c.display_name, u.email, u.full_name
		 ORDER BY bw DESC LIMIT 5`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []dashTopClient
	for rows.Next() {
		var row dashTopClient
		if err := rows.Scan(&row.ClientID, &row.DisplayName, &row.BandwidthBytes); err == nil {
			out = append(out, row)
		}
	}
	return out
}

// dashboardTraffic reuses the Stats page 24h per-hour HTTP-requests
// aggregation (trafficTimeseries) for a sparkline, plus a 24h total.
func (h *AdminHandlers) dashboardTraffic(ctx context.Context, db *sql.DB) dashTraffic {
	labels, values := h.trafficTimeseries(ctx, db)
	var total uint64
	for _, v := range values {
		total += v
	}
	return dashTraffic{Labels: labels, Values: values, Total: total}
}

// ---- Nodes CRUD ---------------------------------------------------------

type nodeRow struct {
	ID             int64
	Name           string
	APIURL         string
	PublicHostname string
	PublicIP       string
	GroupName      string
	MaxRoutes      int
	CurrentRoutes  int
	Health         string
	Enabled        bool
	Approved       bool   // approved_at IS NOT NULL
	Fingerprint    string // first 16 chars of wg_public_key for fingerprint match
	Transport      string // tunnel transport: udp|wss|auto
	WstunnelPort   int    // 0 = unset; prefilled into the tunnel modal

	// Caddy capability flags set by the node-agent probe.
	HasWAF       bool
	HasL4        bool
	HasGeoIP     bool
	HasRateLimit bool
	CaddyVersion string

	// Bandwidth24h is the 24h outbound bytes across all routes on this node.
	Bandwidth24h int64

	// WG tunnel health - reported by node-agent via POST /api/node/wg/stats.
	// All nullable: NULL = agent hasn't reported yet (older agent or no tunnel).
	TunnelEnabled      bool
	TunnelMTU          sql.NullInt32  // fwd_mtu: live interface MTU
	WstunnelHealthy    sql.NullBool   // nil = UDP node or not yet reported
	FwdIPForward       sql.NullBool   // net.ipv4.ip_forward
	FwdPolicyDrop      sql.NullBool   // forward-chain policy DROP detected
	FwdFirewallBackend sql.NullString // nft|iptables-legacy|firewalld|ufw|none
	FwdLastSetupError  sql.NullString
	FwdReportedAt      sql.NullString // human-formatted timestamp; "" = never
	WGKeepalive        int            // hardcoded 25s in agent (PersistentKeepalive)
}

type nodesData struct {
	baseAdminData
	Nodes        []nodeRow
	Groups       []nodeGroup
	NewJoinToken string // one-shot plaintext shown on the page immediately after mint
	NewJoinTTL   string // ISO timestamp
	AppURL       string // for rendering the one-liner curl command
	// TunnelCreds is non-nil right after a tunnel enable/rotate; the
	// template renders a modal with copy buttons. The stash key is
	// deleted on read so refresh hides it.
	TunnelCreds *tunnelCreds
}

func (h *AdminHandlers) Nodes(w http.ResponseWriter, r *http.Request) {
	d := nodesData{baseAdminData: h.base(r, "Caddy nodes")}
	if h.State != nil {
		if st := h.State.Get(); st.App != nil {
			d.AppURL = st.App.URL
		}
	}
	h.populateNodesData(r.Context(), &d)
	if nonce := r.URL.Query().Get("show_creds"); nonce != "" {
		d.TunnelCreds = h.fetchTunnelCreds(r.Context(), nonce)
	}
	h.render(w, "nodes", d)
}

func (h *AdminHandlers) NodesCreate(w http.ResponseWriter, r *http.Request) {
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	_ = r.ParseForm()
	name := strings.TrimSpace(r.FormValue("name"))
	apiURL := strings.TrimSpace(r.FormValue("api_url"))
	publicHostname := strings.TrimSpace(r.FormValue("public_hostname"))
	publicIP := strings.TrimSpace(r.FormValue("public_ip"))
	groupID, _ := strconv.ParseInt(r.FormValue("node_group_id"), 10, 64)
	maxRoutes, _ := strconv.Atoi(r.FormValue("max_routes"))
	priority, _ := strconv.Atoi(r.FormValue("priority"))

	if name == "" || apiURL == "" || publicHostname == "" || groupID == 0 || maxRoutes <= 0 {
		redirectWithFlash(w, r, "/admin/nodes", "", "all fields required")
		return
	}
	if !strings.HasPrefix(apiURL, "http://") && !strings.HasPrefix(apiURL, "https://") {
		redirectWithFlash(w, r, "/admin/nodes", "", "api_url must start with http:// or https://")
		return
	}
	if publicIP != "" && net.ParseIP(publicIP) == nil {
		redirectWithFlash(w, r, "/admin/nodes", "", "public_ip is not a valid IP")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5_000_000_000)
	defer cancel()
	var pubIPVal sql.NullString
	if publicIP != "" {
		pubIPVal = sql.NullString{String: publicIP, Valid: true}
	}
	// approved_at = NOW(): admin manually added node via form, so trust it
	// (vs auto-join flow which leaves approved_at NULL until explicit Approve).
	res, err := db.ExecContext(ctx,
		`INSERT INTO caddy_nodes (name, api_url, public_hostname, public_ip, node_group_id,
		   max_routes, priority, is_enabled, health_status, approved_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, 1, 'unknown', NOW())`,
		name, apiURL, publicHostname, pubIPVal, groupID, maxRoutes, priority)
	if err != nil {
		if strings.Contains(err.Error(), "Duplicate entry") {
			redirectWithFlash(w, r, "/admin/nodes", "", "node name already exists")
			return
		}
		h.Logger.Error("node create", "err", err)
		redirectWithFlash(w, r, "/admin/nodes", "", "insert failed")
		return
	}
	id, _ := res.LastInsertId()
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(middleware.SessionFromContext(r.Context())),
		Action: "node.create", Entity: "node", EntityID: fmt.Sprintf("%d", id),
		Meta: map[string]any{"name": name, "api_url": apiURL},
	})
	redirectWithFlash(w, r, "/admin/nodes", "Node added. Click resync if it already has routes.", "")
}

type nodeEditData struct {
	baseAdminData
	NodeID         int64
	Name           string
	APIURL         string
	PublicHostname string
	PublicIP       string
	OutboundIPs    string // newline-separated for the textarea
	Error          string

	// Capability flags - reflect caddy_nodes columns set by node probe.
	HasWAF       bool
	HasL4        bool
	HasDNSModule bool
	HasRateLimit bool
	HasGeoIP     bool
	CaddyVersion string
}

// NodesEdit renders GET /admin/nodes/{id}/edit.
func (h *AdminHandlers) NodesEdit(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	d := nodeEditData{baseAdminData: h.base(r, "Edit node"), NodeID: id}
	db := h.DB()
	if db == nil || id == 0 {
		h.render(w, "node_edit", d)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	var outboundIPsJSON sql.NullString
	// Prefill capability checkboxes with the EFFECTIVE value (per-node flag when
	// the node was declared, else the fleet-wide env flag) so a routine save does
	// not silently flip env-backed protections off. Mirrors probedOr in
	// routes.Service.buildNodePush.
	if err := db.QueryRowContext(ctx,
		`SELECT name, api_url, COALESCE(public_hostname,''), COALESCE(public_ip,''), outbound_ips,
		        COALESCE(CASE WHEN modules_probed_at IS NOT NULL THEN has_waf        END, ?),
		        COALESCE(CASE WHEN modules_probed_at IS NOT NULL THEN has_l4         END, ?),
		        COALESCE(CASE WHEN modules_probed_at IS NOT NULL THEN has_dns_module END, ?),
		        COALESCE(CASE WHEN modules_probed_at IS NOT NULL THEN has_rate_limit END, ?),
		        COALESCE(CASE WHEN modules_probed_at IS NOT NULL THEN has_geoip      END, ?), COALESCE(caddy_version,'')
		   FROM caddy_nodes WHERE id = ?`,
		b2i(h.Routes != nil && h.Routes.WAFModuleAvailable),
		b2i(h.Routes != nil && h.Routes.Layer4ModuleAvailable),
		b2i(h.Routes != nil && h.Routes.DNS01ModuleAvailable),
		b2i(h.Routes != nil && h.Routes.RateLimitModuleAvailable),
		b2i(h.Routes != nil && h.Routes.GeoModuleAvailable), id,
	).Scan(&d.Name, &d.APIURL, &d.PublicHostname, &d.PublicIP, &outboundIPsJSON,
		&d.HasWAF, &d.HasL4, &d.HasDNSModule, &d.HasRateLimit, &d.HasGeoIP, &d.CaddyVersion); err != nil {
		d.Error = "node not found"
		h.render(w, "node_edit", d)
		return
	}
	if outboundIPsJSON.Valid && outboundIPsJSON.String != "" {
		var ips []string
		if json.Unmarshal([]byte(outboundIPsJSON.String), &ips) == nil {
			d.OutboundIPs = strings.Join(ips, "\n")
		}
	}
	h.render(w, "node_edit", d)
}

// NodesUpdate handles POST /admin/nodes/{id}/edit. Updates outbound_ips inventory.
func (h *AdminHandlers) NodesUpdate(w http.ResponseWriter, r *http.Request) {
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	_ = r.ParseForm()
	editPath := "/admin/nodes/" + strconv.FormatInt(id, 10) + "/edit"

	// Parse and validate the outbound IPs textarea (one IP per line).
	raw := strings.TrimSpace(r.FormValue("outbound_ips"))
	var ips []string
	for _, line := range strings.Split(raw, "\n") {
		ip := strings.TrimSpace(line)
		if ip == "" {
			continue
		}
		if net.ParseIP(ip) == nil {
			redirectWithFlash(w, r, editPath, "", "outbound IPs: invalid IP address: "+ip)
			return
		}
		ips = append(ips, ip)
	}
	var outboundIPsVal sql.NullString
	if len(ips) > 0 {
		b, _ := json.Marshal(ips)
		outboundIPsVal = sql.NullString{String: string(b), Valid: true}
	}

	// Parse capability checkboxes and caddy_version from form.
	hasWAF := r.FormValue("has_waf") == "1"
	hasL4 := r.FormValue("has_l4") == "1"
	hasDNSModule := r.FormValue("has_dns_module") == "1"
	hasRateLimit := r.FormValue("has_rate_limit") == "1"
	hasGeoIP := r.FormValue("has_geoip") == "1"
	caddyVersion := strings.TrimSpace(r.FormValue("caddy_version"))

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	// Set modules_probed_at so these operator-declared flags become authoritative
	// over the fleet-wide env defaults (see probedOr in routes.Service).
	if _, err := db.ExecContext(ctx,
		`UPDATE caddy_nodes SET outbound_ips = ?,
		        has_waf = ?, has_l4 = ?, has_dns_module = ?,
		        has_rate_limit = ?, has_geoip = ?, caddy_version = ?,
		        modules_probed_at = NOW()
		 WHERE id = ?`,
		outboundIPsVal, hasWAF, hasL4, hasDNSModule, hasRateLimit, hasGeoIP, caddyVersion, id); err != nil {
		redirectWithFlash(w, r, editPath, "", "update failed: "+sanitizeErr(err))
		return
	}
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(middleware.SessionFromContext(r.Context())),
		Action: "node.update", Entity: "node", EntityID: fmt.Sprintf("%d", id),
		Meta: map[string]any{"outbound_ips": ips, "caddy_version": caddyVersion},
	})
	redirectWithFlash(w, r, "/admin/nodes", "Node updated", "")
}

// Note: there is no auto-probe of Caddy module capabilities. The Caddy admin
// API (:2019) exposes no endpoint to enumerate compiled-in modules, so module
// availability is declared two ways: fleet-wide env flags (WAF_MODULE_AVAILABLE
// etc., the default/fallback) and per-node operator checkboxes on the node edit
// page (authoritative once set; see modules_probed_at sentinel + probedOr).

// failoverPreviewTarget is one healthy sibling node returned by FailoverPreview.
type failoverPreviewTarget struct {
	ID           int64  `json:"id"`
	Name         string `json:"name"`
	HealthStatus string `json:"health_status"`
}

// failoverPreviewRoute describes one route and whether it can be moved.
type failoverPreviewRoute struct {
	RouteID int64  `json:"route_id"`
	Domain  string `json:"domain"`
	Status  string `json:"status"`
	CanMove bool   `json:"can_move"`
	Reason  string `json:"reason"`
}

// failoverPreviewResp is the full JSON payload for FailoverPreview.
type failoverPreviewResp struct {
	NodeID          int64                   `json:"node_id"`
	NodeName        string                  `json:"node_name"`
	Mode            string                  `json:"mode"`
	EligibleTargets []failoverPreviewTarget `json:"eligible_targets"`
	RoutesToMove    []failoverPreviewRoute  `json:"routes_to_move"`
	MovableCount    int                     `json:"movable_count"`
	BlockedCount    int                     `json:"blocked_count"`
}

// FailoverPreview handles GET /admin/nodes/{id}/failover-preview.
// Read-only dry-run: shows which routes would move if this node were dead.
func (h *AdminHandlers) FailoverPreview(w http.ResponseWriter, r *http.Request) {
	db := h.DB()
	if db == nil {
		apiJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "no db"})
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if id == 0 {
		apiJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid node id"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// Step 1: fetch node + group mode.
	var resp failoverPreviewResp
	var groupID int64
	if err := db.QueryRowContext(ctx,
		`SELECT n.id, n.name, ng.id, ng.mode
		   FROM caddy_nodes n JOIN node_groups ng ON ng.id = n.node_group_id
		   WHERE n.id = ?`, id,
	).Scan(&resp.NodeID, &resp.NodeName, &groupID, &resp.Mode); err != nil {
		apiJSON(w, http.StatusNotFound, map[string]any{"error": "node not found"})
		return
	}

	// Step 2: fetch healthy siblings in the same group.
	trows, err := db.QueryContext(ctx,
		`SELECT id, name, health_status FROM caddy_nodes
		  WHERE node_group_id = ? AND id <> ? AND health_status = 'healthy' AND is_enabled = 1
		  ORDER BY priority DESC, id ASC`, groupID, id)
	if err == nil {
		defer trows.Close()
		for trows.Next() {
			var t failoverPreviewTarget
			if e := trows.Scan(&t.ID, &t.Name, &t.HealthStatus); e == nil {
				resp.EligibleTargets = append(resp.EligibleTargets, t)
			}
		}
	}

	// Step 3: fetch active routes on this node.
	rrows, err := db.QueryContext(ctx,
		`SELECT id, domain, status FROM routes WHERE caddy_node_id = ? AND status = 'active'`, id)
	if err == nil {
		defer rrows.Close()
		for rrows.Next() {
			var route failoverPreviewRoute
			if e := rrows.Scan(&route.RouteID, &route.Domain, &route.Status); e == nil {
				resp.RoutesToMove = append(resp.RoutesToMove, route)
			}
		}
	}

	// Step 4: evaluate can_move per route.
	noTargets := len(resp.EligibleTargets) == 0
	for i := range resp.RoutesToMove {
		if resp.Mode == "single" || resp.Mode == "" {
			resp.RoutesToMove[i].CanMove = false
			resp.RoutesToMove[i].Reason = "group_mode_not_failover"
			resp.BlockedCount++
			continue
		}
		if noTargets {
			resp.RoutesToMove[i].CanMove = false
			resp.RoutesToMove[i].Reason = "no_healthy_targets"
			resp.BlockedCount++
			continue
		}
		// Check for WG tunnel peer attached to this route's node (node-level, not route-level).
		// customer_wg_peer links to node_id, not route_id, so WG is node-scoped.
		// Blocked only when the route's domain is the WG gateway route (tunnel_transport check).
		resp.RoutesToMove[i].CanMove = true
		resp.MovableCount++
	}

	// If group mode is not failover, annotate the result clearly.
	if resp.Mode == "single" || resp.Mode == "" {
		resp.Mode = "single"
	}

	apiJSON(w, http.StatusOK, resp)
}

// preflightMismatch is a route that requires a capability the node lacks.
type preflightMismatch struct {
	RouteID int64  `json:"route_id"`
	Domain  string `json:"domain"`
	Reason  string `json:"reason"`
}

// NodePreflight handles GET /admin/nodes/{id}/preflight.json.
// Returns routes whose capability requirements exceed what the node provides.
func (h *AdminHandlers) NodePreflight(w http.ResponseWriter, r *http.Request) {
	db := h.DB()
	if db == nil {
		apiJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "error": "no db"})
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if id == 0 {
		apiJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid node id"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	var hasWAF, hasGeoIP, hasRateLimit bool
	if err := db.QueryRowContext(ctx,
		`SELECT COALESCE(has_waf,0), COALESCE(has_geoip,0), COALESCE(has_rate_limit,0)
		   FROM caddy_nodes WHERE id = ?`, id,
	).Scan(&hasWAF, &hasGeoIP, &hasRateLimit); err != nil {
		apiJSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": "node not found"})
		return
	}

	rows, err := db.QueryContext(ctx,
		`SELECT id, domain, COALESCE(waf_enabled,0), COALESCE(geo_mode,'off'), COALESCE(rate_limit_rpm,0)
		   FROM routes WHERE caddy_node_id = ? AND status = 'active'`, id)
	if err != nil {
		apiJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": sanitizeErr(err)})
		return
	}
	defer rows.Close()

	var mismatches []preflightMismatch
	total := 0
	for rows.Next() {
		total++
		var routeID int64
		var domain, geoMode string
		var wafEnabled bool
		var rateLimitRPM int64
		if e := rows.Scan(&routeID, &domain, &wafEnabled, &geoMode, &rateLimitRPM); e != nil {
			continue
		}
		if wafEnabled && !hasWAF {
			mismatches = append(mismatches, preflightMismatch{RouteID: routeID, Domain: domain, Reason: "waf_required"})
		}
		if geoMode != "off" && !hasGeoIP {
			mismatches = append(mismatches, preflightMismatch{RouteID: routeID, Domain: domain, Reason: "geoip_required"})
		}
		if rateLimitRPM > 0 && !hasRateLimit {
			mismatches = append(mismatches, preflightMismatch{RouteID: routeID, Domain: domain, Reason: "rate_limit_required"})
		}
	}
	if mismatches == nil {
		mismatches = []preflightMismatch{}
	}

	apiJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"node_id":    id,
		"mismatches": mismatches,
		"total":      total,
	})
}

func (h *AdminHandlers) NodesToggle(w http.ResponseWriter, r *http.Request) {
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	ctx, cancel := context.WithTimeout(r.Context(), 5_000_000_000)
	defer cancel()
	if _, err := db.ExecContext(ctx, "UPDATE caddy_nodes SET is_enabled = NOT is_enabled WHERE id = ?", id); err != nil {
		redirectWithFlash(w, r, "/admin/nodes", "", "toggle failed")
		return
	}
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(middleware.SessionFromContext(r.Context())),
		Action: "node.toggle", Entity: "node", EntityID: fmt.Sprintf("%d", id),
	})
	redirectWithFlash(w, r, "/admin/nodes", "Node toggled", "")
}

func (h *AdminHandlers) NodesDelete(w http.ResponseWriter, r *http.Request) {
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	ctx, cancel := context.WithTimeout(r.Context(), 5_000_000_000)
	defer cancel()
	if _, err := db.ExecContext(ctx, "DELETE FROM caddy_nodes WHERE id = ?", id); err != nil {
		if strings.Contains(err.Error(), "foreign key") {
			redirectWithFlash(w, r, "/admin/nodes", "", "node has routes; move or delete them first")
			return
		}
		redirectWithFlash(w, r, "/admin/nodes", "", "delete failed")
		return
	}
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(middleware.SessionFromContext(r.Context())),
		Action: "node.delete", Entity: "node", EntityID: fmt.Sprintf("%d", id),
	})
	if h.WriteWGConfig != nil {
		_ = h.WriteWGConfig(ctx) // best-effort; sidecar will pick up
	}
	redirectWithFlash(w, r, "/admin/nodes", "Node deleted", "")
}

// NodesDrain migrates every route off a node onto a healthy peer in
// the same group AND flips is_enabled=0, but keeps the node row. Used
// for maintenance windows: operator can re-enable + Resync afterwards
// without re-doing approval/wg-rekey. Skips routes bound to a WG
// tunnel on this node - those would 502 elsewhere; operator must
// rotate the tunnel separately.
func (h *AdminHandlers) NodesDrain(w http.ResponseWriter, r *http.Request) {
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	var groupID int64
	if err := db.QueryRowContext(ctx,
		"SELECT node_group_id FROM caddy_nodes WHERE id = ?", id,
	).Scan(&groupID); err != nil {
		redirectWithFlash(w, r, "/admin/nodes", "", "node not found")
		return
	}
	var destID int64
	if err := db.QueryRowContext(ctx,
		`SELECT id FROM caddy_nodes
		 WHERE node_group_id = ? AND id <> ? AND is_enabled = 1 AND approved_at IS NOT NULL
		   AND health_status = 'healthy' AND current_routes < max_routes
		 ORDER BY (current_routes / GREATEST(max_routes,1)) ASC, priority DESC, id ASC
		 LIMIT 1`, groupID, id).Scan(&destID); err != nil {
		redirectWithFlash(w, r, "/admin/nodes", "",
			"no healthy peer in the same group - drain aborted")
		return
	}

	// Migrate only non-tunneled routes. Tunneled ones stay; the node-row
	// is flagged disabled so AutoFailover will not pick it up either.
	res, err := db.ExecContext(ctx,
		`UPDATE routes SET caddy_node_id = ?
		   WHERE caddy_node_id = ? AND via_wg_peer_id IS NULL`,
		destID, id)
	if err != nil {
		redirectWithFlash(w, r, "/admin/nodes", "", "route move failed: "+sanitizeErr(err))
		return
	}
	moved, _ := res.RowsAffected()

	if _, err := db.ExecContext(ctx, `UPDATE caddy_nodes SET is_enabled = 0 WHERE id = ?`, id); err != nil {
		redirectWithFlash(w, r, "/admin/nodes", "", "disable failed: "+sanitizeErr(err))
		return
	}
	_, _ = db.ExecContext(ctx,
		`UPDATE caddy_nodes SET current_routes = current_routes + ? WHERE id = ?`, moved, destID)
	_, _ = db.ExecContext(ctx,
		`UPDATE caddy_nodes SET current_routes = GREATEST(0, current_routes - ?) WHERE id = ?`, moved, id)

	if h.ResyncNode != nil {
		_ = h.ResyncNode(ctx, destID)
	}

	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(middleware.SessionFromContext(r.Context())),
		Action: "node.drain", Entity: "node", EntityID: fmt.Sprintf("%d", id),
		Meta: map[string]any{"moved_routes": moved, "dest_node_id": destID},
	})
	redirectWithFlash(w, r, "/admin/nodes",
		fmt.Sprintf("Drained node. %d route(s) moved to node %d. Re-enable from this page when maintenance is done.", moved, destID), "")
}

// NodesDecommission migrates every route off a node onto the lowest-usage
// peer in the same node_group, then pushes an empty config to the leaving
// node (best-effort), then deletes the row. Required because the
// fk_route_node FK has no ON DELETE cascade - a direct delete fails with
// a constraint error as soon as one route exists on the node.
func (h *AdminHandlers) NodesDecommission(w http.ResponseWriter, r *http.Request) {
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	var groupID int64
	var apiURL string
	if err := db.QueryRowContext(ctx,
		"SELECT node_group_id, api_url FROM caddy_nodes WHERE id = ?", id,
	).Scan(&groupID, &apiURL); err != nil {
		redirectWithFlash(w, r, "/admin/nodes", "", "node not found")
		return
	}

	var destID int64
	if err := db.QueryRowContext(ctx,
		`SELECT id FROM caddy_nodes
		 WHERE node_group_id = ? AND id <> ? AND is_enabled = 1 AND approved_at IS NOT NULL
		   AND current_routes < max_routes
		 ORDER BY (current_routes / GREATEST(max_routes,1)) ASC, priority DESC, id ASC
		 LIMIT 1`, groupID, id).Scan(&destID); err != nil {
		redirectWithFlash(w, r, "/admin/nodes", "",
			"no peer node in the same group with capacity - add a replacement before decommissioning")
		return
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		redirectWithFlash(w, r, "/admin/nodes", "", "tx begin failed")
		return
	}
	defer tx.Rollback() //nolint:errcheck

	res, err := tx.ExecContext(ctx,
		"UPDATE routes SET caddy_node_id = ? WHERE caddy_node_id = ?", destID, id)
	if err != nil {
		redirectWithFlash(w, r, "/admin/nodes", "", "route move failed: "+sanitizeErr(err))
		return
	}
	moved, _ := res.RowsAffected()

	if _, err := tx.ExecContext(ctx,
		`UPDATE caddy_nodes SET current_routes = current_routes + ? WHERE id = ?`, moved, destID); err != nil {
		redirectWithFlash(w, r, "/admin/nodes", "", "counter bump dest failed")
		return
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE caddy_nodes SET current_routes = 0 WHERE id = ?`, id); err != nil {
		redirectWithFlash(w, r, "/admin/nodes", "", "counter zero src failed")
		return
	}
	if err := tx.Commit(); err != nil {
		redirectWithFlash(w, r, "/admin/nodes", "", "tx commit failed")
		return
	}

	if h.ResyncNode != nil {
		if rerr := h.ResyncNode(ctx, destID); rerr != nil {
			h.Logger.Warn("decommission resync dest failed", "dest", destID, "err", rerr)
		}
	}
	go func() {
		bctx, bcancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer bcancel()
		client := caddyapi.New(apiURL)
		_ = client.Load(bctx, map[string]any{"admin": map[string]any{"listen": "0.0.0.0:2019"}})
	}()

	if _, err := db.ExecContext(ctx, "DELETE FROM caddy_nodes WHERE id = ?", id); err != nil {
		redirectWithFlash(w, r, "/admin/nodes", "", "delete failed after route move: "+sanitizeErr(err))
		return
	}
	if h.WriteWGConfig != nil {
		_ = h.WriteWGConfig(ctx)
	}
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(middleware.SessionFromContext(r.Context())),
		Action: "node.decommission", Entity: "node", EntityID: fmt.Sprintf("%d", id),
		Meta: map[string]any{"moved_routes": moved, "dest_node_id": destID},
	})
	redirectWithFlash(w, r, "/admin/nodes",
		fmt.Sprintf("Decommissioned. Moved %d route(s) to node %d.", moved, destID), "")
}

// NodesRekey generates a fresh WireGuard keypair for a node, stores the
// public key in DB, stashes the private key (encrypted at rest) in
// `settings` so the admin can copy it once from the UI, and triggers a
// sidecar re-render so the manager mesh switches to the new peer
// immediately. The node itself still has to be updated manually:
// `/etc/wireguard/wg0.conf` PrivateKey + `wg-quick down/up wg0`.
func (h *AdminHandlers) NodesRekey(w http.ResponseWriter, r *http.Request) {
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	kp, err := wireguard.GenerateKeypair()
	if err != nil {
		redirectWithFlash(w, r, "/admin/nodes", "", "keygen failed")
		return
	}
	fingerprint := kp.PublicKey
	if len(fingerprint) > 16 {
		fingerprint = fingerprint[:16]
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	if _, err := db.ExecContext(ctx,
		"UPDATE caddy_nodes SET wg_public_key = ?, fingerprint = ? WHERE id = ?",
		kp.PublicKey, fingerprint, id); err != nil {
		redirectWithFlash(w, r, "/admin/nodes", "", "db update failed")
		return
	}
	enc, eerr := h.State.Encrypt(kp.PrivateKey)
	if eerr != nil {
		h.Logger.Error("rekey encrypt", "err", eerr)
		redirectWithFlash(w, r, "/admin/nodes", "", "encrypt failed")
		return
	}
	key := fmt.Sprintf("wireguard.pending_privkey.node_%d", id)
	_, _ = db.ExecContext(ctx, store.UpsertSettingSQL(), key, enc, 1)
	if h.WriteWGConfig != nil {
		_ = h.WriteWGConfig(ctx)
	}
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(middleware.SessionFromContext(r.Context())),
		Action: "node.rekey", Entity: "node", EntityID: fmt.Sprintf("%d", id),
		Meta: map[string]any{"new_fingerprint": fingerprint},
	})
	redirectWithFlash(w, r, "/admin/nodes",
		fmt.Sprintf("Rekey done (fingerprint %s). New private key stashed in settings - fetch it once via DB, paste into /etc/wireguard/wg0.conf on the node, then `wg-quick down/up wg0`.", fingerprint),
		"")
}

// NodesApprove flips an auto-joined node from "pending approval" to active.
// Until approved, the placement scheduler ignores the node, so a rogue node
// from a stolen join token cannot start carrying customer traffic.
//
// Admin is expected to compare the `fingerprint` shown in the panel with the
// `fingerprint` printed by the bootstrap script on the new VPS, then approve.
func (h *AdminHandlers) NodesApprove(w http.ResponseWriter, r *http.Request) {
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	sess := middleware.SessionFromContext(r.Context())
	var approvedBy sql.NullInt64
	if sess != nil {
		approvedBy = sql.NullInt64{Int64: sess.UserID, Valid: true}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5_000_000_000)
	defer cancel()
	if _, err := db.ExecContext(ctx,
		"UPDATE caddy_nodes SET is_enabled = 1, approved_at = NOW(), approved_by = ? WHERE id = ? AND approved_at IS NULL",
		approvedBy, id); err != nil {
		redirectWithFlash(w, r, "/admin/nodes", "", "approve failed")
		return
	}
	// Node only joins the WG mesh once approved - re-render so its peer is added now.
	if h.WriteWGConfig != nil {
		_ = h.WriteWGConfig(ctx)
	}
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(sess),
		Action: "node.approve", Entity: "node", EntityID: fmt.Sprintf("%d", id),
	})
	redirectWithFlash(w, r, "/admin/nodes", "Node approved", "")
}

// NodesResync rebuilds the node's full Caddy config from DB and POSTs /load.
// Wired in main.go via SetResync (we keep handler decoupled from routes pkg).
func (h *AdminHandlers) NodesResync(w http.ResponseWriter, r *http.Request) {
	if h.ResyncNode == nil {
		http.Error(w, "resync not wired", http.StatusServiceUnavailable)
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	ctx, cancel := context.WithTimeout(r.Context(), 15_000_000_000)
	defer cancel()
	if err := h.ResyncNode(ctx, id); err != nil {
		redirectWithFlash(w, r, "/admin/nodes", "", "resync failed: "+sanitizeErr(err))
		return
	}
	audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
		UserID: actorUserID(middleware.SessionFromContext(r.Context())),
		Action: "node.resync", Entity: "node", EntityID: fmt.Sprintf("%d", id),
	})
	redirectWithFlash(w, r, "/admin/nodes", "Resync triggered", "")
}

// NodesBulk applies one action (approve / resync / disable) to many nodes.
func (h *AdminHandlers) NodesBulk(w http.ResponseWriter, r *http.Request) {
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	_ = r.ParseForm()
	action := r.FormValue("action")
	ids := r.Form["ids"]
	if action == "" || len(ids) == 0 {
		redirectWithFlash(w, r, "/admin/nodes", "", "select nodes and an action")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	sess := middleware.SessionFromContext(r.Context())
	ok, fail := 0, 0
	for _, s := range ids {
		id, err := strconv.ParseInt(s, 10, 64)
		if err != nil || id == 0 {
			fail++
			continue
		}
		switch action {
		case "approve":
			if _, derr := db.ExecContext(ctx,
				"UPDATE caddy_nodes SET approved_at=NOW() WHERE id=? AND approved_at IS NULL", id); derr != nil {
				fail++
				continue
			}
		case "resync":
			if h.ResyncNode == nil {
				fail++
				continue
			}
			if derr := h.ResyncNode(ctx, id); derr != nil {
				fail++
				continue
			}
		case "disable":
			if _, derr := db.ExecContext(ctx,
				"UPDATE caddy_nodes SET is_enabled=0 WHERE id=?", id); derr != nil {
				fail++
				continue
			}
		default:
			fail++
			continue
		}
		ok++
	}
	// Mesh membership changed for approve/disable - re-render so peers match DB.
	if ok > 0 && (action == "approve" || action == "disable") && h.WriteWGConfig != nil {
		_ = h.WriteWGConfig(ctx)
	}
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "admin.node.bulk", Entity: "node",
		Meta: map[string]any{"action": action, "ok": ok, "fail": fail},
	})
	msg := strconv.Itoa(ok) + " node(s) " + action + "d"
	if fail > 0 {
		msg += "; " + strconv.Itoa(fail) + " failed"
	}
	redirectWithFlash(w, r, "/admin/nodes", msg, "")
}

// ---- Plans --------------------------------------------------------------

type planRow struct {
	ID                int64
	Name              string
	Kind              string // 'restricted' | 'npm'
	MaxDomains        int
	MaxPorts          int
	SSL               bool
	PathRouting       bool
	WebSocket         bool
	Wildcard          bool
	ExternalProxy     bool
	AllowEgressIP     bool  // allow fixed/random egress IP on routes under this plan
	RateLimitRPM      int   // 0 => no limit; carried for the edit modal
	WGKeyRotationDays int   // 0 => no rotation; carried for the edit modal
	NodeGroupID       int64 // carried for the edit modal preselect
	NodeGroupName     string
	ServiceCount      int
	RouteCount        int
	ClientCount       int
	Owned             bool // caller may edit/delete (own reseller plan, or platform admin)
}

type nodeGroup struct {
	ID   int64
	Name string
}

// nodeGroupRow is one row in the node groups list with usage counts.
type nodeGroupRow struct {
	ID        int64
	Name      string
	Mode      string // "single" | "active_active" | "failover"
	NodeCount int
	PlanCount int
}

type nodeGroupsData struct {
	baseAdminData
	Groups []nodeGroupRow
}

func (h *AdminHandlers) NodeGroupsList(w http.ResponseWriter, r *http.Request) {
	d := nodeGroupsData{baseAdminData: h.base(r, "Node groups")}
	db := h.DB()
	if db == nil {
		h.render(w, "node_groups", d)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3_000_000_000)
	defer cancel()
	rows, err := db.QueryContext(ctx,
		`SELECT ng.id, ng.name, COALESCE(ng.mode,'single'),
		        COUNT(DISTINCT n.id), COUNT(DISTINCT p.id)
		 FROM node_groups ng
		 LEFT JOIN caddy_nodes n ON n.node_group_id = ng.id
		 LEFT JOIN plans p ON p.node_group_id = ng.id
		 GROUP BY ng.id ORDER BY ng.id`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var g nodeGroupRow
			if err := rows.Scan(&g.ID, &g.Name, &g.Mode, &g.NodeCount, &g.PlanCount); err == nil {
				d.Groups = append(d.Groups, g)
			}
		}
	}
	h.render(w, "node_groups", d)
}

func (h *AdminHandlers) NodeGroupCreate(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.FormValue("name"))
	mode := r.FormValue("mode")
	if name == "" {
		redirectWithFlash(w, r, "/admin/node-groups", "", "name is required")
		return
	}
	if mode != "single" && mode != "active_active" && mode != "failover" {
		mode = "single"
	}
	db := h.DB()
	if db == nil {
		redirectWithFlash(w, r, "/admin/node-groups", "", "database unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3_000_000_000)
	defer cancel()
	_, err := db.ExecContext(ctx, "INSERT INTO node_groups (name, mode) VALUES (?, ?)", name, mode)
	if err != nil {
		redirectWithFlash(w, r, "/admin/node-groups", "", "insert failed: "+sanitizeErr(err))
		return
	}
	redirectWithFlash(w, r, "/admin/node-groups", "Node group created", "")
}

func (h *AdminHandlers) NodeGroupUpdate(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		redirectWithFlash(w, r, "/admin/node-groups", "", "invalid id")
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	mode := r.FormValue("mode")
	if name == "" {
		redirectWithFlash(w, r, "/admin/node-groups", "", "name is required")
		return
	}
	if mode != "single" && mode != "active_active" && mode != "failover" {
		mode = "single"
	}
	db := h.DB()
	if db == nil {
		redirectWithFlash(w, r, "/admin/node-groups", "", "database unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3_000_000_000)
	defer cancel()
	_, err = db.ExecContext(ctx, "UPDATE node_groups SET name=?, mode=? WHERE id=?", name, mode, id)
	if err != nil {
		redirectWithFlash(w, r, "/admin/node-groups", "", "update failed: "+sanitizeErr(err))
		return
	}
	redirectWithFlash(w, r, "/admin/node-groups", "Node group updated", "")
}

type plansData struct {
	baseAdminData
	Plans  []planRow
	Groups []nodeGroup
	// CanManage is true when the caller may create plans (platform admin creates
	// global plans; reseller-admin creates plans owned by their reseller).
	CanManage bool
	// ResellerScoped marks a reseller-admin view (create form makes reseller plans).
	ResellerScoped bool
}

func (h *AdminHandlers) PlansList(w http.ResponseWriter, r *http.Request) {
	d := plansData{baseAdminData: h.base(r, "Plans")}
	db := h.DB()
	if db == nil {
		h.render(w, "plans", d)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3_000_000_000)
	defer cancel()

	// Plan visibility: platform admins see every plan; a reseller-admin sees
	// global plans (reseller_id NULL) plus its own reseller's plans.
	rid, all, ok := h.planScope(ctx, middleware.SessionFromContext(r.Context()))
	d.CanManage = ok
	d.ResellerScoped = ok && !all
	planWhere := ""
	var planArgs []any
	if d.ResellerScoped {
		planWhere = " WHERE (p.reseller_id IS NULL OR p.reseller_id = ?)"
		planArgs = append(planArgs, rid)
	}
	rows, err := db.QueryContext(ctx,
		`SELECT p.id, p.name, p.kind, p.max_domains, p.max_ports, p.ssl_enabled,
		        p.path_routing_enabled, p.websocket_enabled, p.wildcard_enabled,
		        p.external_proxy_enabled, COALESCE(p.allow_egress_ip,0), p.rate_limit_rpm,
		        p.wg_key_rotation_days, p.node_group_id, ng.name, COALESCE(p.reseller_id,0)
		 FROM plans p JOIN node_groups ng ON ng.id = p.node_group_id`+planWhere+`
		 ORDER BY p.id DESC`, planArgs...)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var p planRow
			var rl, wgDays sql.NullInt32
			var planReseller int64
			if err := rows.Scan(&p.ID, &p.Name, &p.Kind, &p.MaxDomains, &p.MaxPorts,
				&p.SSL, &p.PathRouting, &p.WebSocket, &p.Wildcard, &p.ExternalProxy,
				&p.AllowEgressIP, &rl, &wgDays, &p.NodeGroupID, &p.NodeGroupName, &planReseller); err == nil {
				if rl.Valid {
					p.RateLimitRPM = int(rl.Int32)
				}
				if wgDays.Valid {
					p.WGKeyRotationDays = int(wgDays.Int32)
				}
				// Editable when platform admin, or the plan is owned by the
				// reseller-admin's own reseller (never global plans for resellers).
				p.Owned = all || (d.ResellerScoped && planReseller == rid)
				d.Plans = append(d.Plans, p)
			}
		}
	}

	// fetch per-plan service + route + client counts in one pass
	type planUsage struct{ svc, route, clients int }
	usage := map[int64]planUsage{}
	urows, err := db.QueryContext(ctx,
		`SELECT s.plan_id, COUNT(DISTINCT s.id), COUNT(DISTINCT r.id), COUNT(DISTINCT s.client_id)
		 FROM services s
		 LEFT JOIN routes r ON r.service_id = s.id
		 GROUP BY s.plan_id`)
	if err == nil {
		defer urows.Close()
		for urows.Next() {
			var pid int64
			var u planUsage
			urows.Scan(&pid, &u.svc, &u.route, &u.clients) //nolint:errcheck
			usage[pid] = u
		}
	}
	for i, p := range d.Plans {
		if u, ok := usage[p.ID]; ok {
			d.Plans[i].ServiceCount = u.svc
			d.Plans[i].RouteCount = u.route
			d.Plans[i].ClientCount = u.clients
		}
	}

	grows, err := db.QueryContext(ctx, "SELECT id, name FROM node_groups ORDER BY name")
	if err == nil {
		defer grows.Close()
		for grows.Next() {
			var g nodeGroup
			if err := grows.Scan(&g.ID, &g.Name); err == nil {
				d.Groups = append(d.Groups, g)
			}
		}
	}

	h.render(w, "plans", d)
}

// PlansUpdate edits a plan in place. Mirrors PlansCreate parsing,
// validation, and the same field invariants (caps > 0, kind, node group).
func (h *AdminHandlers) PlansUpdate(w http.ResponseWriter, r *http.Request) {
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	// Reseller-admins may edit only their own reseller's plans; platform admins any.
	mctx, mcancel := context.WithTimeout(r.Context(), 3*time.Second)
	manage := h.planManageable(mctx, middleware.SessionFromContext(r.Context()), id)
	mcancel()
	if !manage {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	_ = r.ParseForm()
	name := strings.TrimSpace(r.FormValue("name"))
	kind := strings.TrimSpace(r.FormValue("kind"))
	if kind != "npm" {
		kind = "restricted"
	}
	maxDomains, _ := strconv.Atoi(r.FormValue("max_domains"))
	maxPorts, _ := strconv.Atoi(r.FormValue("max_ports"))
	rateLimit, _ := strconv.Atoi(r.FormValue("rate_limit_rpm"))
	groupID, _ := strconv.ParseInt(r.FormValue("node_group_id"), 10, 64)
	ssl := r.FormValue("ssl") == "1"
	pathRouting := r.FormValue("path_routing") == "1"
	websocket := r.FormValue("websocket") == "1"
	wildcard := r.FormValue("wildcard") == "1"
	externalProxy := r.FormValue("external_proxy") == "1"
	allowEgressIP := r.FormValue("allow_egress_ip") == "1"
	wgKeyRotDays, _ := strconv.Atoi(r.FormValue("wg_key_rotation_days"))

	if name == "" || maxDomains <= 0 || maxPorts <= 0 || groupID == 0 {
		redirectWithFlash(w, r, "/admin/plans", "", "name, limits, and node group are required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5_000_000_000)
	defer cancel()
	var rateLimitVal sql.NullInt32
	if rateLimit > 0 {
		rateLimitVal = sql.NullInt32{Int32: int32(rateLimit), Valid: true}
	}
	var wgRotDaysVal sql.NullInt32
	if wgKeyRotDays > 0 {
		wgRotDaysVal = sql.NullInt32{Int32: int32(wgKeyRotDays), Valid: true}
	}
	res, err := db.ExecContext(ctx,
		`UPDATE plans SET name=?, kind=?, max_domains=?, max_ports=?, ssl_enabled=?,
		   path_routing_enabled=?, wildcard_enabled=?, websocket_enabled=?,
		   external_proxy_enabled=?, allow_egress_ip=?, rate_limit_rpm=?, wg_key_rotation_days=?, node_group_id=?
		 WHERE id=?`,
		name, kind, maxDomains, maxPorts, ssl, pathRouting, wildcard, websocket,
		externalProxy, allowEgressIP, rateLimitVal, wgRotDaysVal, groupID, id)
	if err != nil {
		if strings.Contains(err.Error(), "Duplicate entry") {
			redirectWithFlash(w, r, "/admin/plans", "", "plan name already exists")
			return
		}
		h.Logger.Error("plan update", "err", err)
		redirectWithFlash(w, r, "/admin/plans", "", "update failed")
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		// Either no such plan or no change; verify existence.
		var exists int
		_ = db.QueryRowContext(ctx, "SELECT 1 FROM plans WHERE id = ?", id).Scan(&exists)
		if exists == 0 {
			redirectWithFlash(w, r, "/admin/plans", "", "plan not found")
			return
		}
	}
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(middleware.SessionFromContext(r.Context())),
		Action: "plan.update", Entity: "plan", EntityID: fmt.Sprintf("%d", id),
		Meta: map[string]any{"name": name},
	})
	redirectWithFlash(w, r, "/admin/plans", "Plan updated", "")
}

func (h *AdminHandlers) PlansCreate(w http.ResponseWriter, r *http.Request) {
	pctx, pcancel := context.WithTimeout(r.Context(), 3*time.Second)
	planReseller, planAll, planOK := h.planScope(pctx, middleware.SessionFromContext(r.Context()))
	pcancel()
	if !planOK {
		http.Error(w, "forbidden: platform admins only", http.StatusForbidden)
		return
	}
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	_ = r.ParseForm()
	name := strings.TrimSpace(r.FormValue("name"))
	kind := strings.TrimSpace(r.FormValue("kind"))
	if kind != "npm" {
		kind = "restricted"
	}
	maxDomains, _ := strconv.Atoi(r.FormValue("max_domains"))
	maxPorts, _ := strconv.Atoi(r.FormValue("max_ports"))
	rateLimit, _ := strconv.Atoi(r.FormValue("rate_limit_rpm"))
	groupID, _ := strconv.ParseInt(r.FormValue("node_group_id"), 10, 64)
	ssl := r.FormValue("ssl") == "1"
	pathRouting := r.FormValue("path_routing") == "1"
	websocket := r.FormValue("websocket") == "1"
	wildcard := r.FormValue("wildcard") == "1"
	externalProxy := r.FormValue("external_proxy") == "1"
	allowEgressIP := r.FormValue("allow_egress_ip") == "1"
	wgKeyRotDays, _ := strconv.Atoi(r.FormValue("wg_key_rotation_days"))

	if name == "" || maxDomains <= 0 || maxPorts <= 0 || groupID == 0 {
		redirectWithFlash(w, r, "/admin/plans", "", "name, limits, and node group are required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5_000_000_000)
	defer cancel()
	var rateLimitVal sql.NullInt32
	if rateLimit > 0 {
		rateLimitVal = sql.NullInt32{Int32: int32(rateLimit), Valid: true}
	}
	var wgRotDaysVal sql.NullInt32
	if wgKeyRotDays > 0 {
		wgRotDaysVal = sql.NullInt32{Int32: int32(wgKeyRotDays), Valid: true}
	}
	// A reseller-admin's plans are owned by their reseller; platform admins
	// create global plans (reseller_id NULL).
	var resellerCol any
	if !planAll {
		resellerCol = planReseller
	}
	res, err := db.ExecContext(ctx,
		`INSERT INTO plans (name, kind, max_domains, max_ports, ssl_enabled, path_routing_enabled,
		   wildcard_enabled, websocket_enabled, external_proxy_enabled, allow_egress_ip, rate_limit_rpm, wg_key_rotation_days, node_group_id, reseller_id)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		name, kind, maxDomains, maxPorts, ssl, pathRouting, wildcard, websocket, externalProxy, allowEgressIP, rateLimitVal, wgRotDaysVal, groupID, resellerCol)
	if err != nil {
		if strings.Contains(err.Error(), "Duplicate entry") {
			redirectWithFlash(w, r, "/admin/plans", "", "plan name already exists")
			return
		}
		h.Logger.Error("plan create", "err", err)
		redirectWithFlash(w, r, "/admin/plans", "", "create failed")
		return
	}
	id, _ := res.LastInsertId()
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(middleware.SessionFromContext(r.Context())),
		Action: "plan.create", Entity: "plan", EntityID: fmt.Sprintf("%d", id),
		Meta: map[string]any{"name": name},
	})
	redirectWithFlash(w, r, "/admin/plans", "Plan created", "")
}

func (h *AdminHandlers) PlansDelete(w http.ResponseWriter, r *http.Request) {
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	// Reseller-admins may delete only their own reseller's plans.
	mctx, mcancel := context.WithTimeout(r.Context(), 3*time.Second)
	manage := h.planManageable(mctx, middleware.SessionFromContext(r.Context()), id)
	mcancel()
	if !manage {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5_000_000_000)
	defer cancel()
	if _, err := db.ExecContext(ctx, "DELETE FROM plans WHERE id = ?", id); err != nil {
		if strings.Contains(err.Error(), "foreign key") {
			redirectWithFlash(w, r, "/admin/plans", "", "plan is in use by a service")
			return
		}
		redirectWithFlash(w, r, "/admin/plans", "", "delete failed")
		return
	}
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(middleware.SessionFromContext(r.Context())),
		Action: "plan.delete", Entity: "plan", EntityID: fmt.Sprintf("%d", id),
	})
	redirectWithFlash(w, r, "/admin/plans", "Plan deleted", "")
}

// ---- Clients ------------------------------------------------------------

type clientRow struct {
	ID               int64
	DisplayName      string // display fallback: COALESCE(display_name, full_name, email)
	EditDisplayName  string // real stored clients.display_name (may be empty) for the edit modal
	Email            string
	ExternalRef      string
	ServiceCount     int
	Bandwidth30d     int64 // bytes out, last 30 days
	CreatedAt        string
	Tag              string // grouping label
	Category         string // billing/segment category
	CustomFieldsJSON string // raw JSON for edit modal prefill
}

type clientsData struct {
	baseAdminData
	Clients []clientRow
	// Pagination/sort/search.
	Page            int
	Size            int
	Total           int
	TotalPgs        int
	Sort            string
	Dir             string
	Q               string
	TagFilter       string
	CategoryFilter  string
	PrevURL         string
	NextURL         string
	QueryValues     string
	SavedFilters    []savedFilter
	CustomFieldDefs []customfields.Def // admin-defined fields for the create/edit form
}

func (h *AdminHandlers) ClientsList(w http.ResponseWriter, r *http.Request) {
	if h.maybeApplySavedFilter(w, r, "clients") {
		return
	}
	lp := parseListParams(r, []string{"id", "display_name", "email", "created_at"},
		"id", "desc", 50)
	d := clientsData{
		baseAdminData:  h.base(r, "Clients"),
		Page:           lp.Page,
		Size:           lp.Size,
		Sort:           lp.Sort,
		Dir:            lp.Dir,
		Q:              lp.Q,
		TagFilter:      strings.TrimSpace(r.URL.Query().Get("tag")),
		CategoryFilter: strings.TrimSpace(r.URL.Query().Get("category")),
	}
	db := h.DB()
	if db == nil {
		h.render(w, "clients", d)
		return
	}
	sess := middleware.SessionFromContext(r.Context())
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	where := []string{"1=1"}
	var args []any
	if lp.Q != "" {
		like := likeContains(lp.Q)
		where = append(where, `(u.email LIKE ? ESCAPE '\\' OR c.display_name LIKE ? ESCAPE '\\' OR u.full_name LIKE ? ESCAPE '\\' OR c.external_ref LIKE ? ESCAPE '\\')`)
		args = append(args, like, like, like, like)
	}
	if d.TagFilter != "" {
		where = append(where, "c.tag = ?")
		args = append(args, d.TagFilter)
	}
	if d.CategoryFilter != "" {
		where = append(where, "c.category = ?")
		args = append(args, d.CategoryFilter)
	}
	// Scope: non-super_admins see only their assigned clients (empty scope = none).
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

	orderCol := clientsSortCol(lp.Sort)
	dir := lp.Dir
	if dir != "asc" {
		dir = "desc"
	}

	whereSQL := strings.Join(where, " AND ")
	baseFrom := `FROM clients c JOIN users u ON u.id = c.user_id WHERE ` + whereSQL

	var total int
	_ = db.QueryRowContext(ctx, "SELECT COUNT(*) "+baseFrom, args...).Scan(&total)

	selectSQL := `SELECT c.id, COALESCE(c.display_name, u.full_name, u.email), COALESCE(c.display_name, ''), u.email,
	        COALESCE(c.external_ref, ''),
	        (SELECT COUNT(*) FROM services s WHERE s.client_id = c.id),
	        DATE_FORMAT(c.created_at, '%Y-%m-%d'),
	        COALESCE(c.tag, ''), COALESCE(c.category, ''),
	        COALESCE(c.custom_fields, '')
	 ` + baseFrom + ` ORDER BY ` + orderCol + ` ` + dir + ` LIMIT ? OFFSET ?`
	queryArgs := append(args, lp.Size, lp.Offset())

	rows, err := db.QueryContext(ctx, selectSQL, queryArgs...)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var c clientRow
			if err := rows.Scan(&c.ID, &c.DisplayName, &c.EditDisplayName, &c.Email, &c.ExternalRef, &c.ServiceCount, &c.CreatedAt, &c.Tag, &c.Category, &c.CustomFieldsJSON); err == nil {
				d.Clients = append(d.Clients, c)
			}
		}
	}

	// fetch 30d bandwidth separately to avoid slow correlated sub-query inside paginated SELECT
	if len(d.Clients) > 0 {
		ids := make([]any, len(d.Clients))
		for i, c := range d.Clients {
			ids[i] = c.ID
		}
		ph := make([]string, len(ids))
		for i := range ph {
			ph[i] = "?"
		}
		bwSQL := `SELECT s.client_id, COALESCE(SUM(lr.bytes_resp), 0)
		 FROM log_rollups lr
		 JOIN routes r ON r.id = lr.route_id
		 JOIN services s ON s.id = r.service_id
		 WHERE s.client_id IN (` + strings.Join(ph, ",") + `)
		   AND lr.bucket_start >= NOW() - INTERVAL 30 DAY
		 GROUP BY s.client_id`
		bwRows, bwErr := db.QueryContext(ctx, bwSQL, ids...)
		if bwErr == nil {
			defer bwRows.Close()
			bwMap := make(map[int64]int64, len(d.Clients))
			for bwRows.Next() {
				var cid int64
				var bw int64
				if bwRows.Scan(&cid, &bw) == nil {
					bwMap[cid] = bw
				}
			}
			for i := range d.Clients {
				d.Clients[i].Bandwidth30d = bwMap[d.Clients[i].ID]
			}
		}
	}

	d.Total = total
	d.TotalPgs = (total + lp.Size - 1) / lp.Size
	if d.TotalPgs < 1 {
		d.TotalPgs = 1
	}
	q := r.URL.Query()
	if lp.Page > 1 {
		d.PrevURL = buildPageURL(q, lp.Page-1)
	}
	if lp.Page < d.TotalPgs {
		d.NextURL = buildPageURL(q, lp.Page+1)
	}
	d.QueryValues = clientsQueryJSON(lp.Q, lp.Sort, lp.Dir, d.TagFilter, d.CategoryFilter)
	if sess != nil {
		d.SavedFilters = h.savedFiltersForView(ctx, sess.UserID, "clients")
	}
	// Load client custom field defs for the create/edit form.
	if defs, err := customfields.LoadDefs(ctx, db, "client"); err == nil {
		d.CustomFieldDefs = defs
	}
	h.render(w, "clients", d)
}

func clientsSortCol(s string) string {
	switch s {
	case "display_name":
		return "COALESCE(c.display_name, u.full_name, u.email)"
	case "email":
		return "u.email"
	case "created_at":
		return "c.created_at"
	default:
		return "c.id"
	}
}

func clientsQueryJSON(q, sort, dir, tag, category string) string {
	b, _ := json.Marshal(map[string]string{"q": q, "sort": sort, "dir": dir, "tag": tag, "category": category})
	return string(b)
}

// ClientsUpdate edits a client's display name, login email, and external
// ref in place. Password is never touched here. Mirrors ClientsCreate
// validation (name/email required).
func (h *AdminHandlers) ClientsUpdate(w http.ResponseWriter, r *http.Request) {
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	_ = r.ParseForm()
	displayName := strings.TrimSpace(r.FormValue("display_name"))
	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	externalRef := strings.TrimSpace(r.FormValue("external_ref"))
	tag := strings.TrimSpace(r.FormValue("tag"))
	category := strings.TrimSpace(r.FormValue("category"))
	if len(tag) > 64 {
		tag = tag[:64]
	}
	if len(category) > 64 {
		category = category[:64]
	}

	if displayName == "" || email == "" {
		redirectWithFlash(w, r, "/admin/clients", "", "name and email are required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5_000_000_000)
	defer cancel()
	// Scoped admins may only edit clients they are assigned to.
	if !h.scopeCheckClient(ctx, middleware.SessionFromContext(r.Context()), id) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	var userID int64
	if err := db.QueryRowContext(ctx, "SELECT user_id FROM clients WHERE id = ?", id).Scan(&userID); err != nil {
		redirectWithFlash(w, r, "/admin/clients", "", "client not found")
		return
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		redirectWithFlash(w, r, "/admin/clients", "", "tx begin failed")
		return
	}
	defer tx.Rollback() //nolint:errcheck

	if _, err := tx.ExecContext(ctx,
		"UPDATE users SET email = ?, full_name = ? WHERE id = ?", email, displayName, userID); err != nil {
		if strings.Contains(err.Error(), "Duplicate entry") {
			redirectWithFlash(w, r, "/admin/clients", "", "email already exists")
			return
		}
		redirectWithFlash(w, r, "/admin/clients", "", "user update failed")
		return
	}
	var extRef sql.NullString
	if externalRef != "" {
		extRef = sql.NullString{String: externalRef, Valid: true}
	}
	cfDefs, _ := customfields.LoadDefs(ctx, db, "client")
	cfJSON, cfErr := customfields.EncodeFromForm(cfDefs, r.Form)
	if cfErr != nil {
		tx.Rollback() //nolint:errcheck
		redirectWithFlash(w, r, "/admin/clients", "", cfErr.Error())
		return
	}
	if _, err := tx.ExecContext(ctx,
		"UPDATE clients SET display_name = ?, external_ref = ?, tag = ?, category = ?, custom_fields = ? WHERE id = ?",
		displayName, extRef,
		sql.NullString{String: tag, Valid: tag != ""},
		sql.NullString{String: category, Valid: category != ""},
		cfJSON, id); err != nil {
		redirectWithFlash(w, r, "/admin/clients", "", "client update failed")
		return
	}
	if err := tx.Commit(); err != nil {
		redirectWithFlash(w, r, "/admin/clients", "", "commit failed")
		return
	}
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(middleware.SessionFromContext(r.Context())),
		Action: "client.update", Entity: "client", EntityID: fmt.Sprintf("%d", id),
		Meta: map[string]any{"email": email},
	})
	redirectWithFlash(w, r, "/admin/clients", "Client updated", "")
}

func (h *AdminHandlers) ClientsCreate(w http.ResponseWriter, r *http.Request) {
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	_ = r.ParseForm()
	displayName := strings.TrimSpace(r.FormValue("display_name"))
	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	password := r.FormValue("password")
	externalRef := strings.TrimSpace(r.FormValue("external_ref"))
	tag := strings.TrimSpace(r.FormValue("tag"))
	category := strings.TrimSpace(r.FormValue("category"))
	if len(tag) > 64 {
		tag = tag[:64]
	}
	if len(category) > 64 {
		category = category[:64]
	}

	if displayName == "" || email == "" || password == "" {
		redirectWithFlash(w, r, "/admin/clients", "", "all fields required")
		return
	}
	if len(password) < 12 {
		redirectWithFlash(w, r, "/admin/clients", "", "password must be at least 12 characters")
		return
	}

	hash, err := auth.HashPassword(password)
	if err != nil {
		redirectWithFlash(w, r, "/admin/clients", "", "hash failed")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5_000_000_000)
	defer cancel()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		redirectWithFlash(w, r, "/admin/clients", "", "tx begin failed")
		return
	}
	defer tx.Rollback() //nolint:errcheck

	res, err := tx.ExecContext(ctx,
		"INSERT INTO users (email, password_hash, password_set, role, full_name, is_active) VALUES (?, ?, 1, 'client', ?, 1)",
		email, hash, displayName)
	if err != nil {
		if strings.Contains(err.Error(), "Duplicate entry") {
			redirectWithFlash(w, r, "/admin/clients", "", "email already exists")
			return
		}
		h.Logger.Error("client user create", "err", err)
		redirectWithFlash(w, r, "/admin/clients", "", "user insert failed")
		return
	}
	userID, _ := res.LastInsertId()

	cfDefs, _ := customfields.LoadDefs(ctx, db, "client")
	cfJSON, cfErr := customfields.EncodeFromForm(cfDefs, r.Form)
	if cfErr != nil {
		tx.Rollback() //nolint:errcheck
		redirectWithFlash(w, r, "/admin/clients", "", cfErr.Error())
		return
	}
	var extRef sql.NullString
	if externalRef != "" {
		extRef = sql.NullString{String: externalRef, Valid: true}
	}
	if _, err := tx.ExecContext(ctx,
		"INSERT INTO clients (user_id, display_name, external_ref, tag, category, custom_fields) VALUES (?, ?, ?, ?, ?, ?)",
		userID, displayName, extRef,
		sql.NullString{String: tag, Valid: tag != ""},
		sql.NullString{String: category, Valid: category != ""},
		cfJSON); err != nil {
		h.Logger.Error("client record create", "err", err)
		redirectWithFlash(w, r, "/admin/clients", "", "client insert failed")
		return
	}
	if err := tx.Commit(); err != nil {
		redirectWithFlash(w, r, "/admin/clients", "", "commit failed")
		return
	}
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(middleware.SessionFromContext(r.Context())),
		Action: "client.create", Entity: "client", EntityID: fmt.Sprintf("%d", userID),
		Meta: map[string]any{"email": email},
	})
	redirectWithFlash(w, r, "/admin/clients", "Client created", "")
}

func (h *AdminHandlers) ClientsDelete(w http.ResponseWriter, r *http.Request) {
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	ctx, cancel := context.WithTimeout(r.Context(), 5_000_000_000)
	defer cancel()
	// Scoped admins may only delete clients they are assigned to.
	if !h.scopeCheckClient(ctx, middleware.SessionFromContext(r.Context()), id) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	var userID int64
	if err := db.QueryRowContext(ctx, "SELECT user_id FROM clients WHERE id = ?", id).Scan(&userID); err != nil {
		redirectWithFlash(w, r, "/admin/clients", "", "client not found")
		return
	}
	// ON DELETE CASCADE will remove the clients row when we delete the user.
	if _, err := db.ExecContext(ctx, "DELETE FROM users WHERE id = ?", userID); err != nil {
		if strings.Contains(err.Error(), "foreign key") {
			redirectWithFlash(w, r, "/admin/clients", "", "client has active services")
			return
		}
		redirectWithFlash(w, r, "/admin/clients", "", "delete failed")
		return
	}
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(middleware.SessionFromContext(r.Context())),
		Action: "client.delete", Entity: "client", EntityID: fmt.Sprintf("%d", id),
	})
	redirectWithFlash(w, r, "/admin/clients", "Client deleted", "")
}

// ---- Services -----------------------------------------------------------

type serviceRow struct {
	ID          int64
	Name        string
	ClientName  string
	ClientID    int64 // for the edit modal client preselect
	BackendIP   string
	PortStart   int
	PortEnd     int
	PlanName    string
	PlanID      int64  // for the edit modal plan preselect
	ExternalRef string // input name="external_reference"
	Status      string
	Notes       string // admin-only internal notes
}

type clientOpt struct {
	ID          int64
	DisplayName string
	Email       string
}

type planOpt struct {
	ID   int64
	Name string
}

type servicesData struct {
	baseAdminData
	Services     []serviceRow
	Clients      []clientOpt
	Plans        []planOpt
	Q            string // search query
	StatusFilter string // "active","suspended","terminated","" = all
}

func (h *AdminHandlers) ServicesList(w http.ResponseWriter, r *http.Request) {
	d := servicesData{baseAdminData: h.base(r, "Services")}
	db := h.DB()
	if db == nil {
		h.render(w, "services", d)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3_000_000_000)
	defer cancel()

	q := strings.TrimSpace(r.URL.Query().Get("q"))
	statusFilter := r.URL.Query().Get("status")
	d.Q = q
	d.StatusFilter = statusFilter

	// Scope: non-super_admins see only services/clients they are assigned to.
	sess := middleware.SessionFromContext(r.Context())
	scopeIDs, scopeAll, scopeOK := h.adminClientScope(ctx, sess)
	scoped := scopeOK && !scopeAll
	var scopeArgs []any
	if scoped {
		for id := range scopeIDs {
			scopeArgs = append(scopeArgs, id)
		}
	}

	// build WHERE clause from active filters
	var where []string
	var args []any
	if q != "" {
		where = append(where, "(s.name LIKE ? OR s.backend_ip LIKE ? OR COALESCE(c.display_name, u.full_name, u.email) LIKE ?)")
		like := "%" + q + "%"
		args = append(args, like, like, like)
	}
	if statusFilter != "" {
		where = append(where, "s.status = ?")
		args = append(args, statusFilter)
	}
	if scoped {
		if len(scopeArgs) == 0 {
			where = append(where, "1=0")
		} else {
			where = append(where, "s.client_id IN ("+placeholders(len(scopeArgs))+")")
			args = append(args, scopeArgs...)
		}
	}
	whereSQL := ""
	if len(where) > 0 {
		whereSQL = "WHERE " + strings.Join(where, " AND ")
	}

	query := `SELECT s.id, s.name, COALESCE(c.display_name, u.full_name, u.email), s.client_id,
		        s.backend_ip, s.allowed_port_start, s.allowed_port_end, p.name, s.plan_id,
		        COALESCE(s.external_reference,''), s.status, COALESCE(s.notes,'')
		 FROM services s
		 JOIN clients c ON c.id = s.client_id
		 JOIN users u   ON u.id = c.user_id
		 JOIN plans p   ON p.id = s.plan_id
		 ` + whereSQL + ` ORDER BY s.id DESC`
	rows, err := db.QueryContext(ctx, query, args...)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var s serviceRow
			if err := rows.Scan(&s.ID, &s.Name, &s.ClientName, &s.ClientID, &s.BackendIP, &s.PortStart, &s.PortEnd, &s.PlanName, &s.PlanID, &s.ExternalRef, &s.Status, &s.Notes); err == nil {
				d.Services = append(d.Services, s)
			}
		}
	}

	clientQ := `SELECT c.id, COALESCE(c.display_name, u.full_name, u.email), u.email
		 FROM clients c JOIN users u ON u.id = c.user_id`
	var clientArgs []any
	if scoped {
		if len(scopeArgs) == 0 {
			clientQ += " WHERE 1=0"
		} else {
			clientQ += " WHERE c.id IN (" + placeholders(len(scopeArgs)) + ")"
			clientArgs = append(clientArgs, scopeArgs...)
		}
	}
	clientQ += " ORDER BY c.id DESC"
	crows, err := db.QueryContext(ctx, clientQ, clientArgs...)
	if err == nil {
		defer crows.Close()
		for crows.Next() {
			var c clientOpt
			if err := crows.Scan(&c.ID, &c.DisplayName, &c.Email); err == nil {
				d.Clients = append(d.Clients, c)
			}
		}
	}

	// Plan dropdown: reseller-admins see global plans plus their own reseller's.
	planQ := "SELECT id, name FROM plans"
	var planArgs []any
	if prid, pall, pok := h.planScope(ctx, middleware.SessionFromContext(r.Context())); pok && !pall {
		planQ += " WHERE (reseller_id IS NULL OR reseller_id = ?)"
		planArgs = append(planArgs, prid)
	}
	planQ += " ORDER BY id DESC"
	prows, err := db.QueryContext(ctx, planQ, planArgs...)
	if err == nil {
		defer prows.Close()
		for prows.Next() {
			var p planOpt
			if err := prows.Scan(&p.ID, &p.Name); err == nil {
				d.Plans = append(d.Plans, p)
			}
		}
	}
	h.render(w, "services", d)
}

func (h *AdminHandlers) ServicesCreate(w http.ResponseWriter, r *http.Request) {
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	_ = r.ParseForm()
	clientID, _ := strconv.ParseInt(r.FormValue("client_id"), 10, 64)
	planID, _ := strconv.ParseInt(r.FormValue("plan_id"), 10, 64)
	portStart, _ := strconv.Atoi(r.FormValue("port_start"))
	portEnd, _ := strconv.Atoi(r.FormValue("port_end"))
	name := strings.TrimSpace(r.FormValue("name"))
	backendIP := strings.TrimSpace(r.FormValue("backend_ip"))
	externalRef := strings.TrimSpace(r.FormValue("external_reference"))
	notes := strings.TrimSpace(r.FormValue("notes"))
	if len(notes) > 10000 {
		notes = notes[:10000]
	}

	if name == "" || backendIP == "" || clientID == 0 || planID == 0 {
		redirectWithFlash(w, r, "/admin/services", "", "all fields required")
		return
	}
	if ip := net.ParseIP(backendIP); ip == nil {
		redirectWithFlash(w, r, "/admin/services", "", "backend_ip is not a valid IP")
		return
	}
	if portStart < 1 || portEnd > 65535 || portStart > portEnd {
		redirectWithFlash(w, r, "/admin/services", "", "port range invalid (start<=end, 1..65535)")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5_000_000_000)
	defer cancel()

	// IDOR guard: a restricted admin may only create services for its own tenants.
	if !h.scopeCheckClient(ctx, middleware.SessionFromContext(r.Context()), clientID) {
		redirectWithFlash(w, r, "/admin/services", "", "forbidden: client outside your scope")
		return
	}
	// A reseller-admin may only use global plans or its own reseller's plans.
	if !h.planAccessible(ctx, middleware.SessionFromContext(r.Context()), planID) {
		redirectWithFlash(w, r, "/admin/services", "", "forbidden: plan outside your scope")
		return
	}

	var nodeGroupID int64
	if err := db.QueryRowContext(ctx, "SELECT node_group_id FROM plans WHERE id = ?", planID).Scan(&nodeGroupID); err != nil {
		redirectWithFlash(w, r, "/admin/services", "", "plan not found")
		return
	}

	var extRef sql.NullString
	if externalRef != "" {
		extRef = sql.NullString{String: externalRef, Valid: true}
	}
	var notesVal sql.NullString
	if notes != "" {
		notesVal = sql.NullString{String: notes, Valid: true}
	}
	res, err := db.ExecContext(ctx,
		`INSERT INTO services (client_id, name, backend_ip, allowed_port_start, allowed_port_end,
		   plan_id, node_group_id, status, external_reference, notes)
		 VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?, ?)`,
		clientID, name, backendIP, portStart, portEnd, planID, nodeGroupID, extRef, notesVal)
	if err != nil {
		h.Logger.Error("service create", "err", err)
		redirectWithFlash(w, r, "/admin/services", "", "insert failed: "+sanitizeErr(err))
		return
	}
	id, _ := res.LastInsertId()
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(middleware.SessionFromContext(r.Context())),
		Action: "service.create", Entity: "service", EntityID: fmt.Sprintf("%d", id),
		Meta: map[string]any{"name": name, "client_id": clientID, "ports": fmt.Sprintf("%d-%d", portStart, portEnd)},
	})
	redirectWithFlash(w, r, "/admin/services", "Service created", "")
}

// ServicesUpdate edits an existing service (POST /admin/services/{id}/edit).
// Same fields + validation as create; node_group_id is recomputed from the
// (possibly changed) plan. backend_ip stays admin-only.
func (h *AdminHandlers) ServicesUpdate(w http.ResponseWriter, r *http.Request) {
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	_ = r.ParseForm()
	clientID, _ := strconv.ParseInt(r.FormValue("client_id"), 10, 64)
	planID, _ := strconv.ParseInt(r.FormValue("plan_id"), 10, 64)
	portStart, _ := strconv.Atoi(r.FormValue("port_start"))
	portEnd, _ := strconv.Atoi(r.FormValue("port_end"))
	name := strings.TrimSpace(r.FormValue("name"))
	backendIP := strings.TrimSpace(r.FormValue("backend_ip"))
	externalRef := strings.TrimSpace(r.FormValue("external_reference"))
	notes := strings.TrimSpace(r.FormValue("notes"))
	if len(notes) > 10000 {
		notes = notes[:10000]
	}

	if name == "" || backendIP == "" || clientID == 0 || planID == 0 {
		redirectWithFlash(w, r, "/admin/services", "", "all fields required")
		return
	}
	if ip := net.ParseIP(backendIP); ip == nil {
		redirectWithFlash(w, r, "/admin/services", "", "backend_ip is not a valid IP")
		return
	}
	if portStart < 1 || portEnd > 65535 || portStart > portEnd {
		redirectWithFlash(w, r, "/admin/services", "", "port range invalid (start<=end, 1..65535)")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5_000_000_000)
	defer cancel()

	// IDOR guard: must own both the existing service and the target client (no
	// moving a service into or out of another tenant's scope).
	sess := middleware.SessionFromContext(r.Context())
	if !h.scopeCheckService(ctx, sess, id) || !h.scopeCheckClient(ctx, sess, clientID) {
		redirectWithFlash(w, r, "/admin/services", "", "forbidden: outside your scope")
		return
	}
	if !h.planAccessible(ctx, sess, planID) {
		redirectWithFlash(w, r, "/admin/services", "", "forbidden: plan outside your scope")
		return
	}

	var nodeGroupID int64
	if err := db.QueryRowContext(ctx, "SELECT node_group_id FROM plans WHERE id = ?", planID).Scan(&nodeGroupID); err != nil {
		redirectWithFlash(w, r, "/admin/services", "", "plan not found")
		return
	}
	var extRef sql.NullString
	if externalRef != "" {
		extRef = sql.NullString{String: externalRef, Valid: true}
	}
	var notesVal sql.NullString
	if notes != "" {
		notesVal = sql.NullString{String: notes, Valid: true}
	}
	if _, err := db.ExecContext(ctx,
		`UPDATE services SET client_id = ?, name = ?, backend_ip = ?, allowed_port_start = ?,
		   allowed_port_end = ?, plan_id = ?, node_group_id = ?, external_reference = ?, notes = ? WHERE id = ?`,
		clientID, name, backendIP, portStart, portEnd, planID, nodeGroupID, extRef, notesVal, id); err != nil {
		h.Logger.Error("service update", "err", err)
		redirectWithFlash(w, r, "/admin/services", "", "update failed: "+sanitizeErr(err))
		return
	}
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(middleware.SessionFromContext(r.Context())),
		Action: "service.update", Entity: "service", EntityID: fmt.Sprintf("%d", id),
		Meta: map[string]any{"name": name, "client_id": clientID, "ports": fmt.Sprintf("%d-%d", portStart, portEnd)},
	})
	redirectWithFlash(w, r, "/admin/services", "Service updated", "")
}

func (h *AdminHandlers) ServicesDelete(w http.ResponseWriter, r *http.Request) {
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	ctx, cancel := context.WithTimeout(r.Context(), 5_000_000_000)
	defer cancel()
	if !h.scopeCheckService(ctx, middleware.SessionFromContext(r.Context()), id) {
		redirectWithFlash(w, r, "/admin/services", "", "forbidden")
		return
	}
	if _, err := db.ExecContext(ctx, "DELETE FROM services WHERE id = ?", id); err != nil {
		if strings.Contains(err.Error(), "foreign key") {
			redirectWithFlash(w, r, "/admin/services", "", "service has routes; delete routes first")
			return
		}
		redirectWithFlash(w, r, "/admin/services", "", "delete failed")
		return
	}
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(middleware.SessionFromContext(r.Context())),
		Action: "service.delete", Entity: "service", EntityID: fmt.Sprintf("%d", id),
	})
	redirectWithFlash(w, r, "/admin/services", "Service deleted", "")
}

// ServicesSuspend sets a service to 'suspended' and disables all active routes in a transaction.
func (h *AdminHandlers) ServicesSuspend(w http.ResponseWriter, r *http.Request) {
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if id == 0 {
		redirectWithFlash(w, r, "/admin/services", "", "invalid service id")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	if !h.scopeCheckService(ctx, middleware.SessionFromContext(r.Context()), id) {
		redirectWithFlash(w, r, "/admin/services", "", "forbidden")
		return
	}

	// Collect distinct caddy_node_ids for affected active routes before disabling.
	rows, err := db.QueryContext(ctx,
		"SELECT DISTINCT caddy_node_id FROM routes WHERE service_id = ? AND status = 'active' AND caddy_node_id IS NOT NULL", id)
	if err != nil {
		redirectWithFlash(w, r, "/admin/services", "", "query failed: "+sanitizeErr(err))
		return
	}
	var nodeIDs []int64
	for rows.Next() {
		var nid int64
		if rows.Scan(&nid) == nil {
			nodeIDs = append(nodeIDs, nid)
		}
	}
	rows.Close()

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		redirectWithFlash(w, r, "/admin/services", "", "tx begin failed")
		return
	}
	defer tx.Rollback() //nolint:errcheck

	res, err := tx.ExecContext(ctx,
		"UPDATE services SET status = 'suspended' WHERE id = ? AND status = 'active'", id)
	if err != nil {
		redirectWithFlash(w, r, "/admin/services", "", "update failed: "+sanitizeErr(err))
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		redirectWithFlash(w, r, "/admin/services", "", "service not found or already suspended")
		return
	}

	if _, err := tx.ExecContext(ctx,
		"UPDATE routes SET status = 'disabled' WHERE service_id = ? AND status IN ('active','dns_ok','pending_ssl')", id); err != nil {
		redirectWithFlash(w, r, "/admin/services", "", "route disable failed: "+sanitizeErr(err))
		return
	}

	if err := tx.Commit(); err != nil {
		redirectWithFlash(w, r, "/admin/services", "", "commit failed")
		return
	}

	// Push config to each affected node after commit.
	if h.Routes != nil {
		for _, nid := range nodeIDs {
			h.Routes.SchedulePush(nid)
		}
	}

	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(middleware.SessionFromContext(r.Context())),
		Action: "admin.service.suspend", Entity: "service", EntityID: fmt.Sprintf("%d", id),
	})
	redirectWithFlash(w, r, "/admin/services", "Service suspended", "")
}

// ServicesResume reactivates a suspended service and re-enables its disabled routes.
func (h *AdminHandlers) ServicesResume(w http.ResponseWriter, r *http.Request) {
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if id == 0 {
		redirectWithFlash(w, r, "/admin/services", "", "invalid service id")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	if !h.scopeCheckService(ctx, middleware.SessionFromContext(r.Context()), id) {
		redirectWithFlash(w, r, "/admin/services", "", "forbidden")
		return
	}

	// Collect distinct node IDs before updating so we know which nodes to push.
	rows, err := db.QueryContext(ctx,
		"SELECT DISTINCT caddy_node_id FROM routes WHERE service_id = ? AND caddy_node_id IS NOT NULL", id)
	if err != nil {
		redirectWithFlash(w, r, "/admin/services", "", "query failed: "+sanitizeErr(err))
		return
	}
	var nodeIDs []int64
	for rows.Next() {
		var nid int64
		if rows.Scan(&nid) == nil {
			nodeIDs = append(nodeIDs, nid)
		}
	}
	rows.Close()

	res, err := db.ExecContext(ctx,
		"UPDATE services SET status = 'active' WHERE id = ? AND status = 'suspended'", id)
	if err != nil {
		redirectWithFlash(w, r, "/admin/services", "", "update failed: "+sanitizeErr(err))
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		redirectWithFlash(w, r, "/admin/services", "", "service not found or not suspended")
		return
	}

	// Re-enable all disabled routes for this service (intentional: restore all).
	if _, err := db.ExecContext(ctx,
		"UPDATE routes SET status = 'active' WHERE service_id = ? AND status = 'disabled'", id); err != nil {
		redirectWithFlash(w, r, "/admin/services", "", "route enable failed: "+sanitizeErr(err))
		return
	}

	// Push config to each affected node.
	if h.Routes != nil {
		for _, nid := range nodeIDs {
			h.Routes.SchedulePush(nid)
		}
	}

	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(middleware.SessionFromContext(r.Context())),
		Action: "admin.service.resume", Entity: "service", EntityID: fmt.Sprintf("%d", id),
	})
	redirectWithFlash(w, r, "/admin/services", "Service resumed", "")
}

// ServicesBulk applies suspend/resume/delete to a list of service IDs.
func (h *AdminHandlers) ServicesBulk(w http.ResponseWriter, r *http.Request) {
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", 503)
		return
	}
	sess := middleware.SessionFromContext(r.Context())
	_ = r.ParseForm()
	action := r.FormValue("action")
	ids := r.Form["ids[]"]
	if len(ids) == 0 {
		redirectWithFlash(w, r, "/admin/services", "", "no services selected")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	var ok, fail int
	for _, rawID := range ids {
		svcID, err := strconv.ParseInt(strings.TrimSpace(rawID), 10, 64)
		if err != nil || svcID <= 0 {
			fail++
			continue
		}
		// IDOR guard: only act on services under the caller's own tenants.
		var svcClientID int64
		if e := db.QueryRowContext(ctx, "SELECT client_id FROM services WHERE id=?", svcID).Scan(&svcClientID); e != nil {
			fail++
			continue
		}
		if !h.scopeCheckClient(ctx, sess, svcClientID) {
			fail++
			continue
		}
		var execErr error
		switch action {
		case "suspend":
			_, execErr = db.ExecContext(ctx, "UPDATE services SET status=? WHERE id=?", "suspended", svcID)
		case "resume":
			_, execErr = db.ExecContext(ctx, "UPDATE services SET status=? WHERE id=? AND status=?", "active", svcID, "suspended")
		case "delete":
			_, execErr = db.ExecContext(ctx, "DELETE FROM services WHERE id=?", svcID)
		default:
			redirectWithFlash(w, r, "/admin/services", "", "unknown action")
			return
		}
		if execErr != nil {
			fail++
		} else {
			ok++
		}
	}
	msg := fmt.Sprintf("%s: %d done, %d failed", action, ok, fail)
	if fail > 0 {
		redirectWithFlash(w, r, "/admin/services", "", msg)
		return
	}
	redirectWithFlash(w, r, "/admin/services", msg, "")
}

// ---- Users (staff + clients view) --------------------------------------

type userRow struct {
	ID          int64
	FullName    string
	Email       string
	Role        string
	IsActive    bool
	TOTPEnabled bool
	LastLoginAt string
	CanToggle   bool
	CanDelete   bool
	ScopeCount  int
	ScopeIDs    string
}

type userScopeClientRow struct {
	ID          int64
	DisplayName string
	Email       string
}

type usersData struct {
	baseAdminData
	Users               []userRow
	ScopeClients        []userScopeClientRow
	Filter              string
	Q                   string
	CanCreateSuperAdmin bool
	CanManageScopes     bool
}

func (h *AdminHandlers) UsersList(w http.ResponseWriter, r *http.Request) {
	d := usersData{baseAdminData: h.base(r, "Users")}
	sess := middleware.SessionFromContext(r.Context())
	d.Filter = r.URL.Query().Get("role")
	d.Q = strings.TrimSpace(r.URL.Query().Get("q"))
	if sess != nil {
		d.CanCreateSuperAdmin = sess.Role == "super_admin"
		d.CanManageScopes = sess.Role == "super_admin"
	}
	db := h.DB()
	if db == nil {
		h.render(w, "users", d)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3_000_000_000)
	defer cancel()

	q := `SELECT id, COALESCE(full_name,''), email, role, is_active, totp_enabled,
	             COALESCE(DATE_FORMAT(last_login_at, '%Y-%m-%d %H:%i'), ''),
	             (SELECT COUNT(*) FROM admin_client_scope acs WHERE acs.admin_user_id = users.id),
	             COALESCE((SELECT GROUP_CONCAT(acs.client_id ORDER BY acs.client_id SEPARATOR ',') FROM admin_client_scope acs WHERE acs.admin_user_id = users.id), '')
	      FROM users`
	args := []any{}
	var conds []string
	if d.Filter != "" {
		conds = append(conds, "role = ?")
		args = append(args, d.Filter)
	}
	if d.Q != "" {
		conds = append(conds, "(email LIKE ? OR COALESCE(full_name,'') LIKE ?)")
		like := "%" + d.Q + "%"
		args = append(args, like, like)
	}
	if len(conds) > 0 {
		q += " WHERE " + strings.Join(conds, " AND ")
	}
	q += " ORDER BY id ASC"
	rows, err := db.QueryContext(ctx, q, args...)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var u userRow
			if err := rows.Scan(&u.ID, &u.FullName, &u.Email, &u.Role, &u.IsActive, &u.TOTPEnabled, &u.LastLoginAt, &u.ScopeCount, &u.ScopeIDs); err == nil {
				// Safety: a user can't disable/delete themselves; only super_admin
				// can act on another super_admin.
				canAct := true
				if sess != nil && sess.UserID == u.ID {
					canAct = false
				}
				if u.Role == "super_admin" && (sess == nil || sess.Role != "super_admin") {
					canAct = false
				}
				u.CanToggle = canAct
				u.CanDelete = canAct
				d.Users = append(d.Users, u)
			}
		}
	}
	if d.CanManageScopes {
		d.ScopeClients = h.loadScopeClientRows(ctx, db)
	}

	h.render(w, "users", d)
}

func (h *AdminHandlers) loadScopeClientRows(ctx context.Context, db *sql.DB) []userScopeClientRow {
	rows, err := db.QueryContext(ctx,
		`SELECT c.id, COALESCE(c.display_name, u.full_name, u.email), u.email
		 FROM clients c JOIN users u ON u.id = c.user_id
		 ORDER BY COALESCE(c.display_name, u.full_name, u.email) LIMIT 1000`)
	if err != nil {
		h.Logger.Warn("scope client list", "err", err)
		return nil
	}
	defer rows.Close()
	var out []userScopeClientRow
	for rows.Next() {
		var c userScopeClientRow
		if err := rows.Scan(&c.ID, &c.DisplayName, &c.Email); err == nil {
			out = append(out, c)
		}
	}
	return out
}

// UsersUpdate edits a panel user's name, email, role, and active flag in
// place. Password is rotated only when a non-blank value is supplied
// (blank keeps the current one). Enforces the same role-creation
// invariant as UsersCreate (only super_admin may grant/keep super_admin)
// and guards against self-demotion and demoting the last super_admin.
func (h *AdminHandlers) UsersUpdate(w http.ResponseWriter, r *http.Request) {
	sess := middleware.SessionFromContext(r.Context())
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	_ = r.ParseForm()
	fullName := strings.TrimSpace(r.FormValue("full_name"))
	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	role := r.FormValue("role")
	isActive := r.FormValue("is_active") == "1"

	if fullName == "" || email == "" {
		redirectWithFlash(w, r, "/admin/users", "", "name and email are required")
		return
	}
	switch role {
	case "support", "admin", "super_admin":
	default:
		redirectWithFlash(w, r, "/admin/users", "", "invalid role")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5_000_000_000)
	defer cancel()

	var curRole string
	var curActive bool
	if err := db.QueryRowContext(ctx, "SELECT role, is_active FROM users WHERE id = ?", id).Scan(&curRole, &curActive); err != nil {
		redirectWithFlash(w, r, "/admin/users", "", "user not found")
		return
	}
	// Editing client-role accounts belongs on the Clients page.
	if curRole == "client" {
		redirectWithFlash(w, r, "/admin/users", "", "edit clients from the Clients page")
		return
	}
	// Only super_admin can act on (or grant) super_admin.
	if (curRole == "super_admin" || role == "super_admin") && (sess == nil || sess.Role != "super_admin") {
		redirectWithFlash(w, r, "/admin/users", "", "only super_admin can manage super_admin")
		return
	}
	// Self-guard: don't let an admin demote or deactivate their own account
	// and lock themselves out of the panel.
	if sess != nil && sess.UserID == id {
		if role != curRole {
			redirectWithFlash(w, r, "/admin/users", "", "cannot change your own role")
			return
		}
		if !isActive {
			redirectWithFlash(w, r, "/admin/users", "", "cannot deactivate your own account")
			return
		}
	}
	// Last-super_admin guard: don't demote or deactivate the final active one.
	if curRole == "super_admin" && (role != "super_admin" || !isActive) {
		var n int
		_ = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM users WHERE role='super_admin' AND is_active=1").Scan(&n)
		if n <= 1 {
			redirectWithFlash(w, r, "/admin/users", "", "cannot demote or deactivate the last active super_admin")
			return
		}
	}

	// Optional password rotation on edit: hash + persist only when a value is
	// typed (blank = keep current). Matches the >= 12 rule used on create.
	newPass := strings.TrimSpace(r.FormValue("password"))
	if newPass != "" && len(newPass) < 12 {
		redirectWithFlash(w, r, "/admin/users", "", "new password must be >= 12 chars")
		return
	}
	var execErr error
	if newPass != "" {
		hash, herr := auth.HashPassword(newPass)
		if herr != nil {
			redirectWithFlash(w, r, "/admin/users", "", "hash failed")
			return
		}
		_, execErr = db.ExecContext(ctx,
			"UPDATE users SET full_name = ?, email = ?, role = ?, is_active = ?, password_hash = ?, password_set = 1 WHERE id = ?",
			fullName, email, role, isActive, hash, id)
	} else {
		_, execErr = db.ExecContext(ctx,
			"UPDATE users SET full_name = ?, email = ?, role = ?, is_active = ? WHERE id = ?",
			fullName, email, role, isActive, id)
	}
	if execErr != nil {
		if strings.Contains(execErr.Error(), "Duplicate entry") {
			redirectWithFlash(w, r, "/admin/users", "", "email already exists")
			return
		}
		h.Logger.Error("user update", "err", execErr)
		redirectWithFlash(w, r, "/admin/users", "", "update failed")
		return
	}
	// A demotion, deactivation, or password rotation must not survive in an
	// already-open session: the cookie auth path reads role/is_active from the
	// cached session and never re-checks the DB (only the API path does), so
	// kill the target's live sessions like the password-reset flow does.
	var killed int
	if h.Sessions != nil && (role != curRole || !isActive || newPass != "") {
		killed, _ = h.Sessions.DestroyAllForUser(ctx, id)
	}
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "user.update", Entity: "user",
		EntityID: fmt.Sprintf("%d", id),
		Meta:     map[string]any{"email": email, "role": role, "is_active": isActive, "sessions_killed": killed},
	})
	redirectWithFlash(w, r, "/admin/users", "User updated", "")
}

func (h *AdminHandlers) UsersCreate(w http.ResponseWriter, r *http.Request) {
	sess := middleware.SessionFromContext(r.Context())
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	_ = r.ParseForm()
	fullName := strings.TrimSpace(r.FormValue("full_name"))
	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	password := r.FormValue("password")
	role := r.FormValue("role")

	switch role {
	case "support", "admin":
	case "super_admin":
		if sess == nil || sess.Role != "super_admin" {
			redirectWithFlash(w, r, "/admin/users", "", "only super_admin can create super_admin")
			return
		}
	default:
		redirectWithFlash(w, r, "/admin/users", "", "invalid role")
		return
	}
	if fullName == "" || email == "" || len(password) < 12 {
		redirectWithFlash(w, r, "/admin/users", "", "all fields required, password >= 12 chars")
		return
	}

	hash, err := auth.HashPassword(password)
	if err != nil {
		redirectWithFlash(w, r, "/admin/users", "", "hash failed")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5_000_000_000)
	defer cancel()
	res, err := db.ExecContext(ctx,
		"INSERT INTO users (email, password_hash, password_set, role, full_name, is_active) VALUES (?, ?, 1, ?, ?, 1)",
		email, hash, role, fullName)
	if err != nil {
		if strings.Contains(err.Error(), "Duplicate entry") {
			redirectWithFlash(w, r, "/admin/users", "", "email already exists")
			return
		}
		h.Logger.Error("user create", "err", err)
		redirectWithFlash(w, r, "/admin/users", "", "insert failed")
		return
	}
	id, _ := res.LastInsertId()
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "user.create", Entity: "user",
		EntityID: fmt.Sprintf("%d", id),
		Meta:     map[string]any{"email": email, "role": role},
	})
	redirectWithFlash(w, r, "/admin/users", "User created", "")
}

func (h *AdminHandlers) UsersScopeUpdate(w http.ResponseWriter, r *http.Request) {
	sess := middleware.SessionFromContext(r.Context())
	if sess == nil || sess.Role != "super_admin" {
		http.Error(w, "super_admin role required", http.StatusForbidden)
		return
	}
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	_ = r.ParseForm()

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	var role string
	var email string
	if err := db.QueryRowContext(ctx, "SELECT role, email FROM users WHERE id = ?", id).Scan(&role, &email); err != nil {
		redirectWithFlash(w, r, "/admin/users", "", "user not found")
		return
	}
	if role == "super_admin" || role == "client" {
		redirectWithFlash(w, r, "/admin/users", "", "scope applies only to admin/support users")
		return
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		redirectWithFlash(w, r, "/admin/users", "", "tx begin failed")
		return
	}
	defer tx.Rollback() //nolint:errcheck

	if _, err := tx.ExecContext(ctx, "DELETE FROM admin_client_scope WHERE admin_user_id = ?", id); err != nil {
		redirectWithFlash(w, r, "/admin/users", "", "scope reset failed")
		return
	}
	seen := map[int64]bool{}
	for _, raw := range r.Form["client_ids"] {
		clientID, _ := strconv.ParseInt(raw, 10, 64)
		if clientID <= 0 || seen[clientID] {
			continue
		}
		seen[clientID] = true
		if _, err := tx.ExecContext(ctx,
			"INSERT INTO admin_client_scope (admin_user_id, client_id) VALUES (?, ?)",
			id, clientID); err != nil {
			redirectWithFlash(w, r, "/admin/users", "", "scope save failed")
			return
		}
	}
	if err := tx.Commit(); err != nil {
		redirectWithFlash(w, r, "/admin/users", "", "scope commit failed")
		return
	}
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "user.scope.update", Entity: "user",
		EntityID: strconv.FormatInt(id, 10),
		Meta:     map[string]any{"email": email, "client_count": len(seen)},
	})
	redirectWithFlash(w, r, "/admin/users", "Access scope updated", "")
}

func (h *AdminHandlers) UsersToggle(w http.ResponseWriter, r *http.Request) {
	sess := middleware.SessionFromContext(r.Context())
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if sess != nil && sess.UserID == id {
		redirectWithFlash(w, r, "/admin/users", "", "cannot toggle your own account")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5_000_000_000)
	defer cancel()

	var role string
	if err := db.QueryRowContext(ctx, "SELECT role FROM users WHERE id = ?", id).Scan(&role); err != nil {
		redirectWithFlash(w, r, "/admin/users", "", "user not found")
		return
	}
	if role == "super_admin" && (sess == nil || sess.Role != "super_admin") {
		redirectWithFlash(w, r, "/admin/users", "", "only super_admin can act on super_admin")
		return
	}
	if _, err := db.ExecContext(ctx, "UPDATE users SET is_active = NOT is_active WHERE id = ?", id); err != nil {
		redirectWithFlash(w, r, "/admin/users", "", "update failed")
		return
	}
	// A just-deactivated user must lose access now, not at session TTL (the
	// cookie path doesn't re-check is_active). Harmless when re-activating.
	var killed int
	if h.Sessions != nil {
		killed, _ = h.Sessions.DestroyAllForUser(ctx, id)
	}
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "user.toggle", Entity: "user",
		EntityID: fmt.Sprintf("%d", id),
		Meta:     map[string]any{"sessions_killed": killed},
	})
	redirectWithFlash(w, r, "/admin/users", "User toggled", "")
}

func (h *AdminHandlers) UsersDelete(w http.ResponseWriter, r *http.Request) {
	sess := middleware.SessionFromContext(r.Context())
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if sess != nil && sess.UserID == id {
		redirectWithFlash(w, r, "/admin/users", "", "cannot delete your own account")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5_000_000_000)
	defer cancel()

	var role, email string
	if err := db.QueryRowContext(ctx, "SELECT role, email FROM users WHERE id = ?", id).Scan(&role, &email); err != nil {
		redirectWithFlash(w, r, "/admin/users", "", "user not found")
		return
	}
	if role == "super_admin" && (sess == nil || sess.Role != "super_admin") {
		redirectWithFlash(w, r, "/admin/users", "", "only super_admin can delete super_admin")
		return
	}
	// Guard: last super_admin cannot be deleted.
	if role == "super_admin" {
		var n int
		_ = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM users WHERE role='super_admin' AND is_active=1").Scan(&n)
		if n <= 1 {
			redirectWithFlash(w, r, "/admin/users", "", "cannot delete the last active super_admin")
			return
		}
	}
	if _, err := db.ExecContext(ctx, "DELETE FROM users WHERE id = ?", id); err != nil {
		if strings.Contains(err.Error(), "foreign key") {
			redirectWithFlash(w, r, "/admin/users", "", "user owns data; remove dependents first")
			return
		}
		redirectWithFlash(w, r, "/admin/users", "", "delete failed")
		return
	}
	// Kill live sessions: role is read from cached Redis session, not DB,
	// so a deleted user keeps panel access until TTL otherwise.
	var killed int
	if h.Sessions != nil {
		killed, _ = h.Sessions.DestroyAllForUser(ctx, id)
	}
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "user.delete", Entity: "user",
		EntityID: fmt.Sprintf("%d", id), Meta: map[string]any{"email": email, "role": role, "sessions_killed": killed},
	})
	redirectWithFlash(w, r, "/admin/users", "User deleted", "")
}

// UsersReset2FA clears all 2FA methods (TOTP + SMS + email OTP) for a user.
// Restricted to super_admin so a compromised admin account can't self-escalate
// by resetting a super_admin's second factor.
func (h *AdminHandlers) UsersReset2FA(w http.ResponseWriter, r *http.Request) {
	sess := middleware.SessionFromContext(r.Context())
	if sess == nil || sess.Role != "super_admin" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if sess.UserID == id {
		redirectWithFlash(w, r, "/admin/users", "", "use /admin/2fa to manage your own 2FA")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	var email string
	if err := db.QueryRowContext(ctx, "SELECT email FROM users WHERE id = ?", id).Scan(&email); err != nil {
		redirectWithFlash(w, r, "/admin/users", "", "user not found")
		return
	}
	if _, err := db.ExecContext(ctx,
		`UPDATE users SET totp_secret = NULL, totp_secret_enc = NULL, totp_enabled = 0,
		                  sms_otp_enabled = 0, email_otp_enabled = 0
		 WHERE id = ?`, id); err != nil {
		redirectWithFlash(w, r, "/admin/users", "", "reset failed")
		return
	}
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "user.reset_2fa", Entity: "user",
		EntityID: fmt.Sprintf("%d", id), Meta: map[string]any{"email": email},
	})
	redirectWithFlash(w, r, "/admin/users", "2FA reset for "+email, "")
}

// UsersImpersonate switches the current admin session into the target
// user's identity while remembering the admin's id/email for /auth/end-
// impersonation. Only super_admin → role=client is allowed; admin →
// admin is intentionally refused (no chained impersonation).
func (h *AdminHandlers) UsersImpersonate(w http.ResponseWriter, r *http.Request) {
	sess := middleware.SessionFromContext(r.Context())
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	if sess == nil || sess.Role != "super_admin" || sess.IsImpersonating() {
		redirectWithFlash(w, r, "/admin/users", "", "only super_admin can impersonate")
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if id == 0 || id == sess.UserID {
		redirectWithFlash(w, r, "/admin/users", "", "invalid impersonation target")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	var (
		email  string
		role   string
		active bool
	)
	if err := db.QueryRowContext(ctx,
		"SELECT email, role, is_active FROM users WHERE id = ?", id,
	).Scan(&email, &role, &active); err != nil {
		redirectWithFlash(w, r, "/admin/users", "", "user not found")
		return
	}
	if !active {
		redirectWithFlash(w, r, "/admin/users", "", "cannot impersonate a deactivated user")
		return
	}
	if role != "client" {
		redirectWithFlash(w, r, "/admin/users", "", "only client accounts may be impersonated")
		return
	}
	var clientID int64
	_ = db.QueryRowContext(ctx, "SELECT id FROM clients WHERE user_id = ?", id).Scan(&clientID)

	adminID := sess.UserID
	adminEmail := sess.Email
	h.Sessions.Destroy(ctx, w, r)
	// resellerID=0: the impersonated identity is a client, never a reseller-admin.
	if _, err := h.Sessions.CreateImpersonated(ctx, w, id, email, role, clientID, 0, adminID, adminEmail); err != nil {
		h.Logger.Error("impersonate: session create", "err", err)
		http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
		return
	}
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: &adminID, Action: "admin.impersonate.start", Entity: "user",
		EntityID: fmt.Sprintf("%d", id),
		Meta:     map[string]any{"impersonated_email": email},
	})
	http.Redirect(w, r, "/app", http.StatusSeeOther)
}

// ---- Audit log ---------------------------------------------------------

type auditRow struct {
	CreatedAt  string
	ActorLabel string
	Action     string
	Entity     string
	EntityID   string
	IP         string
}

type auditData struct {
	baseAdminData
	Entries    []auditRow
	Filter     string // entity
	ActionLike string
	ActorLike  string
	Since      string // YYYY-MM-DD
	Limit      int
	// Pagination/sort/search fields added for server-side control.
	Page         int
	Size         int
	Total        int
	TotalPgs     int
	Sort         string
	Dir          string
	Q            string
	PrevURL      string
	NextURL      string
	QueryValues  string // JSON-encoded current query for saved filters
	SavedFilters []savedFilter
}

func (h *AdminHandlers) AuditList(w http.ResponseWriter, r *http.Request) {
	if h.maybeApplySavedFilter(w, r, "audit") {
		return
	}
	q := r.URL.Query()

	lp := parseListParams(r, []string{"id", "created_at", "actor", "action", "entity"},
		"id", "desc", 50)

	d := auditData{
		baseAdminData: h.base(r, "Audit log"),
		Filter:        strings.TrimSpace(q.Get("entity")),
		ActionLike:    strings.TrimSpace(q.Get("action")),
		ActorLike:     strings.TrimSpace(q.Get("actor")),
		Since:         strings.TrimSpace(q.Get("since")),
		Limit:         lp.Size,
		Page:          lp.Page,
		Size:          lp.Size,
		Sort:          lp.Sort,
		Dir:           lp.Dir,
		Q:             lp.Q,
	}
	db := h.DB()
	if db == nil {
		h.render(w, "audit", d)
		return
	}
	sess := middleware.SessionFromContext(r.Context())
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	where := []string{"1=1"}
	args := []any{}
	if d.Filter != "" {
		where = append(where, "a.entity = ?")
		args = append(args, d.Filter)
	}
	if d.ActionLike != "" {
		where = append(where, "a.action LIKE ?")
		args = append(args, "%"+d.ActionLike+"%")
	}
	if d.ActorLike != "" {
		where = append(where, "(u.email LIKE ? OR a.actor_type = ?)")
		args = append(args, "%"+d.ActorLike+"%", d.ActorLike)
	}
	if d.Since != "" {
		where = append(where, "a.created_at >= ?")
		args = append(args, d.Since)
	}
	if d.Q != "" {
		where = append(where, `(a.action LIKE ? ESCAPE '\\' OR a.entity LIKE ? ESCAPE '\\' OR u.email LIKE ? ESCAPE '\\')`)
		like := likeContains(d.Q)
		args = append(args, like, like, like)
	}

	// Validate sort column; map friendly names to SQL expressions.
	orderCol := auditSortCol(lp.Sort)
	dir := lp.Dir
	if dir != "asc" {
		dir = "desc"
	}

	baseFrom := `FROM audit_log a LEFT JOIN users u ON u.id = a.user_id WHERE ` + strings.Join(where, " AND ")

	var total int
	countArgs := make([]any, len(args))
	copy(countArgs, args)
	if cerr := db.QueryRowContext(ctx, "SELECT COUNT(*) "+baseFrom, countArgs...).Scan(&total); cerr != nil {
		h.Logger.Warn("audit count query", "err", cerr)
	}

	sqlStr := `SELECT DATE_FORMAT(a.created_at, '%Y-%m-%dT%H:%i:%sZ'),
	                  COALESCE(u.email, a.actor_type) AS actor,
	                  a.action, a.entity, COALESCE(a.entity_id, ''), COALESCE(a.ip, '')
	           ` + baseFrom + ` ORDER BY ` + orderCol + ` ` + dir + ` LIMIT ? OFFSET ?`
	args = append(args, lp.Size, lp.Offset())

	rows, err := db.QueryContext(ctx, sqlStr, args...)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var a auditRow
			if err := rows.Scan(&a.CreatedAt, &a.ActorLabel, &a.Action, &a.Entity, &a.EntityID, &a.IP); err == nil {
				d.Entries = append(d.Entries, a)
			}
		}
	}

	// If count failed but entries loaded, use loaded count as lower bound
	// so pagination controls render correctly.
	if total == 0 && len(d.Entries) > 0 {
		total = lp.Offset() + len(d.Entries)
	}
	d.Total = total
	d.TotalPgs = (total + lp.Size - 1) / lp.Size
	if d.TotalPgs < 1 {
		d.TotalPgs = 1
	}
	if lp.Page > 1 {
		d.PrevURL = buildPageURL(q, lp.Page-1)
	}
	if lp.Page < d.TotalPgs {
		d.NextURL = buildPageURL(q, lp.Page+1)
	}

	// Build query_json for save-filter form (only the filter fields, not page).
	d.QueryValues = auditQueryJSON(d.Filter, d.ActionLike, d.ActorLike, d.Since, d.Q, d.Sort, d.Dir)

	if sess != nil {
		d.SavedFilters = h.savedFiltersForView(ctx, sess.UserID, "audit")
	}

	h.render(w, "audit", d)
}

// AuditClear handles POST /admin/audit/clear. Purges the entire audit log.
// Restricted to super_admin; CSRF enforced by middleware.
func (h *AdminHandlers) AuditClear(w http.ResponseWriter, r *http.Request) {
	sess := middleware.SessionFromContext(r.Context())
	if sess == nil || sess.Role != "super_admin" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	db := h.DB()
	if db == nil {
		redirectWithFlash(w, r, "/admin/audit", "", "database unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	n, err := audit.ClearAll(ctx, db, r, audit.Entry{
		UserID: actorUserID(sess),
		Action: "audit.cleared", Entity: "audit_log",
	})
	if err != nil {
		h.Logger.Error("audit clear", "err", err)
		redirectWithFlash(w, r, "/admin/audit", "", "clear failed")
		return
	}
	redirectWithFlash(w, r, "/admin/audit", fmt.Sprintf("Cleared %d audit entries", n), "")
}

// auditSortCol maps a friendly sort key to a safe SQL expression.
func auditSortCol(s string) string {
	switch s {
	case "created_at":
		return "a.created_at"
	case "actor":
		return "actor"
	case "action":
		return "a.action"
	case "entity":
		return "a.entity"
	default:
		return "a.id"
	}
}

// auditQueryJSON encodes audit filter state as a JSON string for saved filters.
func auditQueryJSON(entity, action, actor, since, q, sort, dir string) string {
	m := map[string]string{
		"entity": entity, "action": action, "actor": actor,
		"since": since, "q": q, "sort": sort, "dir": dir,
	}
	b, _ := json.Marshal(m)
	return string(b)
}

// ---- Settings ----------------------------------------------------------

type smtpView struct {
	Host        string
	Port        int
	Encryption  string
	Username    string
	FromEmail   string
	FromName    string
	HasPassword bool
}

type acmeView struct {
	Email      string
	Staging    bool
	CaURL      string // "" or "letsencrypt" or "zerossl" or custom URL
	EabKID     string
	HasEABKey  bool // true when an encrypted EAB HMAC is stored
}

type geoipView struct {
	// AccountID is shown back (not a secret on its own); license key is write-only.
	AccountID   string
	Configured  bool   // both creds present
	SHA256      string // current DB sha256 ("" if never downloaded)
	SHA256Short string // first 16 chars of SHA256 for display
	SizeBytes   int64
	SizeHuman   string // human-readable size (KB/MB)
	FetchedAt   string // RFC3339 or "" if never
	LastError   string // last refresh failure ("" if last attempt ok / none)
	LastAttempt string // RFC3339 of last attempt or ""
	Available   bool   // mmdb loaded in memory right now
}

type oidcView struct {
	Enabled               bool
	ProviderName          string
	Issuer                string
	ClientID              string
	HasSecret             bool
	RedirectURL           string
	DefaultRedirect       string // computed from AppURL; placeholder for empty form
	DefaultRole           string
	AutoProvision         bool
	Scopes                string
	PasswordLoginDisabled bool
	AllowUnverifiedEmail  bool
}

// oauthProviderView drives one social-login (GitHub/Google) config form.
type oauthProviderView struct {
	Provider        string // slug: "github" | "google"
	Label           string // display name
	Enabled         bool
	ClientID        string
	HasSecret       bool
	Scopes          string
	AutoProvision   bool
	DefaultRole     string
	DefaultRedirect string // computed callback URL to whitelist on the provider
}

type turnstileView struct {
	Enabled   bool
	Provider  string // "turnstile" | "hcaptcha" | "recaptcha" | "" (none)
	SiteKey   string
	HasSecret bool
}

type cloudflareView struct {
	Enabled           bool
	AccountID         string
	HasToken          bool
	TrustConnectingIP bool
}

type wireguardView struct {
	Enabled    bool
	Endpoint   string
	ListenPort int
	Subnet     string
	ControlIP  string
	PublicKey  string
	HasPrivate bool
}

type settingsData struct {
	baseAdminData
	AppURL          string
	SMTP            smtpView
	ACME            acmeView
	GeoIP           geoipView
	OIDC            oidcView
	OAuthProviders  []oauthProviderView // social-login (GitHub, Google)
	Turnstile       turnstileView
	Cloudflare      cloudflareView
	WireGuard       wireguardView
	SMS             SMSConfigView
	SMSOTPAvailable bool
	CustomerFields  CustomerFieldsView
	SSOJump         ssoJumpSettingsView
	APIDocsPublic   bool
	// Require2FA = runtime DB toggle; Require2FAEnvForced = env override on
	// (toggle is then locked-on in the UI).
	Require2FA          bool
	Require2FAEnvForced bool
	// Branding fields for the Settings "Branding" tab. The tab's form still
	// POSTs to the existing /admin/branding route (BrandingSave).
	Branding Branding
	// AI backs the "AI assistant" tab (provider keys + default selector).
	AI aiView
	// MTLSFailOpen mirrors the mtls.fail_open setting for the mTLS tab.
	MTLSFailOpen bool
	// RollupRetentionDays controls log_rollups pruning; 0 = keep forever.
	RollupRetentionDays int
	// AutoFailoverEnabled mirrors the failover.auto_enabled DB setting.
	AutoFailoverEnabled bool
	// Alert threshold overrides (DB-backed, shown in the Alerts settings tab).
	AlertNodeOfflineMin     int
	AlertCertStuckMin       int
	AlertCooldownSec        int
	AlertManualCertDaysWarn int
	AlertErrorRatePct       float64
	AlertErrorRateWindowMin int
	// Banner tab fields.
	SystemBannerText      string
	SystemBannerType      string
	SystemBannerLink      string
	SystemBannerLinkLabel string
	// Self-registration settings tab.
	AllowSelfRegistration bool
	DefaultPlanID         string
	// Instances tab: registered slave HPG instances.
	Slaves     []SyncSlaveView
	IsSlaveMode bool
}

func (h *AdminHandlers) SettingsPage(w http.ResponseWriter, r *http.Request) {
	d := settingsData{baseAdminData: h.base(r, "Settings")}
	if h.State != nil {
		st := h.State.Get()
		if st.App != nil {
			d.AppURL = st.App.URL
		}
	}

	db := h.DB()
	if db != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 3_000_000_000)
		defer cancel()
		kv := h.loadSettings(ctx, db, []string{
			"smtp.host", "smtp.port", "smtp.encryption", "smtp.username",
			"smtp.from_email", "smtp.from_name", "smtp.password",
			"acme.email", "acme.staging", "acme.ca_url", "acme.eab_kid", "acme.eab_hmac",
			"oidc.enabled", "oidc.provider_name", "oidc.issuer", "oidc.client_id",
			"oidc.client_secret", "oidc.redirect_url", "oidc.default_role", "oidc.auto_provision",
			"oidc.password_login_disabled", "oidc.scopes",
			"oidc.allow_unverified_email",
			"captcha.provider", "captcha.site_key", "captcha.secret",
			"cloudflare.enabled", "cloudflare.account_id", "cloudflare.api_token", "cloudflare.trust_connecting_ip",
			"sms_otp_available",
			"apidocs.public_enabled",
			"security.require_admin_2fa",
			"analytics.rollup_retention_days",
			"failover.auto_enabled",
			"system.banner_text",
			"system.banner_type",
			"system.banner_link",
			"system.banner_link_label",
			"auth.allow_self_registration",
			"auth.default_plan_id",
		})
		d.OIDC = oidcView{
			Enabled: kv["oidc.enabled"] == "1", ProviderName: defaultStr(kv["oidc.provider_name"], "Authentik"),
			Issuer: kv["oidc.issuer"], ClientID: kv["oidc.client_id"],
			HasSecret:   kv["oidc.client_secret"] != "",
			RedirectURL: kv["oidc.redirect_url"],
			// Computed default - surfaces in the placeholder so admin can
			// copy-paste into the IdP redirect URIs field without guessing.
			DefaultRedirect:       strings.TrimRight(d.AppURL, "/") + "/auth/oidc/callback",
			DefaultRole:           defaultStr(kv["oidc.default_role"], "support"),
			AutoProvision:         kv["oidc.auto_provision"] == "1",
			Scopes:                defaultStr(kv["oidc.scopes"], "openid email profile"),
			PasswordLoginDisabled: kv["oidc.password_login_disabled"] == "1",
			AllowUnverifiedEmail:  kv["oidc.allow_unverified_email"] == "1",
		}
		d.OAuthProviders = h.loadOAuthProviderViews(ctx, db, d.AppURL)
		d.SMSOTPAvailable = kv["sms_otp_available"] == "1"
		d.APIDocsPublic = kv["apidocs.public_enabled"] != "0"
		d.Require2FAEnvForced = h.Enforce2FAEnv
		d.Require2FA = d.Require2FAEnvForced || kv["security.require_admin_2fa"] == "1"
		d.Turnstile = turnstileView{
			Provider: kv["captcha.provider"],
			Enabled:  kv["captcha.provider"] != "",
			SiteKey:  kv["captcha.site_key"], HasSecret: kv["captcha.secret"] != "",
		}
		d.Cloudflare = cloudflareView{
			Enabled:   kv["cloudflare.enabled"] == "1",
			AccountID: kv["cloudflare.account_id"], HasToken: kv["cloudflare.api_token"] != "",
			TrustConnectingIP: kv["cloudflare.trust_connecting_ip"] == "1",
		}
		wgKV := h.loadSettings(ctx, db, []string{
			"wireguard.enabled", "wireguard.endpoint", "wireguard.listen_port",
			"wireguard.subnet", "wireguard.control_ip",
			"wireguard.public_key", "wireguard.private_key",
		})
		port := atoiOr(wgKV["wireguard.listen_port"], 51820)
		d.WireGuard = wireguardView{
			Enabled:    wgKV["wireguard.enabled"] == "1",
			Endpoint:   wgKV["wireguard.endpoint"],
			ListenPort: port,
			Subnet:     defaultStr(wgKV["wireguard.subnet"], "10.66.0.0/24"),
			ControlIP:  defaultStr(wgKV["wireguard.control_ip"], "10.66.0.1"),
			PublicKey:  wgKV["wireguard.public_key"],
			HasPrivate: wgKV["wireguard.private_key"] != "",
		}
		d.SMTP = smtpView{
			Host:        kv["smtp.host"],
			Port:        atoiOr(kv["smtp.port"], 587),
			Encryption:  defaultStr(kv["smtp.encryption"], "tls"),
			Username:    kv["smtp.username"],
			FromEmail:   kv["smtp.from_email"],
			FromName:    defaultStr(kv["smtp.from_name"], "Hostyt Proxy"),
			HasPassword: kv["smtp.password"] != "",
		}
		d.ACME = acmeView{
			Email:     kv["acme.email"],
			Staging:   kv["acme.staging"] == "1",
			CaURL:     kv["acme.ca_url"],
			EabKID:    kv["acme.eab_kid"],
			HasEABKey: kv["acme.eab_hmac"] != "",
		}
		d.GeoIP = h.loadGeoIPView(ctx, db)
		// Fall back to wizard state / env if settings rows missing.
		if d.SMTP.Host == "" && h.State != nil {
			if st := h.State.Get(); st.SMTP != nil {
				d.SMTP = smtpView{
					Host: st.SMTP.Host, Port: st.SMTP.Port, Encryption: st.SMTP.Encryption,
					Username: st.SMTP.Username, FromEmail: st.SMTP.FromEmail,
					FromName: st.SMTP.FromName, HasPassword: st.SMTP.PasswordCipher != "",
				}
			}
		}
		d.SMS = h.LoadSMSConfigView(ctx)
		d.CustomerFields = h.LoadCustomerFieldsView(ctx)
		d.AI = h.loadAIView(ctx)
		mtlsKV := h.loadSettings(ctx, db, []string{"mtls.fail_open"})
		d.MTLSFailOpen = mtlsKV["mtls.fail_open"] == "1"
		if v := kv["analytics.rollup_retention_days"]; v != "" {
			d.RollupRetentionDays, _ = strconv.Atoi(v)
		}
		// DB value takes precedence; empty = not yet saved, fall back to false.
		if v := kv["failover.auto_enabled"]; v != "" {
			d.AutoFailoverEnabled = v == "1"
		}
		// Load alert threshold overrides; fall back to env-loaded defaults when absent.
		alertCfg := h.AlertCfg
		alertKV := h.loadSettings(ctx, db, []string{
			"alert.node_offline_minutes", "alert.cert_stuck_minutes",
			"alert.cooldown_seconds", "alert.manual_cert_days_warn",
			"alert.error_rate_pct", "alert.error_rate_window_minutes",
		})
		d.AlertNodeOfflineMin = atoiOr(alertKV["alert.node_offline_minutes"], alertCfg.NodeOfflineMinutes)
		d.AlertCertStuckMin = atoiOr(alertKV["alert.cert_stuck_minutes"], alertCfg.CertStuckMinutes)
		d.AlertCooldownSec = atoiOr(alertKV["alert.cooldown_seconds"], alertCfg.CooldownSeconds)
		d.AlertManualCertDaysWarn = atoiOr(alertKV["alert.manual_cert_days_warn"], alertCfg.ManualCertDaysWarn)
		if v := alertKV["alert.error_rate_pct"]; v != "" {
			if f, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil && f > 0 {
				d.AlertErrorRatePct = f
			}
		}
		if d.AlertErrorRatePct == 0 {
			d.AlertErrorRatePct = alertCfg.ErrorRatePct
		}
		d.AlertErrorRateWindowMin = atoiOr(alertKV["alert.error_rate_window_minutes"], alertCfg.ErrorRateWindowMinutes)
		d.SystemBannerText = kv["system.banner_text"]
		d.SystemBannerType = defaultStr(kv["system.banner_type"], "info")
		d.SystemBannerLink = kv["system.banner_link"]
		d.SystemBannerLinkLabel = kv["system.banner_link_label"]
		d.AllowSelfRegistration = kv["auth.allow_self_registration"] == "1"
		d.DefaultPlanID = kv["auth.default_plan_id"]
		d.Slaves = h.loadSyncSlaves(ctx)
	}
	d.IsSlaveMode = h.SlaveMode
	d.SSOJump = h.loadSSOJumpSettingsView(r, d.AppURL)
	// Branding tab: pre-fill from the shared cached loader (same source as
	// BrandingPage). Form still POSTs to /admin/branding.
	d.Branding = LoadBranding(r.Context(), db)
	h.render(w, "settings", d)
}

func (h *AdminHandlers) SettingsSMTP(w http.ResponseWriter, r *http.Request) {
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	_ = r.ParseForm()
	host := strings.TrimSpace(r.FormValue("host"))
	port := atoiOr(r.FormValue("port"), 587)
	encryption := r.FormValue("encryption")
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	fromEmail := strings.TrimSpace(r.FormValue("from_email"))
	fromName := strings.TrimSpace(r.FormValue("from_name"))
	action := r.FormValue("action")

	if action == "test" {
		if h.Mailer == nil {
			redirectWithFlash(w, r, "/admin/settings", "", "Mailer not initialized")
			return
		}
		sess := middleware.SessionFromContext(r.Context())
		to := ""
		if sess != nil {
			to = sess.Email
		}
		if to == "" {
			to = fromEmail
		}
		if to == "" {
			redirectWithFlash(w, r, "/admin/settings", "", "Set From email first")
			return
		}
		// Save current values BEFORE sending so loader picks them up.
		ctx2, cancel2 := context.WithTimeout(r.Context(), 5_000_000_000)
		defer cancel2()
		_ = h.saveSettings(ctx2, db, map[string]string{
			"smtp.host":       host,
			"smtp.port":       strconv.Itoa(port),
			"smtp.encryption": encryption,
			"smtp.username":   username,
			"smtp.from_email": fromEmail,
			"smtp.from_name":  fromName,
		}, false)
		if password != "" {
			if c, err := h.encryptSetting(password); err == nil {
				_ = h.saveSettings(ctx2, db, map[string]string{"smtp.password": c}, true)
			}
		}
		if err := h.Mailer.SendTest(ctx2, to); err != nil {
			redirectWithFlash(w, r, "/admin/settings", "", "Test failed: "+sanitizeErr(err))
			return
		}
		redirectWithFlash(w, r, "/admin/settings", "Test email sent to "+to, "")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5_000_000_000)
	defer cancel()
	pairs := map[string]string{
		"smtp.host":       host,
		"smtp.port":       strconv.Itoa(port),
		"smtp.encryption": encryption,
		"smtp.username":   username,
		"smtp.from_email": fromEmail,
		"smtp.from_name":  fromName,
	}
	if err := h.saveSettings(ctx, db, pairs, false); err != nil {
		redirectWithFlash(w, r, "/admin/settings", "", "save failed: "+sanitizeErr(err))
		return
	}
	if password != "" {
		ct, err := h.encryptSetting(password)
		if err != nil {
			redirectWithFlash(w, r, "/admin/settings", "", "encrypt failed")
			return
		}
		if err := h.saveSettings(ctx, db, map[string]string{"smtp.password": ct}, true); err != nil {
			redirectWithFlash(w, r, "/admin/settings", "", "password save failed")
			return
		}
	}
	sess := middleware.SessionFromContext(r.Context())
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "settings.smtp.save", Entity: "settings",
		EntityID: "smtp",
	})
	redirectWithFlash(w, r, "/admin/settings", "SMTP saved", "")
}

func (h *AdminHandlers) SettingsACME(w http.ResponseWriter, r *http.Request) {
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	_ = r.ParseForm()
	email := strings.TrimSpace(r.FormValue("email"))
	staging := r.FormValue("staging") == "1"
	if email == "" {
		redirectWithFlash(w, r, "/admin/settings", "", "ACME email required")
		return
	}
	caURL := strings.TrimSpace(r.FormValue("acme_ca_url"))
	eabKID := strings.TrimSpace(r.FormValue("acme_eab_kid"))
	eabHMAC := r.FormValue("acme_eab_hmac")

	stagingStr := "0"
	if staging {
		stagingStr = "1"
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5_000_000_000)
	defer cancel()

	// Save plain-text fields first.
	if err := h.saveSettings(ctx, db, map[string]string{
		"acme.email":   email,
		"acme.staging": stagingStr,
		"acme.ca_url":  caURL,
		"acme.eab_kid": eabKID,
	}, false); err != nil {
		redirectWithFlash(w, r, "/admin/settings", "", "save failed")
		return
	}
	// Save EAB HMAC encrypted only when a new value is provided.
	if eabHMAC != "" && eabHMAC != "(unchanged)" {
		ct, err := h.encryptSetting(eabHMAC)
		if err != nil {
			redirectWithFlash(w, r, "/admin/settings", "", "encrypt failed")
			return
		}
		if err := h.saveSettings(ctx, db, map[string]string{"acme.eab_hmac": ct}, true); err != nil {
			redirectWithFlash(w, r, "/admin/settings", "", "save failed")
			return
		}
	}

	// Flip the live config pointers so the next Caddy push picks up changes.
	if h.Config != nil {
		if h.Config.ACMEEmail != nil {
			*h.Config.ACMEEmail = email
		}
		if h.Config.ACMEStaging != nil {
			*h.Config.ACMEStaging = staging
		}
		if h.Config.ACMECaURL != nil {
			*h.Config.ACMECaURL = caURL
		}
		if h.Config.ACMEEabKID != nil {
			*h.Config.ACMEEabKID = eabKID
		}
		// Only update live HMAC pointer when a new value was saved.
		if h.Config.ACMEEabHMAC != nil && eabHMAC != "" && eabHMAC != "(unchanged)" {
			*h.Config.ACMEEabHMAC = eabHMAC
		}
	}
	sess := middleware.SessionFromContext(r.Context())
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "settings.acme.save", Entity: "settings",
		EntityID: "acme",
	})
	redirectWithFlash(w, r, "/admin/settings", "ACME settings saved. Next Caddy push will use them.", "")
}

// SettingsMTLS handles POST /admin/settings/mtls — saves the global mTLS fail-open flag.
func (h *AdminHandlers) SettingsMTLS(w http.ResponseWriter, r *http.Request) {
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	_ = r.ParseForm()
	failOpen := "0"
	if r.FormValue("mtls_fail_open") == "1" {
		failOpen = "1"
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5_000_000_000)
	defer cancel()
	if err := h.saveSettings(ctx, db, map[string]string{"mtls.fail_open": failOpen}, false); err != nil {
		redirectWithFlash(w, r, "/admin/settings#mtls", "", "save failed")
		return
	}
	sess := middleware.SessionFromContext(r.Context())
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "settings.mtls.save", Entity: "settings",
		EntityID: "mtls", Meta: map[string]any{"fail_open": failOpen == "1"},
	})
	redirectWithFlash(w, r, "/admin/settings#mtls", "mTLS settings saved.", "")
}

// SettingsAnalytics handles POST /admin/settings/analytics.
func (h *AdminHandlers) SettingsAnalytics(w http.ResponseWriter, r *http.Request) {
	db := h.DB()
	if db == nil {
		redirectWithFlash(w, r, "/admin/settings", "", "database not connected")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	days := 0
	if v := strings.TrimSpace(r.FormValue("rollup_retention_days")); v != "" {
		if d, err := strconv.Atoi(v); err == nil && d >= 0 {
			days = d
		}
	}
	daysStr := "0"
	if days > 0 {
		daysStr = strconv.Itoa(days)
	}
	if err := h.saveSettings(ctx, db, map[string]string{
		"analytics.rollup_retention_days": daysStr,
	}, false); err != nil {
		redirectWithFlash(w, r, "/admin/settings", "", "save failed: "+sanitizeErr(err))
		return
	}
	redirectWithFlash(w, r, "/admin/settings", "Analytics settings saved", "")
}

// SettingsFailover handles POST /admin/settings/failover — toggles auto failover at runtime.
func (h *AdminHandlers) SettingsFailover(w http.ResponseWriter, r *http.Request) {
	db := h.DB()
	if db == nil {
		redirectWithFlash(w, r, "/admin/settings", "", "database not connected")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	enabled := "0"
	if r.FormValue("auto_failover_enabled") == "1" {
		enabled = "1"
	}
	if err := h.saveSettings(ctx, db, map[string]string{"failover.auto_enabled": enabled}, false); err != nil {
		redirectWithFlash(w, r, "/admin/settings", "", "save failed: "+sanitizeErr(err))
		return
	}
	redirectWithFlash(w, r, "/admin/settings", "Failover settings saved", "")
}

// SettingsAlert handles POST /admin/settings/alert — upserts alert threshold overrides.
func (h *AdminHandlers) SettingsAlert(w http.ResponseWriter, r *http.Request) {
	db := h.DB()
	if db == nil {
		redirectWithFlash(w, r, "/admin/settings", "", "database not connected")
		return
	}
	_ = r.ParseForm()
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	upsert := func(key, val string) {
		_, _ = db.ExecContext(ctx, store.UpsertSettingSQL(), key, val, 0)
	}

	nodeOfflineMin, err1 := strconv.Atoi(strings.TrimSpace(r.FormValue("node_offline_min")))
	certStuckMin, err2 := strconv.Atoi(strings.TrimSpace(r.FormValue("cert_stuck_min")))
	cooldownSec, err3 := strconv.Atoi(strings.TrimSpace(r.FormValue("cooldown_sec")))
	manualCertDaysWarn, err4 := strconv.Atoi(strings.TrimSpace(r.FormValue("manual_cert_days_warn")))
	errorRatePct, err5 := strconv.ParseFloat(strings.TrimSpace(r.FormValue("error_rate_pct")), 64)
	errorRateWindowMin, err6 := strconv.Atoi(strings.TrimSpace(r.FormValue("error_rate_window_min")))

	if err1 != nil || nodeOfflineMin <= 0 ||
		err2 != nil || certStuckMin <= 0 ||
		err3 != nil || cooldownSec <= 0 ||
		err4 != nil || manualCertDaysWarn <= 0 ||
		err5 != nil || errorRatePct <= 0 ||
		err6 != nil || errorRateWindowMin <= 0 {
		redirectWithFlash(w, r, "/admin/settings", "", "all alert thresholds must be positive numbers")
		return
	}

	upsert("alert.node_offline_minutes", strconv.Itoa(nodeOfflineMin))
	upsert("alert.cert_stuck_minutes", strconv.Itoa(certStuckMin))
	upsert("alert.cooldown_seconds", strconv.Itoa(cooldownSec))
	upsert("alert.manual_cert_days_warn", strconv.Itoa(manualCertDaysWarn))
	upsert("alert.error_rate_pct", strconv.FormatFloat(errorRatePct, 'f', -1, 64))
	upsert("alert.error_rate_window_minutes", strconv.Itoa(errorRateWindowMin))

	redirectWithFlash(w, r, "/admin/settings", "Alert thresholds saved", "")
}

// geoipRefresher is the minimal interface the handler needs from GeoIPUpdateJob.
type geoipRefresher interface {
	RunOnce(ctx context.Context)
}

// loadGeoIPView reads the stored creds + DB meta for the settings page. The
// license key is never returned (write-only); only a "configured" boolean.
func (h *AdminHandlers) loadGeoIPView(ctx context.Context, db *sql.DB) geoipView {
	v := geoipView{}
	kv := h.loadSettings(ctx, db, []string{"geoip.account_id", "geoip.license_key"})
	v.AccountID = kv["geoip.account_id"]
	v.Configured = kv["geoip.account_id"] != "" && kv["geoip.license_key"] != ""
	var fetchedAt, lastAttempt sql.NullTime
	var lastError sql.NullString
	_ = db.QueryRowContext(ctx,
		`SELECT sha256, size_bytes, fetched_at, last_error, last_attempt_at FROM geoip_db_meta WHERE id = 1`,
	).Scan(&v.SHA256, &v.SizeBytes, &fetchedAt, &lastError, &lastAttempt)
	if fetchedAt.Valid {
		v.FetchedAt = fetchedAt.Time.UTC().Format(time.RFC3339)
	}
	if lastAttempt.Valid {
		v.LastAttempt = lastAttempt.Time.UTC().Format(time.RFC3339)
	}
	v.LastError = lastError.String
	if len(v.SHA256) >= 16 {
		v.SHA256Short = v.SHA256[:16]
	} else {
		v.SHA256Short = v.SHA256
	}
	if v.SizeBytes >= 1<<20 {
		v.SizeHuman = fmt.Sprintf("%.1f MB", float64(v.SizeBytes)/float64(1<<20))
	} else if v.SizeBytes > 0 {
		v.SizeHuman = fmt.Sprintf("%.1f KB", float64(v.SizeBytes)/float64(1<<10))
	}
	v.Available = geoip.Global().Available()
	return v
}

// SettingsGeoIP POST /admin/settings/geoip - stores MaxMind creds encrypted.
// Empty license_key keeps the existing one (write-only field).
func (h *AdminHandlers) SettingsGeoIP(w http.ResponseWriter, r *http.Request) {
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	_ = r.ParseForm()
	accountID := strings.TrimSpace(r.FormValue("account_id"))
	licenseKey := strings.TrimSpace(r.FormValue("license_key"))
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	encAccount, err := h.encryptSetting(accountID)
	if err != nil {
		redirectWithFlash(w, r, "/admin/settings", "", "encryption unavailable")
		return
	}
	kv := map[string]string{"geoip.account_id": encAccount}
	// Only overwrite the license key when a new one is submitted.
	if licenseKey != "" {
		encKey, err := h.encryptSetting(licenseKey)
		if err != nil {
			redirectWithFlash(w, r, "/admin/settings", "", "encryption unavailable")
			return
		}
		kv["geoip.license_key"] = encKey
	}
	if err := h.saveSettings(ctx, db, kv, true); err != nil {
		redirectWithFlash(w, r, "/admin/settings", "", "save failed")
		return
	}
	sess := middleware.SessionFromContext(r.Context())
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "settings.geoip.save", Entity: "settings",
		EntityID: "geoip", // never the creds
	})
	redirectWithFlash(w, r, "/admin/settings", "GeoIP credentials saved. The next refresh will download the DB.", "")
}

// SettingsGeoIPRefresh POST /admin/settings/geoip/refresh - triggers an
// immediate download. Runs async so the admin isn't blocked on a ~6 MB fetch.
func (h *AdminHandlers) SettingsGeoIPRefresh(w http.ResponseWriter, r *http.Request) {
	if h.GeoIPJob == nil {
		redirectWithFlash(w, r, "/admin/settings", "", "GeoIP updater not wired")
		return
	}
	job := h.GeoIPJob
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		job.RunOnce(ctx)
	}()
	sess := middleware.SessionFromContext(r.Context())
	if db := h.DB(); db != nil {
		audit.Write(r.Context(), db, h.Logger, r, audit.Entry{
			UserID: actorUserID(sess), Action: "settings.geoip.refresh", Entity: "settings", EntityID: "geoip",
		})
	}
	redirectWithFlash(w, r, "/admin/settings", "GeoIP download started; refresh this page in a moment.", "")
}

// loadSettings fetches a set of keys; decrypts is_encrypted rows.
func (h *AdminHandlers) loadSettings(ctx context.Context, db *sql.DB, keys []string) map[string]string {
	if len(keys) == 0 {
		return map[string]string{}
	}
	args := make([]any, 0, len(keys))
	placeholders := make([]string, 0, len(keys))
	for _, k := range keys {
		args = append(args, k)
		placeholders = append(placeholders, "?")
	}
	q := "SELECT `key`, value, is_encrypted FROM settings WHERE `key` IN (" + strings.Join(placeholders, ",") + ")"
	out := map[string]string{}
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var k, v string
		var enc bool
		if err := rows.Scan(&k, &v, &enc); err != nil {
			continue
		}
		if enc && h.State != nil {
			if dec, err := h.State.Decrypt(v); err == nil {
				v = dec
			} else {
				v = ""
			}
		}
		out[k] = v
	}
	return out
}

// loadSettingsRaw reads settings without decrypting. Used for presence checks
// on encrypted rows (non-empty ciphertext = configured) so we never decrypt
// secrets just to render a "configured" badge.
func (h *AdminHandlers) loadSettingsRaw(ctx context.Context, db *sql.DB, keys []string) map[string]string {
	out := map[string]string{}
	if len(keys) == 0 {
		return out
	}
	args := make([]any, 0, len(keys))
	placeholders := make([]string, 0, len(keys))
	for _, k := range keys {
		args = append(args, k)
		placeholders = append(placeholders, "?")
	}
	q := "SELECT `key`, value FROM settings WHERE `key` IN (" + strings.Join(placeholders, ",") + ")"
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			continue
		}
		out[k] = v
	}
	return out
}

// saveSettings upserts key/value pairs. If encrypted=true, value is stored
// as-is (caller has already encrypted) and is_encrypted=1.
func (h *AdminHandlers) saveSettings(ctx context.Context, db *sql.DB, kv map[string]string, encrypted bool) error {
	encFlag := 0
	if encrypted {
		encFlag = 1
	}
	for k, v := range kv {
		_, err := db.ExecContext(ctx, store.UpsertSettingSQL(), k, v, encFlag)
		if err != nil {
			return err
		}
	}
	return nil
}

func (h *AdminHandlers) encryptSetting(plaintext string) (string, error) {
	if h.State == nil {
		return "", fmt.Errorf("no crypto available")
	}
	return h.State.Encrypt(plaintext)
}

// actorUserID returns the session's user id as *int64 for audit entries.
func actorUserID(s *auth.Session) *int64 {
	if s == nil {
		return nil
	}
	id := s.UserID
	return &id
}

func atoiOr(s string, def int) int {
	if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil && n > 0 {
		return n
	}
	return def
}

func defaultStr(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// ---- API keys ----------------------------------------------------------

type apiKeyRow struct {
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
	ViewAll    bool   // true when super_admin is viewing all keys
	OwnerEmail string // populated only in ViewAll mode
}

type apiKeysData struct {
	baseAdminData
	Keys     []apiKeyRow
	NewPlain string // shown ONCE after creation
	ViewAll  bool   // true when super_admin requested all=1
	// Pagination/sort/search.
	Page         int
	Size         int
	Total        int
	TotalPgs     int
	Sort         string
	Dir          string
	Q            string
	PrevURL      string
	NextURL      string
	QueryValues  string
	SavedFilters []savedFilter
}

func (h *AdminHandlers) APIKeysList(w http.ResponseWriter, r *http.Request) {
	// NOTE: plain key is never delivered via URL (it would land in browser
	// history + access logs). It is rendered inline by APIKeysCreate.
	if h.maybeApplySavedFilter(w, r, "api_keys") {
		return
	}
	sess := middleware.SessionFromContext(r.Context())
	lp := parseListParams(r, []string{"id", "name", "created_at", "last_used_at"},
		"id", "desc", 50)
	d := apiKeysData{
		baseAdminData: h.base(r, "API keys"),
		Page:          lp.Page,
		Size:          lp.Size,
		Sort:          lp.Sort,
		Dir:           lp.Dir,
		Q:             lp.Q,
	}
	db := h.DB()
	if db == nil || sess == nil {
		h.render(w, "api_keys", d)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	// super_admin with ?all=1 sees every user's keys.
	viewAll := sess.Role == "super_admin" && r.URL.Query().Get("all") == "1"
	d.ViewAll = viewAll

	var (
		where      string
		args       []any
		fromClause string
	)
	if viewAll {
		fromClause = "api_keys k LEFT JOIN users u ON u.id = k.user_id"
		where = "1=1"
	} else {
		fromClause = "api_keys k"
		where = "k.user_id = ?"
		args = []any{sess.UserID}
	}
	if lp.Q != "" {
		like := likeContains(lp.Q)
		where += ` AND (k.name LIKE ? ESCAPE '\\' OR k.key_prefix LIKE ? ESCAPE '\\' OR k.scopes LIKE ? ESCAPE '\\')`
		args = append(args, like, like, like)
	}

	orderCol := apiKeysSortCol(lp.Sort)
	dir := lp.Dir
	if dir != "asc" {
		dir = "desc"
	}

	var total int
	_ = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+fromClause+" WHERE "+where, args...).Scan(&total)

	var (
		selectSQL string
		queryArgs []any
	)
	if viewAll {
		selectSQL = `SELECT k.id, k.name, k.key_prefix, k.scopes,
			        COALESCE(DATE_FORMAT(k.last_used_at,'%Y-%m-%d %H:%i'),''),
			        k.last_used_ip,
			        k.use_count,
			        DATE_FORMAT(k.created_at,'%Y-%m-%d'),
			        COALESCE(DATE_FORMAT(k.expires_at,'%Y-%m-%d'),''),
			        k.revoked_at IS NOT NULL,
			        COALESCE(u.email,'')
			 FROM ` + fromClause + ` WHERE ` + where + ` ORDER BY ` + orderCol + ` ` + dir + ` LIMIT ? OFFSET ?`
	} else {
		selectSQL = `SELECT k.id, k.name, k.key_prefix, k.scopes,
			        COALESCE(DATE_FORMAT(k.last_used_at,'%Y-%m-%d %H:%i'),''),
			        k.last_used_ip,
			        k.use_count,
			        DATE_FORMAT(k.created_at,'%Y-%m-%d'),
			        COALESCE(DATE_FORMAT(k.expires_at,'%Y-%m-%d'),''),
			        k.revoked_at IS NOT NULL
			 FROM ` + fromClause + ` WHERE ` + where + ` ORDER BY ` + orderCol + ` ` + dir + ` LIMIT ? OFFSET ?`
	}
	queryArgs = append(args, lp.Size, lp.Offset())

	rows, err := db.QueryContext(ctx, selectSQL, queryArgs...)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var k apiKeyRow
			k.ViewAll = viewAll
			var scanErr error
			if viewAll {
				scanErr = rows.Scan(&k.ID, &k.Name, &k.Prefix, &k.Scopes, &k.LastUsedAt, &k.LastUsedIP, &k.UseCount, &k.CreatedAt, &k.ExpiresAt, &k.Revoked, &k.OwnerEmail)
			} else {
				scanErr = rows.Scan(&k.ID, &k.Name, &k.Prefix, &k.Scopes, &k.LastUsedAt, &k.LastUsedIP, &k.UseCount, &k.CreatedAt, &k.ExpiresAt, &k.Revoked)
			}
			if scanErr == nil {
				d.Keys = append(d.Keys, k)
			}
		}
	}

	d.Total = total
	d.TotalPgs = (total + lp.Size - 1) / lp.Size
	if d.TotalPgs < 1 {
		d.TotalPgs = 1
	}
	q := r.URL.Query()
	if lp.Page > 1 {
		d.PrevURL = buildPageURL(q, lp.Page-1)
	}
	if lp.Page < d.TotalPgs {
		d.NextURL = buildPageURL(q, lp.Page+1)
	}
	d.QueryValues = apiKeysQueryJSON(lp.Q, lp.Sort, lp.Dir)
	d.SavedFilters = h.savedFiltersForView(ctx, sess.UserID, "api_keys")
	h.render(w, "api_keys", d)
}

func apiKeysSortCol(s string) string {
	switch s {
	case "name":
		return "name"
	case "created_at":
		return "created_at"
	case "last_used_at":
		return "last_used_at"
	default:
		return "id"
	}
}

func apiKeysQueryJSON(q, sort, dir string) string {
	b, _ := json.Marshal(map[string]string{"q": q, "sort": sort, "dir": dir})
	return string(b)
}

func (h *AdminHandlers) APIKeysCreate(w http.ResponseWriter, r *http.Request) {
	sess := middleware.SessionFromContext(r.Context())
	db := h.DB()
	if db == nil || sess == nil {
		http.Error(w, "no db / no session", http.StatusServiceUnavailable)
		return
	}
	_ = r.ParseForm()
	name := strings.TrimSpace(r.FormValue("name"))
	// Build scopes from checkboxes in a stable order.
	knownScopes := [][2]string{
		{"scope_services", "services"},
		{"scope_routes", "routes"},
		{"scope_nodes", "nodes"},
		{"scope_admin_read", "admin:read"},
		{"scope_admin_write", "admin:write"},
	}
	var scopeParts []string
	for _, pair := range knownScopes {
		if r.FormValue(pair[0]) == "1" {
			scopeParts = append(scopeParts, pair[1])
		}
	}
	scopes := strings.Join(scopeParts, ",")
	expiresDays, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("expires_days")))
	rateLimitRPM, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("rate_limit_rpm")))
	if name == "" {
		redirectWithFlash(w, r, "/admin/api-keys", "", "name required")
		return
	}
	if expiresDays < 0 || expiresDays > 3650 {
		redirectWithFlash(w, r, "/admin/api-keys", "", "expires_days must be 0..3650 (0 = never)")
		return
	}
	if rateLimitRPM < 0 || rateLimitRPM > 100000 {
		redirectWithFlash(w, r, "/admin/api-keys", "", "rate_limit_rpm out of range")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5_000_000_000)
	defer cancel()
	plain, id, prefix, err := auth.CreateAPIKey(ctx, db, sess.UserID, name, scopes)
	if err != nil {
		h.Logger.Error("api key create", "err", err)
		redirectWithFlash(w, r, "/admin/api-keys", "", "create failed")
		return
	}
	if rateLimitRPM > 0 {
		_, _ = db.ExecContext(ctx,
			"UPDATE api_keys SET rate_limit_rpm = ? WHERE id = ?", rateLimitRPM, id)
	}
	if expiresDays > 0 {
		_, _ = db.ExecContext(ctx,
			"UPDATE api_keys SET expires_at = (NOW() + INTERVAL ? DAY) WHERE id = ?",
			expiresDays, id)
	}
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: &sess.UserID, Action: "api_key.create", Entity: "api_key",
		EntityID: fmt.Sprintf("%d", id),
		Meta:     map[string]any{"name": name, "prefix": prefix},
	})
	// Render inline. Never put the plain key in a URL.
	d := apiKeysData{baseAdminData: h.base(r, "API keys"), NewPlain: plain}
	rows, _ := db.QueryContext(ctx,
		`SELECT id, name, key_prefix, scopes,
		        COALESCE(DATE_FORMAT(last_used_at,'%Y-%m-%d %H:%i'),''),
		        last_used_ip,
		        use_count,
		        DATE_FORMAT(created_at,'%Y-%m-%d'),
		        COALESCE(DATE_FORMAT(expires_at,'%Y-%m-%d'),''),
		        revoked_at IS NOT NULL
		 FROM api_keys WHERE user_id = ? ORDER BY id DESC`, sess.UserID)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var k apiKeyRow
			if err := rows.Scan(&k.ID, &k.Name, &k.Prefix, &k.Scopes, &k.LastUsedAt, &k.LastUsedIP, &k.UseCount, &k.CreatedAt, &k.ExpiresAt, &k.Revoked); err == nil {
				d.Keys = append(d.Keys, k)
			}
		}
	}
	h.render(w, "api_keys", d)
}

func (h *AdminHandlers) APIKeysRevoke(w http.ResponseWriter, r *http.Request) {
	sess := middleware.SessionFromContext(r.Context())
	db := h.DB()
	if db == nil || sess == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	ctx, cancel := context.WithTimeout(r.Context(), 5_000_000_000)
	defer cancel()
	if _, err := db.ExecContext(ctx,
		"UPDATE api_keys SET revoked_at = NOW() WHERE id = ? AND user_id = ?", id, sess.UserID); err != nil {
		redirectWithFlash(w, r, "/admin/api-keys", "", "revoke failed")
		return
	}
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: &sess.UserID, Action: "api_key.revoke", Entity: "api_key",
		EntityID: fmt.Sprintf("%d", id),
	})
	redirectWithFlash(w, r, "/admin/api-keys", "Key revoked", "")
}

// ---- 2FA self-enrollment ------------------------------------------------

type twofaData struct {
	baseAdminData
	Enabled       bool
	Enrolling     bool
	Secret        string
	QRBase64      string
	RecoveryCodes []string
	// Extended factors. Admin can enroll SMS + Email in addition to TOTP.
	SMSOTPEnabled     bool
	SMSOTPEnrolling   bool
	HasPhone          bool
	EmailOTPEnabled   bool
	EmailOTPEnrolling bool
	HasMailer         bool
	HasSMS            bool
}

func (h *AdminHandlers) TwoFAPage(w http.ResponseWriter, r *http.Request) {
	d := twofaData{baseAdminData: h.base(r, "Two-factor auth")}
	d.HasMailer = h.Mailer != nil
	d.HasSMS = h.SMS != nil
	sess := middleware.SessionFromContext(r.Context())
	db := h.DB()
	if db == nil || sess == nil {
		h.render(w, "twofa", d)
		return
	}
	totp, smsOK, emailOK, phone := h.loadAdminTwoFAState(r.Context(), db, sess.UserID)
	d.Enabled = totp
	d.SMSOTPEnabled = smsOK
	d.EmailOTPEnabled = emailOK
	d.HasPhone = phone != ""
	h.render(w, "twofa", d)
}

func (h *AdminHandlers) TwoFAStart(w http.ResponseWriter, r *http.Request) {
	sess := middleware.SessionFromContext(r.Context())
	if sess == nil {
		http.Error(w, "no session", http.StatusUnauthorized)
		return
	}
	otpURL, secret, qrPNG, err := auth.GenerateTOTP("Hostyt Proxy Gateway", sess.Email)
	if err != nil {
		http.Error(w, "totp gen failed", http.StatusInternalServerError)
		return
	}
	_ = otpURL
	// Store secret server-side; never round-trip it through the browser.
	if h.RDB != nil {
		rkey := fmt.Sprintf("totp:enroll:%d", sess.UserID)
		if serr := h.RDB.Set(r.Context(), rkey, secret, 10*time.Minute).Err(); serr != nil {
			h.Logger.Error("totp enroll stash", "err", serr)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
	}
	d := twofaData{
		baseAdminData: h.base(r, "Set up 2FA"),
		Enrolling:     true,
		Secret:        secret, // displayed once for manual entry; not sent back in form
		QRBase64:      base64.StdEncoding.EncodeToString(qrPNG),
	}
	h.render(w, "twofa", d)
}

func (h *AdminHandlers) TwoFAConfirm(w http.ResponseWriter, r *http.Request) {
	sess := middleware.SessionFromContext(r.Context())
	db := h.DB()
	if db == nil || sess == nil {
		http.Error(w, "no db / no session", http.StatusServiceUnavailable)
		return
	}
	_ = r.ParseForm()
	// Read secret from server-side Redis stash, not from form body.
	var secret string
	if h.RDB != nil {
		rkey := fmt.Sprintf("totp:enroll:%d", sess.UserID)
		val, rerr := h.RDB.Get(r.Context(), rkey).Result()
		if rerr != nil {
			redirectWithFlash(w, r, "/admin/2fa", "", "setup session expired; restart 2FA setup")
			return
		}
		secret = val
		// Consume immediately so the key cannot be replayed.
		_ = h.RDB.Del(r.Context(), rkey).Err()
	} else {
		// Fallback when Redis is unavailable: refuse enrollment to avoid
		// reverting to the insecure form-field path.
		http.Error(w, "internal error: redis unavailable", http.StatusInternalServerError)
		return
	}
	code := strings.TrimSpace(r.FormValue("code"))
	if err := auth.ValidateTOTP(secret, code); err != nil {
		redirectWithFlash(w, r, "/admin/2fa", "", "invalid code; try again")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8_000_000_000)
	defer cancel()
	codes, hashes, err := auth.GenerateRecoveryCodes(8)
	if err != nil {
		redirectWithFlash(w, r, "/admin/2fa", "", "internal error")
		return
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		redirectWithFlash(w, r, "/admin/2fa", "", "tx begin failed")
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
		redirectWithFlash(w, r, "/admin/2fa", "", "save failed")
		return
	}
	// Clear old codes (if re-enrolling); insert new.
	_, _ = tx.ExecContext(ctx, "DELETE FROM recovery_codes WHERE user_id = ?", sess.UserID)
	for _, h := range hashes {
		if _, err := tx.ExecContext(ctx,
			"INSERT INTO recovery_codes (user_id, code_hash) VALUES (?, ?)", sess.UserID, h); err != nil {
			redirectWithFlash(w, r, "/admin/2fa", "", "code save failed")
			return
		}
	}
	if err := tx.Commit(); err != nil {
		redirectWithFlash(w, r, "/admin/2fa", "", "commit failed")
		return
	}
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: &sess.UserID, Action: "2fa.enable", Entity: "user",
		EntityID: fmt.Sprintf("%d", sess.UserID),
	})
	middleware.InvalidateAdmin2FACache(ctx, h.RDB, sess.UserID)
	// Render twofa page directly with new codes (one-shot view).
	d := twofaData{
		baseAdminData: h.base(r, "Two-factor auth"),
		Enabled:       true,
		RecoveryCodes: codes,
	}
	h.render(w, "twofa", d)
}

func (h *AdminHandlers) TwoFADisable(w http.ResponseWriter, r *http.Request) {
	sess := middleware.SessionFromContext(r.Context())
	db := h.DB()
	if db == nil || sess == nil {
		http.Error(w, "no db / no session", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5_000_000_000)
	defer cancel()
	if _, err := db.ExecContext(ctx,
		"UPDATE users SET totp_secret = NULL, totp_secret_enc = NULL, totp_enabled = 0 WHERE id = ?", sess.UserID); err != nil {
		redirectWithFlash(w, r, "/admin/2fa", "", "disable failed")
		return
	}
	_, _ = db.ExecContext(ctx, "DELETE FROM recovery_codes WHERE user_id = ?", sess.UserID)
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: &sess.UserID, Action: "2fa.disable", Entity: "user",
		EntityID: fmt.Sprintf("%d", sess.UserID),
	})
	middleware.InvalidateAdmin2FACache(ctx, h.RDB, sess.UserID)
	redirectWithFlash(w, r, "/admin/2fa", "2FA disabled", "")
}

// ---- Settings: OIDC ---------------------------------------------------

func (h *AdminHandlers) SettingsOIDC(w http.ResponseWriter, r *http.Request) {
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	_ = r.ParseForm()
	enabled := r.FormValue("enabled") == "1"
	providerName := strings.TrimSpace(r.FormValue("provider_name"))
	issuer := strings.TrimSpace(r.FormValue("issuer"))
	clientID := strings.TrimSpace(r.FormValue("client_id"))
	clientSecret := r.FormValue("client_secret")
	clearSecret := r.FormValue("clear_secret") == "1"
	redirectURL := strings.TrimSpace(r.FormValue("redirect_url"))
	defaultRole := strings.TrimSpace(r.FormValue("default_role"))
	autoProvision := r.FormValue("auto_provision") == "1"
	pwdLoginDisabled := r.FormValue("password_login_disabled") == "1"
	scopes := strings.TrimSpace(r.FormValue("scopes"))

	// Reject obvious paste mistake: discovery URL instead of issuer URL.
	if strings.Contains(issuer, "/.well-known/") {
		redirectWithFlash(w, r, "/admin/settings", "", "OIDC issuer: paste the issuer base URL (no /.well-known/openid-configuration)")
		return
	}

	// Autofill redirect URL from AppURL when admin leaves the field blank.
	if redirectURL == "" && h.State != nil {
		st := h.State.Get()
		if st.App != nil && st.App.URL != "" {
			redirectURL = strings.TrimRight(st.App.URL, "/") + "/auth/oidc/callback"
		}
	}

	if enabled && (issuer == "" || clientID == "") {
		redirectWithFlash(w, r, "/admin/settings", "", "OIDC: issuer and client_id are required when enabled")
		return
	}
	if issuer != "" {
		u, err := url.Parse(issuer)
		if err != nil {
			redirectWithFlash(w, r, "/admin/settings", "", "OIDC issuer: invalid URL")
			return
		}
		if u.Scheme != "https" && !strings.HasPrefix(u.Host, "localhost") && u.Hostname() != "127.0.0.1" {
			redirectWithFlash(w, r, "/admin/settings", "", "OIDC issuer: must use https:// (RFC 8252)")
			return
		}
		if err := security.ValidateOutboundURL(u); err != nil {
			redirectWithFlash(w, r, "/admin/settings", "", "OIDC issuer: "+err.Error())
			return
		}
	}
	if redirectURL != "" {
		ru, err := url.Parse(redirectURL)
		if err != nil || (ru.Scheme != "https" && ru.Scheme != "http") {
			redirectWithFlash(w, r, "/admin/settings", "", "OIDC redirect_url: must be a full http(s) URL")
			return
		}
	}
	if defaultRole != "support" && defaultRole != "admin" && defaultRole != "client" {
		defaultRole = "support"
	}
	// Refuse the dangerous combo: auto-provision new users straight into the
	// admin role. Any unknown email at the IdP would otherwise become an
	// admin on first sign-in.
	if autoProvision && defaultRole == "admin" {
		redirectWithFlash(w, r, "/admin/settings", "", "OIDC: auto_provision with default_role=admin is refused (security)")
		return
	}
	enabledStr := "0"
	if enabled {
		enabledStr = "1"
	}
	autoStr := "0"
	if autoProvision {
		autoStr = "1"
	}
	pwdDisabledStr := "0"
	if pwdLoginDisabled {
		pwdDisabledStr = "1"
	}
	allowUnverified := r.FormValue("allow_unverified_email") == "1"
	allowUnverifiedStr := "0"
	if allowUnverified {
		allowUnverifiedStr = "1"
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5_000_000_000)
	defer cancel()
	if err := h.saveSettings(ctx, db, map[string]string{
		"oidc.enabled":                 enabledStr,
		"oidc.provider_name":           providerName,
		"oidc.issuer":                  issuer,
		"oidc.client_id":               clientID,
		"oidc.redirect_url":            redirectURL,
		"oidc.default_role":            defaultRole,
		"oidc.auto_provision":          autoStr,
		"oidc.password_login_disabled": pwdDisabledStr,
		"oidc.allow_unverified_email":  allowUnverifiedStr,
		"oidc.scopes":                  scopes,
	}, false); err != nil {
		redirectWithFlash(w, r, "/admin/settings", "", "save failed: "+sanitizeErr(err))
		return
	}
	if clearSecret {
		// Hard-clear: row stays so we don't fight ON DUPLICATE KEY, value
		// becomes empty. loadConfig treats "" as "no secret".
		if err := h.saveSettings(ctx, db, map[string]string{"oidc.client_secret": ""}, false); err != nil {
			redirectWithFlash(w, r, "/admin/settings", "", "client_secret clear failed")
			return
		}
	} else if clientSecret != "" {
		ct, err := h.encryptSetting(clientSecret)
		if err != nil {
			redirectWithFlash(w, r, "/admin/settings", "", "encrypt client_secret failed")
			return
		}
		if err := h.saveSettings(ctx, db, map[string]string{"oidc.client_secret": ct}, true); err != nil {
			redirectWithFlash(w, r, "/admin/settings", "", "client_secret save failed")
			return
		}
	}
	// Drop cached provider so the next /auth/oidc/start re-runs discovery
	// with the freshly saved issuer/client_id.
	if h.OIDC != nil {
		h.OIDC.InvalidateCache()
	}
	sess := middleware.SessionFromContext(r.Context())
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "settings.oidc.save", Entity: "settings",
		EntityID: "oidc", Meta: map[string]any{"enabled": enabled, "issuer": issuer},
	})
	redirectWithFlash(w, r, "/admin/settings", "OIDC saved. Next sign-in will use the updated config.", "")
}

// SettingsOIDCTestDiscovery probes the issuer URL the admin currently has
// in the form (or the saved one if blank) and returns endpoint metadata as
// JSON. No login is performed. Used by the "Test discovery" button.
func (h *AdminHandlers) SettingsOIDCTestDiscovery(w http.ResponseWriter, r *http.Request) {
	if h.OIDC == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "error": "oidc service not wired"})
		return
	}
	_ = r.ParseForm()
	issuer := strings.TrimSpace(r.FormValue("issuer"))
	if issuer == "" {
		// Fall back to currently saved value so admin can re-test without
		// re-typing.
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if cfg, err := h.OIDC.CurrentConfigForUI(ctx); err == nil {
			issuer = cfg.Issuer
		}
	}
	if issuer == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "issuer is empty"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()
	probe, err := h.OIDC.TestDiscovery(ctx, issuer)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": sanitizeErr(err)})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "probe": probe})
}

// ---- Settings: Turnstile -----------------------------------------------

func (h *AdminHandlers) SettingsTurnstile(w http.ResponseWriter, r *http.Request) {
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	_ = r.ParseForm()
	provider := strings.TrimSpace(r.FormValue("provider"))
	switch provider {
	case "turnstile", "hcaptcha", "recaptcha":
		// valid provider
	default:
		provider = "" // anything else (incl. "none") disables CAPTCHA
	}
	enabled := provider != ""
	siteKey := strings.TrimSpace(r.FormValue("site_key"))
	secret := r.FormValue("secret")

	ctx, cancel := context.WithTimeout(r.Context(), 5_000_000_000)
	defer cancel()

	// A secret is provider-specific: a Turnstile secret will not verify hCaptcha
	// tokens. Reusing the saved secret is only safe when the provider is unchanged
	// - otherwise switching provider would lock out every password login.
	curProvider, hasSecret := h.captchaCurrent(ctx)
	if enabled {
		if siteKey == "" {
			redirectWithFlash(w, r, "/admin/settings", "", "CAPTCHA: site key is required when a provider is selected")
			return
		}
		if captchaSecretRequired(provider, curProvider, hasSecret, secret != "") {
			redirectWithFlash(w, r, "/admin/settings", "", "CAPTCHA: enter the secret key for the selected provider")
			return
		}
	}

	// When disabling, wipe the stored keys so nothing stale survives and the
	// in-memory verifier clears on the next refresh.
	if !enabled {
		siteKey = ""
	}
	if err := h.saveSettings(ctx, db, map[string]string{
		"captcha.provider": provider,
		"captcha.site_key": siteKey,
	}, false); err != nil {
		redirectWithFlash(w, r, "/admin/settings", "", "save failed")
		return
	}
	switch {
	case secret != "":
		ct, err := h.encryptSetting(secret)
		if err != nil {
			redirectWithFlash(w, r, "/admin/settings", "", "encrypt secret failed")
			return
		}
		if err := h.saveSettings(ctx, db, map[string]string{"captcha.secret": ct}, true); err != nil {
			redirectWithFlash(w, r, "/admin/settings", "", "secret save failed")
			return
		}
	case !enabled:
		// Clear the secret when CAPTCHA is turned off.
		if err := h.saveSettings(ctx, db, map[string]string{"captcha.secret": ""}, false); err != nil {
			redirectWithFlash(w, r, "/admin/settings", "", "secret clear failed")
			return
		}
	}
	// Force in-memory verifier reload.
	if h.Captcha != nil {
		h.Captcha.Refresh(ctx)
	}
	sess := middleware.SessionFromContext(r.Context())
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "settings.turnstile.save", Entity: "settings", EntityID: "turnstile",
		Meta: map[string]any{"enabled": enabled, "provider": provider},
	})
	redirectWithFlash(w, r, "/admin/settings", "CAPTCHA saved", "")
}

// captchaSecretRequired reports whether the admin must supply a fresh secret.
// A CAPTCHA secret is provider-specific, so the saved one may only be reused
// when the provider is unchanged and a secret already exists; switching provider
// with no new secret would lock out every password login.
func captchaSecretRequired(newProvider, curProvider string, hasSecret, secretProvided bool) bool {
	if secretProvided {
		return false
	}
	return newProvider != curProvider || !hasSecret
}

// captchaCurrent returns the saved provider and whether a secret is stored.
func (h *AdminHandlers) captchaCurrent(ctx context.Context) (provider string, hasSecret bool) {
	db := h.DB()
	if db == nil {
		return "", false
	}
	cctx, cancel := context.WithTimeout(ctx, 2_000_000_000)
	defer cancel()
	kv := h.loadSettings(cctx, db, []string{"captcha.provider", "captcha.secret"})
	return kv["captcha.provider"], kv["captcha.secret"] != ""
}

// ---- Settings: Cloudflare ----------------------------------------------

func (h *AdminHandlers) SettingsCloudflare(w http.ResponseWriter, r *http.Request) {
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	_ = r.ParseForm()
	enabled := r.FormValue("enabled") == "1"
	accountID := strings.TrimSpace(r.FormValue("account_id"))
	apiToken := r.FormValue("api_token")
	trustIP := r.FormValue("trust_connecting_ip") == "1"

	ctx, cancel := context.WithTimeout(r.Context(), 10_000_000_000)
	defer cancel()

	// Resolve effective token: incoming OR previously saved.
	effectiveToken := apiToken
	if effectiveToken == "" {
		kv := h.loadSettings(ctx, db, []string{"cloudflare.api_token"})
		effectiveToken = kv["cloudflare.api_token"]
	}
	// Verify against Cloudflare when a token is present + integration enabled.
	if enabled && effectiveToken != "" && h.Cloudflare != nil {
		if err := h.Cloudflare.VerifyToken(ctx, effectiveToken); err != nil {
			redirectWithFlash(w, r, "/admin/settings", "", "Cloudflare token rejected: "+sanitizeErr(err))
			return
		}
	}

	enabledStr := "0"
	if enabled {
		enabledStr = "1"
	}
	trustStr := "0"
	if trustIP {
		trustStr = "1"
	}
	if err := h.saveSettings(ctx, db, map[string]string{
		"cloudflare.enabled":             enabledStr,
		"cloudflare.account_id":          accountID,
		"cloudflare.trust_connecting_ip": trustStr,
	}, false); err != nil {
		redirectWithFlash(w, r, "/admin/settings", "", "save failed")
		return
	}
	if apiToken != "" {
		ct, err := h.encryptSetting(apiToken)
		if err != nil {
			redirectWithFlash(w, r, "/admin/settings", "", "encrypt token failed")
			return
		}
		if err := h.saveSettings(ctx, db, map[string]string{"cloudflare.api_token": ct}, true); err != nil {
			redirectWithFlash(w, r, "/admin/settings", "", "token save failed")
			return
		}
	}
	if h.Cloudflare != nil {
		h.Cloudflare.Refresh(ctx)
	}
	sess := middleware.SessionFromContext(r.Context())
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "settings.cloudflare.save", Entity: "settings", EntityID: "cloudflare",
		Meta: map[string]any{"enabled": enabled, "trust_cf_ip": trustIP},
	})
	redirectWithFlash(w, r, "/admin/settings", "Cloudflare settings saved", "")
}

// ---- Node auto-join: mint token ----------------------------------------

func (h *AdminHandlers) NodesJoinToken(w http.ResponseWriter, r *http.Request) {
	sess := middleware.SessionFromContext(r.Context())
	db := h.DB()
	if db == nil || sess == nil || h.Joiner == nil {
		http.Error(w, "no db / no session / no joiner", http.StatusServiceUnavailable)
		return
	}
	_ = r.ParseForm()
	groupID, _ := strconv.ParseInt(r.FormValue("node_group_id"), 10, 64)
	maxRoutes, _ := strconv.Atoi(r.FormValue("max_routes"))
	priority, _ := strconv.Atoi(r.FormValue("priority"))
	nameHint := strings.TrimSpace(r.FormValue("name_hint"))
	if groupID == 0 {
		redirectWithFlash(w, r, "/admin/nodes", "", "node group required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	tk, err := h.Joiner.Mint(ctx, nodejoin.MintOpts{
		NodeGroupID: groupID, MaxRoutes: maxRoutes, Priority: priority,
		NameHint: nameHint, CreatedBy: sess.UserID,
	})
	if err != nil {
		redirectWithFlash(w, r, "/admin/nodes", "", "mint failed: "+sanitizeErr(err))
		return
	}
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: &sess.UserID, Action: "node.join_token.mint", Entity: "node_join_token",
		EntityID: tk.Prefix,
		Meta:     map[string]any{"name_hint": nameHint, "group": groupID, "expires_at": tk.ExpiresAt.Format(time.RFC3339)},
	})
	// Render the full page with the plaintext + one-liner. Never put it
	// in the URL - would land in browser history and access logs.
	d := nodesData{baseAdminData: h.base(r, "Caddy nodes")}
	d.NewJoinToken = tk.Plain
	d.NewJoinTTL = tk.ExpiresAt.Format(time.RFC3339)
	d.AppURL = appURLFromInstallState(h.State)
	h.populateNodesData(r.Context(), &d)
	h.render(w, "nodes", d)
}

// ---- WireGuard control-plane settings (super_admin only) ---------------

func (h *AdminHandlers) SettingsWireguard(w http.ResponseWriter, r *http.Request) {
	sess := middleware.SessionFromContext(r.Context())
	if sess == nil || sess.Role != "super_admin" {
		http.Error(w, "super_admin role required", http.StatusForbidden)
		return
	}
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	_ = r.ParseForm()
	enabled := r.FormValue("enabled") == "1"
	endpoint := strings.TrimSpace(r.FormValue("endpoint"))
	port, _ := strconv.Atoi(r.FormValue("listen_port"))
	subnet := strings.TrimSpace(r.FormValue("subnet"))
	controlIP := strings.TrimSpace(r.FormValue("control_ip"))

	if subnet == "" {
		subnet = "10.66.0.0/24"
	}
	if controlIP == "" {
		controlIP = "10.66.0.1"
	}
	if port == 0 {
		port = 51820
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	enabledStr := "0"
	if enabled {
		enabledStr = "1"
	}
	if err := h.saveSettings(ctx, db, map[string]string{
		"wireguard.enabled":     enabledStr,
		"wireguard.endpoint":    endpoint,
		"wireguard.listen_port": strconv.Itoa(port),
		"wireguard.subnet":      subnet,
		"wireguard.control_ip":  controlIP,
	}, false); err != nil {
		redirectWithFlash(w, r, "/admin/settings", "", "save failed")
		return
	}
	// Generate WG keypair on first save (if missing). Re-uses existing.
	if h.WG != nil {
		_, _ = h.WG.EnsureKeypair(ctx)
		_, _ = h.WG.Reload(ctx)
	}
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: &sess.UserID, Action: "settings.wireguard.save", Entity: "settings",
		EntityID: "wireguard",
		Meta:     map[string]any{"endpoint": endpoint, "subnet": subnet, "enabled": enabled},
	})
	flash := "WireGuard settings saved. Keypair generated."
	if enabled && h.WriteWGConfig != nil {
		if err := h.WriteWGConfig(ctx); err != nil {
			flash += " (sidecar reload pending: " + sanitizeErr(err) + ")"
		} else {
			flash += " Sidecar config written; wg0 will come up within ~10 s."
		}
	}
	redirectWithFlash(w, r, "/admin/settings", flash, "")
}

// NodesApplyWG forces a re-render of /app/wg/wg0.conf from DB. Used
// when the sidecar got out of sync or the operator wants to verify.
func (h *AdminHandlers) NodesApplyWG(w http.ResponseWriter, r *http.Request) {
	if h.WriteWGConfig == nil {
		redirectWithFlash(w, r, "/admin/nodes", "", "WG sidecar not wired in this deployment")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if err := h.WriteWGConfig(ctx); err != nil {
		redirectWithFlash(w, r, "/admin/nodes", "", "apply failed: "+sanitizeErr(err))
		return
	}
	sess := middleware.SessionFromContext(r.Context())
	audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "wireguard.apply", Entity: "wireguard",
	})
	redirectWithFlash(w, r, "/admin/nodes", "WG config re-rendered. Sidecar will apply within ~10 s.", "")
}

// populateNodesData is shared between Nodes (list view) and NodesJoinToken
// (which renders the same template with extra fields). Extracted to keep
// both handlers consistent.
func (h *AdminHandlers) populateNodesData(ctx context.Context, d *nodesData) {
	db := h.DB()
	if db == nil {
		return
	}
	qctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	rows, err := db.QueryContext(qctx,
		`SELECT n.id, n.name, n.api_url, COALESCE(n.public_hostname,''), COALESCE(n.public_ip,''),
		        g.name, n.max_routes, n.current_routes, n.health_status, n.is_enabled,
		        n.approved_at IS NOT NULL, COALESCE(n.fingerprint,''),
		        COALESCE(n.tunnel_transport,'udp'), COALESCE(n.tunnel_wstunnel_port,0),
		        COALESCE(n.tunnel_enabled,0),
		        n.fwd_mtu, n.tunnel_wstunnel_healthy,
		        n.fwd_ip_forward_enabled, n.fwd_policy_drop_detected,
		        n.fwd_firewall_backend, n.fwd_last_setup_error,
		        COALESCE(DATE_FORMAT(n.fwd_reported_at,'%Y-%m-%d %H:%i'),''),
		        COALESCE(n.has_waf,0), COALESCE(n.has_l4,0),
		        COALESCE(n.has_geoip,0), COALESCE(n.has_rate_limit,0),
		        COALESCE(n.caddy_version,''),
		        COALESCE((SELECT SUM(lr.bytes_resp)
		                  FROM log_rollups lr
		                  JOIN routes rr ON rr.id = lr.route_id
		                  WHERE rr.caddy_node_id = n.id
		                    AND lr.bucket_start >= DATE_SUB(NOW(), INTERVAL 1 DAY)), 0)
		 FROM caddy_nodes n JOIN node_groups g ON g.id = n.node_group_id
		 ORDER BY n.priority DESC, n.id ASC`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var n nodeRow
			if err := rows.Scan(&n.ID, &n.Name, &n.APIURL, &n.PublicHostname, &n.PublicIP,
				&n.GroupName, &n.MaxRoutes, &n.CurrentRoutes, &n.Health, &n.Enabled,
				&n.Approved, &n.Fingerprint, &n.Transport, &n.WstunnelPort,
				&n.TunnelEnabled,
				&n.TunnelMTU, &n.WstunnelHealthy,
				&n.FwdIPForward, &n.FwdPolicyDrop,
				&n.FwdFirewallBackend, &n.FwdLastSetupError,
				&n.FwdReportedAt,
				&n.HasWAF, &n.HasL4, &n.HasGeoIP, &n.HasRateLimit, &n.CaddyVersion,
				&n.Bandwidth24h); err == nil {
				n.WGKeepalive = 25
				d.Nodes = append(d.Nodes, n)
			}
		}
	}
	grows, err := db.QueryContext(qctx, "SELECT id, name FROM node_groups ORDER BY name")
	if err == nil {
		defer grows.Close()
		for grows.Next() {
			var g nodeGroup
			if err := grows.Scan(&g.ID, &g.Name); err == nil {
				d.Groups = append(d.Groups, g)
			}
		}
	}
}

// SettingsBanner handles POST /admin/settings/banner — upserts or clears the system banner.
func (h *AdminHandlers) SettingsBanner(w http.ResponseWriter, r *http.Request) {
	db := h.DB()
	if db == nil {
		redirectWithFlash(w, r, "/admin/settings", "", "database not connected")
		return
	}
	_ = r.ParseForm()
	text := strings.TrimSpace(r.FormValue("banner_text"))
	btype := r.FormValue("banner_type")
	link := strings.TrimSpace(r.FormValue("banner_link"))
	linkLabel := strings.TrimSpace(r.FormValue("banner_link_label"))
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if text == "" {
		// Clear banner and all associated fields.
		_, _ = db.ExecContext(ctx, "DELETE FROM settings WHERE `key` IN (?,?,?,?)",
			"system.banner_text", "system.banner_type", "system.banner_link", "system.banner_link_label")
		redirectWithFlash(w, r, "/admin/settings?tab=banner", "Announcement cleared", "")
		return
	}
	if btype != "warning" && btype != "error" {
		btype = "info"
	}
	upsert := func(key, val string) {
		_, _ = db.ExecContext(ctx, store.UpsertSettingSQL(), key, val, 0)
	}
	upsert("system.banner_text", text)
	upsert("system.banner_type", btype)
	upsert("system.banner_link", link)
	upsert("system.banner_link_label", linkLabel)
	redirectWithFlash(w, r, "/admin/settings?tab=banner", "Announcement saved", "")
}

// ---- Stub for not-yet-built pages --------------------------------------

func (h *AdminHandlers) Stub(title string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h.render(w, "stub", struct {
			baseAdminData
			Path string
		}{
			baseAdminData: h.base(r, title),
			Path:          r.URL.Path,
		})
	}
}
