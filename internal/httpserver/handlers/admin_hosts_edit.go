package handlers

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/host-yt/caddy-proxy-manager/internal/auth"
	"github.com/host-yt/caddy-proxy-manager/internal/caddyapi"
	"github.com/host-yt/caddy-proxy-manager/internal/customfields"
	"github.com/host-yt/caddy-proxy-manager/internal/domain/routes"
	"github.com/host-yt/caddy-proxy-manager/internal/geoip"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
)

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
	CachePublic   bool
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
	// CustomConfigEditable gates the Custom JSON pane: raw handlers are
	// node-operator power, so limited admins never see the field.
	CustomConfigEditable bool

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
	// NodeGeoIPDBMissing: the node's agent reported no GeoIP mmdb, so geo
	// rules are skipped on push for this host until the DB lands.
	NodeGeoIPDBMissing bool
	// NodeCaddyVersion is the operator-declared version of the anchor node;
	// NodePQCapable says whether EVERY node serving the host understands
	// x25519mlkem768 (Caddy 2.10+), fan-out peers included. Both drive the
	// PQ-only warning: the toggle must never look active on a node that would
	// have its /load rejected and the policy dropped. PQBlockingNode names the
	// first incapable node when there is one.
	NodeCaddyVersion  string
	NodePQCapable     bool
	PQBlockingNode    string
	PQBlockingVersion string
	// GeoIPAvailable reflects whether the runtime GeoIP database is loaded.
	GeoIPAvailable bool

	// Wildcard DNS-01 (B1, gated). WildcardZones = datalist of dns_providers.
	WildcardEnabled bool
	WildcardZone    string
	WildcardZones   []string

	// DNS steering: health-driven A/AAAA sync for active_active route groups
	// (internal/domain/dnssteer). DNSProviders feeds the provider dropdown.
	DNSSteeringEnabled  bool
	DNSSteeringProvider int64
	DNSSteeringTTL      int
	DNSProviders        []dnsProviderOption

	// ViaWGPeerID == 0 means "no tunnel". When non-zero, build resolves
	// backend host to that peer's tunnel IP at push time.
	ViaWGPeerID   int64
	ClientTunnels []tunnelOption
	// ResolveNodeSide: backend name the panel cannot resolve, accepted by the
	// operator. Emission then neither resolves nor pins that backend.
	ResolveNodeSide bool

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
	// PortalPublicPaths: comma/whitespace-separated path matchers exempt from
	// the verifier. Empty = no exceptions, every protected request is checked.
	PortalPublicPaths string

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
	// TLSPQOnly pins this host's TLS policy to hybrid ML-KEM + TLS 1.3.
	TLSPQOnly    bool
	MTLSCAActive bool // true when the saved CA status='active'
	MTLSCAs      []mtlsCAOption
	// MTLSPathRules lists RBAC path rules for this route.
	MTLSPathRules []mtlsPathRuleRow
	// MTLSCARoles lists available roles for the selected CA (feeds rule add dropdown).
	MTLSCARoles []mtlsRoleRow

	Groups  []hostGroupOption
	GroupID sql.NullInt64

	// AliasStates mirrors routes.aliases_verified: an unproven alias is neither
	// emitted nor cert-eligible, so the editor must show which is which.
	AliasStates    []aliasHostState
	PendingAliases int
	VerifyToken    string

	CFViews []customfields.View

	// FieldErrors keys a validation message by POST field name ("cf_"+key for
	// custom fields), set only when re-rendering the form after a 422.
	FieldErrors map[string]string
}

// aliasHostState is one alias plus whether its DNS-TXT ownership proof landed.
type aliasHostState struct {
	Host   string
	Proven bool
}

// mtlsCAOption is one selectable trust-anchor CA in the host editor dropdown.
type mtlsCAOption struct {
	ID    int64
	Label string
}

// loadMTLSCAOptions lists active trust-anchor CAs, newest first. Best-effort:
// the dropdown just stays empty on error (create/edit both re-validate).
func loadMTLSCAOptions(ctx context.Context, db *sql.DB) []mtlsCAOption {
	rows, err := db.QueryContext(ctx,
		`SELECT id, COALESCE(NULLIF(name,''), common_name) FROM mtls_cas WHERE status='active' ORDER BY id DESC`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []mtlsCAOption
	for rows.Next() {
		var o mtlsCAOption
		if rows.Scan(&o.ID, &o.Label) == nil {
			out = append(out, o)
		}
	}
	return out
}

// dnsProviderOption is one selectable dns_providers row (DNS steering dropdown).
type dnsProviderOption struct {
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
		        r.cache_enabled, r.cache_ttl_secs, COALESCE(r.cache_public,0), r.custom_headers, r.tag,
		        r.maintenance_mode, r.maintenance_message, r.cache_vary,
		        r.access_allow, r.access_deny,
		        COALESCE(r.access_block_all, 0), COALESCE(r.maintenance_allow,''),
		        r.custom_config,
		        r.via_wg_peer_id, COALESCE(r.backend_resolve_node_side,0), s.client_id,
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
	        COALESCE(r.require_client_cert,0), COALESCE(r.mtls_ca_id,0), COALESCE(r.tls_pq_only,0),
		        COALESCE(n.caddy_version,''),
		        COALESCE(CASE WHEN n.modules_probed_at IS NOT NULL THEN n.has_waf        END, ?), COALESCE(n.has_l4,0),
		        COALESCE(CASE WHEN n.modules_probed_at IS NOT NULL THEN n.has_geoip      END, ?),
		        COALESCE(CASE WHEN n.modules_probed_at IS NOT NULL THEN n.has_rate_limit END, ?),
		        COALESCE(n.geoip_db_present,1)=0,
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
		&d.CacheEnabled, &d.CacheTTLSecs, &d.CachePublic, &headersJSON, &tag,
		&d.MaintenanceMode, &maintMsg, &cacheVary,
		&accessAllow, &accessDeny,
		&accessBlockAll, &maintAllow,
		&customCfg,
		&viaPeerID, &d.ResolveNodeSide, &clientID,
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
		&d.RequireClientCert, &d.MTLSCAID, &d.TLSPQOnly,
		&d.NodeCaddyVersion,
		&d.NodeHasWAF, &d.NodeHasL4, &d.NodeHasGeoIP, &d.NodeHasRateLimit, &d.NodeGeoIPDBMissing,
		&d.DialTimeoutMs, &d.ResponseHeaderTimeoutMs,
		&d.GroupID.Int64)
	if d.GroupID.Int64 > 0 {
		d.GroupID.Valid = true
	}
	d.NodePQCapable = caddyapi.CaddySupportsPQCurve(d.NodeCaddyVersion)
	if !d.NodePQCapable {
		d.PQBlockingNode, d.PQBlockingVersion = d.NodeName, d.NodeCaddyVersion
	}
	if err != nil {
		d.Error = "host not found"
		h.render(w, "hosts_edit", d)
		return
	}
	// The pusher gates PQ-only per node, so a fan-out peer on older Caddy
	// silently drops the policy there - the page must say so, not "enforced".
	if d.TLSPQOnly {
		if name, ver, blocked := pqBlockingNode(ctx, db, id); blocked {
			d.NodePQCapable = false
			d.PQBlockingNode, d.PQBlockingVersion = name, ver
		}
	}
	// Decrypt lb_cookie_secret for the edit form (SECRET-02). Legacy plaintext
	// rows (pre-encryption) fail to decrypt and fall through unchanged.
	if d.LBCookieSecret != "" && h.Routes.DecryptSecret != nil {
		if dec, derr := h.Routes.DecryptSecret(d.LBCookieSecret); derr == nil {
			d.LBCookieSecret = dec
		}
	}
	d.MTLSCAs = loadMTLSCAOptions(ctx, db)
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
	// DNS steering: toggle + provider + TTL (additive query, gated feature,
	// large route SELECT above stays untouched).
	_ = db.QueryRowContext(ctx,
		`SELECT COALESCE(dns_steering_enabled,0), COALESCE(dns_provider_id,0), COALESCE(dns_steering_ttl,60)
		   FROM routes WHERE id = ?`, id,
	).Scan(&d.DNSSteeringEnabled, &d.DNSSteeringProvider, &d.DNSSteeringTTL)
	if pr, prerr := db.QueryContext(ctx, "SELECT id, name FROM dns_providers ORDER BY name ASC"); prerr == nil {
		for pr.Next() {
			var o dnsProviderOption
			if pr.Scan(&o.ID, &o.Label) == nil {
				d.DNSProviders = append(d.DNSProviders, o)
			}
		}
		pr.Close()
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
	if tenantScoped, provOK := h.selfProvisionScope(ctx, sess); provOK && !tenantScoped {
		d.CustomConfigEditable = true
	}
	if aliases.Valid {
		d.Aliases = aliases.String
	}
	// Alias proof state: an alias outside aliases_verified is not in the host
	// matcher and not cert-eligible, so the form has to say so.
	var aliasesVerified string
	_ = db.QueryRowContext(ctx,
		"SELECT COALESCE(aliases_verified,'') FROM routes WHERE id = ?", id).Scan(&aliasesVerified)
	_ = db.QueryRowContext(ctx,
		"SELECT COALESCE(verify_token,'') FROM routes WHERE id = ?", id).Scan(&d.VerifyToken)
	provenAliases := splitHostCSV(aliasesVerified)
	for _, a := range splitHostCSV(d.Aliases) {
		st := aliasHostState{Host: a, Proven: contains(provenAliases, a)}
		d.AliasStates = append(d.AliasStates, st)
		if !st.Proven {
			d.PendingAliases++
		}
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
	_ = db.QueryRowContext(ctx, `SELECT COALESCE(portal_protect,0), COALESCE(portal_public_paths,'') FROM routes WHERE id = ?`, id).Scan(&d.PortalProtect, &d.PortalPublicPaths)
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

// submittedHostEditData rebuilds the edit form's simple/text fields straight
// from the POST body (r.ParseForm already ran), so a validation failure shows
// back what the operator typed instead of the last-saved DB row. Secrets
// (lb_cookie_secret, basic auth password) are deliberately never mirrored.
func submittedHostEditData(r *http.Request, rt *routes.Service) hostEditData {
	f := r.FormValue
	kind := strings.TrimSpace(f("kind"))
	if kind != "redirect" {
		kind = "proxy"
	}
	upstreamScheme := strings.TrimSpace(f("upstream_scheme"))
	if upstreamScheme != "https" {
		upstreamScheme = "http"
	}
	lbPolicy := f("lb_policy")
	switch lbPolicy {
	case "", "round_robin", "least_conn", "ip_hash", "uri_hash", "header", "cookie",
		"random", "random_choose", "client_ip_hash", "query", "first", "weighted_round_robin":
	default:
		lbPolicy = ""
	}
	outboundIPMode := f("outbound_ip_mode")
	switch outboundIPMode {
	case "fixed", "random":
	default:
		outboundIPMode = "default"
	}
	dnsAddressFamily := f("dns_address_family")
	switch dnsAddressFamily {
	case "ipv4", "ipv6":
	default:
		dnsAddressFamily = "any"
	}
	geoMode := strings.ToLower(strings.TrimSpace(f("geo_mode")))
	if geoMode != "allow" && geoMode != "deny" {
		geoMode = "off"
	}
	var groupID sql.NullInt64
	if gid, _ := strconv.ParseInt(f("group_id"), 10, 64); gid > 0 {
		groupID = sql.NullInt64{Int64: gid, Valid: true}
	}
	d := hostEditData{
		Domain:                  strings.TrimSpace(strings.ToLower(f("domain"))),
		Aliases:                 f("aliases"),
		PathPrefix:              strings.TrimSpace(f("path_prefix")),
		BackendIP:               strings.TrimSpace(f("backend_ip")),
		Port:                    atoiDefault(f("port"), 0),
		UpstreamScheme:          upstreamScheme,
		UpstreamSkipTLSVerify:   f("upstream_skip_tls_verify") == "1",
		Kind:                    kind,
		RedirectURL:             strings.TrimSpace(f("redirect_url")),
		RedirectCode:            atoiDefault(f("redirect_code"), 0),
		SSL:                     f("ssl") == "1",
		ForceHTTPS:              f("force_https") == "1",
		WebSocket:               f("websocket") == "1",
		HTTP2:                   f("http2") == "1",
		HTTP3:                   f("http3") == "1",
		CacheEnabled:            f("cache_enabled") == "1",
		CachePublic:             f("cache_public") == "1",
		CacheTTLSecs:            clampInt(atoiDefault(f("cache_ttl_secs"), 60), 1, 86400),
		CustomHeaders:           f("custom_headers"),
		Tag:                     strings.TrimSpace(f("tag")),
		MaintenanceMode:         f("maintenance_mode") == "1",
		MaintenanceMessage:      strings.TrimSpace(f("maintenance_message")),
		ErrorOverride:           f("error_override") == "1",
		ErrorHTML:               f("error_html"),
		ErrorLogoURL:            strings.TrimSpace(f("error_logo_url")),
		ErrorBrand:              strings.TrimSpace(f("error_brand")),
		ErrorBgColor:            strings.TrimSpace(f("error_bg_color")),
		CacheVary:               f("cache_vary"),
		AccessAllow:             f("access_allow"),
		AccessDeny:              f("access_deny"),
		AccessBlockAll:          f("access_block_all") == "1",
		MaintenanceAllow:        f("maintenance_allow"),
		CustomConfig:            f("custom_config"),
		CompressDisabled:        f("compress_disabled") == "1",
		LBPolicy:                lbPolicy,
		LBHeaderField:           strings.TrimSpace(f("lb_header_field")),
		LBCookieName:            strings.TrimSpace(f("lb_cookie_name")),
		LBTryDurationMs:         clampInt(atoiDefault(f("lb_try_duration_ms"), 5000), 100, 300000),
		LBTryIntervalMs:         clampInt(atoiDefault(f("lb_try_interval_ms"), 250), 0, 60000),
		DialTimeoutMs:           clampInt(atoiDefault(f("dial_timeout_ms"), 0), 0, 300000),
		ResponseHeaderTimeoutMs: clampInt(atoiDefault(f("response_header_timeout_ms"), 0), 0, 300000),
		HealthURI:               strings.TrimSpace(f("health_uri")),
		HealthInterval:          clampInt(atoiDefault(f("health_interval"), 10), 1, 300),
		HealthTimeout:           clampInt(atoiDefault(f("health_timeout"), 5), 1, 60),
		HealthStatus:            atoiDefault(f("health_expect_status"), 0),
		HealthFails:             clampInt(atoiDefault(f("health_fails"), 3), 1, 10),
		HealthPassive:           f("health_passive") == "1",
		HealthFailDur:           clampInt(atoiDefault(f("health_fail_dur"), 30), 1, 600),
		HealthMaxFails:          clampInt(atoiDefault(f("health_max_fails"), 3), 1, 10),
		RateLimitEnabled:        f("rate_enabled") == "1",
		RateLimitWindow:         strings.TrimSpace(f("rate_window")),
		RateLimitMaxEvents:      atoiDefault(f("rate_max_events"), 100),
		RateLimitKey:            strings.TrimSpace(f("rate_key")),
		WAFEnabled:              f("waf_enabled") == "1",
		WAFBlocking:             f("waf_blocking") == "1",
		WAFDirectives:           f("waf_directives"),
		GeoMode:                 geoMode,
		GeoCountries:            geoip.NormalizeCountries(f("geo_countries")),
		GeoResponseCode:         atoiDefault(f("geo_response_code"), 403),
		GeoFailClosed:           f("geo_fail_closed") == "1",
		GeoAllowCIDRs:           f("geo_allow_cidrs"),
		GeoContinents:           geoip.NormalizeCountries(f("geo_continents")),
		GeoBlockCIDRs:           f("geo_block_cidrs"),
		GeoIPAvailable:          geoip.Global().Available(),
		WildcardEnabled:         f("wildcard_enabled") == "1",
		WildcardZone:            strings.ToLower(strings.TrimSpace(f("wildcard_zone"))),
		DNSSteeringEnabled:      f("dns_steering_enabled") == "1",
		DNSSteeringProvider:     int64Default(f("dns_provider_id")),
		DNSSteeringTTL:          atoiDefault(f("dns_steering_ttl"), 60),
		ViaWGPeerID:             int64Default(f("via_wg_peer_id")),
		ResolveNodeSide:         f("backend_resolve_node_side") == "1",
		BasicAuthUser:           strings.TrimSpace(f("basic_auth_user")),
		SSOProviderURL:          strings.TrimSpace(f("sso_provider_url")),
		SSOCopyHeaders:          strings.TrimSpace(f("sso_copy_headers")),
		SSOTrustedProxies:       strings.TrimSpace(f("sso_trusted_proxies")),
		SSOPaths:                f("sso_paths"),
		SSOHosts:                f("sso_hosts"),
		SSOViaWGPeerID:          int64Default(f("sso_via_wg_peer_id")),
		SSOStrictMode:           f("sso_strict_mode") == "1",
		PortalProtect:           f("portal_protect") == "1",
		PortalPublicPaths:       f("portal_public_paths"),
		External:                f("upstream_external") == "1",
		ExternalHost:            strings.ToLower(strings.TrimSpace(f("external_host"))),
		UpstreamHostHeader:      strings.TrimSpace(f("upstream_host_header")),
		OutboundIPMode:          outboundIPMode,
		OutboundIP:              strings.TrimSpace(f("outbound_ip")),
		DNSResolverIP:           strings.TrimSpace(f("dns_resolver_ip")),
		DNSResolverViaWGID:      int64Default(f("dns_resolver_via_wg_peer_id")),
		DNSAddressFamily:        dnsAddressFamily,
		RequireClientCert:       f("require_client_cert") == "1",
		MTLSCAID:                int64Default(f("mtls_ca_id")),
		TLSPQOnly:               f("tls_pq_only") == "1",
		GroupID:                 groupID,
	}
	if rt != nil {
		d.WeightedLBAvail = rt.WeightedLBAvailable
		d.RateLimitModuleAvailable = rt.RateLimitModuleAvailable
		d.WAFModuleAvailable = rt.WAFModuleAvailable
		d.GeoModuleAvailable = rt.GeoModuleAvailable
		d.ExternalAllowlist = rt.ExternalAllowlistAll()
	}
	return d
}

// renderHostEditValidationError re-renders the edit form after a validation
// failure: submitted text/toggle fields come from the POST body (never the
// DB), while list/reference data (groups, tunnels, CA options, ...) is
// re-fetched fresh since the form never round-trips it. Returns 422 so a
// browser refresh does not replay the POST.
func (h *AdminHandlers) renderHostEditValidationError(w http.ResponseWriter, r *http.Request, sess *auth.Session, id, clientID int64, field, msg string) {
	d := submittedHostEditData(r, h.Routes)
	d.baseAdminData = h.base(r, "Edit host")
	d.RouteID = id
	d.FieldErrors = map[string]string{field: msg}

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	db := h.DB()
	if db != nil {
		d.Groups = loadHostGroups(ctx, db)
		d.MTLSCAs = loadMTLSCAOptions(ctx, db)
		d.ClientTunnels = loadClientTunnels(ctx, db, clientID)
		d.PortalGroups = h.portalGroupsForRoute(ctx, sess, id, clientID)
		if tenantScoped, provOK := h.selfProvisionScope(ctx, sess); provOK && !tenantScoped {
			d.CustomConfigEditable = true
		}
		if zr, zerr := db.QueryContext(ctx, "SELECT name FROM dns_providers ORDER BY name ASC"); zerr == nil {
			for zr.Next() {
				var z string
				if zr.Scan(&z) == nil {
					d.WildcardZones = append(d.WildcardZones, z)
				}
			}
			zr.Close()
		}
		if pr, prerr := db.QueryContext(ctx, "SELECT id, name FROM dns_providers ORDER BY name ASC"); prerr == nil {
			for pr.Next() {
				var o dnsProviderOption
				if pr.Scan(&o.ID, &o.Label) == nil {
					d.DNSProviders = append(d.DNSProviders, o)
				}
			}
			pr.Close()
		}
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
			   FROM route_location_rules WHERE route_id = ? ORDER BY sort_order ASC, id ASC`, id); lerr == nil {
			for lrows.Next() {
				var lr locationRuleRow
				if lrows.Scan(&lr.Path, &lr.Action, &lr.UpstreamScheme, &lr.UpstreamHost, &lr.UpstreamPort,
					&lr.RedirectURL, &lr.RedirectCode, &lr.RewriteURI) == nil {
					d.LocationRules = append(d.LocationRules, lr)
				}
			}
			lrows.Close()
		}
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
		var nodeOutboundIPsJSON sql.NullString
		var planAllowEgress bool
		_ = db.QueryRowContext(ctx,
			`SELECT n.outbound_ips, COALESCE(p.allow_egress_ip,0)
			   FROM routes r JOIN caddy_nodes n ON n.id = r.caddy_node_id
			   JOIN services s ON s.id = r.service_id JOIN plans p ON p.id = s.plan_id
			  WHERE r.id = ?`, id).Scan(&nodeOutboundIPsJSON, &planAllowEgress)
		d.PlanAllowEgressIP = planAllowEgress
		if nodeOutboundIPsJSON.Valid && nodeOutboundIPsJSON.String != "" {
			var ips []string
			if json.Unmarshal([]byte(nodeOutboundIPsJSON.String), &ips) == nil {
				d.NodeOutboundIPs = ips
			}
		}
		var aliasesDB, aliasesVerified string
		_ = db.QueryRowContext(ctx,
			"SELECT COALESCE(aliases,''), COALESCE(aliases_verified,'') FROM routes WHERE id = ?", id).Scan(&aliasesDB, &aliasesVerified)
		_ = db.QueryRowContext(ctx, "SELECT COALESCE(verify_token,'') FROM routes WHERE id = ?", id).Scan(&d.VerifyToken)
		provenAliases := splitHostCSV(aliasesVerified)
		for _, a := range splitHostCSV(aliasesDB) {
			st := aliasHostState{Host: a, Proven: contains(provenAliases, a)}
			d.AliasStates = append(d.AliasStates, st)
			if !st.Proven {
				d.PendingAliases++
			}
		}
		// CFViews: defs are reference data (DB), values reflect what was just
		// submitted so a bad custom field does not blank the good ones.
		if cfDefs, cfErr := customfields.LoadDefs(ctx, db, "host"); cfErr == nil && len(cfDefs) > 0 {
			vals := make(map[string]string, len(cfDefs))
			for _, def := range cfDefs {
				vals[def.Key] = strings.TrimSpace(r.FormValue("cf_" + def.Key))
			}
			d.CFViews = customfields.Merge(cfDefs, vals)
		}
	}

	var buf bytes.Buffer
	if err := h.Templates.Render(&buf, "hosts_edit", fillBreadcrumbs("hosts_edit", d)); err != nil {
		h.Logger.Error("admin render", "page", "hosts_edit", "err", err)
		http.Error(w, "render failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusUnprocessableEntity)
	_, _ = w.Write(buf.Bytes())
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
