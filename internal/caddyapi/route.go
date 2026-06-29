package caddyapi

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/host-yt/caddy-proxy-manager/internal/geoip"
)

// Route builders. Produce Caddy JSON config fragments for reverse-proxy routes.
// Reference schema: https://caddyserver.com/docs/json/apps/http/servers/routes/

// BasicAuthUser is one account entry for Caddy's http_basic provider.
type BasicAuthUser struct {
	Username string
	Hash     string // bcrypt hash
}

// Route represents a single host(+path) -> upstream rule.
//
// Kind selects the handler family:
//   - "proxy"    (default) - reverse_proxy to UpstreamIP:UpstreamPort.
//   - "redirect"           - static_response with Location: RedirectURL
//     and status RedirectCode (defaults to 308).
type Route struct {
	ID           string   // app-side route id, used as @id in Caddy config
	Hosts        []string // e.g. ["app.customer.com"]
	PathPrefix   string   // optional, e.g. "/api"
	UpstreamIP   string   // backend IP or hostname
	UpstreamPort int
	// BackendResolver: when UpstreamIP is a hostname, emit dynamic_upstreams.a
	// using this resolver IP (e.g. peer tunnel IP that runs dnsmasq).
	BackendResolver string
	// http (default) or https → BuildRoute adds transport.tls when https.
	UpstreamScheme string
	// UpstreamSkipTLSVerify disables upstream cert verification.
	// Needed for self-signed backends (Portainer, internal services).
	UpstreamSkipTLSVerify bool
	WebSocket             bool
	ForceHTTPS            bool
	HTTP2                 bool
	HTTP3                 bool
	Headers               map[string]string // custom upstream request headers

	Kind         string // "" / "proxy" / "redirect"
	RedirectURL  string
	RedirectCode int

	CacheEnabled    bool
	CacheTTLSeconds int
	// CacheVary lists request header names that should be part of the
	// cache key (Souin emits one cached entry per distinct combination).
	// Use this for routes that need cache-by-Accept-Encoding or
	// cache-by-Accept-Language; do NOT include Cookie or Authorization
	// unless you understand the cardinality blow-up.
	CacheVary []string
	// CacheModuleAvailable mirrors NodeSettings.CacheModuleAvailable so
	// BuildRoute can decide whether to emit the real cache handler or
	// fall back to header-only hints. Without this gate, stock caddy
	// rejects the entire route on first push.
	CacheModuleAvailable bool

	// MaintenanceMode short-circuits all traffic with a 503 + HTML body so
	// the operator can take a backend down without dropping the route. When
	// set it overrides Kind (no proxy / no redirect).
	MaintenanceMode    bool
	MaintenanceMessage string // optional plain-text shown inside the page

	// AccessAllow / AccessDeny build a per-route IP allow/deny list using
	// Caddy's remote_ip matcher. Each entry is a CIDR or single IP. Deny
	// is evaluated first (denies short-circuit with 403); allow then
	// gates the remainder (empty allow = allow all not denied). Mirrors
	// NPM's access-list feature, just driven from JSON config instead of
	// nginx snippets.
	AccessAllow    []string
	AccessDeny     []string
	AccessBlockAll bool
	// MaintenanceAllow: IPs that see the real backend even when
	// Kind=maintenance. Empty = everyone gets the maintenance page.
	MaintenanceAllow []string
	// BasicAuthUser + BasicAuthBcrypt drive Caddy's basic_auth handler.
	// Empty means no auth gate. Hash format must be bcrypt (cost ≥ 10).
	BasicAuthUser   string
	BasicAuthBcrypt string
	// BasicAuthUsers overrides single-user fields when non-empty.
	BasicAuthUsers []BasicAuthUser
	// SSO forward-auth (Authentik / Authelia / generic). Empty
	// SSOProviderURL = no SSO gate. CopyHeaders is a list of response
	// headers from the auth subrequest to forward to upstream (e.g.
	// X-Authentik-Username). TrustedProxies caps which networks may
	// set X-Forwarded-* on the auth subrequest.
	SSOProviderURL    string
	SSOCopyHeaders    []string
	SSOTrustedProxies []string
	// SSOPaths / SSOHosts narrow the SSO gate to a subset of paths or
	// hosts. Empty = gate the entire route. Both filters combine as AND:
	// e.g. SSOPaths=["/admin/*"] + SSOHosts=["s1.example.com"] means
	// "only s1.example.com requests under /admin/* go through SSO".
	SSOPaths []string
	SSOHosts []string
	// SSOResolver: when set, the SSO provider hostname is resolved via
	// this DNS resolver IP (e.g. WG peer IP that runs dnsmasq). Lets the
	// forward_auth subrequest reach an IdP that lives on a remote
	// tunnel-only network instead of going over the public internet.
	SSOResolver string
	// SSOStrictMode extends the SSO gate to ALL HTTP methods (not just GET/HEAD)
	// and returns 401 JSON when the IdP replies with a redirect (3xx) instead of
	// passing the redirect through to the client. Use for API-only routes.
	// When false (default), the gate only checks GET/HEAD document loads.
	SSOStrictMode bool

	// External marks a reverse_proxy route whose upstream is an allowlisted
	// EXTERNAL HTTPS origin (e.g. adm.tools), reached from the node's egress
	// IP. When set, BuildRoute emits tls.server_name (SNI) + a Host rewrite,
	// verifies the upstream cert (never skip-verify), and - with ProxySecret -
	// prepends an inbound bearer gate. Not for internal/customer backends.
	External bool
	// UpstreamSNI / UpstreamHostHeader: the SNI sent on the upstream TLS
	// handshake and the Host header sent upstream. Empty falls back to
	// UpstreamIP (the external FQDN).
	UpstreamSNI        string
	UpstreamHostHeader string
	// ProxySecret is the plaintext inbound bearer the node enforces before
	// proxying an External route (panel decrypts it at build time; never
	// logged). Empty disables the gate - the allowlist still applies.
	ProxySecret string

	// ErrorBranding is propagated from NodeSettings so per-route
	// static_response handlers (maintenance) can render the brand-aware
	// HTML page.
	ErrorBranding ErrorBranding

	// Per-route MAINTENANCE (503) page override only. When CustomErrorOverride
	// is set, CustomErrorBranding replaces the node-wide ErrorBranding for this
	// route's maintenance static_response, and a non-empty CustomErrorHTML is
	// used verbatim as that body (admin-scoped; capped + not template-expanded
	// at save time). Generic error pages for other statuses (404/502/504, built
	// by buildErrorRoutes) still use the node-wide ErrorBranding.
	CustomErrorOverride bool
	CustomErrorHTML     string
	CustomErrorBranding ErrorBranding

	// CustomHandlers is a JSON-encoded array of additional Caddy handler
	// objects (e.g. rate_limit, request_body, encode). They run BEFORE
	// the proxy/redirect/maintenance primary in declaration order so the
	// admin can shape requests on the way in. Empty string skips.
	// Validated at save time (must be valid JSON of type []object) so a
	// typo can't take the whole node down.
	CustomHandlers string

	// CompressDisabled opts a route out of the stock `encode` handler.
	// Default false = gzip+zstd on. Set true when the upstream already
	// compresses or streams binary that must not be buffered.
	CompressDisabled bool

	// Upstreams, when len>0, OVERRIDES the single UpstreamIP/UpstreamPort dial
	// for plain internal proxy routes (one {"dial":"host:port"} per element,
	// in order). Ignored for External and BackendResolver routes.
	Upstreams []Upstream
	// LocationRules are ordered path-specific overrides evaluated before the
	// default route target. They let operators model /api or /assets routing
	// without dropping into raw Caddy JSON.
	LocationRules []LocationRule
	// LBPolicy: "" | "round_robin" | "least_conn" | "ip_hash" |
	// "weighted_round_robin" | "uri_hash" | "header" | "cookie".
	LBPolicy string
	// WeightedLBAvailable gates weighted_round_robin (not guaranteed stock).
	// When false and LBPolicy=="weighted_round_robin" the builder downgrades
	// to round_robin so stock Caddy never rejects the /load.
	WeightedLBAvailable bool
	// LBHeaderField is the request header name used by the "header" lb policy.
	LBHeaderField string
	// LBCookieName is the cookie name for the "cookie" lb policy.
	LBCookieName string
	// LBCookieSecret is the optional HMAC secret for the "cookie" lb policy.
	LBCookieSecret string
	// LBTryDurationMs: total time (ms) Caddy may spend retrying across all
	// upstreams. 0 falls back to the 5s default.
	LBTryDurationMs int
	// LBTryIntervalMs: delay (ms) between retry attempts. 0 = no inter-attempt delay.
	LBTryIntervalMs int
	// DialTimeoutMs: per-route dial timeout override (0 = use default 10s).
	DialTimeoutMs int
	// ResponseHeaderTimeoutMs: per-route response header timeout (0 = no limit).
	ResponseHeaderTimeoutMs int

	// Active health check; HealthURI=="" disables it.
	HealthURI          string
	HealthIntervalSecs int
	HealthTimeoutSecs  int
	HealthExpectStatus int // 0 => omit expect_status
	HealthFails        int
	// Passive health check.
	HealthPassive          bool
	HealthFailDurationSecs int
	HealthMaxFails         int

	// Rate limiting (mholt/caddy-ratelimit, non-stock). Emitted only when
	// RateLimitEnabled AND RateLimitModuleAvailable, else stock Caddy rejects
	// the unknown handler and the node goes offline.
	RateLimitEnabled         bool
	RateLimitWindow          string // Go duration, default "1m"
	RateLimitMaxEvents       int    // default 100
	RateLimitKey             string // Caddy placeholder, default per client IP
	RateLimitModuleAvailable bool

	// WAF (corazawaf/coraza-caddy, non-stock). Emitted only when WAFEnabled AND
	// WAFModuleAvailable. WAFBlocking false = detection-only (log, never block).
	WAFEnabled         bool
	WAFBlocking        bool
	WAFDirectives      string // extra SecLang appended after the core ruleset
	WAFModuleAvailable bool

	// Geo blocking (maxmind/caddy-maxmind-geolocation, non-stock). GeoMode is
	// "off" | "allow" | "deny"; GeoCountries is a CSV of ISO alpha-2 codes.
	// Emitted only when GeoMode!=off AND GeoCountries non-empty AND
	// GeoModuleAvailable, else stock Caddy rejects the matcher and the node
	// goes offline.
	GeoMode            string
	GeoCountries       string
	GeoModuleAvailable bool
	GeoResponseCode    int    // HTTP status for blocked requests (0 = use 403)
	GeoFailClosed      bool   // block all traffic when GeoIP module unavailable
	GeoAllowCIDRs      string // comma-separated CIDRs/IPs that bypass country block
	GeoContinents      string // comma-sep continent codes (ISO: AF AN AS EU NA OC SA)
	GeoBlockCIDRs      string // comma-sep CIDRs/IPs to always block, independent of geo mode
	// Geo-block response customisation (resolved per-host from the owning
	// client, else the panel default). GeoBlockAction is "" (plain status
	// body) | "page" (branded HTML) | "redirect" (302 to GeoRedirectURL).
	GeoBlockAction   string
	GeoRedirectURL   string
	GeoBlockTitle    string
	GeoBlockMessage  string
	GeoBlockBranding ErrorBranding // logo + bg + brand for the "page" action

	// OutboundIPMode: "default" = OS picks; "fixed"/"random" = bind transport
	// local_addr to OutboundIP so the connection leaves via a specific NIC IP.
	OutboundIPMode string
	OutboundIP     string // bare IP present on the node NIC

	// DNSResolverIP: when set, upstream hostname resolution uses this custom
	// resolver (e.g. a private dnsmasq or CoreDNS IP). Emitted into
	// dynamic_upstreams.resolver.addresses (port 53). Takes priority over
	// DNSResolverViaWGPeerID when both are non-empty.
	DNSResolverIP string
	// DNSResolverViaWGPeerID: resolved at build time to a WG peer's assigned_ip;
	// used as the DNS resolver for dynamic_upstreams when DNSResolverIP is empty.
	DNSResolverViaWGPeerIP string
	// DNSAddressFamily: "any"/"ipv4" -> Caddy source "a" (A/IPv4 only), "ipv6" -> "aaaa".
	// "any" and "ipv4" both emit A records; there is no mixed A+AAAA source in Caddy.
	DNSAddressFamily string

	// Built-in forward-auth portal. PortalProtect gates the route through the
	// panel's own verifier (a self-hosted alternative to external SSO). The
	// verify subrequest + login UI are dialed at PortalDial (the panel, same
	// host:port the self-bootstrap route uses). PortalTLS selects https on
	// that dial. Empty PortalDial disables the gate even when PortalProtect
	// is set (fail closed: no reachable verifier => skip emission, route is
	// NOT silently left open - see BuildRoute).
	PortalProtect bool
	PortalDial    string // panel host:port reachable from the node
	PortalTLS     bool   // dial the panel over https
	PortalSNI     string // SNI for the panel TLS handshake (panel public host)

	// mTLS client-cert enforcement. When RequireClientCert is set AND
	// MTLSCACertPEM is non-empty, BuildNodeConfig emits a TLS connection
	// policy (matched by this route's Hosts via SNI) that requires + verifies
	// a client cert chaining to the given CA. Enforcement is at the TLS layer
	// (apps.http.servers.srv0.tls_connection_policies), not a route handler.
	// Empty PEM = no enforcement (fail open is acceptable: the CA was deleted,
	// and we never want a missing trust anchor to brick the whole node /load).
	RequireClientCert bool
	MTLSCACertPEM     string // PEM bundle of the trust-anchor CA cert

	// MTLSPathRules drives per-path RBAC when RequireClientCert is true.
	// Non-empty triggers a forward_auth check subroute before the backend.
	MTLSPathRules []MTLSPathRule
	// PanelBaseURL is the panel base URL reachable from Caddy (e.g. http://app:8080).
	// Used to build the internal mTLS RBAC check URL.
	PanelBaseURL string
}

// MTLSPathRule defines one path pattern + required role name for mTLS RBAC.
type MTLSPathRule struct {
	PathPattern  string
	RequiredRole string
}

// Upstream is one backend dial target plus its weighted-LB weight.
type Upstream struct {
	Host        string
	Port        int
	Weight      int // only consumed by weighted_round_robin
	MaxRequests int // Caddy max_requests per upstream (0 = unlimited)
	// No per-upstream passive health fields: stock Caddy's reverse_proxy
	// Upstream supports only dial + max_requests. Passive health is pool-level.
}

// LocationRule is a first-class path override inside one host route.
type LocationRule struct {
	Path           string // Caddy path matcher, e.g. "/api/*"
	Action         string // proxy | redirect | block | rewrite
	UpstreamHost   string
	UpstreamPort   int
	UpstreamScheme string
	RedirectURL    string
	RedirectCode   int
	RewriteURI     string
}

// BuildRoute returns a Caddy route object ready to PATCH into
// /config/apps/http/servers/srv0/routes.
//
// Per-route flags are honoured:
//   - WebSocket=false drops the explicit Upgrade/Connection passthrough so
//     WS connections fall through to a 426 from Caddy's default handler.
//   - ForceHTTPS adds an HTTP→HTTPS upgrade subroute on :80 (Caddy serves
//     the route on both :80 and :443 by default; the subroute returns
//     308 on the cleartext side).
//   - HTTP2 / HTTP3 are protocol toggles surfaced via the server-wide
//     protocols list - see BuildNodeConfig - not per-route.
//
// Example shape produced:
//
//	{
//	  "@id": "route_<id>",
//	  "match": [{"host": ["app.customer.com"], "path": ["/*"]}],
//	  "handle": [
//	    {"handler": "reverse_proxy",
//	     "upstreams": [{"dial": "10.0.0.5:30000"}]}
//	  ],
//	  "terminal": true
//	}
func BuildRoute(r Route) map[string]any {
	match := map[string]any{"host": r.Hosts}
	if r.PathPrefix != "" {
		match["path"] = []string{r.PathPrefix + "*"}
	}

	var primary map[string]any
	if r.MaintenanceMode {
		msg := r.MaintenanceMessage
		if msg == "" {
			msg = "We are performing scheduled maintenance. Please check back shortly."
		}
		maintenancePage := map[string]any{
			"handler":     "static_response",
			"status_code": 503,
			"headers": map[string]any{
				"Content-Type":  []string{"text/html; charset=utf-8"},
				"Retry-After":   []string{"60"},
				"Cache-Control": []string{"no-store"},
			},
			"body": routeMaintenanceBody(r, msg),
		}
		var handlers []any
		if len(r.MaintenanceAllow) > 0 {
			// Allow-listed IPs see the real backend; everyone else gets the
			// 503 page. Build a minimal reverse_proxy primary (no cache, no
			// headers - maintenance is a fault state, keep it boring).
			rp := map[string]any{
				"handler":   "reverse_proxy",
				"upstreams": []any{map[string]any{"dial": dial(r.UpstreamIP, r.UpstreamPort)}},
			}
			if r.UpstreamScheme == "https" {
				tlsBlock := map[string]any{}
				if r.UpstreamSkipTLSVerify {
					tlsBlock["insecure_skip_verify"] = true
				}
				rp["transport"] = map[string]any{"protocol": "http", "tls": tlsBlock}
			}
			handlers = []any{map[string]any{
				"handler": "subroute",
				"routes": []any{
					map[string]any{
						"match": []any{map[string]any{
							"remote_ip": map[string]any{"ranges": r.MaintenanceAllow},
						}},
						"handle":   []any{rp},
						"terminal": true,
					},
					map[string]any{
						"handle":   []any{maintenancePage},
						"terminal": true,
					},
				},
			}}
		} else {
			handlers = []any{maintenancePage}
		}
		if r.ForceHTTPS {
			handlers = forceHTTPSWrap(handlers, r.Hosts)
		}
		return map[string]any{
			"@id":      "route_" + r.ID,
			"match":    []any{match},
			"handle":   handlers,
			"terminal": true,
		}
	}
	switch r.Kind {
	case "redirect":
		code := r.RedirectCode
		if code == 0 {
			code = 308
		}
		primary = map[string]any{
			"handler":     "static_response",
			"status_code": code,
			"headers": map[string]any{
				"Location": []string{r.RedirectURL},
			},
		}
	default:
		primary = map[string]any{"handler": "reverse_proxy"}
		// flush_interval -1 disables response buffering so SSE / chunked /
		// streaming / long-poll upstreams reach the client immediately
		// instead of appearing to hang until Caddy's buffer fills.
		primary["flush_interval"] = -1
		// dnsResolver picks the effective resolver IP: direct IP beats peer IP.
		dnsResolver := firstNonEmpty(r.DNSResolverIP, r.DNSResolverViaWGPeerIP)
		if r.BackendResolver != "" {
			// Resolve the backend name via the peer-side resolver (A records).
			// Note: Caddy reverse_proxy uses EITHER dynamic_upstreams OR a
			// static upstreams list, never both. The previous code emitted both
			// and the static "fallback" dialed the RESOLVER ip:port (the DNS
			// server, not the backend) - dead/wrong config. We emit only the
			// dynamic source; Caddy's own retry handles transient DNS misses.
			primary["dynamic_upstreams"] = map[string]any{
				"source":  "a",
				"name":    r.UpstreamIP,
				"port":    itoa(r.UpstreamPort),
				"refresh": "30s",
				"resolver": map[string]any{
					// JoinHostPort brackets IPv6 literals; bare "ip:53" breaks them.
					"addresses": []string{net.JoinHostPort(r.BackendResolver, "53")},
				},
			}
		} else if dnsResolver != "" && net.ParseIP(r.UpstreamIP) == nil {
			// Custom DNS resolver: upstream host is a name, resolve via the
			// given DNS server. Source "aaaa" for ipv6-only, "a" for all others
			// (ipv4-only and any both use A records; AAAA-only stacks that need
			// "aaaa" source are rare and must explicitly opt in).
			src := "a"
			if r.DNSAddressFamily == "ipv6" {
				src = "aaaa"
			}
			primary["dynamic_upstreams"] = map[string]any{
				"source":  src,
				"name":    r.UpstreamIP,
				"port":    itoa(r.UpstreamPort),
				"refresh": "30s",
				"resolver": map[string]any{
					// JoinHostPort brackets IPv6 literals; bare "ip:53" breaks them.
					"addresses": []string{net.JoinHostPort(dnsResolver, "53")},
				},
			}
		} else if !r.External && len(r.Upstreams) > 0 {
			// Multi-backend pool (plain internal proxy only). Order is
			// significant: weighted_round_robin weights map 1:1 positionally.
			ups := make([]any, 0, len(r.Upstreams))
			for _, u := range r.Upstreams {
				ue := map[string]any{"dial": dial(u.Host, u.Port)}
				// max_requests caps concurrent upstream connections (0 = omit = unlimited).
				if u.MaxRequests > 0 {
					ue["max_requests"] = u.MaxRequests
				}
				// No per-upstream passive health key: stock Caddy's reverse_proxy
				// Upstream has only dial + max_requests, and DisallowUnknownFields
				// rejects the whole /load. Passive health stays pool-level.
				ups = append(ups, ue)
			}
			primary["upstreams"] = ups
		} else {
			primary["upstreams"] = []any{map[string]any{"dial": dial(r.UpstreamIP, r.UpstreamPort)}}
		}
		// Bounded HTTP transport: a dead upstream must fail the dial fast
		// instead of pinning the proxied request. Keep-alive pooling is
		// Caddy's default (32 idle conns/host, 2m idle) so we don't restate it.
		dialTO := "10s"
		if r.DialTimeoutMs > 0 {
			dialTO = fmt.Sprintf("%dms", r.DialTimeoutMs)
		}
		transport := map[string]any{
			"protocol":     "http",
			"dial_timeout": dialTO,
		}
		if r.ResponseHeaderTimeoutMs > 0 {
			transport["response_header_timeout"] = fmt.Sprintf("%dms", r.ResponseHeaderTimeoutMs)
		}
		// https backend → tls block on the same transport.
		if r.UpstreamScheme == "https" {
			tlsBlock := map[string]any{}
			if r.External {
				// External origins MUST validate against the public CA; only
				// pin SNI so the upstream serves the right cert.
				if sni := firstNonEmpty(r.UpstreamSNI, r.UpstreamHostHeader, r.UpstreamIP); sni != "" {
					tlsBlock["server_name"] = sni
				}
			} else if r.UpstreamSkipTLSVerify {
				tlsBlock["insecure_skip_verify"] = true
			}
			transport["tls"] = tlsBlock
		}
		// "random" is resolved to a concrete IP at build time (static Caddy config
		// cannot do true per-request random; we pin one node IP per route).
		if (r.OutboundIPMode == "fixed" || r.OutboundIPMode == "random") && r.OutboundIP != "" {
			transport["local_addr"] = r.OutboundIP
		}
		primary["transport"] = transport
		// Request headers: user-supplied Headers, plus a Host rewrite for
		// External routes so the origin sees its own hostname (not the node
		// domain). The External Host wins over any user-set "Host".
		set := map[string]any{}
		for k, v := range r.Headers {
			set[k] = []string{v}
		}
		if r.External {
			if host := firstNonEmpty(r.UpstreamHostHeader, r.UpstreamIP); host != "" {
				set["Host"] = []string{host}
			}
		}
		request := map[string]any{}
		if len(set) > 0 {
			request["set"] = set
		}
		if r.External {
			// Strip the inbound gate bearer before forwarding: it authenticates
			// the caller to the node, not to the origin. Leaving it on makes the
			// upstream reject the request as a bad token of its own.
			request["delete"] = []string{"Authorization"}
		}
		if len(request) > 0 {
			primary["headers"] = map[string]any{"request": request}
		}
		// Load balancing + health checks apply only to a plain internal proxy
		// pool. External, WG resolver, and custom DNS resolver routes use
		// dynamic_upstreams which forbids mixing with LB selection_policy.
		hasDynUpstreams := r.BackendResolver != "" || (firstNonEmpty(r.DNSResolverIP, r.DNSResolverViaWGPeerIP) != "" && net.ParseIP(r.UpstreamIP) == nil)
		if !r.External && !hasDynUpstreams {
			if lb := buildLoadBalancing(r); lb != nil {
				primary["load_balancing"] = lb
			}
			if hc := buildHealthChecks(r); hc != nil {
				primary["health_checks"] = hc
			}
		}
	}

	handlers := []any{}
	// CIDR block list fires before geo check so explicit IP bans always apply.
	if cidrH := buildCIDRBlock(r); cidrH != nil {
		handlers = append(handlers, cidrH)
	}
	// Geo blocking (maxmind/caddy-maxmind-geolocation, non-stock). Emitted FIRST
	// so a disallowed country gets 403 before reaching the upstream. Module-gated:
	// without it stock Caddy rejects the unknown matcher and the node goes offline.
	if geoH := buildGeoBlock(r); geoH != nil {
		handlers = append(handlers, geoH)
	}
	// WAF (corazawaf/coraza-caddy, non-stock). Runs first so a malicious
	// request is rejected before any other handler. Module-gated; without it
	// stock Caddy rejects the unknown handler and the node goes offline.
	// Detection-only by default; blocking only when the operator opts in.
	if r.WAFEnabled && r.WAFModuleAvailable {
		engine := "DetectionOnly"
		if r.WAFBlocking {
			engine = "On"
		}
		var sb strings.Builder
		sb.WriteString("Include @coraza.conf-recommended\nInclude @crs-setup.conf.example\n")
		if extra := strings.TrimSpace(r.WAFDirectives); extra != "" {
			sb.WriteString(extra)
			sb.WriteString("\n")
		}
		sb.WriteString("Include @owasp_crs/*.conf\nSecRuleEngine ")
		sb.WriteString(engine)
		// Emit a Coraza NDJSON audit log so the node-agent can ship rule matches
		// to the panel (waf_events). Without these, detection fires but produces
		// no consumable output. RelevantOnly = only transactions that matched a
		// rule; Serial + JSON = one JSON object per line at WAFAuditLogFilePath.
		sb.WriteString("\nSecAuditEngine RelevantOnly")
		// Parts ABDFHZ: audit header, request headers, response headers, the
		// trailer (matched-rule messages the agent parses) and boundaries -
		// deliberately NO request/response bodies (C/E/I), which would bloat a
		// single JSON line and risk stalling the agent's bounded tailer.
		sb.WriteString("\nSecAuditLogParts ABDFHZ")
		sb.WriteString("\nSecAuditLogType Serial")
		sb.WriteString("\nSecAuditLogFormat JSON")
		sb.WriteString("\nSecAuditLog ")
		sb.WriteString(WAFAuditLogFilePath)
		handlers = append(handlers, map[string]any{
			"handler":        "waf",
			"load_owasp_crs": true,
			"directives":     sb.String(),
		})
	}
	// Inbound bearer gate for External upstream routes. This route egresses to
	// the public internet from the node's clean IP and the data-plane request
	// is NOT covered by the panel's APIKeyAuth/CSRF, so the node itself returns
	// 403 unless the caller presents the exact bearer. First in the chain so it
	// short-circuits before anything else.
	if r.External && r.ProxySecret != "" {
		handlers = append(handlers, map[string]any{
			"handler": "subroute",
			"routes": []any{
				map[string]any{
					"match": []any{map[string]any{
						"not": []any{map[string]any{
							"header": map[string]any{
								"Authorization": []string{"Bearer " + r.ProxySecret},
							},
						}},
					}},
					"handle": []any{map[string]any{
						"handler":     "static_response",
						"status_code": 403,
						"body":        "forbidden\n",
					}},
				},
			},
		})
	}
	if early := buildEarlyLocationSubroute(r); early != nil {
		handlers = append(handlers, early)
	}
	// Cache: real origin cache via the Souin cache-handler module that the
	// custom Caddy image (deploy/caddy/Dockerfile, xcaddy build with
	// caddy-cache-handler) embeds. The `cache` handler short-circuits
	// upstream on cache hits and stores misses for `ttl` seconds. We also
	// emit a matching Cache-Control response header so downstream CDNs +
	// browsers cache the same response without re-hitting Caddy.
	//
	// Redirect routes are not cached: their handler already short-circuits
	// at the edge and caching a 308 is generally pointless and footguny.
	// Never cache an authed route: the cache handler short-circuits before
	// the SSO forward_auth / basic_auth gates below, so a cache hit would
	// serve one user's authenticated response to an unauthenticated client.
	if r.CacheEnabled && r.Kind != "redirect" && !r.MaintenanceMode &&
		r.SSOProviderURL == "" && r.BasicAuthUser == "" && len(r.BasicAuthUsers) == 0 {
		ttl := r.CacheTTLSeconds
		if ttl <= 0 {
			ttl = 60
		}
		if r.CacheModuleAvailable {
			ttlStr := itoa(ttl) + "s"
			cacheH := map[string]any{
				"handler": "cache",
				"ttl":     ttlStr,
				"stale":   ttlStr,
			}
			if len(r.CacheVary) > 0 {
				// Souin reads `key.headers` to fold the listed request
				// headers into the cache key (one entry per combination).
				cacheH["key"] = map[string]any{
					"headers": r.CacheVary,
				}
			}
			handlers = append(handlers, cacheH)
		}
		// Downstream Cache-Control header is always safe to emit (no
		// module dependency); browsers + CDNs cache regardless of the
		// module's presence on this node.
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"response": map[string]any{
				"set": map[string]any{
					"Cache-Control": []string{"public, max-age=" + itoa(ttl)},
				},
			},
		})
	}
	// Response compression: stock Caddy `encode` (gzip+zstd), no module gate.
	// Emitted after the cache block so a cache hit is compressed on the way
	// out; already-compressed upstreams are skipped by Caddy (Content-Encoding
	// check). Skip for redirect (no body) and when the operator opted out.
	if !r.CompressDisabled && r.Kind != "redirect" {
		handlers = append(handlers, map[string]any{
			"handler": "encode",
			"encodings": map[string]any{
				"zstd": map[string]any{},
				"gzip": map[string]any{},
			},
			"prefer":         []string{"zstd", "gzip"},
			"minimum_length": 1024,
		})
	}
	// Custom handler chain (admin-supplied JSON array). Prepended before
	// `primary` so request-shaping logic (rate_limit, request_body, encode,
	// authentication) runs on the inbound side. Invalid JSON is rejected
	// by the save handler, so we don't validate again here.
	if strings.TrimSpace(r.CustomHandlers) != "" {
		var extra []any
		if err := json.Unmarshal([]byte(r.CustomHandlers), &extra); err == nil {
			handlers = append(handlers, extra...)
		}
	}
	// First-class rate_limit handler (mholt/caddy-ratelimit). Per-route zone so
	// counters never bleed across routes. Module-gated: without the module
	// stock Caddy rejects the unknown handler and the node goes offline.
	if r.RateLimitEnabled && r.RateLimitModuleAvailable {
		window := firstNonEmpty(r.RateLimitWindow, "1m")
		maxEvents := r.RateLimitMaxEvents
		if maxEvents <= 0 {
			maxEvents = 100
		}
		key := firstNonEmpty(r.RateLimitKey, "{http.request.remote.host}")
		handlers = append(handlers, map[string]any{
			"handler": "rate_limit",
			"rate_limits": map[string]any{
				"route_" + r.ID: map[string]any{
					"key":        key,
					"window":     window,
					"max_events": maxEvents,
				},
			},
		})
	}

	// WebSocket gate: Caddy v2 passes WS by default. When operator
	// disables WS for this route, prepend a matcher on the Upgrade
	// header that short-circuits to 426 Upgrade Required so the
	// request never reaches the upstream. Skip for non-proxy kinds.
	if !r.WebSocket && r.Kind != "redirect" && !r.MaintenanceMode {
		handlers = append(handlers, map[string]any{
			"handler": "subroute",
			"routes": []any{
				map[string]any{
					"match": []any{map[string]any{
						"header": map[string]any{"Connection": []string{"*Upgrade*"}},
					}},
					"handle": []any{map[string]any{
						"handler":     "static_response",
						"status_code": 426,
						"headers": map[string]any{
							"Upgrade":    []string{"HTTP/2.0"},
							"Connection": []string{"Upgrade"},
						},
						"body": "WebSocket connections are disabled on this route.\n",
					}},
					"terminal": true,
				},
			},
		})
	}

	// mTLS RBAC: path-based role check via panel internal endpoint.
	// Fires after geo/WAF/CIDR, before SSO/basic-auth so role access
	// is enforced even when those auth layers are not configured.
	if rbacH := buildMTLSRBAC(r); rbacH != nil {
		handlers = append(handlers, rbacH)
	}

	// SSO forward-auth gate: Authentik / Authelia / any provider that
	// answers /auth/caddy with 2xx for authorized users + sets headers.
	//
	// Caddy's `forward_auth` Caddyfile directive expands into a subroute
	// of [rewrite, reverse_proxy] - `rewrite` is NOT a field on
	// reverse_proxy, putting it there makes Caddy reject /load with
	// "loading module 'subroute': provision …". The outpost passthrough
	// is also a subroute so /outpost.goauthentik.io/* never hits the
	// auth gate (the user needs the IdP UI to log in).
	if r.SSOProviderURL != "" {
		dial := dialFromURL(r.SSOProviderURL)
		useTLS := isHTTPSProvider(r.SSOProviderURL)
		// SNI must match the cert presented by the IdP, so it follows the
		// dial hostname - NOT the preserved Host header (which is the
		// protected app's domain).
		sniHost := dial
		if i := strings.LastIndex(sniHost, ":"); i >= 0 {
			sniHost = sniHost[:i]
		}

		// Extract port from dial so SSO-via-tunnel can rebuild dial
		// against peer IP without losing the URL's port.
		ssoPort := ""
		if i := strings.LastIndex(dial, ":"); i >= 0 {
			ssoPort = dial[i+1:]
		}
		// SSO via tunnel: if a tunnel peer is bound, dial peer_ip:port
		// directly. Hostname from the URL is ignored (no DNS needed) -
		// peer host must expose the IdP port on its host network.
		dialHost := dial
		if r.SSOResolver != "" && ssoPort != "" {
			// JoinHostPort brackets IPv6 literals; bare concat breaks them.
			dialHost = net.JoinHostPort(r.SSOResolver, ssoPort)
		}
		mkRP := func(extra map[string]any) map[string]any {
			rp := map[string]any{
				"handler":   "reverse_proxy",
				"upstreams": []any{map[string]any{"dial": dialHost}},
			}
			if useTLS {
				rp["transport"] = map[string]any{
					"protocol": "http",
					"tls":      map[string]any{"server_name": sniHost},
				}
			}
			for k, v := range extra {
				rp[k] = v
			}
			return rp
		}

		// Authentik routes incoming outpost requests to a Provider by the
		// Host header (matching the Provider's External Host). When Caddy
		// proxies to https://sso.example.com, the default rewrite changes Host to
		// "sso.example.com" → no Provider matches → IdP returns a 404 page.
		// Preserving the original Host is mandatory for both subroutes.
		hostPreserve := map[string]any{
			"request": map[string]any{
				"set": map[string]any{
					"Host": []string{"{http.request.host}"},
				},
			},
		}

		// (1) Outpost passthrough - let the IdP serve /outpost.goauthentik.io/*
		// (login page, callback, assets) directly without any auth gate.
		handlers = append(handlers, map[string]any{
			"handler": "subroute",
			"routes": []any{
				map[string]any{
					"match": []any{map[string]any{
						"path": []string{"/outpost.goauthentik.io/*"},
					}},
					"handle":   []any{mkRP(map[string]any{"headers": hostPreserve})},
					"terminal": true,
				},
			},
		})

		// (2) Forward-auth: rewrite + reverse_proxy as TWO handlers inside
		// one subroute. On 2xx the auth response is dropped (handle_response
		// matches), the routes inside handle_response set the upstream
		// request headers from the auth response, and the parent subroute
		// continues to the next handler (the actual backend proxy).
		hr := map[string]any{
			"match": map[string]any{"status_code": []int{2}},
		}
		if h := ssoCopyHeadersHandle(r.SSOCopyHeaders); h != nil {
			hr["routes"] = []any{
				map[string]any{"handle": h},
			}
		}
		// hrHandlers starts with the success handler (2xx = continue to backend).
		// In strict mode, add a 3xx handler: IdP redirect = not authenticated = 401.
		hrHandlers := []any{hr}
		if r.SSOStrictMode {
			hrHandlers = append(hrHandlers, map[string]any{
				"match": map[string]any{"status_code": []int{3}},
				"routes": []any{
					map[string]any{
						"handle": []any{
							map[string]any{
								"handler":     "static_response",
								"status_code": 401,
								"headers":     map[string]any{"Content-Type": []string{"application/json"}},
								"body":        `{"error":"unauthorized"}`,
							},
						},
					},
				},
			})
		}
		// X-Forwarded-Uri MUST be the ORIGINAL request URI, not the
		// rewritten /outpost.goauthentik.io/auth/caddy. Authentik reads
		// that header to know where to redirect the user after login -
		// {http.request.uri} would evaluate to the rewritten URI (auth
		// runs after rewrite) and send the user to /auth/caddy on the
		// protected domain, which the backend treats as a 404.
		// request_buffers: -1 tells Caddy to buffer the entire request body
		// before sending it to the IdP. Without this the body is consumed
		// by the auth subrequest and downstream backend reads EOF - the
		// classic forward_auth + POST symptom (Proxmox's /api2/extjs/...
		// returns 502 because the POST body is empty by the time it
		// reaches port 8006).
		fwd := mkRP(map[string]any{
			"request_buffers": -1,
			"headers": map[string]any{
				"request": map[string]any{
					"set": map[string]any{
						"Host":               []string{"{http.request.host}"},
						"X-Forwarded-Method": []string{"{http.request.method}"},
						"X-Forwarded-Uri":    []string{"{http.request.orig_uri}"},
						"X-Forwarded-Host":   []string{"{http.request.host}"},
						"X-Forwarded-Proto":  []string{"{http.request.scheme}"},
						"X-Real-IP":          []string{"{http.request.remote.host}"},
					},
					// Drop Content-Length on the auth subrequest - the IdP
					// doesn't need the body. Caddy still streams the raw
					// body bytes; this header strip prevents the IdP from
					// blocking on an unexpected payload size.
					"delete": []string{"Content-Length"},
				},
			},
			"handle_response": hrHandlers,
		})
		// Forward-auth ONLY runs on safe methods (GET, HEAD). Caddy's
		// reverse_proxy consumes the request body when it sends the auth
		// subrequest - even with request_buffers + handle_response, the
		// body of a POST/PUT/PATCH/DELETE often arrives empty at the
		// backend (symptom: 502 from Proxmox /api2/extjs/... POSTs).
		//
		// Skipping mutations is safe: the user already proved a valid
		// Authentik session on the initial GET (which DID trigger the
		// auth gate). The session cookie travels with every subsequent
		// request, and the backend application has its own auth layer
		// on top - Proxmox uses its CSRFPreventionToken + auth ticket,
		// Authelia-protected apps typically share the session cookie,
		// etc.
		// Forward-auth matcher: GET/HEAD only, AND skip
		//  (a) common static asset extensions / asset path trees, and
		//  (b) browser XHR / fetch / subresource requests detected via
		//      Sec-Fetch-Dest (anything other than "document"/"iframe").
		//
		// (a) Hard SPA refresh fires dozens of parallel JS/CSS/font
		// requests; each one going through Authentik queues up and the
		// IdP's auth endpoint serialises behind its own DB calls →
		// tail-latency blows past Caddy's read timeout → 504.
		//
		// (b) The browser cannot follow a cross-origin 302 on an XHR /
		// fetch, so if Authentik replies with a redirect to sso.example.com the
		// request is killed by CORS. SPAs talking to their own backend
		// API (Proxmox, internal dashboards…) thus break under SSO
		// unless we bypass forward_auth for those subresource hits. The
		// upstream app must own its own API auth in this mode; SSO only
		// guarantees the document load is gated. Sec-Fetch-Dest is sent
		// by every modern browser - non-browser clients (curl, agents)
		// omit it and are still gated, which is the safer default.
		ssoMatch := map[string]any{
			"method": []string{"GET", "HEAD"},
			"not": []any{
				map[string]any{
					"path": []string{
						"*.js", "*.css", "*.map",
						"*.png", "*.jpg", "*.jpeg", "*.gif", "*.svg", "*.ico", "*.webp", "*.avif",
						"*.woff", "*.woff2", "*.ttf", "*.eot", "*.otf",
						"*.mp4", "*.webm", "*.mp3", "*.wav",
						"/pve2/*", "/static/*", "/assets/*", "/_next/static/*",
					},
				},
				map[string]any{
					"header": map[string]any{
						"Sec-Fetch-Dest": []string{
							"empty", "image", "font", "audio", "video",
							"manifest", "object", "embed", "track",
							"script", "style", "report",
							"worker", "serviceworker", "sharedworker",
						},
					},
				},
			},
		}
		// Per-route SSO scope: narrow the gate to specific paths and/or
		// hosts. Both filters AND with the static/XHR negation above.
		if len(r.SSOPaths) > 0 {
			ssoMatch["path"] = r.SSOPaths
		}
		if len(r.SSOHosts) > 0 {
			ssoMatch["host"] = r.SSOHosts
		}
		// In strict mode: gate all methods with no path/header exclusions.
		// In default mode: gate only GET/HEAD document loads (ssoMatch restrictions apply).
		authRoute := map[string]any{
			"handle": []any{
				map[string]any{
					"handler": "subroute",
					"routes": []any{
						map[string]any{
							"handle": []any{
								map[string]any{
									"handler": "rewrite",
									"method":  "GET",
									"uri":     "/outpost.goauthentik.io/auth/caddy",
								},
								fwd,
							},
						},
					},
				},
			},
		}
		if !r.SSOStrictMode {
			// Default mode only: restrict the auth gate to document-load GET/HEAD.
			// Strict mode (no match key) catches everything after the outpost passthrough.
			authRoute["match"] = []any{ssoMatch}
		}
		handlers = append(handlers, map[string]any{
			"handler": "subroute",
			"routes":  []any{authRoute},
		})
		// Belt + braces: restore the original URI after forward_auth so the
		// downstream backend reverse_proxy never sees the rewritten /auth/caddy
		// path. Caddy subroute scope doesn't reliably isolate URI rewrites;
		// this rewrite back to orig_uri is a no-op on the happy path and
		// safety net otherwise.
		handlers = append(handlers, map[string]any{
			"handler": "rewrite",
			"uri":     "{http.request.orig_uri}",
		})
	}

	// Built-in forward-auth portal. Same Caddy forward_auth mechanism as the
	// external-SSO block above, but the verifier is the panel itself. Fail
	// closed: when PortalProtect is on but no panel dial is reachable we skip
	// emission rather than serve the route unprotected with a stale config -
	// the route stays gated only if the verifier exists (callers must not set
	// PortalProtect without PortalDial).
	if r.PortalProtect && r.PortalDial != "" {
		handlers = append(handlers, buildPortalForwardAuth(r)...)
	}

	// Basic auth gate: Caddy's authentication handler with http_basic
	// provider. Returns 401 (with WWW-Authenticate) until the browser
	// supplies matching creds. Multi-user list takes precedence over single-user fields.
	if len(r.BasicAuthUsers) > 0 {
		accounts := make([]any, 0, len(r.BasicAuthUsers))
		for _, u := range r.BasicAuthUsers {
			accounts = append(accounts, map[string]any{
				"username": u.Username,
				"password": u.Hash,
			})
		}
		handlers = append(handlers, map[string]any{
			"handler": "authentication",
			"providers": map[string]any{
				"http_basic": map[string]any{
					"accounts": accounts,
					"hash":     map[string]any{"algorithm": "bcrypt"},
				},
			},
		})
	} else if r.BasicAuthUser != "" && r.BasicAuthBcrypt != "" {
		handlers = append(handlers, map[string]any{
			"handler": "authentication",
			"providers": map[string]any{
				"http_basic": map[string]any{
					"accounts": []any{
						map[string]any{
							"username": r.BasicAuthUser,
							"password": r.BasicAuthBcrypt,
						},
					},
					"hash": map[string]any{"algorithm": "bcrypt"},
				},
			},
		})
	}

	if len(r.LocationRules) > 0 && r.Kind != "redirect" && !r.MaintenanceMode {
		primary = buildLocationSubroute(r, primary)
	}
	handlers = append(handlers, primary)

	// Access list. Three modes:
	//   open       block_all=0, Deny=[]            -> everyone in
	//   blacklist  block_all=0, Deny=[X]           -> X out, rest in
	//   whitelist  block_all=1 (Allow=[Y], Deny=[Z]) -> Y minus Z in
	// Deny always evaluates first so a bad IP listed in Allow still 403s.
	// Empty config skips emission to keep open routes cheap.
	wantACL := r.AccessBlockAll || len(r.AccessAllow) > 0 || len(r.AccessDeny) > 0
	if wantACL {
		deny403 := map[string]any{
			"handler":     "static_response",
			"status_code": 403,
			"body":        "Forbidden\n",
		}
		var acl []any
		if len(r.AccessDeny) > 0 {
			acl = append(acl, map[string]any{
				"match": []any{map[string]any{
					"remote_ip": map[string]any{"ranges": r.AccessDeny},
				}},
				"handle":   []any{deny403},
				"terminal": true,
			})
		}
		if r.AccessBlockAll {
			if len(r.AccessAllow) > 0 {
				acl = append(acl, map[string]any{
					"match": []any{map[string]any{
						"not": []any{map[string]any{
							"remote_ip": map[string]any{"ranges": r.AccessAllow},
						}},
					}},
					"handle":   []any{deny403},
					"terminal": true,
				})
			} else {
				// block_all=1 with no Allow list = nobody. Single 403 catch-all.
				acl = append(acl, map[string]any{
					"handle":   []any{deny403},
					"terminal": true,
				})
			}
		}
		// ACL routes run BEFORE the proxy/cache chain via a subroute
		// wrapper so a 403 short-circuits without ever invoking upstream.
		inner := append([]any{}, handlers...)
		handlers = []any{map[string]any{
			"handler": "subroute",
			"routes":  append(acl, map[string]any{"handle": inner, "terminal": true}),
		}}
	}

	// Force HTTPS: redirect cleartext traffic on the same host.
	if r.ForceHTTPS {
		handlers = forceHTTPSWrap(handlers, r.Hosts)
	}

	return map[string]any{
		"@id":      "route_" + r.ID,
		"match":    []any{match},
		"handle":   handlers,
		"terminal": true,
	}
}

// forceHTTPSWrap returns a single-element subroute that 308s cleartext
// requests to https:// and otherwise delegates to the supplied handler
// chain. Shared between proxy/redirect/maintenance paths so the upgrade
// behaves identically regardless of Kind.
func forceHTTPSWrap(inner []any, hosts []string) []any {
	innerCopy := append([]any{}, inner...)
	return []any{
		map[string]any{
			"handler": "subroute",
			"routes": []any{
				map[string]any{
					"match": []any{map[string]any{
						"protocol": "http",
						"host":     hosts,
					}},
					"handle": []any{
						map[string]any{
							"handler":     "static_response",
							"status_code": 308,
							"headers": map[string]any{
								"Location": []string{"https://{http.request.host}{http.request.uri}"},
							},
						},
					},
				},
				map[string]any{
					"handle":   innerCopy,
					"terminal": true,
				},
			},
		},
	}
}

// htmlEscape is a tiny escaper for the maintenance page body - operator
// supplies a free-text message, we splice it inside <p>…</p>. Don't pull
// html/template just for one substitution.
func htmlEscape(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '&':
			out = append(out, []byte("&amp;")...)
		case '<':
			out = append(out, []byte("&lt;")...)
		case '>':
			out = append(out, []byte("&gt;")...)
		case '"':
			out = append(out, []byte("&quot;")...)
		case '\'':
			out = append(out, []byte("&#39;")...)
		default:
			out = append(out, s[i])
		}
	}
	return string(out)
}

// dial builds a host:port string for Caddy's upstream dial field.
// net.JoinHostPort brackets bare IPv6 literals so Caddy can parse them.
func dial(ip string, port int) string {
	return net.JoinHostPort(ip, itoa(port))
}

// firstNonEmpty returns the first non-empty string, or "".
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// dialFromURL extracts host:port from a URL string like
// "http://outpost.company:9000" → "outpost.company:9000". Falls back to
// the raw input when parsing fails so a stray hostname still produces
// something dial-able instead of an empty string.
//
// Default port depends on scheme: https → 443, otherwise 9000 (Authentik
// embedded outpost). Without scheme + port → 9000 (legacy behaviour).
func dialFromURL(raw string) string {
	s := strings.TrimSpace(raw)
	scheme := ""
	for _, prefix := range []string{"https://", "http://"} {
		if strings.HasPrefix(s, prefix) {
			scheme = strings.TrimSuffix(prefix, "://")
			s = s[len(prefix):]
			break
		}
	}
	if i := strings.Index(s, "/"); i >= 0 {
		s = s[:i]
	}
	if s == "" {
		return raw
	}
	if !strings.Contains(s, ":") {
		if scheme == "https" {
			s += ":443"
		} else {
			s += ":9000"
		}
	}
	return s
}

// isHTTPSProvider returns true when the SSO URL starts with https://.
// Used to gate the transport.tls block on forward_auth + outpost subroute
// reverse_proxy emissions - without it Caddy speaks plain HTTP to port
// 443 and the outpost rejects the request.
func isHTTPSProvider(raw string) bool {
	return strings.HasPrefix(strings.TrimSpace(raw), "https://")
}

func buildEarlyLocationSubroute(r Route) map[string]any {
	if r.Kind == "redirect" || r.MaintenanceMode {
		return nil
	}
	routes := make([]any, 0, len(r.LocationRules))
	for _, rule := range r.LocationRules {
		switch rule.Action {
		case "block", "redirect":
		default:
			continue
		}
		entry, ok := buildLocationRuleRoute(rule, nil)
		if ok {
			routes = append(routes, entry)
		}
	}
	if len(routes) == 0 {
		return nil
	}
	return map[string]any{"handler": "subroute", "routes": routes}
}

func buildLocationSubroute(r Route, defaultPrimary map[string]any) map[string]any {
	routes := make([]any, 0, len(r.LocationRules)+1)
	for _, rule := range r.LocationRules {
		switch rule.Action {
		case "proxy", "rewrite", "":
		default:
			continue
		}
		entry, ok := buildLocationRuleRoute(rule, defaultPrimary)
		if ok {
			routes = append(routes, entry)
		}
	}
	if len(routes) == 0 {
		return defaultPrimary
	}
	routes = append(routes, map[string]any{
		"handle":   []any{defaultPrimary},
		"terminal": true,
	})
	return map[string]any{
		"handler": "subroute",
		"routes":  routes,
	}
}

func buildLocationRuleRoute(rule LocationRule, defaultPrimary map[string]any) (map[string]any, bool) {
	paths := locationPathMatchers(rule.Path)
	if len(paths) == 0 {
		return nil, false
	}
	entry := map[string]any{
		"match": []any{map[string]any{"path": paths}},
	}
	switch rule.Action {
	case "block":
		entry["handle"] = []any{map[string]any{
			"handler":     "static_response",
			"status_code": 403,
			"body":        "Forbidden\n",
		}}
	case "redirect":
		if strings.TrimSpace(rule.RedirectURL) == "" {
			return nil, false
		}
		code := rule.RedirectCode
		if code == 0 {
			code = 308
		}
		entry["handle"] = []any{map[string]any{
			"handler":     "static_response",
			"status_code": code,
			"headers": map[string]any{
				"Location": []string{rule.RedirectURL},
			},
		}}
	case "rewrite":
		if defaultPrimary == nil || strings.TrimSpace(rule.RewriteURI) == "" {
			return nil, false
		}
		entry["handle"] = []any{
			map[string]any{"handler": "rewrite", "uri": rule.RewriteURI},
			defaultPrimary,
		}
	default:
		if strings.TrimSpace(rule.UpstreamHost) == "" || rule.UpstreamPort <= 0 {
			return nil, false
		}
		transport := map[string]any{
			"protocol":     "http",
			"dial_timeout": "10s",
		}
		if rule.UpstreamScheme == "https" {
			transport["tls"] = map[string]any{}
		}
		entry["handle"] = []any{map[string]any{
			"handler":        "reverse_proxy",
			"flush_interval": -1,
			"upstreams":      []any{map[string]any{"dial": dial(rule.UpstreamHost, rule.UpstreamPort)}},
			"transport":      transport,
		}}
	}
	entry["terminal"] = true
	return entry, true
}

func locationPathMatchers(path string) []string {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if path == "/" || path == "/*" {
		return []string{"/*"}
	}
	if strings.HasSuffix(path, "/*") {
		exact := strings.TrimSuffix(path, "/*")
		if exact == "" {
			return []string{"/*"}
		}
		return []string{exact, path}
	}
	return []string{path}
}

// buildLoadBalancing returns the load_balancing object, or nil when no policy
// is chosen (Caddy then uses its random default). weighted_round_robin is
// downgraded to round_robin when the module isn't guaranteed available so a
// stock node never rejects the /load.
// caddy-maxmind-geolocation module identifiers. DOUBLE-CHECK these field names
// against the actual module before flipping GEOIP_AVAILABLE in prod: matcher name
// "maxmind_geolocation", config keys "db_path" / "allow_countries" /
// "deny_countries". Centralised so a rename is a one-line edit.
const (
	geoMatcherName = "maxmind_geolocation"
	geoFieldDBPath = "db_path"
	geoFieldAllow  = "allow_countries"
	geoFieldDeny   = "deny_countries"
	geoDBPath      = "/data/geoip/GeoLite2-Country.mmdb"
)

// buildGeoBlock returns a subroute handler that blocks requests from disallowed
// countries, or nil when geo blocking is off / no countries / module absent.
//
// deny mode: matcher uses deny_countries=[list] (matches requests FROM those
// countries) -> the matched request is the blocked one, so handle deny directly.
// allow mode: matcher uses allow_countries=[list] (matches requests FROM allowed
// countries); wrap in `not` so the handler fires for the NON-allowed set -> deny.
// splitCIDRList parses a free-form IP/CIDR list from a textarea or comma list.
// Splitting only on comma left newline-separated entries as one bogus "IP",
// which made Caddy reject the whole /load with a remote_ip ParseAddr error.
//
// dropInvalid controls fail direction for unparseable tokens (entries are
// normally validated at save, so this only guards legacy/raw data):
//   - true  (allow-list bypass): drop bad tokens. Failing to bypass is safe -
//     those IPs stay subject to the geo block (more restrictive).
//   - false (block-list deny): keep bad tokens. A dropped deny entry would fail
//     OPEN (let blocked traffic through); keeping it makes Caddy reject the
//     route loudly instead, so the block is never silently lost.
func splitCIDRList(s string, dropInvalid bool) []string {
	var out []string
	for _, p := range strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	}) {
		v := strings.TrimSpace(p)
		if v == "" {
			continue
		}
		if dropInvalid {
			if _, _, err := net.ParseCIDR(v); err != nil && net.ParseIP(v) == nil {
				continue
			}
		}
		out = append(out, v)
	}
	return out
}

// geoBlockResponse builds the handler returned to a geo/CIDR-blocked request.
// 444 maps to Caddy's connection abort (Nginx-style "no response"); other codes
// return that status with a reason body that matches the chosen code (the body
// was previously hardcoded to "Forbidden" regardless of the selected code).
func geoBlockResponse(r Route) map[string]any {
	code := r.GeoResponseCode
	if code == 0 {
		code = 403
	}
	action := strings.ToLower(strings.TrimSpace(r.GeoBlockAction))

	// Redirect: send blocked visitors to another URL instead of an error.
	if action == "redirect" && strings.TrimSpace(r.GeoRedirectURL) != "" {
		return map[string]any{
			"handler":     "static_response",
			"status_code": 302,
			"headers":     map[string]any{"Location": []string{r.GeoRedirectURL}},
		}
	}

	// 444 is not a real HTTP status: drop the connection with no response.
	if code == 444 {
		return map[string]any{"handler": "static_response", "abort": true}
	}

	// Branded HTML page with the client's title/message/logo/background.
	if action == "page" {
		title := strings.TrimSpace(r.GeoBlockTitle)
		if title == "" {
			title = "Access denied"
		}
		msg := strings.TrimSpace(r.GeoBlockMessage)
		if msg == "" {
			msg = "Access from your region is not allowed."
		}
		return map[string]any{
			"handler":     "static_response",
			"status_code": code,
			"headers": map[string]any{
				"Content-Type":  []string{"text/html; charset=utf-8"},
				"Cache-Control": []string{"no-store"},
			},
			"body": renderErrorPage(code, title, msg, r.GeoBlockBranding),
		}
	}

	// Default: plain reason body matching the chosen status code.
	body := http.StatusText(code)
	if body == "" {
		body = "Forbidden"
	}
	return map[string]any{
		"handler":     "static_response",
		"status_code": code,
		"body":        body + "\n",
	}
}

// GeoAllowCIDRs: IPs/CIDRs added as a NOT remote_ip condition, bypassing the block.
// GeoFailClosed: when module unavailable, block all traffic instead of passing through.
func buildGeoBlock(r Route) map[string]any {
	mode := strings.ToLower(strings.TrimSpace(r.GeoMode))
	if mode != "allow" && mode != "deny" {
		return nil
	}

	denyResp := geoBlockResponse(r)

	if !r.GeoModuleAvailable {
		if !r.GeoFailClosed {
			return nil
		}
		// Fail-closed: block everything when geo module is missing.
		return map[string]any{
			"handler": "subroute",
			"routes": []any{map[string]any{
				"handle":   []any{denyResp},
				"terminal": true,
			}},
		}
	}

	// Collect country codes; expand any selected continent to its member ISO
	// codes (the maxmind module matches only on country, so continents are
	// resolved panel-side - emitting *_continents keys would reject /load).
	seen := make(map[string]struct{})
	var countries []string
	addCountry := func(c string) {
		if c = strings.ToUpper(strings.TrimSpace(c)); c == "" {
			return
		}
		if _, dup := seen[c]; dup {
			return
		}
		seen[c] = struct{}{}
		countries = append(countries, c)
	}
	for _, c := range strings.Split(r.GeoCountries, ",") {
		addCountry(c)
	}
	for _, cont := range strings.Split(r.GeoContinents, ",") {
		cont = strings.ToUpper(strings.TrimSpace(cont))
		for _, c := range geoip.CountriesInContinent(cont) {
			addCountry(c)
		}
	}
	if len(countries) == 0 {
		return nil
	}

	// Parse CIDR allow-list; matching IPs skip the country block.
	allowRanges := splitCIDRList(r.GeoAllowCIDRs, true)

	// The maxmind matcher returns TRUE when the request is PERMITTED (country
	// not in deny list / in allow list), so the terminal-deny route must fire on
	// NOT(matcher) in BOTH modes. The only per-mode difference is which field is
	// populated. Wrapping deny in `not` as well fixes the previously inverted
	// deny logic (which blocked everyone EXCEPT the listed country).
	geoConf := map[string]any{geoFieldDBPath: geoDBPath}
	if mode == "deny" {
		geoConf[geoFieldDeny] = countries
	} else {
		geoConf[geoFieldAllow] = countries
	}
	match := map[string]any{
		"not": []any{map[string]any{geoMatcherName: geoConf}},
	}

	// Add NOT remote_ip condition: IPs in allow-list pass through regardless of
	// country (allowlist overrides the geo block, in both modes).
	if len(allowRanges) > 0 {
		notList, _ := match["not"].([]any)
		notList = append(notList, map[string]any{
			"remote_ip": map[string]any{"ranges": allowRanges},
		})
		match["not"] = notList
	}

	// Subroute wrapper: deny short-circuits before any later handler/upstream.
	return map[string]any{
		"handler": "subroute",
		"routes": []any{map[string]any{
			"match":    []any{match},
			"handle":   []any{denyResp},
			"terminal": true,
		}},
	}
}

// buildCIDRBlock returns a subroute that always blocks requests from specific
// IPs/CIDRs, regardless of geo mode. Fires before geo country/continent check.
func buildCIDRBlock(r Route) map[string]any {
	ranges := splitCIDRList(r.GeoBlockCIDRs, false)
	if len(ranges) == 0 {
		return nil
	}
	return map[string]any{
		"handler": "subroute",
		"routes": []any{map[string]any{
			"match": []any{map[string]any{
				"remote_ip": map[string]any{"ranges": ranges},
			}},
			"handle":   []any{geoBlockResponse(r)},
			"terminal": true,
		}},
	}
}

func buildLoadBalancing(r Route) map[string]any {
	policy := r.LBPolicy
	if policy == "weighted_round_robin" && !r.WeightedLBAvailable {
		policy = "round_robin"
	}
	if policy == "" {
		return nil
	}
	sel := map[string]any{"policy": policy}
	switch policy {
	case "header":
		if r.LBHeaderField != "" {
			sel["field"] = r.LBHeaderField
		}
	case "cookie":
		if r.LBCookieName != "" {
			sel["name"] = r.LBCookieName
		}
		if r.LBCookieSecret != "" {
			sel["secret"] = r.LBCookieSecret
		}
	}
	if policy == "weighted_round_robin" {
		// Weights map 1:1 positionally to the emitted upstreams array.
		weights := make([]any, 0, len(r.Upstreams)+1)
		if len(r.Upstreams) > 0 {
			for _, u := range r.Upstreams {
				w := u.Weight
				if w <= 0 {
					w = 1
				}
				weights = append(weights, w)
			}
		} else {
			weights = append(weights, 1)
		}
		sel["weights"] = weights
	}
	// Interval=0 means no delay between attempts; bypass the msDur default path.
	tryInterval := "0s"
	if r.LBTryIntervalMs > 0 {
		tryInterval = msDur(r.LBTryIntervalMs, 250)
	}
	return map[string]any{
		"selection_policy": sel,
		"try_duration":     msDur(r.LBTryDurationMs, 5000),
		"try_interval":     tryInterval,
	}
}

// buildHealthChecks returns the health_checks object, or nil when both active
// and passive checks are disabled.
func buildHealthChecks(r Route) map[string]any {
	active := map[string]any{}
	if strings.TrimSpace(r.HealthURI) != "" {
		active["uri"] = r.HealthURI
		active["interval"] = secs(r.HealthIntervalSecs, 10)
		active["timeout"] = secs(r.HealthTimeoutSecs, 5)
		if r.HealthExpectStatus > 0 {
			active["expect_status"] = r.HealthExpectStatus
		}
		if r.HealthFails > 0 {
			active["fails"] = r.HealthFails
		}
	}
	passive := map[string]any{}
	if r.HealthPassive {
		// fail_duration must be non-zero or Caddy silently disables ejection.
		passive["fail_duration"] = secs(r.HealthFailDurationSecs, 30)
		if r.HealthMaxFails > 0 {
			passive["max_fails"] = r.HealthMaxFails
		}
		passive["unhealthy_status"] = []any{500, 502, 503, 504}
	}
	out := map[string]any{}
	if len(active) > 0 {
		out["active"] = active
	}
	if len(passive) > 0 {
		out["passive"] = passive
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// secs formats N seconds as a Caddy duration string, falling back to def.
func secs(n, def int) string {
	if n <= 0 {
		n = def
	}
	return itoa(n) + "s"
}

// msDur formats N milliseconds as a Caddy duration string, falling back to defMs.
func msDur(n, defMs int) string {
	if n <= 0 {
		n = defMs
	}
	if n%1000 == 0 {
		return itoa(n/1000) + "s"
	}
	return itoa(n) + "ms"
}

// ssoCopyHeadersHandle returns the JSON form Caddy accepts for copying
// selected IdP auth-response headers into the upstream request.
func ssoCopyHeadersHandle(hdrs []string) []any {
	set := map[string]any{}
	for _, h := range hdrs {
		k := strings.TrimSpace(h)
		if k == "" {
			continue
		}
		set[k] = []string{"{http.reverse_proxy.header." + k + "}"}
	}
	if len(set) == 0 {
		return nil
	}
	return []any{
		map[string]any{
			"handler": "headers",
			"request": map[string]any{"set": set},
		},
	}
}

// buildPortalForwardAuth emits the Caddy handler chain for the built-in
// access portal: a passthrough subroute so /hpg-portal/* (login UI + verify)
// reaches the panel un-gated, then a forward_auth subroute that calls the
// panel's verify endpoint on every GET/HEAD document load. The panel returns
// 2xx when the portal session is allowed for this host, 401/302 otherwise.
//
// Mirrors the external-SSO emission: original Host is preserved so the panel
// knows which protected host is being requested, and X-Forwarded-* carry the
// original method/uri/proto for the redirect-back handshake. Static assets +
// XHR are skipped (same rationale as SSO) so a hard refresh doesn't stampede
// the verifier and so cross-origin XHR redirects don't break SPAs.
func buildPortalForwardAuth(r Route) []any {
	mkRP := func(extra map[string]any) map[string]any {
		rp := map[string]any{
			"handler":   "reverse_proxy",
			"upstreams": []any{map[string]any{"dial": r.PortalDial}},
		}
		if r.PortalTLS {
			tls := map[string]any{}
			if r.PortalSNI != "" {
				tls["server_name"] = r.PortalSNI
			}
			rp["transport"] = map[string]any{"protocol": "http", "tls": tls}
		}
		for k, v := range extra {
			rp[k] = v
		}
		return rp
	}
	hostPreserve := map[string]any{
		"request": map[string]any{
			"set": map[string]any{"Host": []string{"{http.request.host}"}},
		},
	}

	out := make([]any, 0, 3)
	// (1) Passthrough: the panel serves /hpg-portal/* (login form, submit,
	// verify, assets) directly without the auth gate, or the user could never
	// reach the login page.
	out = append(out, map[string]any{
		"handler": "subroute",
		"routes": []any{
			map[string]any{
				"match":    []any{map[string]any{"path": []string{"/hpg-portal/*"}}},
				"handle":   []any{mkRP(map[string]any{"headers": hostPreserve})},
				"terminal": true,
			},
		},
	})

	// (2) forward_auth: 2xx continues to the backend; any non-2xx (401/302)
	// is returned to the client so the browser follows the redirect to login.
	hr := map[string]any{"match": map[string]any{"status_code": []int{2}}}
	fwd := mkRP(map[string]any{
		"request_buffers": -1,
		"headers": map[string]any{
			"request": map[string]any{
				"set": map[string]any{
					"Host":               []string{"{http.request.host}"},
					"X-Forwarded-Method": []string{"{http.request.method}"},
					"X-Forwarded-Uri":    []string{"{http.request.orig_uri}"},
					"X-Forwarded-Host":   []string{"{http.request.host}"},
					"X-Forwarded-Proto":  []string{"{http.request.scheme}"},
					"X-Real-IP":          []string{"{http.request.remote.host}"},
				},
				"delete": []string{"Content-Length"},
			},
		},
		"handle_response": []any{hr},
	})
	// All methods verified; skip only static file extensions (no auth bypass for POST/XHR).
	portalMatch := map[string]any{
		"not": []any{
			map[string]any{"path": []string{
				"*.js", "*.css", "*.map",
				"*.png", "*.jpg", "*.jpeg", "*.gif", "*.svg", "*.ico", "*.webp", "*.avif",
				"*.woff", "*.woff2", "*.ttf", "*.eot", "*.otf",
				"*.mp4", "*.webm", "*.mp3", "*.wav",
				"/static/*", "/assets/*", "/_next/static/*",
			}},
		},
	}
	authRoute := map[string]any{
		"match": []any{portalMatch},
		"handle": []any{
			map[string]any{
				"handler": "subroute",
				"routes": []any{
					map[string]any{
						"handle": []any{
							map[string]any{"handler": "rewrite", "method": "GET", "uri": "/hpg-portal/verify"},
							fwd,
						},
					},
				},
			},
		},
	}
	out = append(out, map[string]any{"handler": "subroute", "routes": []any{authRoute}})
	// Restore original URI so the backend proxy never sees /hpg-portal/verify.
	out = append(out, map[string]any{"handler": "rewrite", "uri": "{http.request.orig_uri}"})
	return out
}

// itoa avoids strconv dep in this hot path; ports are 1..65535.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [6]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// buildMTLSRBAC returns a subroute handler that calls the panel's internal
// RBAC endpoint for path-based role checks on mTLS routes. Nil when disabled.
func buildMTLSRBAC(r Route) map[string]any {
	if len(r.MTLSPathRules) == 0 || r.PanelBaseURL == "" {
		return nil
	}
	routeID := strconv.FormatInt(0, 10)
	if id, err := strconv.ParseInt(r.ID, 10, 64); err == nil {
		routeID = strconv.FormatInt(id, 10)
	}
	checkPath := "/internal/mtls-rbac/" + routeID

	// Caddy placeholder for client cert subject DN (available when TLS policy requires client cert).
	const certSubjectPlaceholder = "{http.request.tls.client.subject}"

	return map[string]any{
		"handler": "subroute",
		"routes": []any{
			map[string]any{
				"handle": []any{
					// Inject cert subject header before the auth subrequest.
					map[string]any{
						"handler": "headers",
						"request": map[string]any{
							"set": map[string]any{
								"X-Mtls-Subject": []string{certSubjectPlaceholder},
							},
						},
					},
					// forward_auth pattern: reverse_proxy rewritten to the check endpoint.
					// request_buffers:-1 preserves POST/PUT/PATCH bodies for the backend
					// after the auth subrequest (same pattern as SSO forward_auth).
					// Non-2xx from panel blocks the request with 403.
					map[string]any{
						"handler":         "reverse_proxy",
						"upstreams":       []any{map[string]any{"dial": panelDial(r.PanelBaseURL)}},
						"request_buffers": -1,
						"headers": map[string]any{
							"request": map[string]any{
								"set": map[string]any{
									"X-Mtls-Subject":     []string{certSubjectPlaceholder},
									"X-Forwarded-Uri":    []string{"{http.request.orig_uri}"},
									"X-Forwarded-Method": []string{"{http.request.method}"},
								},
								"delete": []string{"Content-Length"},
							},
						},
						"rewrite": map[string]any{
							"method": "GET",
							"uri":    checkPath,
						},
						"handle_response": []any{
							// 2xx: auth passed - continue to next handler.
							map[string]any{
								"match": map[string]any{"status_code": []int{2}},
							},
							// non-2xx: block with 403.
							map[string]any{
								"routes": []any{
									map[string]any{
										"handle": []any{
											map[string]any{
												"handler":     "static_response",
												"status_code": 403,
												"body":        "Forbidden\n",
											},
										},
										"terminal": true,
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

// panelDial extracts the host:port dial target from a panel base URL.
func panelDial(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return "127.0.0.1:8080"
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	return net.JoinHostPort(host, port)
}
