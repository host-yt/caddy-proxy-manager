package caddyapi

import (
	"encoding/json"
	"strings"
)

// Route builders. Produce Caddy JSON config fragments for reverse-proxy routes.
// Reference schema: https://caddyserver.com/docs/json/apps/http/servers/routes/

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
	// LBPolicy: "" | "round_robin" | "least_conn" | "ip_hash" |
	// "weighted_round_robin". Emitted as load_balancing.selection_policy.
	LBPolicy string
	// WeightedLBAvailable gates weighted_round_robin (not guaranteed stock).
	// When false and LBPolicy=="weighted_round_robin" the builder downgrades
	// to round_robin so stock Caddy never rejects the /load.
	WeightedLBAvailable bool

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

	// OutboundIPMode: "default" = OS picks egress IP; "fixed" = bind transport
	// local_addr to OutboundIP so the connection leaves via a specific NIC IP.
	OutboundIPMode string
	OutboundIP     string // must be a bare IP present on the node NIC
}

// Upstream is one backend dial target plus its weighted-LB weight.
type Upstream struct {
	Host   string
	Port   int
	Weight int // only consumed by weighted_round_robin
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
					"addresses": []string{r.BackendResolver + ":53"},
				},
			}
		} else if !r.External && len(r.Upstreams) > 0 {
			// Multi-backend pool (plain internal proxy only). Order is
			// significant: weighted_round_robin weights map 1:1 positionally.
			ups := make([]any, 0, len(r.Upstreams))
			for _, u := range r.Upstreams {
				ups = append(ups, map[string]any{"dial": dial(u.Host, u.Port)})
			}
			primary["upstreams"] = ups
		} else {
			primary["upstreams"] = []any{map[string]any{"dial": dial(r.UpstreamIP, r.UpstreamPort)}}
		}
		// Bounded HTTP transport: a dead upstream must fail the dial fast
		// instead of pinning the proxied request. Keep-alive pooling is
		// Caddy's default (32 idle conns/host, 2m idle) so we don't restate it.
		transport := map[string]any{
			"protocol":     "http",
			"dial_timeout": "10s",
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
		// Fixed egress IP: bind the outgoing connection to a specific NIC address
		// so the upstream sees a predictable source IP. The IP must be present on
		// the node's network interface; Caddy rejects /load if it is missing.
		if r.OutboundIPMode == "fixed" && r.OutboundIP != "" {
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
		// pool. External (single FQDN) and the WG dynamic_upstreams resolver
		// keep their single-source behaviour (Caddy forbids mixing).
		if !r.External && r.BackendResolver == "" {
			if lb := buildLoadBalancing(r); lb != nil {
				primary["load_balancing"] = lb
			}
			if hc := buildHealthChecks(r); hc != nil {
				primary["health_checks"] = hc
			}
		}
	}

	handlers := []any{}
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
		r.SSOProviderURL == "" && r.BasicAuthUser == "" {
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
			dialHost = r.SSOResolver + ":" + ssoPort
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

	// Basic auth gate: Caddy's authentication handler with http_basic
	// provider. Returns 401 (with WWW-Authenticate) until the browser
	// supplies matching creds. Hash is bcrypt (matches Caddy's default
	// account.password format).
	if r.BasicAuthUser != "" && r.BasicAuthBcrypt != "" {
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

func dial(ip string, port int) string {
	return ip + ":" + itoa(port)
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

// ssoCopyHeadersHandle returns the `handle` slice that, when nested under
// reverse_proxy's `handle_response.routes[].handle`, copies headers from
// the IdP's auth response into the upstream request. The Caddyfile-only
// `copy_headers` shortcut compiles down to a `headers` handler that uses
// the `{http.reverse_proxy.header.X-Foo}` placeholder per header.
//
// Caddy's reverse_proxy schema rejects `copy_headers` as a direct field on
// either reverse_proxy or handle_response - this expansion is the only
// buildLoadBalancing returns the load_balancing object, or nil when no policy
// is chosen (Caddy then uses its random default). weighted_round_robin is
// downgraded to round_robin when the module isn't guaranteed available so a
// stock node never rejects the /load.
func buildLoadBalancing(r Route) map[string]any {
	policy := r.LBPolicy
	if policy == "weighted_round_robin" && !r.WeightedLBAvailable {
		policy = "round_robin"
	}
	if policy == "" {
		return nil
	}
	sel := map[string]any{"policy": policy}
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
	return map[string]any{
		"selection_policy": sel,
		"try_duration":     "5s",
		"try_interval":     "250ms",
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

// JSON form Caddy accepts.
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
