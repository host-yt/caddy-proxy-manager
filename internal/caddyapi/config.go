package caddyapi

import "fmt"

// NodeSettings carries per-node TLS + ACME knobs needed to build a full
// Caddy JSON config.
//
// PanelRoute (when non-nil) is prepended to the route list on every push.
// It is the panel's self-bootstrap route: the operator pointed their
// public panel domain (e.g. proxy.host.yt) at this node's IP via DNS,
// and we want Caddy to forward those requests back to the app container
// without the operator having to first log in and create a client+service
// just to expose the panel itself. This route is "virtual" - it does not
// live in the routes table, so it cannot be edited from the admin UI.
type NodeSettings struct {
	ACMEEmail   string
	ACMEStaging bool
	AskURL      string // e.g. http://app:8080/internal/ask
	PanelRoute  *Route

	// CacheModuleAvailable gates emission of the Souin cache-handler
	// blocks (apps.cache + per-route handler). Stock caddy:2.8 returns
	// "unknown app" / "unknown handler" and rejects the entire config,
	// taking the node offline; only flip this on once every target node
	// runs the custom Caddy image (deploy/caddy/Dockerfile, xcaddy build
	// with caddy-cache-handler). Driven by env CACHE_HANDLER_AVAILABLE=1
	// or the per-node `cache_handler_available` column.
	CacheModuleAvailable bool

	// Layer4ModuleAvailable gates emission of the apps.layer4 block.
	// Same rationale as CacheModuleAvailable: stock Caddy without
	// mholt/caddy-l4 rejects the whole config. Driven by env
	// LAYER4_AVAILABLE=1.
	Layer4ModuleAvailable bool
	StreamRoutes          []StreamRoute

	// RateLimitModuleAvailable gates per-route rate_limit handler emission
	// (mholt/caddy-ratelimit). Env: RATE_LIMIT_AVAILABLE=1. Stock Caddy
	// rejects the unknown handler name, taking the node offline.
	RateLimitModuleAvailable bool

	// WAFModuleAvailable gates the per-route coraza WAF handler. Env:
	// WAF_MODULE_AVAILABLE=1. Non-stock (corazawaf/coraza-caddy).
	WAFModuleAvailable bool

	// DNS01ModuleAvailable gates emission of DNS-01 wildcard automation
	// policies (the caddy-dns provider issuer). Stock Caddy rejects an
	// unknown DNS provider module and fails the whole /load, same footgun as
	// Cache/Layer4 but a bigger blast radius (TLS failure can stall issuance
	// for non-wildcard sites too). Env DNS01_AVAILABLE=1; default off.
	DNS01ModuleAvailable bool

	// WildcardPolicies is the per-node set of wildcard zones to issue via
	// DNS-01, each with its decrypted provider credential. Built by the routes
	// service from dns_providers x routes(wildcard_zone) for this node. Only
	// emitted when DNS01ModuleAvailable is true.
	WildcardPolicies []WildcardPolicy

	// ErrorBranding feeds the shared HTML template used by maintenance
	// pages + handle_errors (404/403/5xx). Empty fields fall back to a
	// neutral deep-gray skin so a brand-less install still looks clean.
	ErrorBranding ErrorBranding

	// WstunnelRoute, when non-nil, adds a reverse-proxy route for the wstunnel
	// WebSocket server that lets customers tunnel WG over HTTPS when UDP is blocked.
	WstunnelRoute *WstunnelRoute

	// AccessLogURL, when non-empty, enables structured JSON access logging on
	// the node. Caddy writes to a rolling file (AccessLogFilePath); the
	// node-agent tails it and forwards lines to the panel's authenticated
	// /internal/access-log. Empty = logs stay on Caddy's stderr.
	AccessLogURL string
}

// AccessLogFilePath is the on-node file both Caddy (writer) and the node-agent
// (tailer/forwarder) agree on. Mount a shared volume here in the node compose.
const AccessLogFilePath = "/var/log/caddy/access.log"

// WstunnelRoute carries the node-level data for the wstunnel Caddy route.
type WstunnelRoute struct {
	NodeID   int64
	Hostname string // node's public hostname (e.g. "p1-tunel.node.yt")
	Port     int    // loopback port where wstunnel server binds
}

// WildcardPolicy describes one DNS-01 automation policy: a *.Zone cert
// (plus the apex Zone itself) issued through Provider. Fields is the decrypted
// credential field map (registry key -> value); it must never be logged.
type WildcardPolicy struct {
	Zone     string            // apex, e.g. "customer.com"
	Provider string            // registry slug, e.g. "cloudflare"
	Fields   map[string]string // decrypted credentials; never logged
}

// providerJSON renders the caddy-dns provider object for an ACME DNS-01
// issuer from the registry: emits {"name": <CaddyModule>, <field key>: <value>}.
// An unknown slug yields nil so the caller drops the policy rather than emit a
// config Caddy would reject. Service-layer validation already gates this.
func providerJSON(slug string, fields map[string]string) map[string]any {
	p, ok := DNSProviderBySlug(slug)
	if !ok {
		return nil
	}
	out := map[string]any{"name": p.CaddyModule}
	for _, f := range p.Fields {
		if v, ok := fields[f.Key]; ok && v != "" {
			out[f.Key] = v
		}
	}
	return out
}

// ErrorBranding lets the panel customise the look of error / maintenance
// pages served by Caddy (no upstream involved). Logo + link come from
// settings; bg colour defaults to deep slate.
type ErrorBranding struct {
	LogoURL  string // absolute or panel-relative URL
	LogoLink string // where the logo links (e.g. brand homepage)
	BgColor  string // CSS colour value (e.g. "#0f172a")
	Brand    string // short brand label shown under the logo when no image
}

// BuildNodeConfig renders the full Caddy JSON config for one node from
// the supplied routes. POST this to /load on the node's Admin API.
//
// Shape (simplified):
//
//	apps.http.servers.srv0.routes = [ ...one per app route... ]
//	apps.tls.automation.on_demand = { ask, rate_limit }
//	apps.tls.automation.policies   = [{ on_demand: true, issuers: [acme(staging?)] }]
func BuildNodeConfig(routes []Route, s NodeSettings) map[string]any {
	out := make([]any, 0, len(routes)+1)
	if s.PanelRoute != nil {
		pr := *s.PanelRoute
		pr.CacheModuleAvailable = s.CacheModuleAvailable
		pr.RateLimitModuleAvailable = s.RateLimitModuleAvailable
		pr.WAFModuleAvailable = s.WAFModuleAvailable
		out = append(out, BuildRoute(pr))
	}
	if wr := s.WstunnelRoute; wr != nil && wr.Hostname != "" && wr.Port > 0 {
		out = append(out, buildWstunnelCaddyRoute(wr))
	}
	for _, r := range routes {
		r.CacheModuleAvailable = s.CacheModuleAvailable
		r.RateLimitModuleAvailable = s.RateLimitModuleAvailable
		r.WAFModuleAvailable = s.WAFModuleAvailable
		out = append(out, BuildRoute(r))
	}

	acmeIssuer := map[string]any{
		"module": "acme",
		"email":  s.ACMEEmail,
	}
	if s.ACMEStaging {
		acmeIssuer["ca"] = "https://acme-staging-v02.api.letsencrypt.org/directory"
	}

	// tls.automation.policies is an ordered, first-match array. Wildcard
	// DNS-01 policies carry explicit subjects (issued eagerly at load) and
	// MUST come before the subject-less on-demand catch-all, which has to be
	// last. Gated: stock Caddy lacks the caddy-dns module and fails /load.
	policies := make([]any, 0, len(s.WildcardPolicies)+1)
	if s.DNS01ModuleAvailable {
		for _, wp := range s.WildcardPolicies {
			prov := providerJSON(wp.Provider, wp.Fields)
			if prov == nil { // unknown slug - never emit a config Caddy would reject
				continue
			}
			dnsIssuer := map[string]any{
				"module": "acme",
				"email":  s.ACMEEmail,
				"challenges": map[string]any{
					"dns": map[string]any{
						"provider": prov,
					},
				},
			}
			if s.ACMEStaging {
				dnsIssuer["ca"] = "https://acme-staging-v02.api.letsencrypt.org/directory"
			}
			policies = append(policies, map[string]any{
				// *.zone does NOT cover the bare apex; list both so an apex route works too.
				"subjects": []string{"*." + wp.Zone, wp.Zone},
				"issuers":  []any{dnsIssuer},
			})
		}
	}
	// Catch-all on-demand policy LAST (no subjects) - unchanged behaviour.
	policies = append(policies, map[string]any{
		"on_demand": true,
		"issuers":   []any{acmeIssuer},
	})

	// h1 + h2 only. HTTP/3 (QUIC) dropped: in Caddy v2 the protocol set
	// is server-wide (negotiated at TLS handshake before route match) so
	// per-route toggles were a lie. Browsers fall back to h2 fine and
	// QUIC over WG often fragments past MTU. NPM doesn't ship it either.
	protocols := []string{"h1", "h2"}

	srv0 := map[string]any{
		"listen":    []string{":80", ":443"},
		"routes":    out,
		"protocols": protocols,
		"metrics":   map[string]any{}, // exposes Prometheus metrics at admin /metrics
		// handle_errors catches every upstream non-2xx (and Caddy-native
		// errors like "no route matched") and rewrites the response body
		// to the brand-aware HTML page. Routes are matched by the
		// {http.error.status_code} placeholder via `expression`.
		"errors": map[string]any{
			"routes": buildErrorRoutes(s.ErrorBranding),
		},
	}
	// Attach per-server access log forwarding when the panel URL is configured.
	// Caddy POSTs one JSON object per request to AccessLogURL via the "net" sink.
	// The logger name "hpg_access" lets us reference it in logs.loggers below.
	if s.AccessLogURL != "" {
		srv0["logs"] = map[string]any{
			"logger_names": map[string]any{
				"*": "hpg_access",
			},
		}
	}

	apps := map[string]any{
		"http": map[string]any{
			"servers": map[string]any{
				"srv0": srv0,
			},
		},
		// Caddy 2.10+ replaced on_demand.ask (string) with permission module.
		"tls": map[string]any{
			"automation": map[string]any{
				// NOTE: Caddy 2.8+ removed on_demand.rate_limit (interval/burst)
				// from the JSON schema in favour of the `permission` module.
				// Re-adding it risks the node rejecting the whole config. Burst
				// protection is enforced at the ask endpoint instead (per-IP
				// rate limit + Redis allow/deny decision cache, see caddy_ask.go).
				"on_demand": map[string]any{
					"permission": map[string]any{
						"module":   "http",
						"endpoint": s.AskURL,
					},
				},
				"policies": policies,
			},
		},
	}

	// Souin cache module is opt-in per-node: stock caddy:2.8 rejects the
	// whole config when `apps.cache` (or the per-route `cache` handler)
	// appears without the module loaded. Operators flip CacheModuleAvailable
	// only after rebuilding the node image (deploy/caddy/Dockerfile, xcaddy
	// build with caddy-cache-handler).
	if s.Layer4ModuleAvailable && len(s.StreamRoutes) > 0 {
		if l4 := buildLayer4App(s.StreamRoutes); l4 != nil {
			apps["layer4"] = l4
		}
	}

	// Only mount apps.cache when at least one route actually wants caching.
	// Souin wraps EVERY route's response pipeline once it's registered and
	// imposes a 10s backend timeout that kills bursts of parallel asset
	// requests (Vue SPA loads 60+ JS files at once) - cascades to 504.
	cacheNeeded := false
	if s.CacheModuleAvailable {
		if s.PanelRoute != nil && s.PanelRoute.CacheEnabled {
			cacheNeeded = true
		}
		if !cacheNeeded {
			for _, r := range routes {
				if r.CacheEnabled {
					cacheNeeded = true
					break
				}
			}
		}
	}
	if cacheNeeded {
		apps["cache"] = map[string]any{
			"ttl": "60s",
			// No stale window: serving stale for 60s after TTL can hand a
			// just-logged-out user's page back, and stacks with auth changes.
			// Static routes can opt into stale per-route if ever needed.
			"stale":                 "0s",
			"default_cache_control": "no-store",
			"allowed_http_verbs":    []string{"GET", "HEAD"},
			// Make per-user credentials part of the cache key so two clients
			// with different sessions never collide on one cached entry. Routes
			// behind SSO/basic-auth already skip the cache handler entirely
			// (see caddyapi.BuildRoute), this guards cookie-authed app routes.
			"key": map[string]any{
				"headers": []string{"Cookie", "Authorization"},
			},
			// Higher backend timeout so a slow upstream doesn't blow up
			// parallel asset bursts; 60s matches Caddy's default proxy idle.
			"timeout": map[string]any{
				"backend": "60s",
				"cache":   "10ms",
			},
			"api": map[string]any{
				"basepath": "/souin-api",
				"souin": map[string]any{
					"basepath": "/souin",
				},
			},
		}
	}

	root := map[string]any{
		"admin": map[string]any{
			// 0.0.0.0:2019 inside the container = docker bridge only,
			// not host net. Compose deliberately does NOT publish 2019.
			// Defense-in-depth: don't `ports: 2019:2019` ever.
			"listen": "0.0.0.0:2019",
		},
		"apps": apps,
	}
	// Top-level logging config: "hpg_access" writes structured JSON access logs
	// to a rolling file on the node. Stock Caddy has no HTTP log writer, and the
	// "net" writer speaks raw TCP (not HTTP) - feeding it an HTTP URL either
	// fails config load or silently never delivers. A file writer is stock,
	// robust, and never breaks a node config load. The node-agent tails this
	// file and forwards lines to the panel's authenticated /internal/access-log.
	if s.AccessLogURL != "" {
		root["logging"] = map[string]any{
			"logs": map[string]any{
				"hpg_access": map[string]any{
					"encoder": map[string]any{"format": "json"},
					// Scope to access logs only. Without include, a named log
					// captures ALL Caddy logs (runtime/admin/error), polluting
					// the file with non-access lines the panel must discard.
					// srv0.logs.logger_names "*" routes access entries here.
					"include": []any{"http.log.access.hpg_access"},
					"writer": map[string]any{
						"output":         "file",
						"filename":       AccessLogFilePath,
						"roll":           true,
						"roll_size_mb":   20,
						"roll_keep":      3,
						"roll_keep_days": 7,
					},
				},
			},
		}
	}
	return root
}

// buildWstunnelCaddyRoute returns a raw Caddy route object that proxies
// WebSocket connections from /wg-tunnel on the node hostname to the local
// wstunnel server. Caddy's reverse_proxy handles WebSocket upgrade automatically.
func buildWstunnelCaddyRoute(wr *WstunnelRoute) map[string]any {
	return map[string]any{
		"@id": fmt.Sprintf("hpg_wstunnel_%d", wr.NodeID),
		"match": []any{
			map[string]any{
				"host": []string{wr.Hostname},
				"path": []string{"/wg-tunnel*"},
			},
		},
		"handle": []any{
			map[string]any{
				"handler": "reverse_proxy",
				"upstreams": []any{
					map[string]any{
						"dial": fmt.Sprintf("host.docker.internal:%d", wr.Port),
					},
				},
			},
		},
	}
}
