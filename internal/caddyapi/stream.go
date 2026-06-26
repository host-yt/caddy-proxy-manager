package caddyapi

// Stream proxy support (L4 - TCP/UDP forward) via the mholt/caddy-l4
// module. Each StreamRoute becomes one server entry in apps.layer4.servers
// listening on the requested port + protocol(s) and forwarding to
// configured upstreams with optional LB, matchers, proxy-protocol, and CIDR ACL.
//
// Stock caddy doesn't ship caddy-l4; the custom image
// (deploy/caddy/Dockerfile, xcaddy --with github.com/mholt/caddy-l4)
// is required. NodeSettings.Layer4ModuleAvailable gates emission so a
// fleet that hasn't upgraded yet doesn't get its config rejected.
//
// NOT fixture-validated against a real Caddy instance (see gating list
// below). All caddy-l4 JSON fields are emitted per the module's documented
// schema but must be verified before flipping to stable.
//
// GATING LIST - fields NOT yet fixture-validated against a running Caddy:
//   - proxy_protocol listener wrapper ("handler":"proxy_protocol", "versions")
//   - proxy_protocol upstream handler ("handler":"proxy_protocol", "version")
//   - SNI matcher ("matcher":"tls","sni")
//   - http_host matcher ("matcher":"http","host")
//   - lb_policy on proxy handler ("load_balancing":{"selection_policy":...})
//   - remote_ip handler for CIDR allow/deny ("handler":"remote_ip",...)
//
// The "any" match mode with single upstream and no proxy-protocol is the
// only path that has been validated end-to-end (WSS tunnel, 2026-06-24).

// StreamUpstream is one entry in the upstream pool for a StreamRoute.
type StreamUpstream struct {
	Address string // host:port or ip:port
	Weight  int    // relative weight for LB; 0 treated as 1
}

// StreamRoute is the panel-side representation of one L4 forward.
type StreamRoute struct {
	ID           int64
	Protocol     string // "tcp" | "udp" | "both"
	ListenPort   int
	UpstreamIP   string // legacy single-upstream; used when Upstreams is empty
	UpstreamPort int    // legacy single-upstream

	// Advanced fields (migration 00061).
	Upstreams     []StreamUpstream // overrides UpstreamIP/UpstreamPort when non-empty
	MatchMode     string           // "any" (default) | "sni" | "http_host"
	MatchValues   []string         // SNI names or HTTP Host values to match
	LBPolicy      string           // "round_robin" | "random" | "least_conn" | "first"
	ProxyProtoIn  string           // listener-level proxy-protocol: "none"|"v1"|"v2"
	ProxyProtoOut string           // upstream-level proxy-protocol: "none"|"v1"|"v2"
	CIDRAllow     []string         // CIDRs that are explicitly permitted
	CIDRDeny      []string         // CIDRs that are explicitly blocked (checked first)
}

// buildLayer4App turns a list of stream routes into the `apps.layer4`
// JSON block. Returns nil when no routes are configured so we don't emit
// an empty servers map (Caddy tolerates it, but it noises up audits).
//
// Each StreamRoute becomes 1 or 2 servers (tcp and/or udp). The server
// key is "<proto>_<port>" so two routes on the same port with different
// protocols don't collide.
func buildLayer4App(routes []StreamRoute) map[string]any {
	if len(routes) == 0 {
		return nil
	}
	servers := map[string]any{}
	for _, r := range routes {
		protos := protoList(r.Protocol)
		for _, p := range protos {
			key := p + "_" + itoa(r.ListenPort)
			servers[key] = buildL4Server(p, r)
		}
	}
	return map[string]any{"servers": servers}
}

// buildL4Server builds the caddy-l4 server object for one proto+route combo.
func buildL4Server(proto string, r StreamRoute) map[string]any {
	listenAddr := proto + "/:" + itoa(r.ListenPort)

	// Build the chain of handlers for the route.
	handlers := buildL4Handlers(r)

	route := map[string]any{"handle": handlers}

	// Inject matchers when not "any" (unset / explicit any = no matcher block).
	// NOT fixture-validated: SNI and http_host matchers.
	if m := buildL4Matcher(r); m != nil {
		route["match"] = []any{m}
	}

	srv := map[string]any{
		"listen": []string{listenAddr},
		"routes": []any{route},
	}

	// Wrap listener with proxy-protocol decoder when requested.
	// NOT fixture-validated against real Caddy.
	if r.ProxyProtoIn != "none" && r.ProxyProtoIn != "" {
		srv["listener_wrappers"] = buildProxyProtoListenerWrapper(r.ProxyProtoIn)
	}

	return srv
}

// buildL4Matcher returns the match block for SNI or http_host modes, nil for "any".
// Falls back to nil (any) when MatchValues is empty to avoid null arrays in Caddy JSON.
// NOT fixture-validated against real Caddy.
func buildL4Matcher(r StreamRoute) map[string]any {
	if len(r.MatchValues) == 0 {
		// Never emit {"tls":{"sni":null}} or {"http":[{"host":null}]}.
		return nil
	}
	switch r.MatchMode {
	case "sni":
		// caddy-l4 TLS SNI matcher: {"tls": {"sni": [...]}}
		return map[string]any{
			"tls": map[string]any{"sni": r.MatchValues},
		}
	case "http_host":
		// caddy-l4 HTTP host matcher: {"http": [{"host": [...]}]}
		return map[string]any{
			"http": []any{map[string]any{"host": r.MatchValues}},
		}
	}
	return nil
}

// buildL4Handlers assembles the ordered handler chain for one route.
func buildL4Handlers(r StreamRoute) []any {
	var handlers []any

	// CIDR deny runs before allow and before proxy - drops forbidden sources.
	// NOT fixture-validated against real Caddy.
	if len(r.CIDRDeny) > 0 || len(r.CIDRAllow) > 0 {
		handlers = append(handlers, buildRemoteIPHandler(r.CIDRAllow, r.CIDRDeny))
	}

	// Proxy handler: routes connections to upstreams.
	handlers = append(handlers, buildProxyHandler(r))

	return handlers
}

// buildRemoteIPHandler emits the remote_ip handler for CIDR ACL.
// Deny is checked first; allow (if non-empty) gates the remainder.
// NOT fixture-validated against real Caddy.
func buildRemoteIPHandler(allow, deny []string) map[string]any {
	h := map[string]any{"handler": "remote_ip"}
	if len(deny) > 0 {
		h["deny"] = deny
	}
	if len(allow) > 0 {
		h["allow"] = allow
	}
	return h
}

// buildProxyHandler emits the proxy handler with upstreams and optional LB.
func buildProxyHandler(r StreamRoute) map[string]any {
	upstreams := buildUpstreamList(r)
	h := map[string]any{
		"handler":   "proxy",
		"upstreams": upstreams,
	}

	// LB policy when more than one upstream or explicitly set.
	// NOT fixture-validated against real Caddy.
	if policy := normLBPolicy(r.LBPolicy); len(upstreams) > 1 || (policy != "" && policy != "round_robin") {
		h["load_balancing"] = map[string]any{
			"selection_policy": map[string]any{"policy": policy},
		}
	}

	// Per-upstream proxy-protocol version for outgoing connections.
	// NOT fixture-validated against real Caddy.
	if r.ProxyProtoOut != "none" && r.ProxyProtoOut != "" {
		h["proxy_protocol"] = map[string]any{
			"version": proxyProtoVersion(r.ProxyProtoOut),
		}
	}

	return h
}

// buildUpstreamList converts StreamRoute upstreams into caddy-l4 dial entries.
func buildUpstreamList(r StreamRoute) []any {
	if len(r.Upstreams) > 0 {
		out := make([]any, 0, len(r.Upstreams))
		for _, u := range r.Upstreams {
			entry := map[string]any{"dial": []string{u.Address}}
			w := u.Weight
			if w <= 0 {
				w = 1
			}
			if w != 1 {
				entry["weight"] = w
			}
			out = append(out, entry)
		}
		return out
	}
	// Legacy single-upstream path.
	return []any{map[string]any{"dial": []string{dial(r.UpstreamIP, r.UpstreamPort)}}}
}

// buildProxyProtoListenerWrapper emits the listener_wrappers block for PROXY protocol.
// NOT fixture-validated against real Caddy.
func buildProxyProtoListenerWrapper(mode string) []any {
	return []any{
		map[string]any{
			"wrapper":  "proxy_protocol",
			"timeout":  "5s",
			"versions": []string{proxyProtoVersion(mode)},
		},
	}
}

// normLBPolicy normalises empty / unknown values to the caddy-l4 default.
func normLBPolicy(p string) string {
	switch p {
	case "random", "least_conn", "first":
		return p
	}
	return "round_robin"
}

// proxyProtoVersion maps our enum values to PROXY protocol version strings.
func proxyProtoVersion(mode string) string {
	if mode == "v2" {
		return "2"
	}
	return "1"
}

func protoList(p string) []string {
	switch p {
	case "udp":
		return []string{"udp"}
	case "both":
		return []string{"tcp", "udp"}
	default:
		return []string{"tcp"}
	}
}
