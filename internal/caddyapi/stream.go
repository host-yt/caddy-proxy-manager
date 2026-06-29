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
// JSON shapes follow the caddy-l4 module schema (verified against the module
// source) and are exercised by TestBuildLayer4* and the /load fixture test in
// internal/integration (layer4_load_test.go):
//   - proxy handler:    {"handler":"proxy","upstreams":[{"dial":[...]}],
//                        "load_balancing":{"selection_policy":{"policy":...}},
//                        "proxy_protocol":"v1"|"v2"}            (string, not object)
//   - proxy_protocol in: {"handler":"proxy_protocol"} prepended to the handle
//                        chain (it is a handler, not a listener wrapper; the
//                        receiver auto-detects v1/v2)
//   - SNI matcher:      {"tls":{"sni":[...]}}
//   - http_host matcher: {"http":[{"host":[...]}]}
//   - CIDR ACL:         remote_ip is a MATCHER, not a handler - deny/allow are
//                        terminal "close" routes gated by {"remote_ip":{"ranges"}}
//                        (allow uses {"not":[{"remote_ip":...}]}) before proxy.

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

	// Inner routes: CIDR ACL (terminal "close") first so denied/non-allowed
	// sources never reach an upstream, then the proxy route.
	inner := buildL4ACLRoutes(r)
	proxyRoute := map[string]any{"handle": []any{buildProxyHandler(r)}}
	if m := buildL4Matcher(r); m != nil {
		proxyRoute["match"] = []any{m}
	}
	inner = append(inner, proxyRoute)

	var routes []any
	if r.ProxyProtoIn == "v1" || r.ProxyProtoIn == "v2" {
		// Decode the PROXY header BEFORE any ACL/matcher runs, so remote_ip and
		// SNI see the real client - not the upstream LB's socket peer. The
		// decoded connection is handed to a subroute carrying the ACL + proxy
		// routes. (Matchers on sibling routes would see the raw, pre-decode
		// connection, which is the access-control bypass we are avoiding.)
		routes = []any{map[string]any{
			"handle": []any{
				map[string]any{"handler": "proxy_protocol", "timeout": "5s"},
				map[string]any{"handler": "subroute", "routes": inner},
			},
		}}
	} else {
		routes = inner
	}

	return map[string]any{
		"listen": []string{listenAddr},
		"routes": routes,
	}
}

// buildL4ACLRoutes emits terminal "close" routes implementing the CIDR ACL.
// remote_ip is a matcher (not a handler): deny ranges close directly; an
// allow-list closes everyone NOT in it via the "not" matcher.
func buildL4ACLRoutes(r StreamRoute) []any {
	var routes []any
	closeHandle := []any{map[string]any{"handler": "close"}}
	if len(r.CIDRDeny) > 0 {
		routes = append(routes, map[string]any{
			"match":  []any{map[string]any{"remote_ip": map[string]any{"ranges": r.CIDRDeny}}},
			"handle": closeHandle,
		})
	}
	if len(r.CIDRAllow) > 0 {
		routes = append(routes, map[string]any{
			"match": []any{map[string]any{
				"not": []any{map[string]any{"remote_ip": map[string]any{"ranges": r.CIDRAllow}}},
			}},
			"handle": closeHandle,
		})
	}
	return routes
}

// buildL4Matcher returns the match block for SNI or http_host modes, nil for "any".
// Falls back to nil (any) when MatchValues is empty to avoid null arrays in Caddy JSON.
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

// buildProxyHandler emits the proxy handler with upstreams and optional LB.
func buildProxyHandler(r StreamRoute) map[string]any {
	upstreams := buildUpstreamList(r)
	h := map[string]any{
		"handler":   "proxy",
		"upstreams": upstreams,
	}

	// LB policy when more than one upstream or explicitly set.
	if policy := normLBPolicy(r.LBPolicy); len(upstreams) > 1 || (policy != "" && policy != "round_robin") {
		h["load_balancing"] = map[string]any{
			"selection_policy": map[string]any{"policy": policy},
		}
	}

	// PROXY protocol to the upstream: a plain "v1"/"v2" string on the handler.
	if r.ProxyProtoOut == "v1" || r.ProxyProtoOut == "v2" {
		h["proxy_protocol"] = r.ProxyProtoOut
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

// normLBPolicy normalises empty / unknown values to the caddy-l4 default.
func normLBPolicy(p string) string {
	switch p {
	case "random", "least_conn", "first":
		return p
	}
	return "round_robin"
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
