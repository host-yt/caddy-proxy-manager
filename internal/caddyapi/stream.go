package caddyapi

// Stream proxy support (L4 - TCP/UDP forward) via the mholt/caddy-l4
// module. Each StreamRoute becomes one server entry in apps.layer4.servers
// listening on the requested port + protocol(s) and forwarding to
// UpstreamIP:UpstreamPort.
//
// Stock caddy doesn't ship caddy-l4; the custom image
// (deploy/caddy/Dockerfile, xcaddy --with github.com/mholt/caddy-l4)
// is required. NodeSettings.Layer4ModuleAvailable gates emission so a
// fleet that hasn't upgraded yet doesn't get its config rejected.

// StreamRoute is the panel-side representation of one L4 forward.
type StreamRoute struct {
	ID           int64
	Protocol     string // "tcp" | "udp" | "both"
	ListenPort   int
	UpstreamIP   string
	UpstreamPort int
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
			servers[key] = map[string]any{
				"listen": []string{p + "/:" + itoa(r.ListenPort)},
				"routes": []any{
					map[string]any{
						"handle": []any{
							map[string]any{
								"handler":   "proxy",
								"upstreams": []any{map[string]any{"dial": []string{dial(r.UpstreamIP, r.UpstreamPort)}}},
							},
						},
					},
				},
			}
		}
	}
	return map[string]any{"servers": servers}
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
