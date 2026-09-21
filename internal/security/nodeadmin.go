package security

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
)

// caddyAdminPort is Caddy's admin API default port. That API has no
// authentication of any kind, so being able to open a TCP connection to it is
// equivalent to root on the node.
const caddyAdminPort = "2019"

// AllowUnauthenticatedNodeAdminEnv re-opens the legacy path for a fleet that is
// mid-migration to the node-agent admin proxy.
const AllowUnauthenticatedNodeAdminEnv = "HPG_ALLOW_UNAUTHENTICATED_NODE_ADMIN"

// UnauthenticatedNodeAdminURL reports whether apiURL addresses a raw Caddy
// admin endpoint on a remote machine (SEC-002).
//
// Only a literal, non-loopback IP on :2019 counts. The manager's own bundled
// Caddy is addressed by compose service name (http://caddy:2019) on a bridge
// that publishes nothing, and a node-agent admin proxy listens on a different
// port - neither is flagged.
func UnauthenticatedNodeAdminURL(apiURL string) bool {
	u, err := url.Parse(strings.TrimSpace(apiURL))
	if err != nil || u.Host == "" || u.Port() != caddyAdminPort {
		return false
	}
	ip := net.ParseIP(u.Hostname())
	return ip != nil && !ip.IsLoopback()
}

// RejectUnauthenticatedNodeAdminURL refuses to register a node against a raw
// remote Caddy admin API. Remote nodes must be reached through the node-agent
// admin proxy, which authenticates the panel with a per-node key.
func RejectUnauthenticatedNodeAdminURL(apiURL string) error {
	if !UnauthenticatedNodeAdminURL(apiURL) || os.Getenv(AllowUnauthenticatedNodeAdminEnv) == "1" {
		return nil
	}
	host, _, _ := net.SplitHostPort(strings.TrimPrefix(strings.TrimPrefix(apiURL, "http://"), "https://"))
	return fmt.Errorf("api_url points straight at Caddy's unauthenticated admin API on :%s - "+
		"run the node-agent admin proxy on that node (HPG_ADMIN_PROXY_LISTEN/HPG_ADMIN_PROXY_KEY) "+
		"and register http://%s:2021 instead, or set %s=1 to keep the legacy path while migrating "+
		"(see docs/MULTI_NODE.md)", caddyAdminPort, host, AllowUnauthenticatedNodeAdminEnv)
}
