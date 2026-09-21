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

// AllowUnauthenticatedNodeAdminEnv re-opens *registration* of a raw admin URL
// for a fleet that is mid-migration. It no longer authorizes an unauthenticated
// push: that decision is per-node (caddy_nodes.allow_unauthenticated_admin).
const AllowUnauthenticatedNodeAdminEnv = "HPG_ALLOW_UNAUTHENTICATED_NODE_ADMIN"

// AdminProxyPortsEnv names the port(s) the node-agent admin proxy listens on
// when a deployment does not use the documented 2021.
const AdminProxyPortsEnv = "HPG_ADMIN_PROXY_PORTS"

// defaultAdminProxyPort is the documented HPG_ADMIN_PROXY_LISTEN port.
const defaultAdminProxyPort = "2021"

// adminProxyPorts lists the ports assumed to be fronted by the node-agent's
// authenticating admin proxy.
func adminProxyPorts() []string {
	raw := strings.TrimSpace(os.Getenv(AdminProxyPortsEnv))
	if raw == "" {
		return []string{defaultAdminProxyPort}
	}
	out := make([]string, 0, 4)
	for _, p := range strings.Split(raw, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return []string{defaultAdminProxyPort}
	}
	return out
}

// remoteAdminHost reports whether host is off the panel's own machine and its
// own compose bridge - i.e. reaching it crosses a network someone else can be
// on. A single-label name only resolves on that bridge (http://caddy:2019); a
// dotted name or a routable literal IP is somewhere else entirely.
func remoteAdminHost(host string) bool {
	h := strings.TrimSpace(strings.ToLower(host))
	if h == "" {
		return false
	}
	if ip := net.ParseIP(h); ip != nil {
		return !ip.IsLoopback() && !ip.IsUnspecified()
	}
	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return false
	}
	return strings.Contains(h, ".")
}

// UnauthenticatedNodeAdminURL reports whether apiURL addresses a remote Caddy
// admin endpoint that nothing authenticates (SEC-002).
//
// Any port other than the node-agent admin proxy's counts: remapping Caddy's
// admin listener to :2020 or naming the node by hostname changes nothing about
// who can take the node over. The manager's own bundled Caddy (compose service
// name), loopback and unix sockets are not flagged - there is no network there
// to authenticate over.
func UnauthenticatedNodeAdminURL(apiURL string) bool {
	u, err := url.Parse(strings.TrimSpace(apiURL))
	if err != nil || u.Host == "" {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	if !remoteAdminHost(u.Hostname()) {
		return false
	}
	port := u.Port()
	for _, p := range adminProxyPorts() {
		if port == p {
			return false
		}
	}
	return true
}

// ValidNodeAPIURL reports whether apiURL is a shape the panel can dial. The
// socket form addresses Caddy's admin endpoint through a shared volume, which
// is the only form that has no address at all for a proxy upstream to name.
func ValidNodeAPIURL(apiURL string) bool {
	s := strings.TrimSpace(apiURL)
	return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") ||
		(strings.HasPrefix(s, "unix://") && len(s) > len("unix:///"))
}

// RejectUnauthenticatedNodeAdminURL refuses to register a node against a raw
// remote Caddy admin API. Remote nodes must be reached through the node-agent
// admin proxy, which authenticates the panel with a per-node key.
func RejectUnauthenticatedNodeAdminURL(apiURL string) error {
	if !UnauthenticatedNodeAdminURL(apiURL) || os.Getenv(AllowUnauthenticatedNodeAdminEnv) == "1" {
		return nil
	}
	host := strings.TrimSpace(apiURL)
	if u, err := url.Parse(host); err == nil && u.Host != "" {
		host = u.Hostname()
	}
	return fmt.Errorf("api_url reaches %s over a network with nothing authenticating Caddy's admin API "+
		"(port %s or any other port that is not the node-agent proxy) - run the node-agent admin proxy on "+
		"that node (HPG_ADMIN_PROXY_LISTEN/HPG_ADMIN_PROXY_KEY) and register http://%s:%s instead, or set "+
		"%s=1 to keep registering the legacy shape while migrating (see docs/MULTI_NODE.md)",
		host, caddyAdminPort, host, defaultAdminProxyPort, AllowUnauthenticatedNodeAdminEnv)
}
