// Package streamguard screens L4 stream destinations against the control-plane
// deny set. It lives outside the HTTP handlers because emission (config push)
// must apply the same check as the write path.
package streamguard

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/host-yt/caddy-proxy-manager/internal/security"
)

// streamDeniedPorts are ports a tenant stream may never dial anywhere: this
// repo publishes Caddy's UNAUTHENTICATED admin API on 2019.
var streamDeniedPorts = map[int]struct{}{2019: {}}

// InfraTargets is the fail-closed deny set of control-plane and managed-node
// addresses. It is independent of the RFC1918 backend policy, which stays
// permissive because tenants legitimately proxy to private backends.
type InfraTargets struct {
	addrs map[netip.Addr]struct{}
	nets  []netip.Prefix
	hosts map[string]struct{}
}

// New returns an empty deny set.
func New() *InfraTargets {
	return &InfraTargets{
		addrs: make(map[netip.Addr]struct{}),
		hosts: make(map[string]struct{}),
	}
}

// LoadInfraTargets builds the deny set from the node table and the WireGuard
// control-plane settings. Any lookup error must abort the caller (fail closed).
func LoadInfraTargets(ctx context.Context, db *sql.DB) (*InfraTargets, error) {
	if db == nil {
		return nil, errors.New("no db")
	}
	t := New()
	rows, err := db.QueryContext(ctx,
		`SELECT COALESCE(public_ip,''), COALESCE(wg_ip,''), COALESCE(api_url,''),
		        COALESCE(public_hostname,''), COALESCE(tunnel_subnet,'')
		   FROM caddy_nodes`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var publicIP, wgIP, apiURL, publicHost, tunnelSubnet string
		if err := rows.Scan(&publicIP, &wgIP, &apiURL, &publicHost, &tunnelSubnet); err != nil {
			return nil, err
		}
		t.Add(publicIP)
		t.Add(wgIP)
		t.Add(publicHost)
		t.AddURLHost(apiURL)
		t.AddTunnelGateway(tunnelSubnet)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	srows, err := db.QueryContext(ctx,
		"SELECT `key`, value FROM settings WHERE `key` IN ('wireguard.subnet','wireguard.control_ip')")
	if err != nil {
		return nil, err
	}
	defer srows.Close()
	for srows.Next() {
		var k, v string
		if err := srows.Scan(&k, &v); err != nil {
			return nil, err
		}
		v = strings.TrimSpace(v)
		switch k {
		case "wireguard.control_ip":
			t.Add(v)
		case "wireguard.subnet":
			// Whole control-plane mesh: node admin APIs bind their wg_ip here.
			if p, err := netip.ParsePrefix(v); err == nil {
				t.AddPrefix(p)
			}
		}
	}
	return t, srows.Err()
}

// Add records an IP literal or a hostname.
func (t *InfraTargets) Add(v string) {
	v = strings.TrimSpace(v)
	if v == "" {
		return
	}
	if a, err := netip.ParseAddr(v); err == nil {
		t.addrs[a.Unmap()] = struct{}{}
		return
	}
	t.hosts[strings.ToLower(strings.TrimSuffix(v, "."))] = struct{}{}
}

// AddPrefix records a whole denied network.
func (t *InfraTargets) AddPrefix(p netip.Prefix) {
	t.nets = append(t.nets, p.Masked())
}

// AddURLHost records the host part of a stored URL such as api_url.
func (t *InfraTargets) AddURLHost(raw string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return
	}
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		t.Add(u.Hostname())
		return
	}
	t.Add(raw)
}

// AddTunnelGateway denies the node's own address inside a customer tunnel
// subnet (the .1 bridge); tenant peer addresses in that subnet stay allowed.
func (t *InfraTargets) AddTunnelGateway(subnet string) {
	subnet = strings.TrimSpace(subnet)
	if subnet == "" {
		return
	}
	p, err := netip.ParsePrefix(subnet)
	if err != nil {
		return
	}
	base := p.Masked().Addr()
	t.addrs[base.Unmap()] = struct{}{}
	if gw := base.Next(); gw.IsValid() {
		t.addrs[gw.Unmap()] = struct{}{}
	}
}

// Blocked reports whether host (IP literal or hostname) hits the deny set.
func (t *InfraTargets) Blocked(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" {
		return false
	}
	if _, ok := t.hosts[host]; ok {
		return true
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	a = a.Unmap()
	if _, ok := t.addrs[a]; ok {
		return true
	}
	for _, p := range t.nets {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// ScreenTarget applies the infrastructure deny rules to one resolved stream
// destination. hosts must already carry every address the target resolves to,
// so a hostname cannot smuggle a node address past the check.
func (t *InfraTargets) ScreenTarget(port int, hosts ...string) error {
	if _, bad := streamDeniedPorts[port]; bad {
		return fmt.Errorf("port %d is reserved for the node admin API", port)
	}
	for _, h := range hosts {
		if t.Blocked(h) {
			return fmt.Errorf("%s is a managed node or control-plane address", h)
		}
	}
	return nil
}

// lookupAddrs is swappable in tests; production always uses the system resolver.
var lookupAddrs = func(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// ScreenAndPin validates one stream destination and returns the literal address
// to dial. The lookup happens exactly ONCE and every answer is checked against
// both the generic SSRF policy and the infra deny set, so a DNS answer that
// alternates between a safe and an internal address cannot be pinned.
func (t *InfraTargets) ScreenAndPin(ctx context.Context, host string, port int) (string, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return "", errors.New("empty host")
	}
	if port <= 0 || port > 65535 {
		return "", fmt.Errorf("invalid port %d", port)
	}
	if _, bad := streamDeniedPorts[port]; bad {
		return "", fmt.Errorf("port %d is reserved for the node admin API", port)
	}
	if t.Blocked(host) {
		return "", fmt.Errorf("%s is a managed node or control-plane address", host)
	}
	if ip := net.ParseIP(host); ip != nil {
		if security.IsDangerousProxyBackend(ip) {
			return "", fmt.Errorf("address %s is not allowed", host)
		}
		return host, nil
	}
	addrs, err := lookupAddrs(ctx, host)
	if err != nil || len(addrs) == 0 {
		return "", fmt.Errorf("host %s did not resolve", host)
	}
	for _, a := range addrs {
		lit := a.Unmap().String()
		if security.IsDangerousProxyBackend(net.IP(a.Unmap().AsSlice())) {
			return "", fmt.Errorf("host %s resolves to a blocked address", host)
		}
		if t.Blocked(lit) {
			return "", fmt.Errorf("host %s resolves to %s, a managed node or control-plane address", host, lit)
		}
	}
	// Pin from the validated set: Caddy re-resolves at dial time otherwise,
	// which would leave a DNS-rebinding window after validation.
	return addrs[0].Unmap().String(), nil
}

// ScreenAndPinAddress is ScreenAndPin over a "host:port" literal, returning the
// pinned "ip:port" to emit.
func (t *InfraTargets) ScreenAndPinAddress(ctx context.Context, addr string) (string, error) {
	host, portStr, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil || host == "" {
		return "", fmt.Errorf("invalid address %q", addr)
	}
	port, perr := strconv.Atoi(portStr)
	if perr != nil || port <= 0 || port > 65535 {
		return "", fmt.Errorf("invalid port in %q", addr)
	}
	pinned, err := t.ScreenAndPin(ctx, host, port)
	if err != nil {
		return "", err
	}
	return net.JoinHostPort(pinned, portStr), nil
}
