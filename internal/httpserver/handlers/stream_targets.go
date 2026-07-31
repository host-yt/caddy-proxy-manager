package handlers

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"
)

// streamDeniedPorts are ports a tenant stream may never dial anywhere: this
// repo publishes Caddy's UNAUTHENTICATED admin API on 2019.
var streamDeniedPorts = map[int]struct{}{2019: {}}

// infraTargets is the fail-closed deny set of control-plane and managed-node
// addresses. It is independent of the RFC1918 backend policy, which stays
// permissive because tenants legitimately proxy to private backends.
type infraTargets struct {
	addrs map[netip.Addr]struct{}
	nets  []netip.Prefix
	hosts map[string]struct{}
}

// loadInfraTargets builds the deny set from the node table and the WireGuard
// control-plane settings. Any lookup error must abort the caller (fail closed).
func loadInfraTargets(ctx context.Context, db *sql.DB) (*infraTargets, error) {
	if db == nil {
		return nil, errors.New("no db")
	}
	t := &infraTargets{
		addrs: make(map[netip.Addr]struct{}),
		hosts: make(map[string]struct{}),
	}
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
		t.add(publicIP)
		t.add(wgIP)
		t.add(publicHost)
		t.addURLHost(apiURL)
		t.addTunnelGateway(tunnelSubnet)
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
			t.add(v)
		case "wireguard.subnet":
			// Whole control-plane mesh: node admin APIs bind their wg_ip here.
			if p, err := netip.ParsePrefix(v); err == nil {
				t.nets = append(t.nets, p.Masked())
			}
		}
	}
	return t, srows.Err()
}

// add records an IP literal or a hostname.
func (t *infraTargets) add(v string) {
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

// addURLHost records the host part of a stored URL such as api_url.
func (t *infraTargets) addURLHost(raw string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return
	}
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		t.add(u.Hostname())
		return
	}
	t.add(raw)
}

// addTunnelGateway denies the node's own address inside a customer tunnel
// subnet (the .1 bridge); tenant peer addresses in that subnet stay allowed.
func (t *infraTargets) addTunnelGateway(subnet string) {
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

// blocked reports whether host (IP literal or hostname) hits the deny set.
func (t *infraTargets) blocked(host string) bool {
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

// screenStreamTarget applies the infrastructure deny rules to one resolved
// stream destination. hosts must already carry every address the target
// resolves to, so a hostname cannot smuggle a node address past the check.
func (t *infraTargets) screenStreamTarget(port int, hosts ...string) error {
	if _, bad := streamDeniedPorts[port]; bad {
		return fmt.Errorf("port %d is reserved for the node admin API", port)
	}
	for _, h := range hosts {
		if t.blocked(h) {
			return fmt.Errorf("%s is a managed node or control-plane address", h)
		}
	}
	return nil
}

// resolveStreamHost returns the literal addresses a stream target resolves to.
// IP literals pass through; hostnames are resolved once here so the caller can
// pin the result - Caddy's L4 upstream re-resolves at dial time otherwise,
// which would leave a DNS-rebinding window after validation.
func resolveStreamHost(ctx context.Context, host string) ([]string, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return nil, errors.New("empty host")
	}
	if ip := net.ParseIP(host); ip != nil {
		return []string{host}, nil
	}
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil || len(addrs) == 0 {
		return nil, fmt.Errorf("host %s did not resolve", host)
	}
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, a.Unmap().String())
	}
	return out, nil
}
