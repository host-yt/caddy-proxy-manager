package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	mdns "github.com/miekg/dns"
)

var ErrDNSMismatch = errors.New("dns: domain does not resolve to node")

// Check verifies that `domain` resolves to one of the node's published
// addresses. Either of these match:
//   - any A record == nodeIP (if set)
//   - the resolved CNAME chain ends at nodeHostname (when set)
//   - looking up nodeHostname returns at least one IP that overlaps the
//     domain's A records
func Check(ctx context.Context, domain, nodeHostname, nodeIP string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// Public resolvers, not the container's default: the panel's Docker DNS can
	// be stale/split-horizon, matching the TXTContains rationale.
	resolver := reliableResolver()
	ips, err := resolver.LookupHost(ctx, domain)
	if err != nil {
		return fmt.Errorf("lookup %s: %w", domain, err)
	}
	if len(ips) == 0 {
		return fmt.Errorf("no A records for %s", domain)
	}

	if nodeIP != "" {
		for _, ip := range ips {
			if ip == nodeIP {
				return nil
			}
		}
	}

	if nodeHostname != "" {
		nodeIPs, err := resolver.LookupHost(ctx, nodeHostname)
		if err == nil {
			set := map[string]struct{}{}
			for _, ip := range nodeIPs {
				set[ip] = struct{}{}
			}
			for _, ip := range ips {
				if _, ok := set[ip]; ok {
					return nil
				}
			}
		}

		// CNAME match: domain → ... → nodeHostname.
		cname, err := resolver.LookupCNAME(ctx, domain)
		if err == nil && strings.EqualFold(strings.TrimSuffix(cname, "."), strings.TrimSuffix(nodeHostname, ".")) {
			return nil
		}
	}

	return fmt.Errorf("%w (got %v, expected node %s / %s)", ErrDNSMismatch, ips, nodeHostname, nodeIP)
}

// bootstrapResolvers are the recursive resolvers used to discover authoritative
// nameservers and resolve NS hostnames - NOT to read the ownership token itself.
// Public by default because the panel's container resolver (Docker 127.0.0.11)
// can be broken; overridable with HPG_DNS_RESOLVERS (comma-separated ip[:port]).
func bootstrapResolvers() []string {
	if env := strings.TrimSpace(os.Getenv("HPG_DNS_RESOLVERS")); env != "" {
		var out []string
		for _, s := range strings.Split(env, ",") {
			if s = strings.TrimSpace(s); s != "" {
				out = append(out, withDNSPort(s))
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	return []string{"1.1.1.1:53", "8.8.8.8:53"}
}

func withDNSPort(s string) string {
	if _, _, err := net.SplitHostPort(s); err == nil {
		return s
	}
	return net.JoinHostPort(s, "53")
}

// reliableResolver returns a *net.Resolver whose Dial falls through the
// bootstrap servers in order, so one dead resolver doesn't fail the lookup.
func reliableResolver() *net.Resolver {
	servers := bootstrapResolvers()
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			var lastErr error
			for _, s := range servers {
				if conn, err := d.DialContext(ctx, network, s); err == nil {
					return conn, nil
				} else {
					lastErr = err
				}
			}
			if lastErr == nil {
				lastErr = errors.New("dns: no bootstrap resolver reachable")
			}
			return nil, lastErr
		},
	}
}

// TXTContains proves domain ownership by reading the TXT record at `name` from
// the domain's AUTHORITATIVE nameservers, matching want exactly (trimmed). Going
// straight to the zone's real NS both dodges the panel container's broken/split-
// horizon default resolver and anchors the proof to the delegation, so a cached-
// negative or spoofed recursive answer can neither block nor forge a match.
// Fails closed; only falls back to recursive resolvers if NS discovery fails.
func TXTContains(ctx context.Context, name, want string) bool {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	want = strings.TrimSpace(want)
	if want == "" {
		return false
	}
	servers, err := authoritativeNS(ctx, name)
	if err != nil || len(servers) == 0 {
		servers = bootstrapResolvers() // last resort when the zone cut can't be found
	}
	for _, srv := range servers {
		for _, rec := range queryTXT(ctx, srv, name) {
			if strings.TrimSpace(rec) == want {
				return true
			}
		}
	}
	return false
}

// authoritativeNS returns ip:53 addresses of the nameservers authoritative for
// name's zone, walking up labels until an NS set is found (so a token at
// _hpg-verify.<domain> resolves to <domain>'s NS).
func authoritativeNS(ctx context.Context, name string) ([]string, error) {
	res := reliableResolver()
	labels := strings.Split(strings.TrimSuffix(name, "."), ".")
	for i := 0; i < len(labels)-1; i++ {
		zone := strings.Join(labels[i:], ".")
		nss, err := res.LookupNS(ctx, zone)
		if err != nil || len(nss) == 0 {
			continue
		}
		var addrs []string
		seen := map[string]struct{}{}
		for _, ns := range nss {
			ips, err := res.LookupHost(ctx, strings.TrimSuffix(ns.Host, "."))
			if err != nil {
				continue
			}
			for _, ip := range ips {
				a := net.JoinHostPort(ip, "53")
				if _, dup := seen[a]; dup {
					continue
				}
				seen[a] = struct{}{}
				addrs = append(addrs, a)
			}
		}
		if len(addrs) > 0 {
			return addrs, nil
		}
	}
	return nil, errors.New("dns: no authoritative nameservers for " + name)
}

// queryTXT asks one server directly for name's TXT records (UDP, retried over
// TCP on truncation). Returns nil on any error - callers try the next server.
func queryTXT(ctx context.Context, server, name string) []string {
	m := new(mdns.Msg)
	m.SetQuestion(mdns.Fqdn(name), mdns.TypeTXT)
	c := &mdns.Client{Timeout: 3 * time.Second}
	resp, _, err := c.ExchangeContext(ctx, m, server)
	if err != nil {
		return nil
	}
	if resp.Truncated {
		c.Net = "tcp"
		if r2, _, err := c.ExchangeContext(ctx, m, server); err == nil {
			resp = r2
		}
	}
	var out []string
	for _, rr := range resp.Answer {
		if t, ok := rr.(*mdns.TXT); ok {
			out = append(out, strings.Join(t.Txt, ""))
		}
	}
	return out
}
