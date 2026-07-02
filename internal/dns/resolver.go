package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
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

	resolver := net.DefaultResolver
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

// publicResolvers are queried in addition to the host's default resolver when
// proving domain ownership. The panel usually runs in a container whose default
// resolver is Docker's embedded DNS (127.0.0.11); that can return stale/negative
// answers or a split-horizon view, so a TXT record the owner has published (and
// external tools see) reads as missing. Consulting public recursive resolvers
// makes verification match what the rest of the internet sees. Overridable with
// HPG_DNS_RESOLVERS (comma-separated ip or ip:port).
func publicResolvers() []string {
	if env := strings.TrimSpace(os.Getenv("HPG_DNS_RESOLVERS")); env != "" {
		var out []string
		for _, s := range strings.Split(env, ",") {
			if s = strings.TrimSpace(s); s != "" {
				out = append(out, withDNSPort(s))
			}
		}
		return out
	}
	return []string{"1.1.1.1:53", "8.8.8.8:53"}
}

func withDNSPort(s string) string {
	if _, _, err := net.SplitHostPort(s); err == nil {
		return s
	}
	return net.JoinHostPort(s, "53")
}

// resolverFor returns a *net.Resolver that sends queries to the given server,
// or net.DefaultResolver when server is empty.
func resolverFor(server string) *net.Resolver {
	if server == "" {
		return net.DefaultResolver
	}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, server)
		},
	}
}

// TXTContains reports whether any TXT record at `name` equals `want`. Used for
// domain-ownership proof: the owner publishes the route's verify token at
// _hpg-verify.<domain>. Exact match (trimmed) so a squatter cannot piggyback on
// an unrelated TXT value. The host's default resolver is tried first, then public
// resolvers; true on the first match. Returns false only when no resolver sees
// the token (fail closed).
func TXTContains(ctx context.Context, name, want string) bool {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	want = strings.TrimSpace(want)
	if want == "" {
		return false
	}
	servers := append([]string{""}, publicResolvers()...) // "" = default resolver
	for _, srv := range servers {
		records, err := resolverFor(srv).LookupTXT(ctx, name)
		if err != nil {
			continue
		}
		for _, rec := range records {
			if strings.TrimSpace(rec) == want {
				return true
			}
		}
	}
	return false
}
