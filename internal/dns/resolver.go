package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
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

// TXTContains reports whether any TXT record at `name` equals `want`. Used for
// domain-ownership proof: the owner publishes the route's verify token at
// _hpg-verify.<domain>. Exact match (trimmed) so a squatter cannot piggyback on
// an unrelated TXT value. Returns false on lookup error (fail closed).
func TXTContains(ctx context.Context, name, want string) bool {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	want = strings.TrimSpace(want)
	if want == "" {
		return false
	}
	records, err := net.DefaultResolver.LookupTXT(ctx, name)
	if err != nil {
		return false
	}
	for _, rec := range records {
		if strings.TrimSpace(rec) == want {
			return true
		}
	}
	return false
}
