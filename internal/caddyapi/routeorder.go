package caddyapi

import (
	"sort"
	"strings"

	"golang.org/x/net/idna"
)

// Route emission order. Caddy matches srv0.routes top-down and every route we
// emit is terminal, so the FIRST matching route wins. A host catch-all (no path
// prefix) matches every path on that host, which means a broader sibling placed
// earlier silently shadows a narrower one - including a fail-closed deny route.
// DB id order (see routes.buildRoutesForNode) is therefore not a safe emission
// order once two routes share a host.

// EmissionOrder returns the index permutation that routes should be emitted in.
// Routes that share no host with any other route keep their exact slot, so a
// deployment without overlapping hosts gets the identity permutation (and thus
// a byte-identical config + unchanged drift hash).
func EmissionOrder(routes []Route) []int {
	order := make([]int, len(routes))
	for i := range order {
		order[i] = i
	}
	if len(routes) < 2 {
		return order
	}

	// Union-find over routes that can match the same request host.
	parent := make([]int, len(routes))
	for i := range parent {
		parent[i] = i
	}
	var find func(int) int
	find = func(i int) int {
		for parent[i] != i {
			parent[i] = parent[parent[i]]
			i = parent[i]
		}
		return i
	}
	union := func(a, b int) {
		ra, rb := find(a), find(b)
		if ra != rb {
			parent[rb] = ra
		}
	}

	byHost := make(map[string][]int)
	var hosts []string
	for i, r := range routes {
		n := 0
		for _, h := range r.Hosts {
			h = NormalizeHost(h)
			if h == "" {
				continue
			}
			n++
			if _, seen := byHost[h]; !seen {
				hosts = append(hosts, h)
			}
			byHost[h] = append(byHost[h], i)
		}
		// No host matcher at all is Caddy's catch-all: it shadows every sibling.
		if n == 0 {
			for j := range routes {
				union(i, j)
			}
		}
	}
	for _, idxs := range byHost {
		for _, j := range idxs[1:] {
			union(idxs[0], j)
		}
	}
	// Distinct host strings can still collide (wildcard covers concrete).
	for i := 0; i < len(hosts); i++ {
		for j := i + 1; j < len(hosts); j++ {
			if HostsOverlap(hosts[i], hosts[j]) {
				union(byHost[hosts[i]][0], byHost[hosts[j]][0])
			}
		}
	}

	groups := make(map[int][]int)
	for i := range routes {
		root := find(i)
		groups[root] = append(groups[root], i)
	}
	for _, slots := range groups {
		if len(slots) < 2 {
			continue
		}
		members := append([]int(nil), slots...)
		sort.SliceStable(members, func(a, b int) bool {
			ra, rb := routes[members[a]], routes[members[b]]
			sa, sb := pathSpecificity(ra), pathSpecificity(rb)
			if sa != sb {
				return sa > sb
			}
			// Equal specificity: a fail-closed deny must win over its twin.
			return denyRank(ra) < denyRank(rb)
		})
		// Write back into the same slots, so unrelated routes never move.
		for k, slot := range slots {
			order[slot] = members[k]
		}
	}
	return order
}

// SortRoutesForEmission returns a copy of routes in EmissionOrder.
func SortRoutesForEmission(routes []Route) []Route {
	order := EmissionOrder(routes)
	out := make([]Route, len(routes))
	for k, i := range order {
		out[k] = routes[i]
	}
	return out
}

// NormalizeHost canonicalises a host matcher the way Caddy's MatchHost.Provision
// does (IDNA-to-ASCII then lowercase), so a Unicode matcher and its punycode
// twin compare equal instead of looking like two unrelated hosts.
func NormalizeHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	if h == "" {
		return ""
	}
	// A root-dotted name and its bare form address the same host; collapsing
	// them can only widen overlap, never hide one.
	for len(h) > 1 && strings.HasSuffix(h, ".") {
		h = h[:len(h)-1]
	}
	if ascii, err := idna.ToASCII(h); err == nil && ascii != "" {
		h = strings.ToLower(ascii)
	}
	return h
}

// HostsOverlap reports whether two host matchers can match the same request
// host. Single source of truth: the full-config ordering and the incremental
// clash probe must never disagree, or a permissive wildcard silently shadows a
// newly appended gated route.
func HostsOverlap(a, b string) bool {
	a, b = NormalizeHost(a), NormalizeHost(b)
	// An absent host matcher is Caddy's catch-all - it matches everything.
	if a == "" || b == "" {
		return true
	}
	// Anything we cannot model (placeholders, ports, partial-label wildcards)
	// is assumed to overlap so the caller falls back to a safe full resync.
	if !ValidHostMatcher(a) || !ValidHostMatcher(b) {
		return true
	}
	return hostPatternsIntersect(a, b)
}

// HostSetsOverlap reports whether any host in a can match the same request host
// as some host in b. An empty set is a route with no host matcher, i.e. a
// catch-all that overlaps every other route.
func HostSetsOverlap(a, b []string) bool {
	if hostSetIsCatchAll(a) || hostSetIsCatchAll(b) {
		return true
	}
	for _, x := range a {
		for _, y := range b {
			if HostsOverlap(x, y) {
				return true
			}
		}
	}
	return false
}

func hostSetIsCatchAll(hs []string) bool {
	for _, h := range hs {
		if NormalizeHost(h) != "" {
			return false
		}
	}
	return true
}

// hostPatternsIntersect mirrors MatchHost: both sides are split on ".", the
// label counts must be equal, and a whole-label "*" matches any single label.
// Two patterns intersect when every label pair can be satisfied at once.
func hostPatternsIntersect(a, b string) bool {
	la, lb := strings.Split(a, "."), strings.Split(b, ".")
	if len(la) != len(lb) {
		return false
	}
	for i := range la {
		if la[i] == "*" || lb[i] == "*" {
			continue
		}
		if !strings.EqualFold(la[i], lb[i]) {
			return false
		}
	}
	return true
}

// ValidHostMatcher reports whether a host matcher has a shape the overlap
// predicate can reason about exactly. Write paths must reject the rest, because
// an unmodellable matcher can only be handled by assuming it shadows everything.
func ValidHostMatcher(h string) bool {
	// Checked before NormalizeHost: that collapses a root dot for a conservative
	// comparison, but "example.com." is its own literal matcher to Caddy.
	if raw := strings.TrimSpace(h); raw == "" || strings.HasPrefix(raw, ".") || strings.HasSuffix(raw, ".") {
		return false
	}
	h = NormalizeHost(h)
	if h == "" || len(h) > 253 {
		return false
	}
	// Placeholders expand at request time and ports never match (Caddy strips
	// the port from the request host before comparing), so neither is modellable.
	if strings.ContainsAny(h, "{}:/ \t\r\n") {
		return false
	}
	if _, err := idna.ToASCII(h); err != nil {
		return false
	}
	for _, label := range strings.Split(h, ".") {
		if label == "*" {
			continue
		}
		if label == "" || len(label) > 63 {
			return false
		}
		// A "*" inside a label is not a wildcard for Caddy - it matches the
		// literal star, i.e. nothing - so treat it as unsupported.
		if strings.Contains(label, "*") {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return false
			}
		}
	}
	return true
}

// pathSpecificity ranks a route's path matcher by prefix containment: a longer
// prefix matches a strict subset, so it must be emitted first. The trailing
// slash is significant - /api* is broader than /api/* and must not tie with it.
// Empty or "/" is the host catch-all and sorts last within its group.
func pathSpecificity(r Route) int {
	p := strings.TrimSpace(r.PathPrefix)
	if p == "/" {
		return 0
	}
	return len(p)
}

// denyRank sorts fail-closed deny routes, then gated ones, ahead of equally
// specific siblings: at equal specificity the guarded route must win.
func denyRank(r Route) int {
	switch {
	case r.MTLSDenyOnMisconfig || r.PortalDenyOnMisconfig:
		return 0
	case RouteAuthGated(r):
		return 1
	default:
		return 2
	}
}
