package caddyapi

import (
	"sort"
	"strings"
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
	var wildcards []string
	for i, r := range routes {
		for _, h := range r.Hosts {
			h = strings.ToLower(strings.TrimSpace(h))
			if h == "" {
				continue
			}
			if _, seen := byHost[h]; !seen && strings.HasPrefix(h, "*.") {
				wildcards = append(wildcards, h)
			}
			byHost[h] = append(byHost[h], i)
		}
	}
	for _, idxs := range byHost {
		for _, j := range idxs[1:] {
			union(idxs[0], j)
		}
	}
	// A wildcard host also overlaps every concrete host it covers.
	for _, w := range wildcards {
		for h, idxs := range byHost {
			if h != w && wildcardCovers(w, h) {
				union(byHost[w][0], idxs[0])
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

// wildcardCovers reports whether pattern "*.example.com" matches host, i.e. the
// host is exactly one label deeper (Caddy's wildcard semantics).
func wildcardCovers(pattern, host string) bool {
	if !strings.HasPrefix(pattern, "*.") || strings.HasPrefix(host, "*.") {
		return false
	}
	suffix := pattern[1:] // ".example.com"
	if !strings.HasSuffix(host, suffix) {
		return false
	}
	label := strings.TrimSuffix(host, suffix)
	return label != "" && !strings.Contains(label, ".")
}

// pathSpecificity ranks a route's path matcher: longer prefix = narrower match,
// empty prefix = host catch-all (must be emitted last within its host group).
func pathSpecificity(r Route) int {
	p := strings.TrimSpace(r.PathPrefix)
	if p == "/" {
		return 0
	}
	return len(strings.TrimSuffix(p, "/"))
}

// denyRank sorts fail-closed deny routes ahead of equally specific siblings.
func denyRank(r Route) int {
	if r.MTLSDenyOnMisconfig || r.PortalDenyOnMisconfig {
		return 0
	}
	return 1
}
