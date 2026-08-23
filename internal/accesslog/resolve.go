package accesslog

import (
	"context"
	"database/sql"
	"sort"
	"strings"
)

// routeEntry is one candidate route for a hostname: its id plus the path prefix
// it is mounted on ("" or "/" = the whole host).
type routeEntry struct {
	id     int64
	prefix string
}

// NodeRouteIndex maps a lowercase hostname (primary domain or a *verified*
// alias) to the routes the authenticated node actually serves for it, longest
// path prefix first.
//
// The index exists so an authenticated node-agent can only attribute access-log
// lines to routes that node serves: a stolen node token must not be able to
// poison another node's - or another tenant's - traffic history (LOG-01).
type NodeRouteIndex map[string][]routeEntry

// LoadNodeRouteIndex loads every non-disabled route served by nodeID: the
// anchor placement (routes.caddy_node_id) plus every active-active fan-out peer
// (route_node_assignments). A route the node does not serve is never indexed,
// so it can never be the target of that node's log lines.
func LoadNodeRouteIndex(ctx context.Context, db *sql.DB, nodeID int64) (NodeRouteIndex, error) {
	idx := NodeRouteIndex{}
	if db == nil || nodeID <= 0 {
		return idx, nil
	}
	rows, err := db.QueryContext(ctx, `
		SELECT r.id, LOWER(r.domain), COALESCE(r.path_prefix,''), COALESCE(r.aliases_verified,'')
		  FROM routes r
		 WHERE r.status <> 'disabled'
		   AND (r.caddy_node_id = ?
		        OR EXISTS (SELECT 1 FROM route_node_assignments rna
		                    WHERE rna.route_id = r.id AND rna.node_id = ?))`, nodeID, nodeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var (
			ent     routeEntry
			domain  string
			aliases string
		)
		if rows.Scan(&ent.id, &domain, &ent.prefix, &aliases) != nil {
			continue
		}
		idx.add(domain, ent)
		// Only proven aliases reach the node's host matcher, so only those can
		// legitimately appear as a Host in that node's access log.
		for _, a := range splitHostList(aliases) {
			idx.add(a, ent)
		}
	}
	for _, list := range idx {
		sort.SliceStable(list, func(a, b int) bool { return len(list[a].prefix) > len(list[b].prefix) })
	}
	return idx, rows.Err()
}

func (idx NodeRouteIndex) add(host string, ent routeEntry) {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return
	}
	idx[host] = append(idx[host], ent)
}

// Resolve maps one log line's Host and request URI to a route id served by the
// authenticated node. Path routing is honoured: the longest matching
// path_prefix wins, and a bare-host route ("" or "/") is the fallback. Returns
// false when this node serves no route for that host, in which case the line is
// dropped rather than attributed to somebody else's route.
func (idx NodeRouteIndex) Resolve(host, uri string) (int64, bool) {
	host = strings.ToLower(strings.TrimSpace(stripPort(host)))
	if host == "" {
		return 0, false
	}
	path := uri
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	var fallback int64
	for _, ent := range idx[host] {
		if ent.prefix == "" || ent.prefix == "/" {
			if fallback == 0 {
				fallback = ent.id
			}
			continue
		}
		if strings.HasPrefix(path, ent.prefix) {
			return ent.id, true // longest prefix first (sorted at load)
		}
	}
	if fallback > 0 {
		return fallback, true
	}
	return 0, false
}

// splitHostList splits the comma/whitespace separated alias column.
func splitHostList(s string) []string {
	if s == "" {
		return nil
	}
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == ';'
	})
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if f = strings.ToLower(strings.TrimSpace(f)); f != "" {
			out = append(out, f)
		}
	}
	return out
}
