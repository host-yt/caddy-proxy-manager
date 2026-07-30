package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/host-yt/caddy-proxy-manager/internal/auth"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
)

// searchScope resolves the caller's client-scope for AdminSearch. scoped=false
// means unfiltered (super_admin/unrestricted); scoped=true means only rows
// whose client_id is in allowed may be returned. Fails closed (empty allowed)
// when a non-super_admin has no scope service wired or ScopeFilter errors.
func (h *AdminHandlers) searchScope(ctx context.Context, sess *auth.Session) (allowed map[int64]bool, scoped bool) {
	if sess == nil {
		return map[int64]bool{}, true // no session: fail closed, not unfiltered
	}
	if sess.Role == "super_admin" {
		return nil, false
	}
	if h.AdminScope == nil {
		return map[int64]bool{}, true
	}
	ids, all, err := h.AdminScope.ScopeFilter(ctx, sess.UserID)
	if err != nil || all {
		return nil, err != nil // err -> fail closed (scoped, empty); all -> unfiltered
	}
	m := make(map[int64]bool, len(ids))
	for _, id := range ids {
		m[id] = true
	}
	return m, true
}

// SearchResult is a single command-palette hit.
type SearchResult struct {
	Kind  string `json:"kind"`  // "host" | "client" | "node" | "tunnel" | "service" | "api_key"
	Label string `json:"label"` // display text
	Sub   string `json:"sub"`   // secondary (email, status, etc.)
	URL   string `json:"url"`   // navigation target
}

// AdminSearch handles GET /admin/search?q=<term>.
// Returns JSON {"results":[...]}; protected by the /admin router's RequireRole.
func (h *AdminHandlers) AdminSearch(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if len(q) < 2 {
		writeSearchJSON(w, nil)
		return
	}
	like := "%" + q + "%"

	db := h.DB()
	if db == nil {
		writeSearchJSON(w, nil)
		return
	}

	const limit = 5
	ctx, cancel := context.WithTimeout(r.Context(), 2_000_000_000)
	defer cancel()

	sess := middleware.SessionFromContext(r.Context())
	allowed, scoped := h.searchScope(ctx, sess)
	// Scoped admin: over-fetch then filter client-side, so filtering doesn't
	// starve the result list down to fewer than `limit` hits.
	fetchLimit := limit
	if scoped {
		fetchLimit = limit * 5
	}

	var results []SearchResult

	// hosts - pre-filter list by domain; scoped to routes under an allowed client.
	hostsQ := `SELECT r.domain, r.status FROM routes r WHERE r.domain LIKE ? ORDER BY r.id DESC LIMIT ?`
	hostsArgs := []any{like, fetchLimit}
	if scoped {
		hostsQ = `SELECT r.domain, r.status FROM routes r
		 JOIN services sv ON sv.id = r.service_id
		 WHERE r.domain LIKE ? AND sv.client_id IN (` + placeholders(len(allowed)) + `)
		 ORDER BY r.id DESC LIMIT ?`
		hostsArgs = append([]any{like}, append(int64KeysAsAny(allowed), fetchLimit)...)
	}
	if !scoped || len(allowed) > 0 {
		rows, err := db.QueryContext(ctx, hostsQ, hostsArgs...)
		if err == nil {
			defer rows.Close()
			for rows.Next() && countKind(results, "host") < limit {
				var domain, status string
				if rows.Scan(&domain, &status) == nil {
					results = append(results, SearchResult{
						Kind: "host", Label: domain, Sub: status,
						URL: "/admin/hosts?q=" + url.QueryEscape(domain),
					})
				}
			}
		}
	}

	// clients - link to detail page
	clientsQ := `SELECT c.id, COALESCE(c.display_name, u.email), u.email
		 FROM clients c JOIN users u ON u.id = c.user_id
		 WHERE (u.email LIKE ? OR c.display_name LIKE ?)`
	clientsArgs := []any{like, like}
	if scoped {
		clientsQ += ` AND c.id IN (` + placeholders(len(allowed)) + `)`
		clientsArgs = append(clientsArgs, int64KeysAsAny(allowed)...)
	}
	clientsQ += ` ORDER BY c.id DESC LIMIT ?`
	clientsArgs = append(clientsArgs, fetchLimit)
	if !scoped || len(allowed) > 0 {
		rows2, err := db.QueryContext(ctx, clientsQ, clientsArgs...)
		if err == nil {
			defer rows2.Close()
			for rows2.Next() && countKind(results, "client") < limit {
				var id int64
				var name, email string
				if rows2.Scan(&id, &name, &email) == nil {
					results = append(results, SearchResult{
						Kind: "client", Label: name, Sub: email,
						URL: "/admin/clients/" + strconv.FormatInt(id, 10),
					})
				}
			}
		}
	}

	// caddy nodes - global infrastructure, no client dimension: hidden from scoped admins.
	if !scoped {
		rows3, err := db.QueryContext(ctx,
			`SELECT id, name, health_status FROM caddy_nodes WHERE name LIKE ? ORDER BY id DESC LIMIT ?`,
			like, limit)
		if err == nil {
			defer rows3.Close()
			for rows3.Next() {
				var id int64
				var name, health string
				if rows3.Scan(&id, &name, &health) == nil {
					results = append(results, SearchResult{
						Kind: "node", Label: name, Sub: health, URL: "/admin/nodes",
					})
				}
			}
		}
	}

	// tunnels (WireGuard peers)
	tunnelsQ := `SELECT p.id, p.name, u.email
		 FROM customer_wg_peer p
		 JOIN clients c ON c.id = p.client_id
		 JOIN users u   ON u.id = c.user_id
		 WHERE p.name LIKE ?`
	tunnelsArgs := []any{like}
	if scoped {
		tunnelsQ += ` AND p.client_id IN (` + placeholders(len(allowed)) + `)`
		tunnelsArgs = append(tunnelsArgs, int64KeysAsAny(allowed)...)
	}
	tunnelsQ += ` ORDER BY p.id DESC LIMIT ?`
	tunnelsArgs = append(tunnelsArgs, fetchLimit)
	if !scoped || len(allowed) > 0 {
		rows4, err := db.QueryContext(ctx, tunnelsQ, tunnelsArgs...)
		if err == nil {
			defer rows4.Close()
			for rows4.Next() && countKind(results, "tunnel") < limit {
				var id int64
				var name, email string
				if rows4.Scan(&id, &name, &email) == nil {
					results = append(results, SearchResult{
						Kind: "tunnel", Label: name, Sub: email, URL: "/admin/tunnels",
					})
				}
			}
		}
	}

	// services - pre-filter list by name
	svcQ := `SELECT s.id, s.name, s.backend_ip, s.status FROM services s
		 WHERE (s.name LIKE ? OR s.backend_ip LIKE ?)`
	svcArgs := []any{like, like}
	if scoped {
		svcQ += ` AND s.client_id IN (` + placeholders(len(allowed)) + `)`
		svcArgs = append(svcArgs, int64KeysAsAny(allowed)...)
	}
	svcQ += ` ORDER BY s.id DESC LIMIT ?`
	svcArgs = append(svcArgs, fetchLimit)
	if !scoped || len(allowed) > 0 {
		rows5, err := db.QueryContext(ctx, svcQ, svcArgs...)
		if err == nil {
			defer rows5.Close()
			for rows5.Next() && countKind(results, "service") < limit {
				var id int64
				var name, backendIP, status string
				if rows5.Scan(&id, &name, &backendIP, &status) == nil {
					results = append(results, SearchResult{
						Kind: "service", Label: name, Sub: backendIP + " - " + status,
						URL: "/admin/services?q=" + url.QueryEscape(name),
					})
				}
			}
		}
	}

	// api keys - global (user-level, not client-scoped): hidden from scoped admins.
	if !scoped {
		rows6, err := db.QueryContext(ctx,
			`SELECT id, name, key_prefix FROM api_keys
			 WHERE name LIKE ? OR key_prefix LIKE ? LIMIT ?`,
			like, like, limit)
		if err == nil {
			defer rows6.Close()
			for rows6.Next() {
				var id int64
				var name, prefix string
				if rows6.Scan(&id, &name, &prefix) == nil {
					results = append(results, SearchResult{
						Kind: "api_key", Label: name, Sub: prefix + "...", URL: "/admin/api-keys",
					})
				}
			}
		}
	}

	// plans - platform/reseller-global, no client dimension: hidden from scoped admins.
	if !scoped {
		rows7p, err := db.QueryContext(ctx,
			`SELECT p.id, p.name, p.max_domains, ng.name FROM plans p
			 JOIN node_groups ng ON ng.id = p.node_group_id
			 WHERE p.name LIKE ? ORDER BY p.name LIMIT ?`,
			like, limit)
		if err == nil {
			defer rows7p.Close()
			for rows7p.Next() {
				var id int64
				var name, ng string
				var maxDomains int
				if rows7p.Scan(&id, &name, &maxDomains, &ng) == nil {
					results = append(results, SearchResult{
						Kind:  "plan",
						Label: name,
						Sub:   ng + " · " + strconv.Itoa(maxDomains) + " domains",
						URL:   "/admin/plans",
					})
				}
			}
		}
	}

	// webhook endpoints - global infrastructure: hidden from scoped admins.
	if !scoped {
		rows7, err := db.QueryContext(ctx,
			`SELECT id, name, is_enabled FROM webhook_endpoints WHERE name LIKE ? ORDER BY id DESC LIMIT ?`,
			like, limit)
		if err == nil {
			defer rows7.Close()
			for rows7.Next() {
				var id int64
				var name string
				var isEnabled bool
				if rows7.Scan(&id, &name, &isEnabled) == nil {
					sub := "disabled"
					if isEnabled {
						sub = "enabled"
					}
					results = append(results, SearchResult{
						Kind: "webhook_endpoint", Label: name, Sub: sub, URL: "/admin/webhooks",
					})
				}
			}
		}
	}

	// recent fired alerts - global (no client dimension): hidden from scoped admins.
	if !scoped {
		rows8, err := db.QueryContext(ctx,
			`SELECT id, rule_id, title, severity FROM alert_log WHERE title LIKE ? ORDER BY fired_at DESC LIMIT ?`,
			like, limit)
		if err != nil {
			writeSearchJSON(w, results)
			return
		}
		defer rows8.Close()
		for rows8.Next() {
			var id int64
			var ruleID, title, severity string
			if rows8.Scan(&id, &ruleID, &title, &severity) == nil {
				results = append(results, SearchResult{
					Kind: "alert", Label: title, Sub: severity + " - " + ruleID, URL: "/admin/alerts",
				})
			}
		}
	}

	writeSearchJSON(w, results)
}

// int64KeysAsAny flattens a client-id set into driver args for an IN (...) clause.
func int64KeysAsAny(m map[int64]bool) []any {
	out := make([]any, 0, len(m))
	for id := range m {
		out = append(out, id)
	}
	return out
}

// countKind counts how many results of a given kind are already collected,
// so per-source over-fetch (scoped filtering) still respects the display limit.
func countKind(results []SearchResult, kind string) int {
	n := 0
	for _, r := range results {
		if r.Kind == kind {
			n++
		}
	}
	return n
}

func writeSearchJSON(w http.ResponseWriter, results []SearchResult) {
	if results == nil {
		results = []SearchResult{}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"results": results})
}
