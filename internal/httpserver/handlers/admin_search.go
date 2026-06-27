package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

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

	var results []SearchResult

	// hosts - pre-filter list by domain
	rows, err := db.QueryContext(ctx,
		`SELECT domain, status FROM routes WHERE domain LIKE ? ORDER BY id DESC LIMIT ?`,
		like, limit)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var domain, status string
			if rows.Scan(&domain, &status) == nil {
				results = append(results, SearchResult{
					Kind: "host", Label: domain, Sub: status,
					URL: "/admin/hosts?q=" + url.QueryEscape(domain),
				})
			}
		}
	}

	// clients - link to detail page
	rows2, err := db.QueryContext(ctx,
		`SELECT c.id, COALESCE(c.display_name, u.email), u.email
		 FROM clients c JOIN users u ON u.id = c.user_id
		 WHERE u.email LIKE ? OR c.display_name LIKE ?
		 ORDER BY c.id DESC LIMIT ?`,
		like, like, limit)
	if err == nil {
		defer rows2.Close()
		for rows2.Next() {
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

	// caddy nodes - list (no individual node page)
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

	// tunnels (WireGuard peers)
	rows4, err := db.QueryContext(ctx,
		`SELECT p.id, p.name, u.email
		 FROM customer_wg_peer p
		 JOIN clients c ON c.id = p.client_id
		 JOIN users u   ON u.id = c.user_id
		 WHERE p.name LIKE ?
		 ORDER BY p.id DESC LIMIT ?`,
		like, limit)
	if err == nil {
		defer rows4.Close()
		for rows4.Next() {
			var id int64
			var name, email string
			if rows4.Scan(&id, &name, &email) == nil {
				results = append(results, SearchResult{
					Kind: "tunnel", Label: name, Sub: email, URL: "/admin/tunnels",
				})
			}
		}
	}

	// services - pre-filter list by name
	rows5, err := db.QueryContext(ctx,
		`SELECT s.id, s.name, s.backend_ip, s.status FROM services s
		 WHERE s.name LIKE ? OR s.backend_ip LIKE ? ORDER BY s.id DESC LIMIT ?`,
		like, like, limit)
	if err == nil {
		defer rows5.Close()
		for rows5.Next() {
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

	// api keys - name or prefix match
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

	writeSearchJSON(w, results)
}

func writeSearchJSON(w http.ResponseWriter, results []SearchResult) {
	if results == nil {
		results = []SearchResult{}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"results": results})
}
