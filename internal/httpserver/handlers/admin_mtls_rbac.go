package handlers

import (
	"context"
	"database/sql"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/host-yt/caddy-proxy-manager/internal/security"
)

// MTLSRBACCheck handles GET /internal/mtls-rbac/{route_id}.
// Called by Caddy forward_auth on routes with mTLS path rules.
// Reads cert subject from X-Mtls-Subject and original path from X-Forwarded-Uri.
// Returns 200 when the cert's roles satisfy the path rule, 403 otherwise.
func (h *AdminHandlers) MTLSRBACCheck(w http.ResponseWriter, r *http.Request) {
	routeID, err := strconv.ParseInt(chi.URLParam(r, "route_id"), 10, 64)
	if err != nil || routeID <= 0 {
		http.Error(w, "bad route", http.StatusBadRequest)
		return
	}
	subject := r.Header.Get("X-Mtls-Subject")
	origURI := r.Header.Get("X-Forwarded-Uri")
	if subject == "" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if origURI == "" {
		origURI = r.URL.Path
	}

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	db := h.DB()
	if db == nil {
		http.Error(w, "db unavailable", http.StatusServiceUnavailable)
		return
	}

	// The subject header is set by the caller, and the entrypoint gate is an
	// IP allow-list covering the whole mesh plus every trusted proxy. Require
	// the panel-issued (node, route) token so only a node this route is placed
	// on can run checks for it, and re-verify that placement server-side.
	if !h.rbacCallerAllowed(ctx, db, r, routeID) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	// Load path rules for this route. No rules = no restriction.
	type pathRule struct {
		Pattern  string
		RoleName string
	}
	rows, err := db.QueryContext(ctx, `
		SELECT pr.path_pattern, ro.name
		  FROM mtls_path_rules pr
		  JOIN mtls_roles ro ON ro.id = pr.required_role_id
		 WHERE pr.route_id = ?
		 ORDER BY pr.id`, routeID)
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var rules []pathRule
	for rows.Next() {
		var p pathRule
		_ = rows.Scan(&p.Pattern, &p.RoleName)
		rules = append(rules, p)
	}
	if len(rules) == 0 {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Strip query string; match on path only.
	reqPath := origURI
	if i := strings.Index(reqPath, "?"); i >= 0 {
		reqPath = reqPath[:i]
	}

	// First matching rule wins.
	var requiredRole string
	for _, rule := range rules {
		if pathMatchesPattern(reqPath, rule.Pattern) {
			requiredRole = rule.RoleName
			break
		}
	}
	if requiredRole == "" {
		// No rule matches this path - allow.
		w.WriteHeader(http.StatusOK)
		return
	}

	// Resolve cert by route CA + subject.
	var caID int64
	if err := db.QueryRowContext(ctx, "SELECT COALESCE(mtls_ca_id,0) FROM routes WHERE id=?", routeID).Scan(&caID); err != nil || caID == 0 {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	// Check across ALL active certs with this subject (subject is not unique per CA).
	// Any active cert carrying the required role grants access.
	var count int
	_ = db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM mtls_issued_certs c
		  JOIN mtls_cert_roles cr ON cr.cert_id = c.id
		  JOIN mtls_roles ro ON ro.id = cr.role_id
		 WHERE c.ca_id = ? AND c.subject = ? AND c.status = 'active'
		   AND ro.name = ?`, caID, subject, requiredRole).Scan(&count)
	if count == 0 {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// rbacCallerAllowed authenticates the forward_auth check subrequest.
//
// A valid caller presents the node id and the MAC the control plane wrote into
// that node's Caddy config, and the route must still be placed on that node
// (anchor placement or an active-active fan-out peer). Anything else - a host
// inside the mesh CIDR with no token, a token minted for a different route, a
// node the route has since moved off - is refused.
func (h *AdminHandlers) rbacCallerAllowed(ctx context.Context, db *sql.DB, r *http.Request, routeID int64) bool {
	token := strings.TrimSpace(r.Header.Get(security.MTLSRBACHeaderToken))
	nodeID, _ := strconv.ParseInt(strings.TrimSpace(r.Header.Get(security.MTLSRBACHeaderNode)), 10, 64)

	if token == "" || nodeID <= 0 || len(h.MTLSRBACKey) == 0 {
		// Upgrade window only: a fleet whose pushed config predates signed
		// checks. Loud, because it leaves the pre-fix trust model in place.
		if h.MTLSRBACAllowUnsigned {
			if h.Logger != nil {
				h.Logger.Warn("mtls rbac check accepted without node token (MTLS_RBAC_ALLOW_UNSIGNED)",
					"route_id", routeID, "ip", security.ClientIP(r))
			}
			return true
		}
		if h.Logger != nil {
			h.Logger.Warn("mtls rbac check rejected: missing or unverifiable node token",
				"route_id", routeID, "ip", security.ClientIP(r))
		}
		return false
	}
	if !security.VerifyMTLSRBACToken(h.MTLSRBACKey, nodeID, routeID, token) {
		if h.Logger != nil {
			h.Logger.Warn("mtls rbac check rejected: bad node token",
				"route_id", routeID, "node_id", nodeID, "ip", security.ClientIP(r))
		}
		return false
	}
	// Placement is re-read per check: a route that moved to another node stops
	// being checkable from the old one without waiting for a config push.
	var served int
	if err := db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM routes r
		 WHERE r.id = ?
		   AND (r.caddy_node_id = ?
		        OR EXISTS (SELECT 1 FROM route_node_assignments rna
		                    WHERE rna.route_id = r.id AND rna.node_id = ?))`,
		routeID, nodeID, nodeID).Scan(&served); err != nil || served == 0 {
		if h.Logger != nil {
			h.Logger.Warn("mtls rbac check rejected: route not served by node",
				"route_id", routeID, "node_id", nodeID, "err", err)
		}
		return false
	}
	return true
}

// pathMatchesPattern matches a request path against a rule pattern.
// Trailing "/*" = prefix match; otherwise exact match.
func pathMatchesPattern(path, pattern string) bool {
	if strings.HasSuffix(pattern, "/*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(path, prefix)
	}
	return path == pattern
}
