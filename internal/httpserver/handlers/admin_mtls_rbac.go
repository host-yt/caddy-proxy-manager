package handlers

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
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

// pathMatchesPattern matches a request path against a rule pattern.
// Trailing "/*" = prefix match; otherwise exact match.
func pathMatchesPattern(path, pattern string) bool {
	if strings.HasSuffix(pattern, "/*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(path, prefix)
	}
	return path == pattern
}
