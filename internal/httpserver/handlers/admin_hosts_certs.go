package handlers

import (
	"context"
	"net/http"
	"time"
)

// ---- Certs (per-route SSL cockpit) -------------------------------------

type certRow struct {
	RouteID     int64
	Domain      string
	Status      string // route status
	SSLEnabled  bool
	IssuedAt    string
	ClientEmail string
	NodeName    string
	NodeHost    string
	LastError   string
}

type certsData struct {
	baseAdminData
	Certs []certRow
	Total int
}

// CertsList renders /admin/certs: SSL-focused per-route view. Reuses the
// retry / toggle endpoints under /admin/hosts/{id}/*, so renewal is a
// single button click that triggers a DNS re-check + Caddy re-push (and
// thereby reissues on-demand TLS).
func (h *AdminHandlers) CertsList(w http.ResponseWriter, r *http.Request) {
	d := certsData{baseAdminData: h.base(r, "Certificates")}
	db := h.DB()
	if db == nil {
		h.render(w, "certs", d)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	rows, err := db.QueryContext(ctx,
		`SELECT r.id, r.domain, r.status, r.ssl_enabled,
		        COALESCE(DATE_FORMAT(r.ssl_issued_at,'%Y-%m-%d %H:%i'),''),
		        u.email, n.name, n.public_hostname, COALESCE(r.last_error,'')
		 FROM routes r
		 JOIN services s    ON s.id = r.service_id
		 JOIN clients c     ON c.id = s.client_id
		 JOIN users u       ON u.id = c.user_id
		 JOIN caddy_nodes n ON n.id = r.caddy_node_id
		 WHERE r.kind = 'proxy' OR r.kind IS NULL
		 ORDER BY r.ssl_enabled DESC, r.status, r.domain
		 LIMIT 500`)
	if err != nil {
		h.Logger.Error("certs list", "err", err)
		d.Error = "Could not load the certificate list. Refresh to retry; if it persists, check the panel logs for 'certs list'."
		h.render(w, "certs", d)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var c certRow
		if err := rows.Scan(&c.RouteID, &c.Domain, &c.Status, &c.SSLEnabled,
			&c.IssuedAt, &c.ClientEmail, &c.NodeName, &c.NodeHost, &c.LastError); err == nil {
			d.Certs = append(d.Certs, c)
		}
	}
	d.Total = len(d.Certs)
	h.render(w, "certs", d)
}
