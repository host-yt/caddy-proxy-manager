package handlers

// api_v1_ext.go - CRUD extensions for clients, plans, services (list/delete),
// routes (get), and node pools. All endpoints share APIKeyAuth+APIQuota
// middleware applied in server.go.

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/host-yt/caddy-proxy-manager/internal/audit"
	"github.com/host-yt/caddy-proxy-manager/internal/auth"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
)

// ---- Services (list + delete) ------------------------------------------

func (h *APIHandlers) ServicesList(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(r) {
		apiErr(w, http.StatusForbidden, "admin role required")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	ids, all, serr := h.apiScope(ctx, middleware.CallerFromContext(r.Context()))
	if serr != nil {
		apiErr(w, http.StatusForbidden, "scope unresolved")
		return
	}
	query := `SELECT id, client_id, name, backend_ip, allowed_port_start, allowed_port_end,
	        plan_id, status, COALESCE(external_reference,''), created_at
	 FROM services`
	var args []any
	if !all {
		// Reseller/scoped admin: only services of owned clients.
		if len(ids) == 0 {
			apiJSON(w, http.StatusOK, map[string]any{"services": []apiService{}})
			return
		}
		query += " WHERE client_id IN (" + adminMapPlaceholders(len(ids)) + ")"
		for _, id := range ids {
			args = append(args, id)
		}
	}
	query += " ORDER BY id DESC"
	rows, err := h.DB().QueryContext(ctx, query, args...)
	if err != nil {
		apiErr(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()
	out := []apiService{}
	for rows.Next() {
		var s apiService
		if err := rows.Scan(&s.ID, &s.ClientID, &s.Name, &s.BackendIP,
			&s.AllowedPortStart, &s.AllowedPortEnd, &s.PlanID, &s.Status,
			&s.ExternalReference, &s.CreatedAt); err == nil {
			out = append(out, s)
		}
	}
	apiJSON(w, http.StatusOK, map[string]any{"services": out})
}

func (h *APIHandlers) ServiceDelete(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(r) {
		apiErr(w, http.StatusForbidden, "admin role required")
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	// Ownership: a reseller/scoped admin may only delete its own services.
	if !h.serviceInScope(ctx, w, r, id) {
		return
	}
	res, err := h.DB().ExecContext(ctx, "DELETE FROM services WHERE id = ?", id)
	if err != nil {
		if strings.Contains(err.Error(), "foreign key") {
			apiErr(w, http.StatusConflict, "service has active routes")
			return
		}
		apiErr(w, http.StatusInternalServerError, "delete failed")
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		apiErr(w, http.StatusNotFound, "not found")
		return
	}
	uid := apiCallerID(r)
	audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
		UserID: &uid, ActorType: audit.ActorAPI, Action: "service.delete", Entity: "service",
		EntityID: strconv.FormatInt(id, 10),
	})
	apiJSON(w, http.StatusOK, map[string]any{"id": id, "deleted": true})
}

// ---- Routes (list, get, update) ----------------------------------------

type apiRoute struct {
	ID           int64     `json:"id"`
	ServiceID    int64     `json:"service_id"`
	Domain       string    `json:"domain"`
	PathPrefix   string    `json:"path_prefix"`
	UpstreamPort int       `json:"upstream_port"`
	SSL          bool      `json:"ssl"`
	WebSocket    bool      `json:"websocket"`
	ForceHTTPS   bool      `json:"force_https"`
	Status       string    `json:"status"`
	CaddyNodeID  int64     `json:"caddy_node_id"`
	CreatedAt    time.Time `json:"created_at"`
}

const routeSelectCols = `r.id, r.service_id, r.domain, COALESCE(r.path_prefix,''), r.upstream_port,
	COALESCE(r.ssl_enabled,0), COALESCE(r.websocket,0), COALESCE(r.force_https,0),
	r.status, r.caddy_node_id, r.created_at`

func scanRoute(row interface {
	Scan(...any) error
}, rt *apiRoute) error {
	return row.Scan(&rt.ID, &rt.ServiceID, &rt.Domain, &rt.PathPrefix, &rt.UpstreamPort,
		&rt.SSL, &rt.WebSocket, &rt.ForceHTTPS, &rt.Status, &rt.CaddyNodeID, &rt.CreatedAt)
}

func (h *APIHandlers) RoutesList(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	c := middleware.CallerFromContext(r.Context())
	if c == nil {
		apiErr(w, http.StatusUnauthorized, "auth required")
		return
	}

	svcIDFilter, _ := strconv.ParseInt(r.URL.Query().Get("service_id"), 10, 64)

	var (
		query string
		args  []any
	)
	if c.Role == "client" {
		clientID, err := clientIDForUserStrict(ctx, h.DB(), c.UserID)
		if err != nil {
			apiErr(w, http.StatusForbidden, "client scope unresolved")
			return
		}
		if svcIDFilter > 0 {
			query = "SELECT " + routeSelectCols + " FROM routes r JOIN services s ON s.id=r.service_id WHERE s.client_id=? AND r.service_id=? ORDER BY r.id DESC"
			args = []any{clientID, svcIDFilter}
		} else {
			query = "SELECT " + routeSelectCols + " FROM routes r JOIN services s ON s.id=r.service_id WHERE s.client_id=? ORDER BY r.id DESC"
			args = []any{clientID}
		}
	} else {
		// Admin: bare admin sees all; reseller/scoped admin is limited to routes
		// whose service belongs to an owned client.
		ids, all, serr := h.apiScope(ctx, c)
		if serr != nil {
			apiErr(w, http.StatusForbidden, "scope unresolved")
			return
		}
		base := "SELECT " + routeSelectCols + " FROM routes r"
		var where []string
		if !all {
			if len(ids) == 0 {
				apiJSON(w, http.StatusOK, map[string]any{"routes": []apiRoute{}})
				return
			}
			base += " JOIN services s ON s.id=r.service_id"
			where = append(where, "s.client_id IN ("+adminMapPlaceholders(len(ids))+")")
			for _, id := range ids {
				args = append(args, id)
			}
		}
		if svcIDFilter > 0 {
			where = append(where, "r.service_id=?")
			args = append(args, svcIDFilter)
		}
		if len(where) > 0 {
			base += " WHERE " + strings.Join(where, " AND ")
		}
		query = base + " ORDER BY r.id DESC"
	}

	rows, err := h.DB().QueryContext(ctx, query, args...)
	if err != nil {
		apiErr(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()
	out := []apiRoute{}
	for rows.Next() {
		var rt apiRoute
		if err := scanRoute(rows, &rt); err == nil {
			out = append(out, rt)
		}
	}
	apiJSON(w, http.StatusOK, map[string]any{"routes": out})
}

func (h *APIHandlers) RouteGet(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	var rt apiRoute
	err := h.DB().QueryRowContext(ctx,
		"SELECT "+routeSelectCols+" FROM routes r WHERE r.id = ?", id,
	).Scan(&rt.ID, &rt.ServiceID, &rt.Domain, &rt.PathPrefix, &rt.UpstreamPort,
		&rt.SSL, &rt.WebSocket, &rt.ForceHTTPS, &rt.Status, &rt.CaddyNodeID, &rt.CreatedAt)
	if err == sql.ErrNoRows {
		apiErr(w, http.StatusNotFound, "not found")
		return
	}
	if err != nil {
		apiErr(w, http.StatusInternalServerError, "query failed")
		return
	}
	// Clients can only see their own routes via ownership of the service.
	c := middleware.CallerFromContext(r.Context())
	if c != nil && c.Role == "client" {
		clientID, lerr := clientIDForUserStrict(ctx, h.DB(), c.UserID)
		if lerr != nil {
			apiErr(w, http.StatusForbidden, "client scope unresolved")
			return
		}
		var svcOwner int64
		if err2 := h.DB().QueryRowContext(ctx,
			"SELECT client_id FROM services WHERE id = ?", rt.ServiceID,
		).Scan(&svcOwner); err2 != nil || svcOwner != clientID {
			apiErr(w, http.StatusForbidden, "forbidden")
			return
		}
	} else if c != nil && !h.routeInScope(ctx, w, r, id) {
		// Reseller/scoped admin: route's service must belong to an owned client.
		return
	}
	apiJSON(w, http.StatusOK, rt)
}

func (h *APIHandlers) RouteUpdate(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(r) {
		apiErr(w, http.StatusForbidden, "admin role required")
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	var in struct {
		UpstreamPort *int    `json:"upstream_port"`
		SSLEnabled   *bool   `json:"ssl_enabled"`
		WebSocket    *bool   `json:"websocket"`
		ForceHTTPS   *bool   `json:"force_https"`
		PathPrefix   *string `json:"path_prefix"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		apiErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if in.UpstreamPort != nil && (*in.UpstreamPort < 1 || *in.UpstreamPort > 65535) {
		apiErr(w, http.StatusBadRequest, "upstream_port out of range")
		return
	}
	if in.PathPrefix != nil && len(*in.PathPrefix) > 100 {
		apiErr(w, http.StatusBadRequest, "path_prefix max 100 chars")
		return
	}
	parts := []string{}
	args := []any{}
	if in.UpstreamPort != nil {
		parts = append(parts, "upstream_port=?")
		args = append(args, *in.UpstreamPort)
	}
	if in.SSLEnabled != nil {
		parts = append(parts, "ssl_enabled=?")
		args = append(args, *in.SSLEnabled)
	}
	if in.WebSocket != nil {
		parts = append(parts, "websocket=?")
		args = append(args, *in.WebSocket)
	}
	if in.ForceHTTPS != nil {
		parts = append(parts, "force_https=?")
		args = append(args, *in.ForceHTTPS)
	}
	if in.PathPrefix != nil {
		parts = append(parts, "path_prefix=?")
		args = append(args, *in.PathPrefix)
	}
	if len(parts) == 0 {
		apiJSON(w, http.StatusOK, map[string]any{"id": id, "updated": false, "resync_required": false})
		return
	}
	args = append(args, id)
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if !h.routeInScope(ctx, w, r, id) {
		return
	}
	res, err := h.DB().ExecContext(ctx,
		"UPDATE routes SET "+strings.Join(parts, ", ")+" WHERE id=?", args...)
	if err != nil {
		apiErr(w, http.StatusInternalServerError, "update failed")
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		apiErr(w, http.StatusNotFound, "not found")
		return
	}
	uid := apiCallerID(r)
	audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
		UserID: &uid, ActorType: audit.ActorAPI, Action: "route.updated", Entity: "route",
		EntityID: strconv.FormatInt(id, 10),
	})
	apiJSON(w, http.StatusOK, map[string]any{"id": id, "updated": true, "resync_required": true})
}

// ---- Plans CRUD --------------------------------------------------------

type apiPlan struct {
	ID                 int64     `json:"id"`
	Name               string    `json:"name"`
	Kind               string    `json:"kind"`
	MaxDomains         int       `json:"max_domains"`
	MaxPorts           int       `json:"max_ports"`
	SSLEnabled         bool      `json:"ssl_enabled"`
	PathRoutingEnabled bool      `json:"path_routing_enabled"`
	WildcardEnabled    bool      `json:"wildcard_enabled"`
	WebsocketEnabled   bool      `json:"websocket_enabled"`
	ExternalProxy      bool      `json:"external_proxy_enabled"`
	AllowEgressIP      bool      `json:"allow_egress_ip"`
	RateLimitRPM       *int      `json:"rate_limit_rpm"`
	WGKeyRotationDays  *int      `json:"wg_key_rotation_days"`
	NodeGroupID        int64     `json:"node_group_id"`
	CreatedAt          time.Time `json:"created_at"`
}

func scanPlan(rows *sql.Rows) (apiPlan, error) {
	var p apiPlan
	var rl, wgDays sql.NullInt32
	err := rows.Scan(
		&p.ID, &p.Name, &p.Kind, &p.MaxDomains, &p.MaxPorts,
		&p.SSLEnabled, &p.PathRoutingEnabled, &p.WildcardEnabled,
		&p.WebsocketEnabled, &p.ExternalProxy, &p.AllowEgressIP,
		&rl, &wgDays, &p.NodeGroupID, &p.CreatedAt,
	)
	if rl.Valid {
		v := int(rl.Int32)
		p.RateLimitRPM = &v
	}
	if wgDays.Valid {
		v := int(wgDays.Int32)
		p.WGKeyRotationDays = &v
	}
	return p, err
}

const planSelectCols = `id, name, kind, max_domains, max_ports, ssl_enabled,
	path_routing_enabled, wildcard_enabled, websocket_enabled,
	external_proxy_enabled, COALESCE(allow_egress_ip,0),
	rate_limit_rpm, wg_key_rotation_days, node_group_id, created_at`

func (h *APIHandlers) PlansList(w http.ResponseWriter, r *http.Request) {
	if !h.requireGlobalAPIAdmin(w, r) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	rows, err := h.DB().QueryContext(ctx,
		"SELECT "+planSelectCols+" FROM plans ORDER BY id DESC")
	if err != nil {
		apiErr(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()
	out := []apiPlan{}
	for rows.Next() {
		if p, err := scanPlan(rows); err == nil {
			out = append(out, p)
		}
	}
	apiJSON(w, http.StatusOK, map[string]any{"plans": out})
}

func (h *APIHandlers) PlanGet(w http.ResponseWriter, r *http.Request) {
	if !h.requireGlobalAPIAdmin(w, r) {
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	rows, err := h.DB().QueryContext(ctx,
		"SELECT "+planSelectCols+" FROM plans WHERE id = ? LIMIT 1", id)
	if err != nil {
		apiErr(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()
	if !rows.Next() {
		apiErr(w, http.StatusNotFound, "not found")
		return
	}
	p, err := scanPlan(rows)
	if err != nil {
		apiErr(w, http.StatusInternalServerError, "scan failed")
		return
	}
	apiJSON(w, http.StatusOK, p)
}

func (h *APIHandlers) PlanCreate(w http.ResponseWriter, r *http.Request) {
	if !h.requireGlobalAPIAdmin(w, r) {
		return
	}
	var in struct {
		Name               string `json:"name"`
		Kind               string `json:"kind"`
		MaxDomains         int    `json:"max_domains"`
		MaxPorts           int    `json:"max_ports"`
		NodeGroupID        int64  `json:"node_group_id"`
		SSLEnabled         bool   `json:"ssl_enabled"`
		PathRoutingEnabled bool   `json:"path_routing_enabled"`
		WildcardEnabled    bool   `json:"wildcard_enabled"`
		WebsocketEnabled   bool   `json:"websocket_enabled"`
		ExternalProxy      bool   `json:"external_proxy_enabled"`
		AllowEgressIP      bool   `json:"allow_egress_ip"`
		RateLimitRPM       int    `json:"rate_limit_rpm"`
		WGKeyRotationDays  int    `json:"wg_key_rotation_days"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		apiErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if in.Name == "" || in.MaxDomains <= 0 || in.MaxPorts <= 0 || in.NodeGroupID == 0 {
		apiErr(w, http.StatusBadRequest, "name, max_domains, max_ports, node_group_id required")
		return
	}
	if in.Kind != "npm" {
		in.Kind = "restricted"
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	var rl, wgDays sql.NullInt32
	if in.RateLimitRPM > 0 {
		rl = sql.NullInt32{Int32: int32(in.RateLimitRPM), Valid: true}
	}
	if in.WGKeyRotationDays > 0 {
		wgDays = sql.NullInt32{Int32: int32(in.WGKeyRotationDays), Valid: true}
	}
	res, err := h.DB().ExecContext(ctx,
		`INSERT INTO plans (name, kind, max_domains, max_ports, ssl_enabled,
		   path_routing_enabled, wildcard_enabled, websocket_enabled,
		   external_proxy_enabled, allow_egress_ip, rate_limit_rpm, wg_key_rotation_days, node_group_id)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		in.Name, in.Kind, in.MaxDomains, in.MaxPorts, in.SSLEnabled,
		in.PathRoutingEnabled, in.WildcardEnabled, in.WebsocketEnabled,
		in.ExternalProxy, in.AllowEgressIP, rl, wgDays, in.NodeGroupID,
	)
	if err != nil {
		if strings.Contains(err.Error(), "Duplicate entry") {
			apiErr(w, http.StatusConflict, "plan name already exists")
			return
		}
		apiErr(w, http.StatusInternalServerError, "insert failed")
		return
	}
	id, _ := res.LastInsertId()
	uid := apiCallerID(r)
	audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
		UserID: &uid, ActorType: audit.ActorAPI, Action: "plan.create", Entity: "plan",
		EntityID: strconv.FormatInt(id, 10), Meta: map[string]any{"name": in.Name},
	})
	apiJSON(w, http.StatusCreated, map[string]any{"id": id})
}

func (h *APIHandlers) PlanUpdate(w http.ResponseWriter, r *http.Request) {
	if !h.requireGlobalAPIAdmin(w, r) {
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	var in struct {
		Name               *string `json:"name"`
		Kind               *string `json:"kind"`
		MaxDomains         *int    `json:"max_domains"`
		MaxPorts           *int    `json:"max_ports"`
		NodeGroupID        *int64  `json:"node_group_id"`
		SSLEnabled         *bool   `json:"ssl_enabled"`
		PathRoutingEnabled *bool   `json:"path_routing_enabled"`
		WildcardEnabled    *bool   `json:"wildcard_enabled"`
		WebsocketEnabled   *bool   `json:"websocket_enabled"`
		ExternalProxy      *bool   `json:"external_proxy_enabled"`
		AllowEgressIP      *bool   `json:"allow_egress_ip"`
		RateLimitRPM       *int    `json:"rate_limit_rpm"`
		WGKeyRotationDays  *int    `json:"wg_key_rotation_days"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		apiErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	parts := []string{}
	args := []any{}
	if in.Name != nil {
		parts = append(parts, "name=?")
		args = append(args, *in.Name)
	}
	if in.Kind != nil {
		k := *in.Kind
		if k != "npm" {
			k = "restricted"
		}
		parts = append(parts, "kind=?")
		args = append(args, k)
	}
	if in.MaxDomains != nil {
		parts = append(parts, "max_domains=?")
		args = append(args, *in.MaxDomains)
	}
	if in.MaxPorts != nil {
		parts = append(parts, "max_ports=?")
		args = append(args, *in.MaxPorts)
	}
	if in.NodeGroupID != nil {
		parts = append(parts, "node_group_id=?")
		args = append(args, *in.NodeGroupID)
	}
	if in.SSLEnabled != nil {
		parts = append(parts, "ssl_enabled=?")
		args = append(args, *in.SSLEnabled)
	}
	if in.PathRoutingEnabled != nil {
		parts = append(parts, "path_routing_enabled=?")
		args = append(args, *in.PathRoutingEnabled)
	}
	if in.WildcardEnabled != nil {
		parts = append(parts, "wildcard_enabled=?")
		args = append(args, *in.WildcardEnabled)
	}
	if in.WebsocketEnabled != nil {
		parts = append(parts, "websocket_enabled=?")
		args = append(args, *in.WebsocketEnabled)
	}
	if in.ExternalProxy != nil {
		parts = append(parts, "external_proxy_enabled=?")
		args = append(args, *in.ExternalProxy)
	}
	if in.AllowEgressIP != nil {
		parts = append(parts, "allow_egress_ip=?")
		args = append(args, *in.AllowEgressIP)
	}
	if in.RateLimitRPM != nil {
		if *in.RateLimitRPM > 0 {
			parts = append(parts, "rate_limit_rpm=?")
			args = append(args, *in.RateLimitRPM)
		} else {
			parts = append(parts, "rate_limit_rpm=NULL")
		}
	}
	if in.WGKeyRotationDays != nil {
		if *in.WGKeyRotationDays > 0 {
			parts = append(parts, "wg_key_rotation_days=?")
			args = append(args, *in.WGKeyRotationDays)
		} else {
			parts = append(parts, "wg_key_rotation_days=NULL")
		}
	}
	if len(parts) == 0 {
		apiJSON(w, http.StatusOK, map[string]any{"id": id, "updated": false})
		return
	}
	args = append(args, id)
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	res, err := h.DB().ExecContext(ctx,
		"UPDATE plans SET "+strings.Join(parts, ", ")+" WHERE id = ?", args...)
	if err != nil {
		if strings.Contains(err.Error(), "Duplicate entry") {
			apiErr(w, http.StatusConflict, "plan name already exists")
			return
		}
		apiErr(w, http.StatusInternalServerError, "update failed")
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		apiErr(w, http.StatusNotFound, "not found")
		return
	}
	uid := apiCallerID(r)
	audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
		UserID: &uid, ActorType: audit.ActorAPI, Action: "plan.update", Entity: "plan",
		EntityID: strconv.FormatInt(id, 10),
	})
	apiJSON(w, http.StatusOK, map[string]any{"id": id, "updated": true})
}

func (h *APIHandlers) PlanDelete(w http.ResponseWriter, r *http.Request) {
	if !h.requireGlobalAPIAdmin(w, r) {
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	res, err := h.DB().ExecContext(ctx, "DELETE FROM plans WHERE id = ?", id)
	if err != nil {
		if strings.Contains(err.Error(), "foreign key") {
			apiErr(w, http.StatusConflict, "plan is in use by a service")
			return
		}
		apiErr(w, http.StatusInternalServerError, "delete failed")
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		apiErr(w, http.StatusNotFound, "not found")
		return
	}
	uid := apiCallerID(r)
	audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
		UserID: &uid, ActorType: audit.ActorAPI, Action: "plan.delete", Entity: "plan",
		EntityID: strconv.FormatInt(id, 10),
	})
	apiJSON(w, http.StatusOK, map[string]any{"id": id, "deleted": true})
}

// ---- Clients CRUD -------------------------------------------------------

type apiClient struct {
	ID          int64     `json:"id"`
	UserID      int64     `json:"user_id"`
	DisplayName string    `json:"display_name"`
	Email       string    `json:"email"`
	ExternalRef string    `json:"external_ref,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

func (h *APIHandlers) ClientsList(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(r) {
		apiErr(w, http.StatusForbidden, "admin role required")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	ids, all, serr := h.apiScope(ctx, middleware.CallerFromContext(r.Context()))
	if serr != nil {
		apiErr(w, http.StatusForbidden, "scope unresolved")
		return
	}
	query := `SELECT c.id, c.user_id, COALESCE(c.display_name,''), u.email,
	        COALESCE(c.external_ref,''), c.created_at
	 FROM clients c JOIN users u ON u.id=c.user_id`
	var args []any
	if !all {
		// Reseller/scoped admin: only owned clients.
		if len(ids) == 0 {
			apiJSON(w, http.StatusOK, map[string]any{"clients": []apiClient{}})
			return
		}
		query += " WHERE c.id IN (" + adminMapPlaceholders(len(ids)) + ")"
		for _, id := range ids {
			args = append(args, id)
		}
	}
	query += " ORDER BY c.id DESC"
	rows, err := h.DB().QueryContext(ctx, query, args...)
	if err != nil {
		apiErr(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()
	out := []apiClient{}
	for rows.Next() {
		var c apiClient
		if err := rows.Scan(&c.ID, &c.UserID, &c.DisplayName, &c.Email,
			&c.ExternalRef, &c.CreatedAt); err == nil {
			out = append(out, c)
		}
	}
	apiJSON(w, http.StatusOK, map[string]any{"clients": out})
}

func (h *APIHandlers) ClientGet(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(r) {
		apiErr(w, http.StatusForbidden, "admin role required")
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	var c apiClient
	err := h.DB().QueryRowContext(ctx,
		`SELECT c.id, c.user_id, COALESCE(c.display_name,''), u.email,
		        COALESCE(c.external_ref,''), c.created_at
		 FROM clients c JOIN users u ON u.id=c.user_id WHERE c.id=?`, id,
	).Scan(&c.ID, &c.UserID, &c.DisplayName, &c.Email, &c.ExternalRef, &c.CreatedAt)
	if err == sql.ErrNoRows {
		apiErr(w, http.StatusNotFound, "not found")
		return
	}
	if err != nil {
		apiErr(w, http.StatusInternalServerError, "query failed")
		return
	}
	if !h.apiAllowClient(ctx, middleware.CallerFromContext(r.Context()), c.ID) {
		apiErr(w, http.StatusForbidden, "forbidden")
		return
	}
	apiJSON(w, http.StatusOK, c)
}

func (h *APIHandlers) ClientCreate(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(r) {
		apiErr(w, http.StatusForbidden, "admin role required")
		return
	}
	var in struct {
		Email       string `json:"email"`
		Name        string `json:"name"`
		Password    string `json:"password"`
		ExternalRef string `json:"external_ref"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		apiErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	in.Email = strings.ToLower(strings.TrimSpace(in.Email))
	in.Name = strings.TrimSpace(in.Name)
	if in.Email == "" || in.Name == "" {
		apiErr(w, http.StatusBadRequest, "email and name required")
		return
	}
	// Require at least 12-char password; callers may use a generated value.
	if len(in.Password) < 12 {
		apiErr(w, http.StatusBadRequest, "password must be >= 12 characters")
		return
	}
	hash, err := auth.HashPassword(in.Password)
	if err != nil {
		apiErr(w, http.StatusInternalServerError, "hash failed")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	// Scope: an unrestricted admin creates a platform-direct client; a reseller-
	// admin creates one owned by their reseller; a client-scoped admin is denied.
	caller := middleware.CallerFromContext(r.Context())
	_, all, serr := h.apiScope(ctx, caller)
	if serr != nil {
		apiErr(w, http.StatusForbidden, "scope unresolved")
		return
	}
	var resellerCol any
	if !all {
		var rid sql.NullInt64
		if err := h.DB().QueryRowContext(ctx, "SELECT reseller_id FROM users WHERE id=?", caller.UserID).Scan(&rid); err != nil || !rid.Valid {
			apiErr(w, http.StatusForbidden, "client provisioning requires a global or reseller admin key")
			return
		}
		resellerCol = rid.Int64
		// Reseller aggregate quota: cap the number of clients.
		if h.Quota != nil {
			if qerr := h.Quota.CanCreateClient(ctx, rid.Int64); qerr != nil {
				apiErr(w, http.StatusForbidden, qerr.Error())
				return
			}
		}
	}
	tx, err := h.DB().BeginTx(ctx, nil)
	if err != nil {
		apiErr(w, http.StatusInternalServerError, "tx begin failed")
		return
	}
	defer tx.Rollback() //nolint:errcheck

	res, err := tx.ExecContext(ctx,
		"INSERT INTO users (email, password_hash, password_set, role, full_name, is_active) VALUES (?, ?, 1, 'client', ?, 1)",
		in.Email, hash, in.Name)
	if err != nil {
		if strings.Contains(err.Error(), "Duplicate entry") {
			apiErr(w, http.StatusConflict, "email already exists")
			return
		}
		apiErr(w, http.StatusInternalServerError, "user insert failed")
		return
	}
	userID, _ := res.LastInsertId()
	var extRef sql.NullString
	if in.ExternalRef != "" {
		extRef = sql.NullString{String: in.ExternalRef, Valid: true}
	}
	if _, err := tx.ExecContext(ctx,
		"INSERT INTO clients (user_id, display_name, external_ref, reseller_id) VALUES (?, ?, ?, ?)",
		userID, in.Name, extRef, resellerCol); err != nil {
		apiErr(w, http.StatusInternalServerError, "client insert failed")
		return
	}
	if err := tx.Commit(); err != nil {
		apiErr(w, http.StatusInternalServerError, "commit failed")
		return
	}
	uid := apiCallerID(r)
	audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
		UserID: &uid, ActorType: audit.ActorAPI, Action: "client.create", Entity: "client",
		EntityID: strconv.FormatInt(userID, 10), Meta: map[string]any{"email": in.Email},
	})
	// Return both IDs so callers can reference either record.
	apiJSON(w, http.StatusCreated, map[string]any{"user_id": userID})
}

func (h *APIHandlers) ClientUpdate(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(r) {
		apiErr(w, http.StatusForbidden, "admin role required")
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	var in struct {
		Name        *string `json:"name"`
		Email       *string `json:"email"`
		ExternalRef *string `json:"external_ref"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		apiErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if !h.apiAllowClient(ctx, middleware.CallerFromContext(r.Context()), id) {
		apiErr(w, http.StatusForbidden, "forbidden")
		return
	}

	var userID int64
	if err := h.DB().QueryRowContext(ctx,
		"SELECT user_id FROM clients WHERE id = ?", id,
	).Scan(&userID); err != nil {
		apiErr(w, http.StatusNotFound, "not found")
		return
	}

	tx, err := h.DB().BeginTx(ctx, nil)
	if err != nil {
		apiErr(w, http.StatusInternalServerError, "tx begin failed")
		return
	}
	defer tx.Rollback() //nolint:errcheck

	if in.Email != nil || in.Name != nil {
		// Load current values FIRST so a partial update (e.g. name-only) does not
		// deref a nil pointer or blank the other column on a stale read.
		var email, name string
		if err := tx.QueryRowContext(ctx,
			"SELECT email, COALESCE(full_name,'') FROM users WHERE id=?", userID,
		).Scan(&email, &name); err != nil && err != sql.ErrNoRows {
			apiErr(w, http.StatusInternalServerError, "user fetch failed")
			return
		}
		if in.Email != nil {
			email = strings.ToLower(strings.TrimSpace(*in.Email))
		}
		if in.Name != nil {
			name = strings.TrimSpace(*in.Name)
		}
		if _, err := tx.ExecContext(ctx,
			"UPDATE users SET email=?, full_name=? WHERE id=?", email, name, userID,
		); err != nil {
			if strings.Contains(err.Error(), "Duplicate entry") {
				apiErr(w, http.StatusConflict, "email already exists")
				return
			}
			apiErr(w, http.StatusInternalServerError, "user update failed")
			return
		}
	}
	if in.ExternalRef != nil {
		var extRef sql.NullString
		if *in.ExternalRef != "" {
			extRef = sql.NullString{String: *in.ExternalRef, Valid: true}
		}
		if in.Name != nil {
			if _, err := tx.ExecContext(ctx,
				"UPDATE clients SET display_name=?, external_ref=? WHERE id=?",
				*in.Name, extRef, id); err != nil {
				apiErr(w, http.StatusInternalServerError, "client update failed")
				return
			}
		} else {
			if _, err := tx.ExecContext(ctx,
				"UPDATE clients SET external_ref=? WHERE id=?", extRef, id); err != nil {
				apiErr(w, http.StatusInternalServerError, "client update failed")
				return
			}
		}
	} else if in.Name != nil {
		if _, err := tx.ExecContext(ctx,
			"UPDATE clients SET display_name=? WHERE id=?", *in.Name, id); err != nil {
			apiErr(w, http.StatusInternalServerError, "client update failed")
			return
		}
	}
	if err := tx.Commit(); err != nil {
		apiErr(w, http.StatusInternalServerError, "commit failed")
		return
	}
	uid := apiCallerID(r)
	audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
		UserID: &uid, ActorType: audit.ActorAPI, Action: "client.update", Entity: "client",
		EntityID: strconv.FormatInt(id, 10),
	})
	apiJSON(w, http.StatusOK, map[string]any{"id": id, "updated": true})
}

func (h *APIHandlers) ClientDelete(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(r) {
		apiErr(w, http.StatusForbidden, "admin role required")
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// Scoped delete: a reseller-admin may remove only its own reseller's client,
	// symmetric with ClientCreate/ClientGet. Unrestricted admins pass through.
	if !h.apiAllowClient(ctx, middleware.CallerFromContext(r.Context()), id) {
		apiErr(w, http.StatusForbidden, "forbidden")
		return
	}

	var userID int64
	if err := h.DB().QueryRowContext(ctx,
		"SELECT user_id FROM clients WHERE id = ?", id,
	).Scan(&userID); err != nil {
		apiErr(w, http.StatusNotFound, "not found")
		return
	}
	// Deleting the user cascades to the clients row.
	if _, err := h.DB().ExecContext(ctx, "DELETE FROM users WHERE id = ?", userID); err != nil {
		if strings.Contains(err.Error(), "foreign key") {
			apiErr(w, http.StatusConflict, "client has active services")
			return
		}
		apiErr(w, http.StatusInternalServerError, "delete failed")
		return
	}
	uid := apiCallerID(r)
	audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
		UserID: &uid, ActorType: audit.ActorAPI, Action: "client.delete", Entity: "client",
		EntityID: strconv.FormatInt(id, 10),
	})
	apiJSON(w, http.StatusOK, map[string]any{"id": id, "deleted": true})
}

// ---- Node Pools (node_groups) CRUD -------------------------------------

type apiNodePool struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	Mode      string    `json:"mode"`
	CreatedAt time.Time `json:"created_at"`
}

func (h *APIHandlers) NodePoolsList(w http.ResponseWriter, r *http.Request) {
	if !h.requireGlobalAPIAdmin(w, r) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	rows, err := h.DB().QueryContext(ctx,
		"SELECT id, name, mode, created_at FROM node_groups ORDER BY id ASC")
	if err != nil {
		apiErr(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()
	out := []apiNodePool{}
	for rows.Next() {
		var p apiNodePool
		if err := rows.Scan(&p.ID, &p.Name, &p.Mode, &p.CreatedAt); err == nil {
			out = append(out, p)
		}
	}
	apiJSON(w, http.StatusOK, map[string]any{"node_pools": out})
}

func (h *APIHandlers) NodePoolGet(w http.ResponseWriter, r *http.Request) {
	if !h.requireGlobalAPIAdmin(w, r) {
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	var p apiNodePool
	err := h.DB().QueryRowContext(ctx,
		"SELECT id, name, mode, created_at FROM node_groups WHERE id=?", id,
	).Scan(&p.ID, &p.Name, &p.Mode, &p.CreatedAt)
	if err == sql.ErrNoRows {
		apiErr(w, http.StatusNotFound, "not found")
		return
	}
	if err != nil {
		apiErr(w, http.StatusInternalServerError, "query failed")
		return
	}
	apiJSON(w, http.StatusOK, p)
}

func (h *APIHandlers) NodePoolCreate(w http.ResponseWriter, r *http.Request) {
	if !h.requireGlobalAPIAdmin(w, r) {
		return
	}
	var in struct {
		Name string `json:"name"`
		Mode string `json:"mode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		apiErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if in.Name == "" {
		apiErr(w, http.StatusBadRequest, "name required")
		return
	}
	switch in.Mode {
	case "active_active", "failover":
		// valid
	default:
		in.Mode = "single"
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	res, err := h.DB().ExecContext(ctx,
		"INSERT INTO node_groups (name, mode) VALUES (?, ?)", in.Name, in.Mode)
	if err != nil {
		if strings.Contains(err.Error(), "Duplicate entry") {
			apiErr(w, http.StatusConflict, "pool name already exists")
			return
		}
		apiErr(w, http.StatusInternalServerError, "insert failed")
		return
	}
	id, _ := res.LastInsertId()
	uid := apiCallerID(r)
	audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
		UserID: &uid, ActorType: audit.ActorAPI, Action: "node_pool.create", Entity: "node_pool",
		EntityID: strconv.FormatInt(id, 10), Meta: map[string]any{"name": in.Name},
	})
	apiJSON(w, http.StatusCreated, map[string]any{"id": id})
}

func (h *APIHandlers) NodePoolUpdate(w http.ResponseWriter, r *http.Request) {
	if !h.requireGlobalAPIAdmin(w, r) {
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	var in struct {
		Name *string `json:"name"`
		Mode *string `json:"mode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		apiErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	parts := []string{}
	args := []any{}
	if in.Name != nil {
		parts = append(parts, "name=?")
		args = append(args, *in.Name)
	}
	if in.Mode != nil {
		m := *in.Mode
		switch m {
		case "active_active", "failover", "single":
			// valid
		default:
			m = "single"
		}
		parts = append(parts, "mode=?")
		args = append(args, m)
	}
	if len(parts) == 0 {
		apiJSON(w, http.StatusOK, map[string]any{"id": id, "updated": false})
		return
	}
	args = append(args, id)
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	res, err := h.DB().ExecContext(ctx,
		"UPDATE node_groups SET "+strings.Join(parts, ", ")+" WHERE id=?", args...)
	if err != nil {
		if strings.Contains(err.Error(), "Duplicate entry") {
			apiErr(w, http.StatusConflict, "pool name already exists")
			return
		}
		apiErr(w, http.StatusInternalServerError, "update failed")
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		apiErr(w, http.StatusNotFound, "not found")
		return
	}
	uid := apiCallerID(r)
	audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
		UserID: &uid, ActorType: audit.ActorAPI, Action: "node_pool.update", Entity: "node_pool",
		EntityID: strconv.FormatInt(id, 10),
	})
	apiJSON(w, http.StatusOK, map[string]any{"id": id, "updated": true})
}

func (h *APIHandlers) NodePoolDelete(w http.ResponseWriter, r *http.Request) {
	if !h.requireGlobalAPIAdmin(w, r) {
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	res, err := h.DB().ExecContext(ctx, "DELETE FROM node_groups WHERE id=?", id)
	if err != nil {
		if strings.Contains(err.Error(), "foreign key") {
			apiErr(w, http.StatusConflict, "pool is used by plans or nodes")
			return
		}
		apiErr(w, http.StatusInternalServerError, "delete failed")
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		apiErr(w, http.StatusNotFound, "not found")
		return
	}
	uid := apiCallerID(r)
	audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
		UserID: &uid, ActorType: audit.ActorAPI, Action: "node_pool.delete", Entity: "node_pool",
		EntityID: strconv.FormatInt(id, 10),
	})
	apiJSON(w, http.StatusOK, map[string]any{"id": id, "deleted": true})
}

// ---- Nodes (get/update/delete) -----------------------------------------

type apiNode struct {
	ID             int64   `json:"id"`
	Name           string  `json:"name"`
	APIURL         string  `json:"api_url"`
	PublicHostname string  `json:"public_hostname"`
	PublicIP       string  `json:"public_ip"`
	NodeGroupID    int64   `json:"node_group_id"`
	MaxRoutes      int     `json:"max_routes"`
	CurrentRoutes  int     `json:"current_routes"`
	Priority       int     `json:"priority"`
	Enabled        bool    `json:"is_enabled"`
	Health         string  `json:"health_status"`
	HasWAF         bool    `json:"has_waf"`
	HasL4          bool    `json:"has_l4"`
	HasGeoIP       bool    `json:"has_geoip"`
	CaddyVersion   *string `json:"caddy_version,omitempty"`
}

func (h *APIHandlers) NodeGet(w http.ResponseWriter, r *http.Request) {
	if !h.requireGlobalAPIAdmin(w, r) {
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	var n apiNode
	var pubHostname, pubIP sql.NullString
	var caddyVer sql.NullString
	err := h.DB().QueryRowContext(ctx,
		`SELECT id, name, api_url, COALESCE(public_hostname,''), COALESCE(public_ip,''),
		        node_group_id, max_routes, current_routes, priority, is_enabled, health_status,
		        COALESCE(has_waf,0), COALESCE(has_l4,0), COALESCE(has_geoip,0), caddy_version
		 FROM caddy_nodes WHERE id=?`, id,
	).Scan(&n.ID, &n.Name, &n.APIURL, &pubHostname, &pubIP,
		&n.NodeGroupID, &n.MaxRoutes, &n.CurrentRoutes, &n.Priority, &n.Enabled, &n.Health,
		&n.HasWAF, &n.HasL4, &n.HasGeoIP, &caddyVer)
	_ = pubHostname
	_ = pubIP
	if err == sql.ErrNoRows {
		apiErr(w, http.StatusNotFound, "not found")
		return
	}
	if err != nil {
		apiErr(w, http.StatusInternalServerError, "query failed")
		return
	}
	if caddyVer.Valid {
		n.CaddyVersion = &caddyVer.String
	}
	apiJSON(w, http.StatusOK, n)
}

func (h *APIHandlers) NodeUpdate(w http.ResponseWriter, r *http.Request) {
	if !h.requireGlobalAPIAdmin(w, r) {
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	var in struct {
		Name      *string `json:"name"`
		IsEnabled *bool   `json:"is_enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		apiErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	parts := []string{}
	args := []any{}
	if in.Name != nil {
		parts = append(parts, "name=?")
		args = append(args, *in.Name)
	}
	if in.IsEnabled != nil {
		parts = append(parts, "is_enabled=?")
		args = append(args, *in.IsEnabled)
	}
	if len(parts) == 0 {
		apiJSON(w, http.StatusOK, map[string]any{"id": id, "updated": false})
		return
	}
	args = append(args, id)
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	res, err := h.DB().ExecContext(ctx,
		"UPDATE caddy_nodes SET "+strings.Join(parts, ", ")+" WHERE id=?", args...)
	if err != nil {
		if strings.Contains(err.Error(), "Duplicate entry") {
			apiErr(w, http.StatusConflict, "node name already exists")
			return
		}
		apiErr(w, http.StatusInternalServerError, "update failed")
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		apiErr(w, http.StatusNotFound, "not found")
		return
	}
	uid := apiCallerID(r)
	audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
		UserID: &uid, ActorType: audit.ActorAPI, Action: "node.updated", Entity: "node",
		EntityID: strconv.FormatInt(id, 10),
	})
	apiJSON(w, http.StatusOK, map[string]any{"id": id, "updated": true})
}

func (h *APIHandlers) NodeDelete(w http.ResponseWriter, r *http.Request) {
	if !h.requireGlobalAPIAdmin(w, r) {
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// Refuse deletion when the node still serves active routes.
	var activeRoutes int
	if err := h.DB().QueryRowContext(ctx,
		"SELECT COUNT(*) FROM routes WHERE caddy_node_id=? AND status NOT IN ('disabled','failed')", id,
	).Scan(&activeRoutes); err != nil {
		apiErr(w, http.StatusInternalServerError, "check failed")
		return
	}
	if activeRoutes > 0 {
		apiErr(w, http.StatusConflict, "node has "+strconv.Itoa(activeRoutes)+" active routes, reassign first")
		return
	}
	res, err := h.DB().ExecContext(ctx, "DELETE FROM caddy_nodes WHERE id=?", id)
	if err != nil {
		if strings.Contains(err.Error(), "foreign key") {
			apiErr(w, http.StatusConflict, "node is referenced by routes")
			return
		}
		apiErr(w, http.StatusInternalServerError, "delete failed")
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		apiErr(w, http.StatusNotFound, "not found")
		return
	}
	uid := apiCallerID(r)
	audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
		UserID: &uid, ActorType: audit.ActorAPI, Action: "node.deleted", Entity: "node",
		EntityID: strconv.FormatInt(id, 10),
	})
	apiJSON(w, http.StatusOK, map[string]any{"id": id, "deleted": true})
}
