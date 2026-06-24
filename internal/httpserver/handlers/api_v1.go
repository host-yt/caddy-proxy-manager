package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/hostyt/proxy-gateway/internal/audit"
	"github.com/hostyt/proxy-gateway/internal/domain/routes"
	"github.com/hostyt/proxy-gateway/internal/httpserver/middleware"
)

// APIHandlers groups all /api/v1 endpoints. They share APIKeyAuth middleware.
type APIHandlers struct {
	DB     func() *sql.DB
	Logger *slog.Logger
	Routes *routes.Service
}

// ---- helpers -----------------------------------------------------------

func apiJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func apiErr(w http.ResponseWriter, status int, msg string) {
	apiJSON(w, status, map[string]string{"error": msg})
}

func apiCallerID(r *http.Request) int64 {
	if c := middleware.CallerFromContext(r.Context()); c != nil {
		return c.UserID
	}
	return 0
}

func requireAdmin(r *http.Request) bool {
	c := middleware.CallerFromContext(r.Context())
	if c == nil {
		return false
	}
	return c.Role == "admin" || c.Role == "super_admin"
}

// clientIDForUserStrict returns the caller's `clients.id` or an error.
// Unlike the legacy pattern `_ = QueryRowContext(...).Scan(&clientID)`
// (which silently set clientID=0 on error, and `0` was overloaded as
// "admin scope - skip ownership check" in the domain service), this
// helper distinguishes "row missing" / "DB error" from "actually 0" and
// makes the caller decide. Used by every client-facing API endpoint to
// fix the audit's P0 privilege-escalation finding.
func clientIDForUserStrict(ctx context.Context, db *sql.DB, userID int64) (int64, error) {
	if db == nil {
		return 0, errors.New("db not ready")
	}
	var id int64
	if err := db.QueryRowContext(ctx, "SELECT id FROM clients WHERE user_id = ?", userID).Scan(&id); err != nil {
		return 0, err
	}
	if id == 0 {
		return 0, errors.New("client id zero")
	}
	return id, nil
}

// ---- Services ----------------------------------------------------------

type apiService struct {
	ID                int64     `json:"id"`
	ClientID          int64     `json:"client_id"`
	Name              string    `json:"name"`
	BackendIP         string    `json:"backend_ip"`
	AllowedPortStart  int       `json:"allowed_port_start"`
	AllowedPortEnd    int       `json:"allowed_port_end"`
	PlanID            int64     `json:"plan_id"`
	Status            string    `json:"status"`
	ExternalReference string    `json:"external_reference,omitempty"`
	CreatedAt         time.Time `json:"created_at"`
}

func (h *APIHandlers) ServiceCreate(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(r) {
		apiErr(w, http.StatusForbidden, "admin role required")
		return
	}
	var in struct {
		ClientID          int64  `json:"client_id"`
		Name              string `json:"name"`
		BackendIP         string `json:"backend_ip"`
		AllowedPortStart  int    `json:"allowed_port_start"`
		AllowedPortEnd    int    `json:"allowed_port_end"`
		PlanID            int64  `json:"plan_id"`
		ExternalReference string `json:"external_reference"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		apiErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if in.Name == "" || in.BackendIP == "" || in.ClientID == 0 || in.PlanID == 0 {
		apiErr(w, http.StatusBadRequest, "required fields missing")
		return
	}
	if net.ParseIP(in.BackendIP) == nil {
		apiErr(w, http.StatusBadRequest, "backend_ip invalid")
		return
	}
	if in.AllowedPortStart < 1 || in.AllowedPortEnd > 65535 || in.AllowedPortStart > in.AllowedPortEnd {
		apiErr(w, http.StatusBadRequest, "port range invalid")
		return
	}
	db := h.DB()
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	var nodeGroupID int64
	if err := db.QueryRowContext(ctx, "SELECT node_group_id FROM plans WHERE id = ?", in.PlanID).Scan(&nodeGroupID); err != nil {
		apiErr(w, http.StatusBadRequest, "plan not found")
		return
	}
	var extRef sql.NullString
	if in.ExternalReference != "" {
		extRef = sql.NullString{String: in.ExternalReference, Valid: true}
	}
	res, err := db.ExecContext(ctx,
		`INSERT INTO services (client_id, name, backend_ip, allowed_port_start, allowed_port_end,
		   plan_id, node_group_id, status, external_reference)
		 VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?)`,
		in.ClientID, in.Name, in.BackendIP, in.AllowedPortStart, in.AllowedPortEnd,
		in.PlanID, nodeGroupID, extRef)
	if err != nil {
		apiErr(w, http.StatusInternalServerError, "insert failed")
		return
	}
	id, _ := res.LastInsertId()
	uid := apiCallerID(r)
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: &uid, ActorType: audit.ActorAPI, Action: "service.create", Entity: "service",
		EntityID: strconv.FormatInt(id, 10),
		Meta:     map[string]any{"name": in.Name, "ext": in.ExternalReference},
	})
	apiJSON(w, http.StatusCreated, map[string]any{"id": id})
}

func (h *APIHandlers) ServiceGet(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	var s apiService
	var extRef sql.NullString
	err := h.DB().QueryRowContext(ctx,
		`SELECT id, client_id, name, backend_ip, allowed_port_start, allowed_port_end,
		        plan_id, status, COALESCE(external_reference,''), created_at
		 FROM services WHERE id = ?`, id,
	).Scan(&s.ID, &s.ClientID, &s.Name, &s.BackendIP, &s.AllowedPortStart, &s.AllowedPortEnd,
		&s.PlanID, &s.Status, &s.ExternalReference, &s.CreatedAt)
	_ = extRef
	if errors.Is(err, sql.ErrNoRows) {
		apiErr(w, http.StatusNotFound, "not found")
		return
	}
	if err != nil {
		apiErr(w, http.StatusInternalServerError, "query failed")
		return
	}
	// Clients can only fetch their own service. Use the strict lookup so a DB
	// error fails closed instead of leaving clientID=0 (the old admin-scope
	// sentinel) and silently widening access.
	c := middleware.CallerFromContext(r.Context())
	if c.Role == "client" {
		clientID, err := clientIDForUserStrict(ctx, h.DB(), c.UserID)
		if err != nil || clientID != s.ClientID {
			apiErr(w, http.StatusForbidden, "forbidden")
			return
		}
	}
	apiJSON(w, http.StatusOK, s)
}

func (h *APIHandlers) ServiceUpdate(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(r) {
		apiErr(w, http.StatusForbidden, "admin role required")
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	var in struct {
		Status            *string `json:"status"`
		ExternalReference *string `json:"external_reference"`
		Notes             *string `json:"notes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		apiErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	parts := []string{}
	args := []any{}
	if in.Status != nil {
		switch *in.Status {
		case "active", "suspended", "terminated":
			parts = append(parts, "status = ?")
			args = append(args, *in.Status)
		default:
			apiErr(w, http.StatusBadRequest, "invalid status")
			return
		}
	}
	if in.ExternalReference != nil {
		parts = append(parts, "external_reference = ?")
		args = append(args, *in.ExternalReference)
	}
	if in.Notes != nil {
		parts = append(parts, "notes = ?")
		args = append(args, *in.Notes)
	}
	if len(parts) == 0 {
		apiJSON(w, http.StatusOK, map[string]any{"id": id, "updated": false})
		return
	}
	args = append(args, id)
	if _, err := h.DB().ExecContext(ctx, "UPDATE services SET "+strings.Join(parts, ", ")+" WHERE id = ?", args...); err != nil {
		apiErr(w, http.StatusInternalServerError, "update failed")
		return
	}
	uid := apiCallerID(r)
	audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
		UserID: &uid, ActorType: audit.ActorAPI, Action: "service.update", Entity: "service",
		EntityID: strconv.FormatInt(id, 10),
	})
	apiJSON(w, http.StatusOK, map[string]any{"id": id, "updated": true})
}

func (h *APIHandlers) ServicePorts(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(r) {
		apiErr(w, http.StatusForbidden, "admin role required")
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	var in struct {
		AllowedPortStart int `json:"allowed_port_start"`
		AllowedPortEnd   int `json:"allowed_port_end"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		apiErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if in.AllowedPortStart < 1 || in.AllowedPortEnd > 65535 || in.AllowedPortStart > in.AllowedPortEnd {
		apiErr(w, http.StatusBadRequest, "port range invalid")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if _, err := h.DB().ExecContext(ctx,
		"UPDATE services SET allowed_port_start = ?, allowed_port_end = ? WHERE id = ?",
		in.AllowedPortStart, in.AllowedPortEnd, id); err != nil {
		apiErr(w, http.StatusInternalServerError, "update failed")
		return
	}
	uid := apiCallerID(r)
	audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
		UserID: &uid, ActorType: audit.ActorAPI, Action: "service.ports", Entity: "service",
		EntityID: strconv.FormatInt(id, 10),
		Meta:     map[string]any{"start": in.AllowedPortStart, "end": in.AllowedPortEnd},
	})
	apiJSON(w, http.StatusOK, map[string]any{"id": id})
}

func (h *APIHandlers) ServiceRoutes(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	// Ownership enforcement: clients may only list routes for services they
	// own. Admin/api roles see everything. Without this gate a client API
	// key could enumerate every tenant's domain mappings by incrementing
	// the service_id parameter (audit/challenger P0).
	caller := middleware.CallerFromContext(r.Context())
	if caller == nil {
		apiErr(w, http.StatusUnauthorized, "auth required")
		return
	}
	if caller.Role == "client" {
		ownerClientID, err := clientIDForUserStrict(ctx, h.DB(), caller.UserID)
		if err != nil {
			apiErr(w, http.StatusForbidden, "client scope unresolved")
			return
		}
		var svcOwner int64
		if err := h.DB().QueryRowContext(ctx,
			"SELECT client_id FROM services WHERE id = ?", id,
		).Scan(&svcOwner); err != nil {
			apiErr(w, http.StatusNotFound, "service not found")
			return
		}
		if svcOwner != ownerClientID {
			apiErr(w, http.StatusForbidden, "service not yours")
			return
		}
	}
	rows, err := h.DB().QueryContext(ctx,
		`SELECT id, domain, COALESCE(path_prefix,''), upstream_port, status
		 FROM routes WHERE service_id = ? ORDER BY id DESC`, id)
	if err != nil {
		apiErr(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()
	type rr struct {
		ID           int64  `json:"id"`
		Domain       string `json:"domain"`
		PathPrefix   string `json:"path_prefix"`
		UpstreamPort int    `json:"upstream_port"`
		Status       string `json:"status"`
	}
	out := []rr{}
	for rows.Next() {
		var x rr
		if err := rows.Scan(&x.ID, &x.Domain, &x.PathPrefix, &x.UpstreamPort, &x.Status); err == nil {
			out = append(out, x)
		}
	}
	apiJSON(w, http.StatusOK, map[string]any{"routes": out})
}

// ---- Routes ------------------------------------------------------------

func (h *APIHandlers) RouteCreate(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ServiceID    int64  `json:"service_id"`
		UpstreamPort int    `json:"upstream_port"`
		Domain       string `json:"domain"`
		PathPrefix   string `json:"path_prefix"`
		SSL          bool   `json:"ssl"`
		WebSocket    bool   `json:"websocket"`
		ForceHTTPS   bool   `json:"force_https"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		apiErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	// Admin/api role: clientID=0 means "skip ownership check" in domain svc.
	// Client role: scope to their client_id (strict - fail closed on lookup
	// error so a missing/broken clients row never escalates to admin scope).
	var clientID int64
	c := middleware.CallerFromContext(r.Context())
	if c == nil {
		apiErr(w, http.StatusUnauthorized, "auth required")
		return
	}
	if c.Role == "client" {
		cid, lerr := clientIDForUserStrict(ctx, h.DB(), c.UserID)
		if lerr != nil {
			apiErr(w, http.StatusForbidden, "client scope unresolved")
			return
		}
		clientID = cid
	}
	id, err := h.Routes.Create(ctx, clientID, routes.CreateInput{
		ServiceID:    in.ServiceID,
		UpstreamPort: in.UpstreamPort,
		Domain:       in.Domain,
		PathPrefix:   in.PathPrefix,
		SSL:          in.SSL,
		WebSocket:    in.WebSocket,
		ForceHTTPS:   in.ForceHTTPS,
	})
	if err != nil {
		switch {
		case errors.Is(err, routes.ErrServiceNotYours):
			apiErr(w, http.StatusForbidden, "service not yours")
		case errors.Is(err, routes.ErrPortOutOfRange):
			apiErr(w, http.StatusBadRequest, "port out of range")
		case errors.Is(err, routes.ErrInvalidDomain):
			apiErr(w, http.StatusBadRequest, "invalid domain")
		case errors.Is(err, routes.ErrDomainTaken):
			apiErr(w, http.StatusConflict, "domain already mapped")
		case errors.Is(err, routes.ErrNoNodeFound):
			apiErr(w, http.StatusConflict, "no node available")
		case errors.Is(err, routes.ErrMaxDomains):
			apiErr(w, http.StatusConflict, "plan domain limit reached")
		default:
			apiErr(w, http.StatusInternalServerError, "create failed")
		}
		return
	}
	uid := apiCallerID(r)
	audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
		UserID: &uid, ActorType: audit.ActorAPI, Action: "route.create", Entity: "route",
		EntityID: strconv.FormatInt(id, 10),
		Meta:     map[string]any{"domain": in.Domain},
	})
	apiJSON(w, http.StatusCreated, map[string]any{"id": id})
}

func (h *APIHandlers) RouteDelete(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	var clientID int64
	c := middleware.CallerFromContext(r.Context())
	if c == nil {
		apiErr(w, http.StatusUnauthorized, "auth required")
		return
	}
	if c.Role == "client" {
		cid, lerr := clientIDForUserStrict(ctx, h.DB(), c.UserID)
		if lerr != nil {
			apiErr(w, http.StatusForbidden, "client scope unresolved")
			return
		}
		clientID = cid
	}
	if err := h.Routes.Delete(ctx, clientID, id); err != nil {
		apiErr(w, http.StatusInternalServerError, "delete failed")
		return
	}
	uid := apiCallerID(r)
	audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
		UserID: &uid, ActorType: audit.ActorAPI, Action: "route.delete", Entity: "route",
		EntityID: strconv.FormatInt(id, 10),
	})
	apiJSON(w, http.StatusOK, map[string]any{"id": id, "deleted": true})
}

func (h *APIHandlers) RouteVerifyDNS(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	var clientID int64
	c := middleware.CallerFromContext(r.Context())
	if c == nil {
		apiErr(w, http.StatusUnauthorized, "auth required")
		return
	}
	if c.Role == "client" {
		cid, lerr := clientIDForUserStrict(ctx, h.DB(), c.UserID)
		if lerr != nil {
			apiErr(w, http.StatusForbidden, "client scope unresolved")
			return
		}
		clientID = cid
	}
	if err := h.Routes.VerifyDNS(ctx, clientID, id); err != nil {
		apiErr(w, http.StatusInternalServerError, "verify failed")
		return
	}
	apiJSON(w, http.StatusOK, map[string]any{"id": id, "queued": true})
}

func (h *APIHandlers) RouteRetrySSL(w http.ResponseWriter, r *http.Request) {
	h.RouteVerifyDNS(w, r)
}

// ---- Nodes -------------------------------------------------------------

func (h *APIHandlers) NodesList(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(r) {
		apiErr(w, http.StatusForbidden, "admin role required")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	rows, err := h.DB().QueryContext(ctx,
		`SELECT id, name, api_url, COALESCE(public_hostname,''), COALESCE(public_ip,''),
		        node_group_id, max_routes, current_routes, is_enabled, health_status
		 FROM caddy_nodes ORDER BY priority DESC, id ASC`)
	if err != nil {
		apiErr(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()
	type nr struct {
		ID             int64  `json:"id"`
		Name           string `json:"name"`
		APIURL         string `json:"api_url"`
		PublicHostname string `json:"public_hostname"`
		PublicIP       string `json:"public_ip"`
		NodeGroupID    int64  `json:"node_group_id"`
		MaxRoutes      int    `json:"max_routes"`
		CurrentRoutes  int    `json:"current_routes"`
		Enabled        bool   `json:"enabled"`
		Health         string `json:"health"`
	}
	out := []nr{}
	for rows.Next() {
		var x nr
		if err := rows.Scan(&x.ID, &x.Name, &x.APIURL, &x.PublicHostname, &x.PublicIP,
			&x.NodeGroupID, &x.MaxRoutes, &x.CurrentRoutes, &x.Enabled, &x.Health); err == nil {
			out = append(out, x)
		}
	}
	apiJSON(w, http.StatusOK, map[string]any{"nodes": out})
}

func (h *APIHandlers) NodeCreate(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(r) {
		apiErr(w, http.StatusForbidden, "admin role required")
		return
	}
	var in struct {
		Name           string `json:"name"`
		APIURL         string `json:"api_url"`
		PublicHostname string `json:"public_hostname"`
		PublicIP       string `json:"public_ip"`
		NodeGroupID    int64  `json:"node_group_id"`
		MaxRoutes      int    `json:"max_routes"`
		Priority       int    `json:"priority"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		apiErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if in.Name == "" || in.APIURL == "" || in.NodeGroupID == 0 || in.MaxRoutes <= 0 {
		apiErr(w, http.StatusBadRequest, "required fields missing")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	var pubIP sql.NullString
	if in.PublicIP != "" {
		pubIP = sql.NullString{String: in.PublicIP, Valid: true}
	}
	res, err := h.DB().ExecContext(ctx,
		`INSERT INTO caddy_nodes (name, api_url, public_hostname, public_ip,
		   node_group_id, max_routes, priority, is_enabled, health_status)
		 VALUES (?, ?, ?, ?, ?, ?, ?, 1, 'unknown')`,
		in.Name, in.APIURL, in.PublicHostname, pubIP, in.NodeGroupID, in.MaxRoutes, in.Priority)
	if err != nil {
		apiErr(w, http.StatusInternalServerError, "insert failed")
		return
	}
	id, _ := res.LastInsertId()
	uid := apiCallerID(r)
	audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
		UserID: &uid, ActorType: audit.ActorAPI, Action: "node.create", Entity: "node",
		EntityID: strconv.FormatInt(id, 10),
		Meta:     map[string]any{"name": in.Name},
	})
	apiJSON(w, http.StatusCreated, map[string]any{"id": id})
}

func (h *APIHandlers) NodeResync(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(r) {
		apiErr(w, http.StatusForbidden, "admin role required")
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	if err := h.Routes.Resync(ctx, id); err != nil {
		apiErr(w, http.StatusInternalServerError, "resync failed: "+err.Error())
		return
	}
	uid := apiCallerID(r)
	audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
		UserID: &uid, ActorType: audit.ActorAPI, Action: "node.resync", Entity: "node",
		EntityID: strconv.FormatInt(id, 10),
	})
	apiJSON(w, http.StatusOK, map[string]any{"id": id, "resynced": true})
}

// ---- legacy stubs kept compiling --------------------------------------

func APIServiceCreate(w http.ResponseWriter, _ *http.Request) {
	notImplemented(w, "APIServiceCreate")
}
func APIServiceGet(w http.ResponseWriter, _ *http.Request) {
	notImplemented(w, "APIServiceGet")
}
func APIServiceUpdate(w http.ResponseWriter, _ *http.Request) {
	notImplemented(w, "APIServiceUpdate")
}
func APIServicePorts(w http.ResponseWriter, _ *http.Request) {
	notImplemented(w, "APIServicePorts")
}
func APIServiceRoutes(w http.ResponseWriter, _ *http.Request) {
	notImplemented(w, "APIServiceRoutes")
}
func APIRouteCreate(w http.ResponseWriter, _ *http.Request) {
	notImplemented(w, "APIRouteCreate")
}
func APIRouteDelete(w http.ResponseWriter, _ *http.Request) {
	notImplemented(w, "APIRouteDelete")
}
func APIRouteVerifyDNS(w http.ResponseWriter, _ *http.Request) {
	notImplemented(w, "APIRouteVerifyDNS")
}
func APIRouteRetrySSL(w http.ResponseWriter, _ *http.Request) {
	notImplemented(w, "APIRouteRetrySSL")
}
func APINodesList(w http.ResponseWriter, _ *http.Request) {
	notImplemented(w, "APINodesList")
}
func APINodeCreate(w http.ResponseWriter, _ *http.Request) {
	notImplemented(w, "APINodeCreate")
}
func APINodeResync(w http.ResponseWriter, _ *http.Request) {
	notImplemented(w, "APINodeResync")
}
