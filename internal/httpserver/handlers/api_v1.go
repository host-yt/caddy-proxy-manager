package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/host-yt/caddy-proxy-manager/internal/adminscope"
	"github.com/host-yt/caddy-proxy-manager/internal/auth"
	"github.com/host-yt/caddy-proxy-manager/internal/audit"
	"github.com/host-yt/caddy-proxy-manager/internal/domain/routes"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
	"github.com/host-yt/caddy-proxy-manager/internal/quota"
	"github.com/host-yt/caddy-proxy-manager/internal/reseller"
	"github.com/host-yt/caddy-proxy-manager/internal/security"
)

// APIHandlers groups all /api/v1 endpoints. They share APIKeyAuth middleware.
type APIHandlers struct {
	DB     func() *sql.DB
	Logger *slog.Logger
	Routes *routes.Service
	// AdminScope resolves an admin caller's client visibility (reseller-aware).
	// nil = no enforcement (a bare admin key stays unrestricted). A reseller-admin
	// key is scoped to its reseller's clients; global infra is denied.
	AdminScope *adminscope.Service
	// Quota enforces reseller aggregate package limits at create surfaces. nil-safe.
	Quota *quota.Service
	// Resellers backs the /api/v1/resellers + /reseller-plans endpoints. nil-safe.
	Resellers *reseller.Store
	// Sessions is used to revoke reseller users on suspend/delete via API. nil-safe.
	Sessions *auth.Manager
}

// apiScope returns the client ids an admin-role caller may act on. all=true means
// unrestricted (super_admin, api role, or a bare admin). A reseller-admin or a
// client-scoped admin gets all=false plus the exhaustive id allow-list.
func (h *APIHandlers) apiScope(ctx context.Context, c *middleware.APICaller) (ids []int64, all bool, err error) {
	if c == nil {
		return nil, false, errors.New("no caller")
	}
	// super_admin and machine (api) keys are platform-wide by design.
	if c.Role == "super_admin" || c.Role == "api" {
		return nil, true, nil
	}
	if h.AdminScope == nil {
		return nil, true, nil
	}
	return h.AdminScope.ScopeFilter(ctx, c.UserID)
}

// apiAllowClient reports whether an admin caller may act on clientID. Fails
// closed on scope-resolution error.
func (h *APIHandlers) apiAllowClient(ctx context.Context, c *middleware.APICaller, clientID int64) bool {
	ids, all, err := h.apiScope(ctx, c)
	if err != nil {
		return false
	}
	if all {
		return true
	}
	for _, id := range ids {
		if id == clientID {
			return true
		}
	}
	return false
}

// apiPlanAccessible reports whether an admin caller may attach a service to a
// plan: unrestricted admins any plan; a reseller/scoped admin only a global
// plan (reseller_id NULL) or one owned by its own reseller. Fails closed.
func (h *APIHandlers) apiPlanAccessible(ctx context.Context, c *middleware.APICaller, planID int64) bool {
	_, all, err := h.apiScope(ctx, c)
	if err != nil {
		return false
	}
	if all {
		return true
	}
	var planReseller sql.NullInt64
	if err := h.DB().QueryRowContext(ctx, "SELECT reseller_id FROM plans WHERE id=?", planID).Scan(&planReseller); err != nil {
		return false
	}
	if !planReseller.Valid {
		return true // global plan, available to everyone
	}
	var callerReseller sql.NullInt64
	if err := h.DB().QueryRowContext(ctx, "SELECT reseller_id FROM users WHERE id=?", c.UserID).Scan(&callerReseller); err != nil {
		return false
	}
	return callerReseller.Valid && callerReseller.Int64 == planReseller.Int64
}

// requireGlobalAPIAdmin gates platform-global resources (plans, nodes, node
// pools, client provisioning): only an unrestricted admin passes. A reseller- or
// client-scoped admin key is denied - it must never touch shared infra.
func (h *APIHandlers) requireGlobalAPIAdmin(w http.ResponseWriter, r *http.Request) bool {
	if !requireAdmin(r) {
		apiErr(w, http.StatusForbidden, "admin role required")
		return false
	}
	c := middleware.CallerFromContext(r.Context())
	_, all, err := h.apiScope(r.Context(), c)
	if err != nil || !all {
		apiErr(w, http.StatusForbidden, "global admin scope required")
		return false
	}
	return true
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
	// reseller keys pass the role gate; apiScope then narrows their data reach.
	return c.Role == "admin" || c.Role == "super_admin" || c.Role == "reseller"
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

// serviceClientID resolves a service's owning client_id.
func (h *APIHandlers) serviceClientID(ctx context.Context, id int64) (int64, error) {
	var cid int64
	err := h.DB().QueryRowContext(ctx, "SELECT client_id FROM services WHERE id = ?", id).Scan(&cid)
	return cid, err
}

// routeClientID resolves a route's owning client_id via its service.
func (h *APIHandlers) routeClientID(ctx context.Context, routeID int64) (int64, error) {
	var cid int64
	err := h.DB().QueryRowContext(ctx,
		"SELECT s.client_id FROM routes r JOIN services s ON s.id=r.service_id WHERE r.id = ?",
		routeID).Scan(&cid)
	return cid, err
}

// serviceInScope resolves a service's client and verifies the admin caller may
// act on it, writing 404/403 itself. Returns false when the caller should stop.
func (h *APIHandlers) serviceInScope(ctx context.Context, w http.ResponseWriter, r *http.Request, serviceID int64) bool {
	cid, err := h.serviceClientID(ctx, serviceID)
	if err != nil {
		apiErr(w, http.StatusNotFound, "not found")
		return false
	}
	if !h.apiAllowClient(ctx, middleware.CallerFromContext(r.Context()), cid) {
		apiErr(w, http.StatusForbidden, "forbidden")
		return false
	}
	return true
}

// containsID reports membership in an id slice.
func containsID(ids []int64, x int64) bool {
	for _, id := range ids {
		if id == x {
			return true
		}
	}
	return false
}

// routeInScope is the route-level twin of serviceInScope.
func (h *APIHandlers) routeInScope(ctx context.Context, w http.ResponseWriter, r *http.Request, routeID int64) bool {
	cid, err := h.routeClientID(ctx, routeID)
	if err != nil {
		apiErr(w, http.StatusNotFound, "not found")
		return false
	}
	if !h.apiAllowClient(ctx, middleware.CallerFromContext(r.Context()), cid) {
		apiErr(w, http.StatusForbidden, "forbidden")
		return false
	}
	return true
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
	// Scope: a reseller/scoped admin may only create services for its own clients
	// and only with a global plan or one owned by its reseller (else it could
	// attach a foreign reseller's private/high-limit plan by guessing the id).
	if !h.apiAllowClient(r.Context(), middleware.CallerFromContext(r.Context()), in.ClientID) {
		apiErr(w, http.StatusForbidden, "client outside your scope")
		return
	}
	if !h.apiPlanAccessible(r.Context(), middleware.CallerFromContext(r.Context()), in.PlanID) {
		apiErr(w, http.StatusForbidden, "plan outside your scope")
		return
	}
	backendIP := net.ParseIP(in.BackendIP)
	if backendIP == nil {
		apiErr(w, http.StatusBadRequest, "backend_ip invalid")
		return
	}
	// Screen the backend for SSRF-sensitive ranges (loopback/link-local/
	// metadata) - twin of CADDY-02 on the web path (API-02).
	if security.IsDangerousProxyBackend(backendIP) {
		apiErr(w, http.StatusBadRequest, "backend_ip not allowed (loopback/link-local/metadata)")
		return
	}
	if in.AllowedPortStart < 1 || in.AllowedPortEnd > 65535 || in.AllowedPortStart > in.AllowedPortEnd {
		apiErr(w, http.StatusBadRequest, "port range invalid")
		return
	}
	db := h.DB()
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	// Reseller aggregate quota (subscriptions + allocated domain capacity).
	if h.Quota != nil {
		if rid, qerr := h.Quota.ResellerOfClient(ctx, in.ClientID); qerr == nil && rid != 0 {
			if qerr = h.Quota.CanCreateService(ctx, rid, in.PlanID); qerr != nil {
				apiErr(w, http.StatusForbidden, qerr.Error())
				return
			}
		}
	}
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
	} else if !h.apiAllowClient(ctx, c, s.ClientID) {
		// Reseller/scoped admin: service must belong to an owned client.
		apiErr(w, http.StatusForbidden, "forbidden")
		return
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
	if !h.serviceInScope(ctx, w, r, id) {
		return
	}
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
	if !h.serviceInScope(ctx, w, r, id) {
		return
	}
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
	} else if !h.serviceInScope(ctx, w, r, id) {
		// Reseller/scoped admin: only routes of an owned service.
		return
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
	} else if ids, all, serr := h.apiScope(ctx, c); serr != nil {
		apiErr(w, http.StatusForbidden, "scope unresolved")
		return
	} else if !all {
		// Scoped/reseller admin: bind to the target service's client so the
		// domain layer enforces ownership; deny a service outside scope.
		svcClient, cerr := h.serviceClientID(ctx, in.ServiceID)
		if cerr != nil {
			apiErr(w, http.StatusNotFound, "service not found")
			return
		}
		if !containsID(ids, svcClient) {
			apiErr(w, http.StatusForbidden, "service outside your scope")
			return
		}
		clientID = svcClient
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
		case errors.Is(err, routes.ErrPortInUse):
			apiErr(w, http.StatusConflict, "port already in use by another route")
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
	} else if ids, all, serr := h.apiScope(ctx, c); serr != nil {
		apiErr(w, http.StatusForbidden, "scope unresolved")
		return
	} else if !all {
		rc, rerr := h.routeClientID(ctx, id)
		if rerr != nil {
			apiErr(w, http.StatusNotFound, "not found")
			return
		}
		if !containsID(ids, rc) {
			apiErr(w, http.StatusForbidden, "route outside your scope")
			return
		}
		clientID = rc
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
	} else if ids, all, serr := h.apiScope(ctx, c); serr != nil {
		apiErr(w, http.StatusForbidden, "scope unresolved")
		return
	} else if !all {
		rc, rerr := h.routeClientID(ctx, id)
		if rerr != nil {
			apiErr(w, http.StatusNotFound, "not found")
			return
		}
		if !containsID(ids, rc) {
			apiErr(w, http.StatusForbidden, "route outside your scope")
			return
		}
		clientID = rc
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
	if !h.requireGlobalAPIAdmin(w, r) {
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
	if !h.requireGlobalAPIAdmin(w, r) {
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
	// Screen the node admin URL (API-03). Nodes live on the private WG mesh so
	// RFC1918/hostnames are allowed by design; block only a literal-IP host in
	// the loopback/link-local/metadata ranges (node-local admin / SSRF probe).
	if u, perr := url.Parse(in.APIURL); perr != nil || (u.Scheme != "http" && u.Scheme != "https") {
		apiErr(w, http.StatusBadRequest, "api_url must be a valid http(s) URL")
		return
	} else if ip := net.ParseIP(u.Hostname()); ip != nil && security.IsDangerousProxyBackend(ip) {
		apiErr(w, http.StatusBadRequest, "api_url host not allowed (loopback/link-local/metadata)")
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
	if !h.requireGlobalAPIAdmin(w, r) {
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
