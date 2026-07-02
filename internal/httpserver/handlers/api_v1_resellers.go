package handlers

// /api/v1/resellers + /api/v1/reseller-plans - platform-admin-only management
// of the reseller layer (F6). Reseller keys are denied by requireGlobalAPIAdmin;
// they manage their tenants through the scoped clients/services endpoints.

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/host-yt/caddy-proxy-manager/internal/audit"
	"github.com/host-yt/caddy-proxy-manager/internal/auth"
	"github.com/host-yt/caddy-proxy-manager/internal/quota"
	"github.com/host-yt/caddy-proxy-manager/internal/reseller"
	"github.com/go-chi/chi/v5"
)

// Resellers/Quota stores are injected from main (nil-safe guards below).
type apiReseller struct {
	ID             int64        `json:"id"`
	Name           string       `json:"name"`
	Slug           string       `json:"slug"`
	Status         string       `json:"status"`
	BrandName      string       `json:"brand_name,omitempty"`
	SupportEmail   string       `json:"support_email,omitempty"`
	ResellerPlanID int64        `json:"reseller_plan_id,omitempty"`
	Overselling    bool         `json:"overselling_allowed"`
	CanCreatePlans bool         `json:"can_create_plans"`
	OwnerUserID    int64        `json:"owner_user_id,omitempty"`
	Usage          *quota.Usage `json:"usage,omitempty"`
}

func (h *APIHandlers) resellerStoreOK(w http.ResponseWriter) bool {
	if h.Resellers == nil {
		apiErr(w, http.StatusServiceUnavailable, "reseller store unavailable")
		return false
	}
	return true
}

func (h *APIHandlers) apiResellerOut(r *http.Request, rs reseller.Reseller, withUsage bool) apiReseller {
	out := apiReseller{ID: rs.ID, Name: rs.Name, Slug: rs.Slug, Status: rs.Status,
		BrandName: rs.BrandName, SupportEmail: rs.SupportEmail}
	ctx := r.Context()
	if pol, err := h.Resellers.PolicyFor(ctx, rs.ID); err == nil {
		out.ResellerPlanID = pol.PlanID
		out.Overselling = pol.Overselling
		out.CanCreatePlans = pol.CanCreatePlans
	}
	var owner sql.NullInt64
	_ = h.DB().QueryRowContext(ctx, `SELECT owner_user_id FROM resellers WHERE id=?`, rs.ID).Scan(&owner)
	out.OwnerUserID = owner.Int64
	if withUsage && h.Quota != nil {
		if u, err := h.Quota.UsageFor(ctx, rs.ID); err == nil {
			out.Usage = &u
		}
	}
	return out
}

// ResellersList handles GET /api/v1/resellers.
func (h *APIHandlers) ResellersList(w http.ResponseWriter, r *http.Request) {
	if !h.requireGlobalAPIAdmin(w, r) || !h.resellerStoreOK(w) {
		return
	}
	list, err := h.Resellers.List(r.Context())
	if err != nil {
		apiErr(w, http.StatusInternalServerError, "list failed")
		return
	}
	out := []apiReseller{}
	for _, rs := range list {
		out = append(out, h.apiResellerOut(r, rs, false))
	}
	apiJSON(w, http.StatusOK, map[string]any{"resellers": out})
}

// ResellerGet handles GET /api/v1/resellers/{id} (includes usage).
func (h *APIHandlers) ResellerGet(w http.ResponseWriter, r *http.Request) {
	if !h.requireGlobalAPIAdmin(w, r) || !h.resellerStoreOK(w) {
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	rs, err := h.Resellers.Get(r.Context(), id)
	if errors.Is(err, reseller.ErrNotFound) {
		apiErr(w, http.StatusNotFound, "not found")
		return
	}
	if err != nil {
		apiErr(w, http.StatusInternalServerError, "get failed")
		return
	}
	apiJSON(w, http.StatusOK, h.apiResellerOut(r, rs, true))
}

// ResellerCreate handles POST /api/v1/resellers - atomic reseller + owner login.
func (h *APIHandlers) ResellerCreate(w http.ResponseWriter, r *http.Request) {
	if !h.requireGlobalAPIAdmin(w, r) || !h.resellerStoreOK(w) {
		return
	}
	var in struct {
		Name          string `json:"name"`
		Slug          string `json:"slug"`
		OwnerEmail    string `json:"owner_email"`
		OwnerPassword string `json:"owner_password"`
		BrandName     string `json:"brand_name"`
		SupportEmail  string `json:"support_email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		apiErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	in.Slug = strings.ToLower(strings.TrimSpace(in.Slug))
	in.OwnerEmail = strings.ToLower(strings.TrimSpace(in.OwnerEmail))
	if in.Name == "" || !slugRe.MatchString(in.Slug) {
		apiErr(w, http.StatusBadRequest, "name required; slug lowercase alphanumeric/dashes")
		return
	}
	if !strings.Contains(in.OwnerEmail, "@") {
		apiErr(w, http.StatusBadRequest, "owner_email required")
		return
	}
	if len(in.OwnerPassword) < 12 {
		apiErr(w, http.StatusBadRequest, "owner_password must be >= 12 characters")
		return
	}
	hash, err := auth.HashPassword(in.OwnerPassword)
	if err != nil {
		apiErr(w, http.StatusInternalServerError, "hash failed")
		return
	}
	id, ownerID, err := h.Resellers.CreateWithOwner(r.Context(), reseller.Reseller{
		Name: in.Name, Slug: in.Slug, Status: reseller.StatusActive,
		BrandName: in.BrandName, SupportEmail: in.SupportEmail,
	}, in.OwnerEmail, in.Name, hash)
	if errors.Is(err, reseller.ErrDuplicate) {
		apiErr(w, http.StatusConflict, "slug or owner email already exists")
		return
	}
	if err != nil {
		apiErr(w, http.StatusInternalServerError, "create failed")
		return
	}
	uid := apiCallerID(r)
	audit.Write(r.Context(), h.DB(), h.Logger, r, audit.Entry{
		UserID: &uid, ActorType: audit.ActorAPI, Action: "reseller.create", Entity: "reseller",
		EntityID: strconv.FormatInt(id, 10), Meta: map[string]any{"slug": in.Slug},
	})
	apiJSON(w, http.StatusCreated, map[string]any{"id": id, "owner_user_id": ownerID})
}

// ResellerUpdate handles PATCH /api/v1/resellers/{id}: name/status/branding and
// policy (reseller_plan_id / overselling_allowed / can_create_plans).
func (h *APIHandlers) ResellerUpdate(w http.ResponseWriter, r *http.Request) {
	if !h.requireGlobalAPIAdmin(w, r) || !h.resellerStoreOK(w) {
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	ctx := r.Context()
	rs, err := h.Resellers.Get(ctx, id)
	if errors.Is(err, reseller.ErrNotFound) {
		apiErr(w, http.StatusNotFound, "not found")
		return
	}
	if err != nil {
		apiErr(w, http.StatusInternalServerError, "get failed")
		return
	}
	var in struct {
		Name           *string `json:"name"`
		Status         *string `json:"status"`
		BrandName      *string `json:"brand_name"`
		SupportEmail   *string `json:"support_email"`
		ResellerPlanID *int64  `json:"reseller_plan_id"`
		Overselling    *bool   `json:"overselling_allowed"`
		CanCreatePlans *bool   `json:"can_create_plans"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		apiErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if in.Name != nil && strings.TrimSpace(*in.Name) != "" {
		rs.Name = strings.TrimSpace(*in.Name)
	}
	suspended := false
	if in.Status != nil {
		if *in.Status != reseller.StatusActive && *in.Status != reseller.StatusSuspended {
			apiErr(w, http.StatusBadRequest, "status must be active or suspended")
			return
		}
		suspended = *in.Status == reseller.StatusSuspended && rs.Status != reseller.StatusSuspended
		rs.Status = *in.Status
	}
	if in.BrandName != nil {
		rs.BrandName = strings.TrimSpace(*in.BrandName)
	}
	if in.SupportEmail != nil {
		rs.SupportEmail = strings.TrimSpace(*in.SupportEmail)
	}
	if err := h.Resellers.Update(ctx, rs); err != nil {
		apiErr(w, http.StatusInternalServerError, "update failed")
		return
	}
	if in.ResellerPlanID != nil || in.Overselling != nil || in.CanCreatePlans != nil {
		pol, _ := h.Resellers.PolicyFor(ctx, id)
		if in.ResellerPlanID != nil {
			pol.PlanID = *in.ResellerPlanID
		}
		if in.Overselling != nil {
			pol.Overselling = *in.Overselling
		}
		if in.CanCreatePlans != nil {
			pol.CanCreatePlans = *in.CanCreatePlans
		}
		if err := h.Resellers.SetPolicy(ctx, id, pol); err != nil {
			apiErr(w, http.StatusInternalServerError, "policy update failed")
			return
		}
	}
	// Suspension keystone: scope already fails closed per-request; revoking the
	// reseller users' sessions mirrors the panel behaviour.
	if suspended && h.Sessions != nil {
		rows, err := h.DB().QueryContext(ctx, `SELECT id FROM users WHERE reseller_id=?`, id)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var uid int64
				if rows.Scan(&uid) == nil {
					_, _ = h.Sessions.DestroyAllForUser(ctx, uid)
				}
			}
		}
	}
	uid := apiCallerID(r)
	audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
		UserID: &uid, ActorType: audit.ActorAPI, Action: "reseller.update", Entity: "reseller",
		EntityID: strconv.FormatInt(id, 10),
	})
	apiJSON(w, http.StatusOK, h.apiResellerOut(r, rs, false))
}

// ResellerDelete handles DELETE /api/v1/resellers/{id}. FK ON DELETE SET NULL
// returns owned rows to platform-direct; freed users' sessions are revoked.
func (h *APIHandlers) ResellerDelete(w http.ResponseWriter, r *http.Request) {
	if !h.requireGlobalAPIAdmin(w, r) || !h.resellerStoreOK(w) {
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	ctx := r.Context()
	var freed []int64
	if rows, err := h.DB().QueryContext(ctx, `SELECT id FROM users WHERE reseller_id=?`, id); err == nil {
		for rows.Next() {
			var uid int64
			if rows.Scan(&uid) == nil {
				freed = append(freed, uid)
			}
		}
		rows.Close()
	}
	if err := h.Resellers.Delete(ctx, id); err != nil {
		if errors.Is(err, reseller.ErrNotFound) {
			apiErr(w, http.StatusNotFound, "not found")
			return
		}
		apiErr(w, http.StatusInternalServerError, "delete failed")
		return
	}
	if h.Sessions != nil {
		for _, uid := range freed {
			_, _ = h.Sessions.DestroyAllForUser(ctx, uid)
		}
	}
	uid := apiCallerID(r)
	audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
		UserID: &uid, ActorType: audit.ActorAPI, Action: "reseller.delete", Entity: "reseller",
		EntityID: strconv.FormatInt(id, 10),
	})
	apiJSON(w, http.StatusOK, map[string]any{"id": id, "deleted": true})
}

// ---- Reseller packages ---------------------------------------------------

type apiResellerPlan struct {
	ID              int64    `json:"id"`
	Name            string   `json:"name"`
	MaxClients      int      `json:"max_clients"`
	MaxServices     int      `json:"max_services_total"`
	MaxDomainsTotal int      `json:"max_domains_total"`
	RateLimitCap    int      `json:"rate_limit_rpm_cap"`
	NodeGroupIDs    []int64  `json:"node_group_ids"`
	Features        []string `json:"features"`
}

func planOut(p reseller.Plan) apiResellerPlan {
	return apiResellerPlan{ID: p.ID, Name: p.Name, MaxClients: p.MaxClients,
		MaxServices: p.MaxServices, MaxDomainsTotal: p.MaxDomainsTotal,
		RateLimitCap: p.RateLimitCap, NodeGroupIDs: p.NodeGroupIDs, Features: p.Features}
}

// ResellerPlansList handles GET /api/v1/reseller-plans.
func (h *APIHandlers) ResellerPlansList(w http.ResponseWriter, r *http.Request) {
	if !h.requireGlobalAPIAdmin(w, r) || !h.resellerStoreOK(w) {
		return
	}
	list, err := h.Resellers.PlansList(r.Context())
	if err != nil {
		apiErr(w, http.StatusInternalServerError, "list failed")
		return
	}
	out := []apiResellerPlan{}
	for _, p := range list {
		out = append(out, planOut(p))
	}
	apiJSON(w, http.StatusOK, map[string]any{"reseller_plans": out})
}

// resellerPlanIn decodes + validates the shared create/update payload.
func resellerPlanIn(w http.ResponseWriter, r *http.Request, id int64) (reseller.Plan, bool) {
	var in apiResellerPlan
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		apiErr(w, http.StatusBadRequest, "invalid json")
		return reseller.Plan{}, false
	}
	if strings.TrimSpace(in.Name) == "" {
		apiErr(w, http.StatusBadRequest, "name required")
		return reseller.Plan{}, false
	}
	clampNonNeg := func(v int) int { if v < 0 { return 0 }; return v }
	return reseller.Plan{
		ID: id, Name: strings.TrimSpace(in.Name),
		MaxClients:      clampNonNeg(in.MaxClients),
		MaxServices:     clampNonNeg(in.MaxServices),
		MaxDomainsTotal: clampNonNeg(in.MaxDomainsTotal),
		RateLimitCap:    clampNonNeg(in.RateLimitCap),
		NodeGroupIDs:    in.NodeGroupIDs,
		Features:        in.Features,
	}, true
}

// ResellerPlanCreate handles POST /api/v1/reseller-plans.
func (h *APIHandlers) ResellerPlanCreate(w http.ResponseWriter, r *http.Request) {
	if !h.requireGlobalAPIAdmin(w, r) || !h.resellerStoreOK(w) {
		return
	}
	p, ok := resellerPlanIn(w, r, 0)
	if !ok {
		return
	}
	id, err := h.Resellers.PlanSave(r.Context(), p)
	if errors.Is(err, reseller.ErrDuplicate) {
		apiErr(w, http.StatusConflict, "package name already exists")
		return
	}
	if err != nil {
		apiErr(w, http.StatusInternalServerError, "save failed")
		return
	}
	uid := apiCallerID(r)
	audit.Write(r.Context(), h.DB(), h.Logger, r, audit.Entry{
		UserID: &uid, ActorType: audit.ActorAPI, Action: "reseller_plan.create", Entity: "reseller_plan",
		EntityID: strconv.FormatInt(id, 10),
	})
	apiJSON(w, http.StatusCreated, map[string]any{"id": id})
}

// ResellerPlanUpdate handles PATCH /api/v1/reseller-plans/{id} (full replace of
// limits + grant sets - PUT semantics on a small object keeps it simple).
func (h *APIHandlers) ResellerPlanUpdate(w http.ResponseWriter, r *http.Request) {
	if !h.requireGlobalAPIAdmin(w, r) || !h.resellerStoreOK(w) {
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	p, ok := resellerPlanIn(w, r, id)
	if !ok {
		return
	}
	if _, err := h.Resellers.PlanSave(r.Context(), p); err != nil {
		if errors.Is(err, reseller.ErrDuplicate) {
			apiErr(w, http.StatusConflict, "package name already exists")
			return
		}
		apiErr(w, http.StatusInternalServerError, "save failed")
		return
	}
	uid := apiCallerID(r)
	audit.Write(r.Context(), h.DB(), h.Logger, r, audit.Entry{
		UserID: &uid, ActorType: audit.ActorAPI, Action: "reseller_plan.update", Entity: "reseller_plan",
		EntityID: strconv.FormatInt(id, 10),
	})
	apiJSON(w, http.StatusOK, map[string]any{"id": id, "updated": true})
}

// ResellerPlanDelete handles DELETE /api/v1/reseller-plans/{id}.
func (h *APIHandlers) ResellerPlanDelete(w http.ResponseWriter, r *http.Request) {
	if !h.requireGlobalAPIAdmin(w, r) || !h.resellerStoreOK(w) {
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err := h.Resellers.PlanDelete(r.Context(), id); err != nil {
		switch {
		case errors.Is(err, reseller.ErrPlanInUse):
			apiErr(w, http.StatusConflict, "package in use - reassign resellers first")
		case errors.Is(err, reseller.ErrNotFound):
			apiErr(w, http.StatusNotFound, "not found")
		default:
			apiErr(w, http.StatusInternalServerError, "delete failed")
		}
		return
	}
	uid := apiCallerID(r)
	audit.Write(r.Context(), h.DB(), h.Logger, r, audit.Entry{
		UserID: &uid, ActorType: audit.ActorAPI, Action: "reseller_plan.delete", Entity: "reseller_plan",
		EntityID: strconv.FormatInt(id, 10),
	})
	apiJSON(w, http.StatusOK, map[string]any{"id": id, "deleted": true})
}
