package handlers

// Reseller packages (reseller_plans) management + per-reseller policy. All
// super_admin-only, same guard as the rest of the resellers surface.

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/host-yt/caddy-proxy-manager/internal/reseller"
	"github.com/go-chi/chi/v5"
)

// ResellerPlanSave handles POST /admin/reseller-plans (id=0 creates).
func (h *AdminHandlers) ResellerPlanSave(w http.ResponseWriter, r *http.Request) {
	sess := h.guardSuperAdmin(w, r)
	if sess == nil {
		return
	}
	if h.Resellers == nil {
		redirectWithFlash(w, r, "/admin/resellers", "", "reseller store unavailable")
		return
	}
	_ = r.ParseForm()
	atoi := func(k string) int { n, _ := strconv.Atoi(r.FormValue(k)); if n < 0 { n = 0 }; return n }
	id, _ := strconv.ParseInt(r.FormValue("id"), 10, 64)
	p := reseller.Plan{
		ID:              id,
		Name:            strings.TrimSpace(r.FormValue("name")),
		MaxClients:      atoi("max_clients"),
		MaxDomainsTotal: atoi("max_domains_total"),
		MaxServices:     atoi("max_services_total"),
		RateLimitCap:    atoi("rate_limit_rpm_cap"),
	}
	for _, v := range r.Form["node_group_id"] {
		if ng, err := strconv.ParseInt(v, 10, 64); err == nil && ng > 0 {
			p.NodeGroupIDs = append(p.NodeGroupIDs, ng)
		}
	}
	p.Features = r.Form["feature"]
	savedID, err := h.Resellers.PlanSave(r.Context(), p)
	if err != nil {
		if err == reseller.ErrDuplicate {
			redirectWithFlash(w, r, "/admin/resellers", "", "package name already exists")
			return
		}
		h.Logger.Error("reseller plan save", "err", err)
		redirectWithFlash(w, r, "/admin/resellers", "", "could not save package")
		return
	}
	h.auditReseller(r, sess, "reseller_plan.saved", strconv.FormatInt(savedID, 10),
		map[string]any{"name": p.Name})
	redirectWithFlash(w, r, "/admin/resellers", "Package saved", "")
}

// ResellerPlanDelete handles POST /admin/reseller-plans/{id}/delete.
func (h *AdminHandlers) ResellerPlanDelete(w http.ResponseWriter, r *http.Request) {
	sess := h.guardSuperAdmin(w, r)
	if sess == nil {
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if id <= 0 || h.Resellers == nil {
		redirectWithFlash(w, r, "/admin/resellers", "", "bad package id")
		return
	}
	if err := h.Resellers.PlanDelete(r.Context(), id); err != nil {
		if err == reseller.ErrPlanInUse {
			redirectWithFlash(w, r, "/admin/resellers", "", "package is in use - reassign resellers first")
			return
		}
		redirectWithFlash(w, r, "/admin/resellers", "", "could not delete package")
		return
	}
	h.auditReseller(r, sess, "reseller_plan.deleted", strconv.FormatInt(id, 10), nil)
	redirectWithFlash(w, r, "/admin/resellers", "Package deleted", "")
}

// ResellerSetPolicy handles POST /admin/resellers/{id}/policy (package assign +
// per-reseller overselling / can_create_plans flags).
func (h *AdminHandlers) ResellerSetPolicy(w http.ResponseWriter, r *http.Request) {
	sess := h.guardSuperAdmin(w, r)
	if sess == nil {
		return
	}
	id := h.resellerParam(w, r)
	if id == 0 {
		return
	}
	_ = r.ParseForm()
	planID, _ := strconv.ParseInt(r.FormValue("reseller_plan_id"), 10, 64)
	pol := reseller.Policy{
		PlanID:         planID,
		Overselling:    r.FormValue("overselling_allowed") == "1",
		CanCreatePlans: r.FormValue("can_create_plans") == "1",
	}
	if err := h.Resellers.SetPolicy(r.Context(), id, pol); err != nil {
		redirectWithFlash(w, r, "/admin/resellers", "", "could not update policy")
		return
	}
	h.auditReseller(r, sess, "reseller.policy_updated", strconv.FormatInt(id, 10),
		map[string]any{"plan_id": pol.PlanID, "overselling": pol.Overselling, "can_create_plans": pol.CanCreatePlans})
	redirectWithFlash(w, r, "/admin/resellers", "Policy updated", "")
}
