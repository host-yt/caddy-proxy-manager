package handlers

import (
	"fmt"
	"net/http"

	"github.com/host-yt/caddy-proxy-manager/internal/audit"
	"github.com/host-yt/caddy-proxy-manager/internal/deployment"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
)

// deploymentProfileOption is one switchable profile rendered as a card. All
// display strings are computed in Go so the template never calls Profile methods.
type deploymentProfileOption struct {
	Value        string // raw profile id, submitted as form "profile"
	Label        string
	Description  string
	RecommendDB  string // "mysql" | "sqlite" recommendation for the profile
	RequireMySQL bool
	Current      bool // this option equals the active profile
	IsDowngrade  bool // switching to it from current hides modules
	IsUpgrade    bool // switching to it from current adds modules
}

type deploymentData struct {
	baseAdminData
	CurrentLabel       string
	CurrentDescription string
	CurrentUIMode      string
	CurrentTenantMode  string
	CurrentRBACMode    string
	DBDriver           string
	CanSwitch          bool // viewer is super_admin
	SQLiteAvailable    bool
	Options            []deploymentProfileOption
}

// buildDeploymentData assembles the read-only view model from install state.
// canSwitch is precomputed so the template only renders mutate controls for
// super_admin (defense in depth alongside the POST authz gate).
func (h *AdminHandlers) buildDeploymentData(base baseAdminData, canSwitch bool) deploymentData {
	st := h.State.Get()
	current := deployment.Parse(st.Profile)
	driver := st.DBDriver
	if driver == "" {
		driver = "mysql"
	}

	d := deploymentData{
		baseAdminData:      base,
		CurrentLabel:       current.Label(),
		CurrentDescription: current.Description(),
		CurrentUIMode:      current.UIMode(),
		CurrentTenantMode:  current.TenantMode(),
		CurrentRBACMode:    current.RBACMode(),
		DBDriver:           driver,
		CanSwitch:          canSwitch,
		SQLiteAvailable:    deployment.SQLiteAvailable,
	}
	for _, p := range deployment.All() {
		db := p.DB()
		d.Options = append(d.Options, deploymentProfileOption{
			Value:        string(p),
			Label:        p.Label(),
			Description:  p.Description(),
			RecommendDB:  db.Recommended,
			RequireMySQL: db.RequireMySQL,
			Current:      p == current,
			IsDowngrade:  current.IsDowngrade(p),
			IsUpgrade:    p.IsDowngrade(current), // reverse direction == upgrade
		})
	}
	return d
}

// DeploymentPage renders GET /admin/deployment. Any logged-in admin role may
// view; switch controls are gated to super_admin via CanSwitch.
func (h *AdminHandlers) DeploymentPage(w http.ResponseWriter, r *http.Request) {
	base := h.base(r, "Deployment mode")
	base.PageDesc = "Install profile - controls which modules and roles are visible"
	canSwitch := base.Role == "super_admin"
	h.render(w, "deployment", h.buildDeploymentData(base, canSwitch))
}

// DeploymentUpdate handles POST /admin/deployment. Security-sensitive: it
// changes which modules/RBAC surfaces are visible, so only super_admin may
// switch, provider needs MySQL, and downgrades need explicit confirmation.
func (h *AdminHandlers) DeploymentUpdate(w http.ResponseWriter, r *http.Request) {
	sess := middleware.SessionFromContext(r.Context())
	// Authz: profile changes are owner-level; super_admin only.
	if sess == nil || sess.Role != "super_admin" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	_ = r.ParseForm()
	target := deployment.Parse(r.FormValue("profile"))
	// Parse falls back to Default for unknown input, so re-check the raw value
	// matched a real profile rather than silently switching to the default.
	if string(target) != r.FormValue("profile") || !target.Valid() {
		redirectWithFlash(w, r, "/admin/deployment", "", "unknown deployment profile")
		return
	}

	st := h.State.Get()
	current := deployment.Parse(st.Profile)
	driver := st.DBDriver
	if driver == "" {
		driver = "mysql"
	}

	// Provider (and any RequireMySQL profile) cannot run on SQLite.
	if target.DB().RequireMySQL && driver != "mysql" {
		redirectWithFlash(w, r, "/admin/deployment", "",
			"provider mode requires MySQL/MariaDB; current database is SQLite")
		return
	}

	// Downgrades hide active modules/data (data is kept, only hidden), so they
	// require an explicit confirm to avoid an operator silently losing surfaces.
	if current.IsDowngrade(target) && r.FormValue("confirm_downgrade") != "yes" {
		redirectWithFlash(w, r, "/admin/deployment", "",
			"downgrading to "+target.Label()+" hides active modules (data is kept, not deleted) - re-submit with confirmation to proceed")
		return
	}

	st.Profile = string(target)
	if err := h.State.Save(&st); err != nil {
		h.Logger.Error("deployment profile save", "err", err)
		redirectWithFlash(w, r, "/admin/deployment", "", "could not save profile")
		return
	}

	h.Logger.Info("deployment profile changed",
		"actor", sess.Email, "from", string(current), "to", string(target))
	// audit.Write is nil-DB safe, but h.DB itself may be unwired (tests).
	if h.DB != nil {
		audit.Write(r.Context(), h.DB(), h.Logger, r, audit.Entry{
			UserID: actorUserID(sess),
			Action: "deployment.profile_changed", Entity: "deployment", EntityID: string(target),
			Meta: map[string]any{"from": string(current), "to": string(target)},
		})
	}
	redirectWithFlash(w, r, "/admin/deployment",
		fmt.Sprintf("Deployment mode switched to %s", target.Label()), "")
}
