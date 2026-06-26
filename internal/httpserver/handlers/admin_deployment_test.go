package handlers

import (
	"bytes"
	"database/sql"
	"html/template"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/host-yt/caddy-proxy-manager/internal/auth"
	"github.com/host-yt/caddy-proxy-manager/internal/deployment"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
	"github.com/host-yt/caddy-proxy-manager/internal/installstate"
	"github.com/host-yt/caddy-proxy-manager/internal/view"
)

// newDeploymentHandler builds an AdminHandlers backed by a real on-disk
// install-state Manager seeded with the given profile/driver. No DB needed -
// these handlers only touch State + templates (audit.Write is nil-DB safe).
func newDeploymentHandler(t *testing.T, profile, driver string) *AdminHandlers {
	t.Helper()
	mgr, err := installstate.New(t.TempDir(), strings.Repeat("x", 32))
	if err != nil {
		t.Fatalf("installstate.New: %v", err)
	}
	st := mgr.Get()
	st.Profile = profile
	st.DBDriver = driver
	if err := mgr.Save(&st); err != nil {
		t.Fatalf("seed save: %v", err)
	}
	tpls, err := view.LoadAdminTemplates()
	if err != nil {
		t.Fatalf("load admin templates: %v", err)
	}
	return &AdminHandlers{
		State:     mgr,
		Templates: tpls,
		Logger:    slog.Default(),
		// DB is wired in production; nil-returning func keeps base()/audit safe.
		DB: func() *sql.DB { return nil },
	}
}

// postDeployment posts a profile switch as the given role and returns the
// recorder plus the persisted profile after the call.
func postDeployment(h *AdminHandlers, role string, form url.Values) (*httptest.ResponseRecorder, string) {
	r := httptest.NewRequest(http.MethodPost, "/admin/deployment", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = r.WithContext(middleware.ContextWithSession(r.Context(),
		&auth.Session{Role: role, Email: "op@example.com"}))
	w := httptest.NewRecorder()
	h.DeploymentUpdate(w, r)
	return w, h.State.Get().Profile
}

// TestDeploymentSuperAdminUpgrade: super_admin homelab->advanced switches.
func TestDeploymentSuperAdminUpgrade(t *testing.T) {
	h := newDeploymentHandler(t, "homelab", "mysql")
	w, got := postDeployment(h, "super_admin", url.Values{"profile": {"advanced"}})
	if got != "advanced" {
		t.Fatalf("profile = %q, want advanced", got)
	}
	if w.Code < 200 || w.Code >= 400 {
		t.Fatalf("status = %d, want 2xx/3xx", w.Code)
	}
}

// TestDeploymentNonSuperAdminForbidden: role admin cannot switch.
func TestDeploymentNonSuperAdminForbidden(t *testing.T) {
	h := newDeploymentHandler(t, "homelab", "mysql")
	w, got := postDeployment(h, "admin", url.Values{"profile": {"advanced"}})
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
	if got != "homelab" {
		t.Fatalf("profile = %q, want unchanged homelab", got)
	}
}

// TestDeploymentInvalidProfileRejected: unknown value does not switch.
func TestDeploymentInvalidProfileRejected(t *testing.T) {
	h := newDeploymentHandler(t, "advanced", "mysql")
	_, got := postDeployment(h, "super_admin", url.Values{"profile": {"bogus"}})
	if got != "advanced" {
		t.Fatalf("profile = %q, want unchanged advanced", got)
	}
}

// TestDeploymentDowngradeNeedsConfirm: provider->homelab blocked without
// confirm, allowed with confirm_downgrade=yes.
func TestDeploymentDowngradeNeedsConfirm(t *testing.T) {
	h := newDeploymentHandler(t, "provider", "mysql")
	if _, got := postDeployment(h, "super_admin", url.Values{"profile": {"homelab"}}); got != "provider" {
		t.Fatalf("downgrade without confirm: profile = %q, want unchanged provider", got)
	}
	if _, got := postDeployment(h, "super_admin", url.Values{
		"profile": {"homelab"}, "confirm_downgrade": {"yes"},
	}); got != "homelab" {
		t.Fatalf("downgrade with confirm: profile = %q, want homelab", got)
	}
}

// TestDeploymentProviderRequiresMySQL: provider target on SQLite is rejected.
func TestDeploymentProviderRequiresMySQL(t *testing.T) {
	h := newDeploymentHandler(t, "homelab", "sqlite")
	_, got := postDeployment(h, "super_admin", url.Values{"profile": {"provider"}})
	if got != "homelab" {
		t.Fatalf("profile = %q, want unchanged homelab (provider needs MySQL)", got)
	}
}

// TestDeploymentPageStatus: GET renders 200 for any admin role. (Visible body
// content arrives once the orchestrator wires the layout's page dispatch.)
func TestDeploymentPageStatus(t *testing.T) {
	h := newDeploymentHandler(t, "advanced", "mysql")
	for _, role := range []string{"super_admin", "admin", "support"} {
		r := httptest.NewRequest(http.MethodGet, "/admin/deployment", nil)
		r = r.WithContext(middleware.ContextWithSession(r.Context(),
			&auth.Session{Role: role, Email: "op@example.com"}))
		w := httptest.NewRecorder()
		h.DeploymentPage(w, r)
		if w.Code != http.StatusOK {
			t.Errorf("role %s: status = %d, want 200", role, w.Code)
		}
	}
}

// TestDeploymentPartialRoleGate renders the deployment partial directly (not
// through the layout dispatch, which the orchestrator wires) to prove the
// switch controls show only for super_admin.
func TestDeploymentPartialRoleGate(t *testing.T) {
	src, err := os.ReadFile("../../view/admin/deployment.html.tmpl")
	if err != nil {
		t.Fatalf("read template: %v", err)
	}
	tpl, err := template.New("deployment").Funcs(view.CommonFuncs()).Parse(string(src))
	if err != nil {
		t.Fatalf("parse template: %v", err)
	}

	for _, tc := range []struct {
		role       string
		canSwitch  bool
		wantSwitch bool
	}{
		{"super_admin", true, true},
		{"admin", false, false},
	} {
		data := deploymentData{
			baseAdminData:      baseAdminData{Role: tc.role},
			CurrentLabel:       deployment.ProfileAdvanced.Label(),
			CurrentDescription: deployment.ProfileAdvanced.Description(),
			CanSwitch:          tc.canSwitch,
			SQLiteAvailable:    deployment.SQLiteAvailable,
		}
		for _, p := range deployment.All() {
			data.Options = append(data.Options, deploymentProfileOption{
				Value: string(p), Label: p.Label(), Description: p.Description(),
				RecommendDB: p.DB().Recommended, Current: p == deployment.ProfileAdvanced,
			})
		}
		var buf bytes.Buffer
		if err := tpl.ExecuteTemplate(&buf, "deployment", data); err != nil {
			t.Fatalf("role %s: execute: %v", tc.role, err)
		}
		hasSwitch := strings.Contains(buf.String(), "Switch deployment mode")
		if hasSwitch != tc.wantSwitch {
			t.Errorf("role %s: switch button present = %v, want %v", tc.role, hasSwitch, tc.wantSwitch)
		}
	}
}
