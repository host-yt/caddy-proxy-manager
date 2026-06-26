package handlers

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/host-yt/caddy-proxy-manager/internal/installstate"
	"github.com/host-yt/caddy-proxy-manager/internal/view"
)

func newTestWizard(t *testing.T) *Wizard {
	t.Helper()
	mgr, err := installstate.New(t.TempDir(), "12345678901234567890123456789012")
	if err != nil {
		t.Fatalf("installstate.New: %v", err)
	}
	tpls, err := view.LoadInstallTemplates()
	if err != nil {
		t.Fatalf("LoadInstallTemplates: %v", err)
	}
	return &Wizard{
		State:     mgr,
		Templates: tpls,
		Logger:    slog.Default(),
	}
}

func postProfile(t *testing.T, wiz *Wizard, profile string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{}
	form.Set("profile", profile)
	req := httptest.NewRequest(http.MethodPost, "/install/profile",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	wiz.ProfileSubmit(rr, req)
	return rr
}

// TestWizardProfileSubmit_Valid verifies a valid profile is persisted and
// CurrentStep advances to db.
func TestWizardProfileSubmit_Valid(t *testing.T) {
	wiz := newTestWizard(t)

	rr := postProfile(t, wiz, "homelab")

	if rr.Code != http.StatusSeeOther {
		t.Fatalf("want 303, got %d", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if !strings.Contains(loc, "step=db") {
		t.Fatalf("want redirect to db step, got %q", loc)
	}

	s := wiz.State.Get()
	if s.Profile != "homelab" {
		t.Errorf("Profile = %q, want homelab", s.Profile)
	}
	if s.CurrentStep != installstate.StepDB {
		t.Errorf("CurrentStep = %q, want %q", s.CurrentStep, installstate.StepDB)
	}
}

// TestWizardProfileSubmit_AllProfiles ensures every known profile is accepted.
func TestWizardProfileSubmit_AllProfiles(t *testing.T) {
	for _, p := range []string{"homelab", "smallteam", "advanced", "provider"} {
		t.Run(p, func(t *testing.T) {
			wiz := newTestWizard(t)
			rr := postProfile(t, wiz, p)
			if rr.Code != http.StatusSeeOther {
				t.Fatalf("profile %q: want 303, got %d", p, rr.Code)
			}
			if s := wiz.State.Get(); s.Profile != p {
				t.Errorf("profile %q: State.Profile = %q", p, s.Profile)
			}
		})
	}
}

// TestWizardProfileSubmit_Invalid verifies bad input is rejected without
// advancing the step.
func TestWizardProfileSubmit_Invalid(t *testing.T) {
	for _, bad := range []string{"", "superuser", "HOMELAB", "root"} {
		t.Run(bad, func(t *testing.T) {
			wiz := newTestWizard(t)
			rr := postProfile(t, wiz, bad)

			// Must not redirect.
			if rr.Code == http.StatusSeeOther {
				t.Fatalf("bad input %q should not redirect", bad)
			}
			// Must re-render profile step (200) with an error message.
			if rr.Code != http.StatusOK {
				t.Fatalf("want 200 re-render, got %d", rr.Code)
			}
			body := rr.Body.String()
			if !strings.Contains(body, "profile") {
				t.Error("response body should contain profile form")
			}

			// Step must not have advanced.
			s := wiz.State.Get()
			if s.CurrentStep == installstate.StepDB {
				t.Error("CurrentStep must not advance on invalid profile")
			}
			if s.Profile != "" {
				t.Errorf("Profile must be empty, got %q", s.Profile)
			}
		})
	}
}
