package handlers

import (
	"bytes"
	"strings"
	"testing"

	"github.com/host-yt/caddy-proxy-manager/internal/deployment"
	"github.com/host-yt/caddy-proxy-manager/internal/view"
)

// TestNavGatingHomelab: homelab profile hides Clients, shows Hosts + Deployment link.
func TestNavGatingHomelab(t *testing.T) {
	tpls, err := view.LoadAdminTemplates()
	if err != nil {
		t.Fatalf("load admin templates: %v", err)
	}

	var buf bytes.Buffer
	err = tpls.Render(&buf, "dashboard", dashboardData{
		baseAdminData: baseAdminData{
			Role:     "super_admin",
			CSRF:     "csrf",
			CSPNonce: "nonce",
			Features: deployment.ProfileHomelab.Features(),
		},
	})
	if err != nil {
		t.Fatalf("render dashboard (homelab): %v", err)
	}
	html := buf.String()

	if strings.Contains(html, "/admin/clients") {
		t.Error("homelab nav must not contain /admin/clients")
	}
	if !strings.Contains(html, "/admin/hosts") {
		t.Error("homelab nav must contain /admin/hosts")
	}
	if !strings.Contains(html, "/admin/deployment") {
		t.Error("super_admin homelab nav must contain /admin/deployment link")
	}
}

// TestNavGatingProvider: provider profile shows Clients and Nodes.
func TestNavGatingProvider(t *testing.T) {
	tpls, err := view.LoadAdminTemplates()
	if err != nil {
		t.Fatalf("load admin templates: %v", err)
	}

	var buf bytes.Buffer
	err = tpls.Render(&buf, "dashboard", dashboardData{
		baseAdminData: baseAdminData{
			Role:     "super_admin",
			CSRF:     "csrf",
			CSPNonce: "nonce",
			Features: deployment.ProfileProvider.Features(),
		},
	})
	if err != nil {
		t.Fatalf("render dashboard (provider): %v", err)
	}
	html := buf.String()

	if !strings.Contains(html, "/admin/clients") {
		t.Error("provider nav must contain /admin/clients")
	}
	if !strings.Contains(html, "/admin/nodes") {
		t.Error("provider nav must contain /admin/nodes")
	}
}
