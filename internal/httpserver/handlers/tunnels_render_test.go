package handlers

import (
	"bytes"
	"strings"
	"testing"

	"github.com/hostyt/proxy-gateway/internal/view"
)

func TestAdminTunnelsRenderWithNewTunnel(t *testing.T) {
	tpls, err := view.LoadAdminTemplates()
	if err != nil {
		t.Fatalf("load admin templates: %v", err)
	}

	var buf bytes.Buffer
	err = tpls.Render(&buf, "tunnels", tunnelsData{
		baseAdminData: baseAdminData{
			Role:     "admin",
			CSRF:     "csrf",
			CSPNonce: "nonce",
		},
		NewTunnel: &newTunnelView{
			Name:           "prod-backend",
			ClientEmail:    "client@example.test",
			NodeName:       "edge-1",
			AssignedIP:     "100.96.0.10",
			InstallCommand: "curl -fsSL https://proxy.example.test/api/wg/install.sh?token=abc | sudo bash",
			ConfURL:        "https://proxy.example.test/api/wg/bootstrap?token=abc",
			StatusURL:      "https://proxy.example.test/api/wg/status?token=abc",
			ExpiresAt:      "2026-06-26T12:00:00Z",
		},
	})
	if err != nil {
		t.Fatalf("render tunnels: %v", err)
	}
	html := buf.String()
	if !strings.Contains(html, "Tunnel ready") {
		t.Fatalf("rendered page does not include new tunnel card")
	}
	if !strings.Contains(html, `var statusURL = "https://proxy.example.test/api/wg/status?token=abc";`) {
		t.Fatalf("status URL was not emitted as a JavaScript string")
	}
}

func TestClientTunnelsRenderWithNewTunnel(t *testing.T) {
	tpls, err := view.LoadAppTemplates()
	if err != nil {
		t.Fatalf("load app templates: %v", err)
	}

	var buf bytes.Buffer
	err = tpls.Render(&buf, "tunnels", clientTunnelsData{
		baseAppData: baseAppData{
			CSRF:     "csrf",
			CSPNonce: "nonce",
		},
		NewTunnel: &newTunnelView{
			Name:           "prod-backend",
			NodeName:       "edge-1",
			AssignedIP:     "100.96.0.10",
			InstallCommand: "curl -fsSL https://proxy.example.test/api/wg/install.sh?token=abc | sudo bash",
			ConfURL:        "https://proxy.example.test/api/wg/bootstrap?token=abc",
		},
	})
	if err != nil {
		t.Fatalf("render client tunnels: %v", err)
	}
	if !strings.Contains(buf.String(), "Tunnel ready") {
		t.Fatalf("rendered page does not include new client tunnel card")
	}
}
