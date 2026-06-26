package handlers

import (
	"bytes"
	"strings"
	"testing"

	"github.com/host-yt/caddy-proxy-manager/internal/view"
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

func TestAdminMapRenderWithTopology(t *testing.T) {
	tpls, err := view.LoadAdminTemplates()
	if err != nil {
		t.Fatalf("load admin templates: %v", err)
	}

	client := &adminMapClient{
		ID:           1,
		Name:         "Acme Hosting",
		Email:        "ops@example.test",
		ServiceCount: 1,
		RouteCount:   1,
		TunnelCount:  1,
	}
	svc := &adminMapService{
		ID:        10,
		ClientID:  1,
		Name:      "prod-api",
		BackendIP: "10.10.0.5",
		PortStart: 30000,
		PortEnd:   30010,
		Status:    "active",
	}
	rt := &adminMapRoute{
		ID:           20,
		ServiceID:    10,
		Domain:       "api.example.test",
		UpstreamPort: 30001,
		Status:       "active",
		NodeID:       2,
		NodeName:     "edge-1",
		NodeHealth:   "healthy",
		NodeEnabled:  true,
		WGPeerID:     30,
		WGPeerIP:     "100.96.0.10",
	}
	svc.Routes = []*adminMapRoute{rt}
	client.Services = []*adminMapService{svc}
	client.Tunnels = []*adminMapTunnel{{
		ID:         30,
		ClientID:   1,
		NodeID:     2,
		NodeName:   "edge-1",
		Name:       "customer-lan",
		AssignedIP: "100.96.0.10",
		Status:     "active",
	}}

	var buf bytes.Buffer
	err = tpls.Render(&buf, "map", adminMapData{
		baseAdminData: baseAdminData{Role: "admin", CSRF: "csrf", CSPNonce: "nonce"},
		Counts: adminMapCounts{
			Clients:       1,
			Services:      1,
			Routes:        1,
			ActiveRoutes:  1,
			Nodes:         1,
			HealthyNodes:  1,
			Tunnels:       1,
			ActiveTunnels: 1,
		},
		Clients: []*adminMapClient{client},
		Limits:  adminMapLimits{Clients: 40, Services: 160, Routes: 400, Nodes: 80, Tunnels: 300},
	})
	if err != nil {
		t.Fatalf("render admin map: %v", err)
	}
	html := buf.String()
	for _, want := range []string{"Live topology", "Traffic path from customer to edge", "api.example.test", "customer-lan"} {
		if !strings.Contains(html, want) {
			t.Fatalf("rendered map missing %q", want)
		}
	}
}
