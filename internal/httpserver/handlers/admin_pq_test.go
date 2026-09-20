package handlers

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/host-yt/caddy-proxy-manager/internal/view"
)

func TestCaddyHybridKEX(t *testing.T) {
	for in, want := range map[string]bool{
		"v2.11.4":          true,
		"2.10.0":           true,
		"2.10":             true,
		"v2.9.1":           false,
		"2.4.6":            false,
		"":                 false,
		"unknown":          false,
		"v2.11.4 h1:abcde": true,
		"3.0.0-beta.1":     true,
		"v2":               false,
	} {
		if got := caddyHybridKEX(in); got != want {
			t.Errorf("caddyHybridKEX(%q) = %v, want %v", in, got, want)
		}
	}
}

// The settings page is rendered through a wrapper struct so admin.go keeps a
// single call site; this guards both the reflect-based breadcrumb fill (which
// has to find baseAdminData two levels down) and the pane markup.
func TestSettingsRendersPQCard(t *testing.T) {
	tpls, err := view.LoadAdminTemplates()
	if err != nil {
		t.Fatalf("load admin templates: %v", err)
	}
	d := settingsPQData{
		settingsData: settingsData{baseAdminData: baseAdminData{Role: "admin", CSRF: "csrf", CSPNonce: "nonce"}},
		PQ: pqStatusView{
			GoVersion: "go1.25.1", GoHybrid: true,
			Nodes:       []pqNodeView{{Name: "edge-1", CaddyVersion: "v2.11.4", HybridKEX: true, PSK: "active", AgentPSK: true}},
			NodesHybrid: 1, MeshActive: 1, AgentPSK: 1, PeerPSK: 2, PeerTotal: 3,
			PQHosts: []string{"pq.example.test"}, PQHostCount: 1,
		},
	}
	filled, ok := fillBreadcrumbs("settings", d).(settingsPQData)
	if !ok || len(filled.Breadcrumbs) == 0 {
		t.Fatalf("fillBreadcrumbs did not reach baseAdminData through the wrapper: %+v", filled.Breadcrumbs)
	}
	var buf bytes.Buffer
	if err := tpls.Render(&buf, "settings", filled); err != nil {
		t.Fatalf("render settings: %v", err)
	}
	html := buf.String()
	for _, want := range []string{
		`data-settings-pane="pq"`, "Post-quantum readiness", "go1.25.1",
		"edge-1 v2.11.4", "pq.example.test", "docs/POST_QUANTUM.md",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("rendered settings page is missing %q", want)
		}
	}
}

// Counts are global, so assert on deltas: the scratch DB may already hold
// nodes, peers and routes from other tests.
func TestPQStatusCounts(t *testing.T) {
	db := openTestDBHandlers(t)
	h := &AdminHandlers{DB: func() *sql.DB { return db }, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	ctx := context.Background()
	before := h.pqStatus(ctx)

	// One node: mesh PSK active, agent PSK supported, PQ-capable Caddy, one
	// peer with a PSK (from insertPSKNode) and one without.
	nodeID, _ := insertPSKNode(t, db, 1)
	if _, err := db.ExecContext(ctx,
		`UPDATE caddy_nodes SET wg_psk_enc = 'ciphertext', caddy_version = 'v2.11.4' WHERE id = ?`, nodeID); err != nil {
		t.Fatalf("stage mesh psk: %v", err)
	}
	// Same FK bypass insertPSKNode uses: client 1 need not exist on a fresh DB.
	_, _ = db.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS=0")
	_, errPeer := db.ExecContext(ctx,
		`INSERT INTO customer_wg_peer (client_id, node_id, name, pubkey, assigned_ip, status)
		 VALUES (1, ?, 'nopsk', 'PUBKEY2', '100.96.9.6', 'active')`, nodeID)
	_, _ = db.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS=1")
	if errPeer != nil {
		t.Fatalf("insert peer without psk: %v", errPeer)
	}
	// Two PQ-only routes on ONE domain (the card counts hosts, not routes) plus
	// a third PQ-only route with SSL off, whose connection policy is never
	// emitted - neither the count nor the list may show it.
	domain := fmt.Sprintf("pq-%d.example.test", time.Now().UnixNano())
	noSSLDomain := "nossl-" + domain
	_, _ = db.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS=0")
	_, err := db.ExecContext(ctx,
		`INSERT INTO routes (service_id, caddy_node_id, domain, path_prefix, upstream_port, ssl_enabled, tls_pq_only)
		 VALUES (999999, ?, ?, '',       8080, 1, 1),
		        (999999, ?, ?, '/api',   8080, 1, 1),
		        (999999, ?, ?, '',       8080, 0, 1)`,
		nodeID, domain, nodeID, domain, nodeID, noSSLDomain)
	_, _ = db.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS=1")
	if err != nil {
		t.Fatalf("insert pq-only routes: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec("DELETE FROM routes WHERE domain IN (?, ?)", domain, noSSLDomain)
	})

	got := h.pqStatus(ctx)
	for _, c := range []struct {
		name      string
		got, want int
	}{
		{"nodes", got.NodeTotal(), before.NodeTotal() + 1},
		{"mesh active", got.MeshActive, before.MeshActive + 1},
		{"hybrid nodes", got.NodesHybrid, before.NodesHybrid + 1},
		{"agent psk", got.AgentPSK, before.AgentPSK + 1},
		{"peers", got.PeerTotal, before.PeerTotal + 2},
		{"peers with psk", got.PeerPSK, before.PeerPSK + 1},
		{"pq hosts", got.PQHostCount, before.PQHostCount + 1},
	} {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d", c.name, c.got, c.want)
		}
	}
	if got.PQHostCount <= pqHostsShown {
		seen := 0
		for _, d := range got.PQHosts {
			switch d {
			case domain:
				seen++
			case noSSLDomain:
				t.Errorf("PQHosts lists %s, but SSL is off for it", noSSLDomain)
			}
		}
		if seen != 1 {
			t.Errorf("PQHosts %v lists %s %d times, want exactly 1", got.PQHosts, domain, seen)
		}
	}
	var seeded *pqNodeView
	for i := range got.Nodes {
		if got.Nodes[i].CaddyVersion == "v2.11.4" && got.Nodes[i].PSK == "active" {
			seeded = &got.Nodes[i]
		}
	}
	if seeded == nil {
		t.Fatal("seeded node missing from the node list")
	}
	if !seeded.HybridKEX || !seeded.AgentPSK {
		t.Errorf("seeded node = %+v, want HybridKEX and AgentPSK true", *seeded)
	}
}

// The edit page must agree with the pusher, which gates PQ-only per node: a
// fan-out peer on older Caddy drops the policy there, so the host is not
// enforced even when the anchor node is fine.
func TestPQBlockingNodeSeesFanoutPeer(t *testing.T) {
	db := openTestDBHandlers(t)
	ctx := context.Background()
	anchor, _ := insertPSKNode(t, db, 0)
	peer, _ := insertPSKNode(t, db, 0)
	if _, err := db.ExecContext(ctx,
		`UPDATE caddy_nodes SET caddy_version = CASE id WHEN ? THEN 'v2.11.4' ELSE 'v2.9.1' END,
		        name = CASE id WHEN ? THEN 'pq-anchor' ELSE 'pq-laggard' END
		 WHERE id IN (?, ?)`, anchor, anchor, anchor, peer); err != nil {
		t.Fatalf("stage node versions: %v", err)
	}
	domain := fmt.Sprintf("fanout-%d.example.test", time.Now().UnixNano())
	_, _ = db.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS=0")
	res, err := db.ExecContext(ctx,
		`INSERT INTO routes (service_id, caddy_node_id, domain, upstream_port, tls_pq_only)
		 VALUES (999999, ?, ?, 8080, 1)`, anchor, domain)
	_, _ = db.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS=1")
	if err != nil {
		t.Fatalf("insert route: %v", err)
	}
	routeID, _ := res.LastInsertId()
	t.Cleanup(func() {
		_, _ = db.Exec("DELETE FROM route_node_assignments WHERE route_id = ?", routeID)
		_, _ = db.Exec("DELETE FROM routes WHERE id = ?", routeID)
	})

	// Anchor alone is capable: no blocker yet.
	if name, _, blocked := pqBlockingNode(ctx, db, routeID); blocked {
		t.Fatalf("anchor-only route reported blocker %q, want none", name)
	}
	if _, err := db.ExecContext(ctx,
		`INSERT INTO route_node_assignments (route_id, node_id) VALUES (?, ?)`, routeID, peer); err != nil {
		t.Fatalf("insert fan-out assignment: %v", err)
	}
	name, ver, blocked := pqBlockingNode(ctx, db, routeID)
	if !blocked || name != "pq-laggard" || ver != "v2.9.1" {
		t.Errorf("pqBlockingNode = (%q, %q, %v), want the fan-out peer on v2.9.1", name, ver, blocked)
	}
}

// Wiring guard: the "saved, not active" line must name the blocking node, not
// the anchor, or the page contradicts the verdict it just rendered.
func TestHostEditPQWarningNamesBlockingNode(t *testing.T) {
	tpls, err := view.LoadAdminTemplates()
	if err != nil {
		t.Fatalf("load admin templates: %v", err)
	}
	d := hostEditData{
		baseAdminData:     baseAdminData{Role: "admin", CSRF: "csrf", CSPNonce: "nonce"},
		RouteID:           1,
		Domain:            "pq.example.test",
		SSL:               true,
		TLSPQOnly:         true,
		NodeName:          "pq-anchor",
		NodeCaddyVersion:  "v2.11.4",
		NodePQCapable:     false,
		PQBlockingNode:    "pq-laggard",
		PQBlockingVersion: "v2.9.1",
	}
	var buf bytes.Buffer
	if err := tpls.Render(&buf, "hosts_edit", fillBreadcrumbs("hosts_edit", d)); err != nil {
		t.Fatalf("render hosts_edit: %v", err)
	}
	html := buf.String()
	if !strings.Contains(html, "saved, not active") {
		t.Error("PQ pill does not warn that the policy is inert")
	}
	if !strings.Contains(html, "pq-laggard") || !strings.Contains(html, "v2.9.1") {
		t.Error("PQ warning does not name the blocking fan-out node")
	}
}
