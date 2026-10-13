package routes

import (
	"context"
	"log/slog"
	"slices"
	"testing"

	"github.com/host-yt/caddy-proxy-manager/internal/caddyapi"
)

// A platform-admin "*.zone" alias on a wildcard route reaches the Caddy
// config as a host matcher plus an eagerly ordered cert, with no TXT proof.
func TestWildcardAliasReachesNodeConfig(t *testing.T) {
	db := migratedSQLite(t)
	ctx := context.Background()
	for _, s := range []string{
		`INSERT INTO node_groups (id, name) VALUES (1, 'g1')`,
		`INSERT INTO caddy_nodes (id, name, api_url, is_enabled, node_group_id) VALUES (1, 'p1', 'http://n1:2019', 1, 1)`,
		`INSERT INTO plans (id, name, node_group_id) VALUES (1, 'p1', 1)`,
		`INSERT INTO services (id, client_id, name, backend_ip, allowed_port_start, allowed_port_end, plan_id, node_group_id)
		   VALUES (1, 1, 'svc', '10.0.0.9', 1, 65535, 1, 1)`,
		`INSERT INTO dns_providers (id, name, provider, api_token_enc) VALUES (1, 'shop.example', 'cloudflare', 'enc')`,
		`INSERT INTO routes (id, service_id, caddy_node_id, domain, aliases, aliases_verified, upstream_port, upstream_scheme,
		   ssl_enabled, status, kind, domain_verified, wildcard_enabled, wildcard_zone)
		   VALUES (44, 1, 1, 'shop.example', '*.shop.example', '*.shop.example', 8080, 'http', 1, 'active', 'proxy', 1, 1, 'shop.example')`,
	} {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("exec %q: %v", s, err)
		}
	}
	svc := &Service{DB: db, Logger: slog.Default(), DNS01ModuleAvailable: true,
		DecryptSecret: func(string) (string, error) { return "cf-token", nil }}
	built, _, err := svc.buildRoutesForNode(ctx, 1)
	if err != nil {
		t.Fatalf("buildRoutesForNode: %v", err)
	}
	if len(built) != 1 || built[0].WildcardZone != "shop.example" {
		t.Fatalf("route did not carry its wildcard zone: %+v", built)
	}
	if slices.Contains(built[0].Hosts, "*.shop.example") {
		t.Error("*.zone emitted before the DNS-01 policy gate")
	}
	pol := svc.buildWildcardPolicies(ctx, 1)
	if len(pol) != 1 || pol[0].Zone != "shop.example" {
		t.Fatalf("policies = %+v", pol)
	}
	cfg := caddyapi.BuildNodeConfig(built, caddyapi.NodeSettings{DNS01ModuleAvailable: true, WildcardPolicies: pol})
	certs := cfg["apps"].(map[string]any)["tls"].(map[string]any)["certificates"].(map[string]any)
	if got := certs["automate"].([]string); !slices.Equal(got, []string{"*.shop.example", "shop.example"}) {
		t.Errorf("automate = %v", got)
	}

	// Unapproved (scoped-admin) wildcard alias: never emitted.
	if _, err := db.Exec(`UPDATE routes SET aliases_verified = '' WHERE id = 44`); err != nil {
		t.Fatal(err)
	}
	if b, _, _ := svc.buildRoutesForNode(ctx, 1); len(b) != 1 || b[0].WildcardZone != "" {
		t.Errorf("unverified wildcard alias emitted: %+v", b)
	}

	// Without the zone's provider the alias stays out and nothing is ordered.
	if _, err := db.Exec(`DELETE FROM dns_providers`); err != nil {
		t.Fatal(err)
	}
	if pol := svc.buildWildcardPolicies(ctx, 1); len(pol) != 0 {
		t.Errorf("policy emitted without a provider: %+v", pol)
	}
}

func TestWildcardAliasNeedsNoTXT(t *testing.T) {
	// Not owed a TXT proof, so the recheck loop never chases it.
	if got := unprovenHosts("*.shop.example,a.example", ""); !slices.Equal(got, []string{"a.example"}) {
		t.Errorf("unprovenHosts = %v, want only a.example", got)
	}
}
