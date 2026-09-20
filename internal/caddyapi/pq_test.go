package caddyapi

import (
	"encoding/json"
	"testing"
)

func TestBuildConnPolicies_PQOnly(t *testing.T) {
	pols := buildConnPolicies([]Route{{
		ID: "1", Hosts: []string{"pq.example.com"}, UpstreamIP: "10.0.0.1", UpstreamPort: 443,
		TLSPQOnly: true,
	}}, false)
	if len(pols) != 2 {
		t.Fatalf("want 2 policies (pq + catch-all), got %d", len(pols))
	}
	b, _ := json.Marshal(pols[0])
	for _, want := range []string{
		`"curves":["x25519mlkem768"]`,
		`"protocol_min":"tls1.3"`,
		`"match":{"sni":["pq.example.com"]}`,
	} {
		if !contains(string(b), want) {
			t.Errorf("PQ policy missing %q\nfull: %s", want, string(b))
		}
	}
	if contains(string(b), "client_authentication") {
		t.Errorf("PQ-only route must not get client_authentication: %s", string(b))
	}
}

func TestBuildConnPolicies_MTLSAndPQMerged(t *testing.T) {
	// One entry per SNI: Caddy matches first-match, so a second policy for the
	// same host would never be reached and one of the two options would be lost.
	pols := buildConnPolicies([]Route{{
		ID: "1", Hosts: []string{"both.example.com"}, UpstreamIP: "10.0.0.1", UpstreamPort: 443,
		RequireClientCert: true, MTLSCACertPEM: testCAPEM(t), TLSPQOnly: true,
	}}, false)
	if len(pols) != 2 {
		t.Fatalf("want 1 merged policy + catch-all, got %d", len(pols))
	}
	b, _ := json.Marshal(pols[0])
	for _, want := range []string{
		`"curves":["x25519mlkem768"]`,
		`"protocol_min":"tls1.3"`,
		`"mode":"require_and_verify"`,
		`"match":{"sni":["both.example.com"]}`,
	} {
		if !contains(string(b), want) {
			t.Errorf("merged policy missing %q\nfull: %s", want, string(b))
		}
	}
	if last := pols[1].(map[string]any); len(last) != 0 {
		t.Errorf("last policy must be the empty catch-all, got %v", last)
	}
}

func TestBuildConnPolicies_NoneWhenNobodyOptsIn(t *testing.T) {
	if got := buildConnPolicies([]Route{
		{ID: "1", Hosts: []string{"a.example.com"}, UpstreamIP: "10.0.0.1", UpstreamPort: 80},
		{ID: "2", Hosts: []string{"b.example.com"}, UpstreamIP: "10.0.0.2", UpstreamPort: 80},
	}, false); got != nil {
		t.Errorf("no route opted in, want nil policies, got %v", got)
	}
}

// TestBuildNodeConfig_PQDriftHashSafety pins the no-opt-in JSON: a node whose
// routes use neither mTLS nor PQ-only must serialize byte-identically to
// before the tls_pq_only column existed, or every such node sees a spurious
// drift push on upgrade.
func TestBuildNodeConfig_PQDriftHashSafety(t *testing.T) {
	routes := []Route{{ID: "1", Hosts: []string{"plain.example.com"}, UpstreamIP: "10.0.0.1", UpstreamPort: 8080}}
	b, err := json.Marshal(BuildNodeConfig(routes, NodeSettings{ACMEEmail: "a@b.c"}))
	if err != nil {
		t.Fatal(err)
	}
	if contains(string(b), "tls_connection_policies") {
		t.Errorf("plain node must emit no tls_connection_policies\n%s", string(b))
	}
	// Same routes with the flag off on the struct = same bytes.
	routes[0].TLSPQOnly = false
	b2, _ := json.Marshal(BuildNodeConfig(routes, NodeSettings{ACMEEmail: "a@b.c"}))
	if string(b) != string(b2) {
		t.Error("config JSON is not stable for routes without PQ-only")
	}
}

func TestBuildNodeConfig_PQEmitsPolicy(t *testing.T) {
	cfg := BuildNodeConfig([]Route{{
		ID: "1", Hosts: []string{"pq.example.com"}, UpstreamIP: "10.0.0.1", UpstreamPort: 443, TLSPQOnly: true,
	}}, NodeSettings{ACMEEmail: "a@b.c"})
	b, _ := json.Marshal(cfg)
	if !contains(string(b), `"curves":["x25519mlkem768"]`) {
		t.Errorf("node config missing PQ-only connection policy\n%s", string(b))
	}
}
