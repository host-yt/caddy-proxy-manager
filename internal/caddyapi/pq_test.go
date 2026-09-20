package caddyapi

import (
	"encoding/json"
	"testing"
)

func TestBuildConnPolicies_PQOnly(t *testing.T) {
	pols := buildConnPolicies([]Route{{
		ID: "1", Hosts: []string{"pq.example.com"}, UpstreamIP: "10.0.0.1", UpstreamPort: 443,
		TLSPQOnly: true,
	}}, false, true)
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
	}}, false, true)
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

// TestBuildConnPolicies_MergedPerSNI is the regression for the per-route
// emission bug: routes is UNIQUE(domain, path_prefix), so two routes can share
// a hostname. mTLS on / and PQ-only on /api used to emit two sni:[same host]
// entries, of which Caddy silently honoured only the first.
func TestBuildConnPolicies_MergedPerSNI(t *testing.T) {
	ca := testCAPEM(t)
	pols := buildConnPolicies([]Route{
		{ID: "1", Hosts: []string{"shared.example.com"}, PathPrefix: "/",
			RequireClientCert: true, MTLSCACertPEM: ca},
		{ID: "2", Hosts: []string{"shared.example.com"}, PathPrefix: "/api",
			TLSPQOnly: true},
	}, false, true)
	if len(pols) != 2 {
		t.Fatalf("want 1 merged policy + catch-all, got %d: %v", len(pols), pols)
	}
	b, _ := json.Marshal(pols[0])
	for _, want := range []string{
		`"match":{"sni":["shared.example.com"]}`,
		`"curves":["x25519mlkem768"]`,
		`"mode":"require_and_verify"`,
	} {
		if !contains(string(b), want) {
			t.Errorf("merged per-SNI policy missing %q\nfull: %s", want, string(b))
		}
	}
}

// TestBuildConnPolicies_CAConflictFirstWins: two routes on one host with
// different trust anchors cannot both be honoured. The first in route order
// (the SELECT is ORDER BY r.id) wins, deterministically.
func TestBuildConnPolicies_CAConflictFirstWins(t *testing.T) {
	first, second := testCAPEM(t), testCAPEM(t)
	pols := buildConnPolicies([]Route{
		{ID: "1", Hosts: []string{"h.example.com"}, RequireClientCert: true, MTLSCACertPEM: first},
		{ID: "2", Hosts: []string{"h.example.com"}, RequireClientCert: true, MTLSCACertPEM: second},
	}, false, true)
	if len(pols) != 2 {
		t.Fatalf("want 1 policy + catch-all, got %d", len(pols))
	}
	certs := pols[0].(map[string]any)["client_authentication"].(map[string]any)["ca"].(map[string]any)["trusted_ca_certs"].([]string)
	want := pemCertsToBase64DER(first)
	if len(certs) != 1 || certs[0] != want[0] {
		t.Errorf("first route's CA must win the conflict")
	}
}

// TestBuildConnPolicies_AliasesShareOneEntry: a route's aliases all carry the
// same policy, so they stay in one entry's sni list (byte-identical to the
// pre-merge output for the single-route case).
func TestBuildConnPolicies_AliasesShareOneEntry(t *testing.T) {
	pols := buildConnPolicies([]Route{{
		ID: "1", Hosts: []string{"a.example.com", "www.a.example.com"}, TLSPQOnly: true,
	}}, false, true)
	if len(pols) != 2 {
		t.Fatalf("want 1 policy + catch-all, got %d", len(pols))
	}
	b, _ := json.Marshal(pols[0])
	if !contains(string(b), `"match":{"sni":["a.example.com","www.a.example.com"]}`) {
		t.Errorf("aliases must share one entry: %s", string(b))
	}
}

func TestBuildConnPolicies_NoneWhenNobodyOptsIn(t *testing.T) {
	if got := buildConnPolicies([]Route{
		{ID: "1", Hosts: []string{"a.example.com"}, UpstreamIP: "10.0.0.1", UpstreamPort: 80},
		{ID: "2", Hosts: []string{"b.example.com"}, UpstreamIP: "10.0.0.2", UpstreamPort: 80},
	}, false, true); got != nil {
		t.Errorf("no route opted in, want nil policies, got %v", got)
	}
}

// TestBuildConnPolicies_VersionGate: an incapable node must get NO PQ knob -
// Caddy < 2.10 rejects the whole /load on an unknown curve, freezing every
// route on that node.
func TestBuildConnPolicies_VersionGate(t *testing.T) {
	pq := []Route{{ID: "1", Hosts: []string{"pq.example.com"}, TLSPQOnly: true}}
	if got := buildConnPolicies(pq, false, false); got != nil {
		t.Errorf("incapable node must get no policies at all, got %v", got)
	}
	// A host that also uses mTLS keeps its client_authentication, minus the curve.
	pols := buildConnPolicies([]Route{{
		ID: "1", Hosts: []string{"pq.example.com"}, TLSPQOnly: true,
		RequireClientCert: true, MTLSCACertPEM: testCAPEM(t),
	}}, false, false)
	b, _ := json.Marshal(pols[0])
	if contains(string(b), "x25519mlkem768") || contains(string(b), "protocol_min") {
		t.Errorf("incapable node must not see the PQ knob: %s", string(b))
	}
	if !contains(string(b), "client_authentication") {
		t.Errorf("mTLS must survive the PQ gate: %s", string(b))
	}
}

func TestCaddySupportsPQCurve(t *testing.T) {
	for _, v := range []string{"2.10.0", "v2.10.0", "2.11.4", "2.10.0-beta.1", " 2.10.0 h1:abc", "3.0.0"} {
		if !CaddySupportsPQCurve(v) {
			t.Errorf("version %q must be treated as capable", v)
		}
	}
	// Unknown / unparsable / older must all be unsupported: never flip a gated
	// feature on before the node proves capability.
	for _, v := range []string{"", "   ", "unknown", "2", "2.9.1", "1.99.0", "v2.x", "abc.def"} {
		if CaddySupportsPQCurve(v) {
			t.Errorf("version %q must be treated as incapable", v)
		}
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
	// Same routes with the flag off on the struct = same bytes, and turning the
	// node capability on changes nothing while no route opts in.
	routes[0].TLSPQOnly = false
	b2, _ := json.Marshal(BuildNodeConfig(routes, NodeSettings{ACMEEmail: "a@b.c", PQCurveAvailable: true}))
	if string(b) != string(b2) {
		t.Error("config JSON is not stable for routes without PQ-only")
	}
}

func TestBuildNodeConfig_PQEmitsPolicy(t *testing.T) {
	routes := []Route{{
		ID: "1", Hosts: []string{"pq.example.com"}, UpstreamIP: "10.0.0.1", UpstreamPort: 443, TLSPQOnly: true,
	}}
	b, _ := json.Marshal(BuildNodeConfig(routes, NodeSettings{ACMEEmail: "a@b.c", PQCurveAvailable: true}))
	if !contains(string(b), `"curves":["x25519mlkem768"]`) {
		t.Errorf("node config missing PQ-only connection policy\n%s", string(b))
	}
	// Unknown Caddy version on the node: the whole policy list disappears again.
	b2, _ := json.Marshal(BuildNodeConfig(routes, NodeSettings{ACMEEmail: "a@b.c"}))
	if contains(string(b2), "tls_connection_policies") {
		t.Errorf("ungated node must emit no connection policies\n%s", string(b2))
	}
}
