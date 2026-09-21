package caddyapi

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// testCAPEM mints a throwaway self-signed CA cert PEM for shape assertions.
func testCAPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestBuildConnPolicies_Shape(t *testing.T) {
	caPEM := testCAPEM(t)
	routes := []Route{{
		ID:                "7",
		Hosts:             []string{"secure.example.com"},
		UpstreamIP:        "10.0.0.9",
		UpstreamPort:      8443,
		RequireClientCert: true,
		MTLSCACertPEM:     caPEM,
	}}
	pols := buildConnPolicies(routes, false, true)
	if len(pols) != 2 {
		t.Fatalf("want 2 policies (mTLS + catch-all), got %d", len(pols))
	}
	b, _ := json.Marshal(pols[0])
	s := string(b)
	for _, want := range []string{
		`"match":{"sni":["secure.example.com"]}`,
		`"provider":"inline"`,
		`"mode":"require_and_verify"`,
		`"trusted_ca_certs"`,
	} {
		if !contains(s, want) {
			t.Errorf("policy JSON missing %q\nfull: %s", want, s)
		}
	}
	// trusted_ca_certs must be base64-StdEncoding DER (Caddy inline pool form),
	// not raw PEM. Round-trip: decode the emitted entry back to a parsable cert.
	m := pols[0].(map[string]any)
	ca := m["client_authentication"].(map[string]any)["ca"].(map[string]any)
	certs := ca["trusted_ca_certs"].([]string)
	if len(certs) != 1 {
		t.Fatalf("want 1 trusted cert, got %d", len(certs))
	}
	der, err := base64.StdEncoding.DecodeString(certs[0])
	if err != nil {
		t.Fatalf("trusted_ca_certs[0] is not base64 DER: %v", err)
	}
	if _, err := x509.ParseCertificate(der); err != nil {
		t.Fatalf("decoded DER is not a valid cert: %v", err)
	}
}

func TestBuildConnPolicies_CatchAllLast(t *testing.T) {
	// Caddy only injects a default policy when the list is nil. With a non-empty
	// list, an SNI that matches nothing aborts the handshake - so the last entry
	// must be an unconditional {} that keeps every other host on plain TLS.
	routes := []Route{{
		ID: "1", Hosts: []string{"secure.example.com"}, UpstreamIP: "10.0.0.1", UpstreamPort: 443,
		RequireClientCert: true, MTLSCACertPEM: testCAPEM(t),
	}}
	pols := buildConnPolicies(routes, false, true)
	last, ok := pols[len(pols)-1].(map[string]any)
	if !ok {
		t.Fatalf("last policy has unexpected type %T", pols[len(pols)-1])
	}
	if len(last) != 0 {
		t.Errorf("last policy must be an empty catch-all, got %v", last)
	}
	for i, p := range pols[:len(pols)-1] {
		if _, has := p.(map[string]any)["match"]; !has {
			t.Errorf("policy %d before the catch-all has no match", i)
		}
	}
}

func TestBuildConnPolicies_SkippedWhenNoCAOrFlag(t *testing.T) {
	// flag on but no PEM -> fail open, no policy emitted.
	if got := buildConnPolicies([]Route{{Hosts: []string{"h"}, RequireClientCert: true}}, false, true); got != nil {
		t.Errorf("expected nil policies with empty CA PEM, got %v", got)
	}
	// PEM present but flag off -> no policy.
	if got := buildConnPolicies([]Route{{Hosts: []string{"h"}, MTLSCACertPEM: testCAPEM(t)}}, false, true); got != nil {
		t.Errorf("expected nil policies with flag off, got %v", got)
	}
}

func TestBuildNodeConfig_EmitsConnPolicies(t *testing.T) {
	routes := []Route{{
		ID: "1", Hosts: []string{"m.example.com"}, UpstreamIP: "10.0.0.1", UpstreamPort: 443,
		RequireClientCert: true, MTLSCACertPEM: testCAPEM(t),
	}}
	cfg := BuildNodeConfig(routes, NodeSettings{ACMEEmail: "a@b.c"})
	b, _ := json.Marshal(cfg)
	if !contains(string(b), `"tls_connection_policies"`) {
		t.Errorf("node config missing tls_connection_policies\n%s", string(b))
	}
}

func TestMTLSCAUsable(t *testing.T) {
	if !MTLSCAUsable(testCAPEM(t)) {
		t.Error("valid CA PEM must be usable")
	}
	for _, bad := range []string{"", "not a pem", "-----BEGIN CERTIFICATE-----\ngarbage\n-----END CERTIFICATE-----\n"} {
		if MTLSCAUsable(bad) {
			t.Errorf("unusable PEM reported usable: %q", bad)
		}
	}
}

func TestBuildNodeConfig_DenyRouteStillValid(t *testing.T) {
	// Unparsable CA + fail-closed: route must be emitted as a deny, never as a
	// naked proxy, and the config must contain no client_authentication policy.
	routes := []Route{{
		ID: "9", Hosts: []string{"x.example.com"}, UpstreamIP: "10.0.0.2", UpstreamPort: 443,
		MTLSDenyOnMisconfig: true, MTLSCACertPEM: "-----BEGIN CERTIFICATE-----\nbad\n-----END CERTIFICATE-----\n",
	}}
	b, err := json.Marshal(BuildNodeConfig(routes, NodeSettings{ACMEEmail: "a@b.c"}))
	if err != nil {
		t.Fatalf("config must marshal: %v", err)
	}
	s := string(b)
	if contains(s, `"handler":"reverse_proxy","upstreams":[{"dial":"10.0.0.2:443"}`) {
		t.Errorf("misconfigured mTLS route must not proxy upstream\n%s", s)
	}
	if !contains(s, `"status_code":503`) {
		t.Errorf("expected deny handler in config\n%s", s)
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// cleartextBranch walks a built route's handler chain and returns the
// force-HTTPS subroute's two branches: the one matched for protocol=http and
// the fall-through that carries the real handlers. ok=false when the route
// has no such wrapper at all.
func cleartextBranch(t *testing.T, route map[string]any) (httpBranch, rest map[string]any, ok bool) {
	t.Helper()
	handle := route["handle"].([]any)
	if len(handle) != 1 {
		return nil, nil, false
	}
	sub, _ := handle[0].(map[string]any)
	if sub["handler"] != "subroute" {
		return nil, nil, false
	}
	routes := sub["routes"].([]any)
	if len(routes) != 2 {
		return nil, nil, false
	}
	first := routes[0].(map[string]any)
	m, _ := first["match"].([]any)
	if len(m) != 1 || m[0].(map[string]any)["protocol"] != "http" {
		return nil, nil, false
	}
	return first, routes[1].(map[string]any), true
}

// TestBuildRoute_MTLSNeverProxiesPlaintext is the invariant itself, asserted
// on the emitted config rather than on a write path: srv0 also listens on
// :80, where no TLS connection policy applies, so an mTLS host whose stored
// force_https is 0 would hand its backend to anyone over plain HTTP. The
// redirect must be derived from the enforcement flag - for every shape of
// route that can carry a reverse_proxy.
func TestBuildRoute_MTLSNeverProxiesPlaintext(t *testing.T) {
	ca := testCAPEM(t)
	base := Route{
		ID: "7", Hosts: []string{"secure.example.com", "alias.example.com"},
		UpstreamIP: "10.0.0.9", UpstreamPort: 8443,
		RequireClientCert: true, MTLSCACertPEM: ca,
		ForceHTTPS: false, // the stored flag is what round 4 bypassed
	}
	maint := base
	maint.MaintenanceMode = true
	maint.MaintenanceAllow = []string{"192.0.2.0/24"} // allow-listed IPs still reach the backend
	for name, r := range map[string]Route{"proxy": base, "maintenance allow-list": maint} {
		t.Run(name, func(t *testing.T) {
			route := BuildRoute(r)
			httpBranch, rest, ok := cleartextBranch(t, route)
			if !ok {
				b, _ := json.Marshal(route)
				t.Fatalf("mTLS route is served as-is on :80 (no protocol=http redirect wrapper)\n%s", b)
			}
			hb, _ := json.Marshal(httpBranch)
			if contains(string(hb), "reverse_proxy") || !contains(string(hb), `"status_code":308`) {
				t.Errorf("cleartext branch must be a redirect, got %s", hb)
			}
			if hosts, _ := json.Marshal(httpBranch["match"]); !contains(string(hosts), `"alias.example.com"`) {
				t.Errorf("redirect must cover every hostname of the route, got %s", hosts)
			}
			rb, _ := json.Marshal(rest)
			if !contains(string(rb), `"dial":"10.0.0.9:8443"`) {
				t.Errorf("backend must still be reachable behind the redirect, got %s", rb)
			}
		})
	}
}

// A route the operator did not lock keeps honouring its own force_https.
func TestBuildRoute_ForceHTTPSStillOptionalWithoutMTLS(t *testing.T) {
	route := BuildRoute(Route{ID: "8", Hosts: []string{"open.example.com"}, UpstreamIP: "10.0.0.1", UpstreamPort: 80})
	if _, _, ok := cleartextBranch(t, route); ok {
		t.Error("a plain route must not gain a forced redirect")
	}
}

// Connection policies match on SNI while routes match on Host, so a client
// can handshake under an unprotected SNI and name the mTLS host in the Host
// header. Caddy closes that by default whenever client auth is configured;
// the config pins it so the guarantee is ours, not a default's.
func TestBuildNodeConfig_MTLSPinsStrictSNIHost(t *testing.T) {
	srv := func(routes []Route) map[string]any {
		cfg := BuildNodeConfig(routes, NodeSettings{ACMEEmail: "a@b.c"})
		return cfg["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)["srv0"].(map[string]any)
	}
	locked := srv([]Route{{
		ID: "1", Hosts: []string{"m.example.com"}, UpstreamIP: "10.0.0.1", UpstreamPort: 443,
		RequireClientCert: true, MTLSCACertPEM: testCAPEM(t),
	}})
	if locked["strict_sni_host"] != true {
		t.Error("node with an mTLS host must set strict_sni_host")
	}
	// PQ-only alone is a policy without client auth: no Host/SNI binding needed,
	// and existing nodes must keep byte-identical JSON.
	pq := srv([]Route{{ID: "2", Hosts: []string{"pq.example.com"}, UpstreamIP: "10.0.0.1", UpstreamPort: 443, TLSPQOnly: true}})
	if _, has := pq["strict_sni_host"]; has {
		t.Error("strict_sni_host must only appear alongside client authentication")
	}
}
