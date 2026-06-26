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

func TestBuildMTLSConnPolicies_Shape(t *testing.T) {
	caPEM := testCAPEM(t)
	routes := []Route{{
		ID:                "7",
		Hosts:             []string{"secure.example.com"},
		UpstreamIP:        "10.0.0.9",
		UpstreamPort:      8443,
		RequireClientCert: true,
		MTLSCACertPEM:     caPEM,
	}}
	pols := buildMTLSConnPolicies(routes)
	if len(pols) != 1 {
		t.Fatalf("want 1 policy, got %d", len(pols))
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

func TestBuildMTLSConnPolicies_SkippedWhenNoCAOrFlag(t *testing.T) {
	// flag on but no PEM -> fail open, no policy emitted.
	if got := buildMTLSConnPolicies([]Route{{Hosts: []string{"h"}, RequireClientCert: true}}); got != nil {
		t.Errorf("expected nil policies with empty CA PEM, got %v", got)
	}
	// PEM present but flag off -> no policy.
	if got := buildMTLSConnPolicies([]Route{{Hosts: []string{"h"}, MTLSCACertPEM: testCAPEM(t)}}); got != nil {
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
