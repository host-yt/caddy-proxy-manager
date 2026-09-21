package caddyapi

import (
	"encoding/json"
	"strings"
	"testing"
)

// Fail-open must still verify a certificate that is presented. Caddy's
// "request" mode accepts any certificate unverified, and its subject is what
// reaches RBAC and the upstream as X-Mtls-Subject - so that mode turned the
// toggle into "anyone may claim any identity".
func TestBuildConnPolicies_FailOpenStillVerifies(t *testing.T) {
	caPEM := testCAPEM(t)
	routes := []Route{{
		ID:                "7",
		Hosts:             []string{"secure.example.com"},
		UpstreamIP:        "10.0.0.9",
		UpstreamPort:      8443,
		RequireClientCert: true,
		MTLSCACertPEM:     caPEM,
	}}
	b, _ := json.Marshal(buildConnPolicies(routes, true, true))
	s := string(b)
	if !strings.Contains(s, `"mode":"verify_if_given"`) {
		t.Errorf("fail-open must use verify_if_given, got: %s", s)
	}
	if strings.Contains(s, `"mode":"request"`) {
		t.Errorf(`"request" accepts an unverified certificate: %s`, s)
	}
	if !strings.Contains(s, `"trusted_ca_certs"`) {
		t.Errorf("fail-open policy must still carry the trust anchor: %s", s)
	}
}

// A client must not be able to supply X-Mtls-Subject itself: it is the channel
// a verified subject travels on, to RBAC and to the upstream.
func TestBuildRoute_StripsInboundMTLSSubject(t *testing.T) {
	for _, r := range []Route{
		{ID: "1", Hosts: []string{"plain.example.com"}, UpstreamIP: "10.0.0.1", UpstreamPort: 80},
		{ID: "2", Hosts: []string{"secure.example.com"}, UpstreamIP: "10.0.0.2", UpstreamPort: 443,
			RequireClientCert: true, MTLSCACertPEM: testCAPEM(t)},
	} {
		b, err := json.Marshal(BuildRoute(r))
		if err != nil {
			t.Fatalf("route %s: %v", r.ID, err)
		}
		const want = `{"handler":"headers","request":{"delete":["X-Mtls-Subject"]}}`
		if !strings.Contains(string(b), want) {
			t.Errorf("route %s does not strip the inbound header: %s", r.ID, b)
		}
	}
}
