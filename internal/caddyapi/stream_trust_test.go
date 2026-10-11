package caddyapi

import (
	"encoding/json"
	"strings"
	"testing"
)

// A PROXY header is a client-supplied claim: only trusted balancers may reach
// the decoder, and PROXY-in without a trusted list must close everything (#56).
func TestBuildLayer4ProxyProtoInTrustedGate(t *testing.T) {
	r := StreamRoute{ID: 1, Protocol: "tcp", ListenPort: 7000, UpstreamIP: "10.0.0.1", UpstreamPort: 7000,
		ProxyProtoIn: "v1", ProxyProtoTrusted: []string{"192.0.2.10/32"}, CIDRAllow: []string{"198.51.100.0/24"}}
	b, _ := json.Marshal(buildL4Server("tcp", r))
	s := string(b)
	gate := `{"handle":[{"handler":"close"}],"match":[{"not":[{"remote_ip":{"ranges":["192.0.2.10/32"]}}]}]}`
	if i, j := strings.Index(s, gate), strings.Index(s, `"handler":"proxy_protocol"`); i == -1 || j == -1 || i > j {
		t.Errorf("untrusted peers must be closed before the PROXY decoder\nfull: %s", s)
	}
	if !strings.Contains(s, `"allow":["192.0.2.10/32"]`) {
		t.Errorf("decoder must carry the trusted allow list\nfull: %s", s)
	}

	r.ProxyProtoTrusted = nil
	b, _ = json.Marshal(buildL4Server("tcp", r))
	if s := string(b); s != `{"listen":["tcp/:7000"],"routes":[{"handle":[{"handler":"close"}]}]}` {
		t.Errorf("PROXY-in without trusted senders must fail closed\nfull: %s", s)
	}
}
