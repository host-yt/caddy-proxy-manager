package handlers

import "testing"

// Enabling inbound PROXY without a trusted balancer would trust every client.
func TestParseProxyProtoTrusted(t *testing.T) {
	if _, err := parseProxyProtoTrusted("v2", ""); err == nil {
		t.Error("PROXY in without trusted CIDRs must be rejected")
	}
	if _, err := parseProxyProtoTrusted("v1", "not-a-cidr"); err == nil {
		t.Error("invalid CIDR must be rejected")
	}
	if got, err := parseProxyProtoTrusted("v1", "192.0.2.10/32\n198.51.100.0/24"); err != nil || len(got) != 2 {
		t.Errorf("valid list rejected: %v %v", got, err)
	}
	if _, err := parseProxyProtoTrusted("none", ""); err != nil {
		t.Errorf("PROXY off needs no trusted list: %v", err)
	}
}
