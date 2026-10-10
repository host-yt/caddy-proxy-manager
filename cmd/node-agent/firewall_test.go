package main

import (
	"strings"
	"testing"
)

// Peers may only answer node-initiated flows: no rule may accept a new flow
// entering from the tunnel, and both hooks must end tunnel ingress in a drop.
func TestTunnelFirewallBlocksPeerInitiatedFlows(t *testing.T) {
	script := tunnelNftScript("hpg_tunnel", "wg-tun0", "51821")
	for _, line := range strings.Split(script, "\n") {
		if strings.Contains(line, `iifname "wg-tun0"`) && strings.Contains(line, "accept") &&
			!strings.Contains(line, "established,related") && !strings.Contains(line, "echo-request") {
			t.Errorf("tunnel ingress accepted without conntrack state: %s", line)
		}
	}
	for _, want := range []string{
		`forward iifname "wg-tun0" drop`,
		`input iifname "wg-tun0" drop`,
	} {
		if !strings.Contains(script, want) {
			t.Errorf("missing %q", want)
		}
	}
	for _, r := range dockerUserTunnelRules("wg-tun0") {
		joined := strings.Join(r, " ")
		if strings.Contains(joined, "-i wg-tun0") && !strings.Contains(joined, "RELATED,ESTABLISHED") {
			t.Errorf("DOCKER-USER admits new tunnel flows: %s", joined)
		}
	}
}
