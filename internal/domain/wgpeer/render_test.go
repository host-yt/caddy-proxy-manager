package wgpeer

import (
	"strings"
	"testing"
)

// GH issue #5: HA nodes sharing a tunnel subnet can allocate the same
// customer IP; a repeated Address entry makes wg-quick die with
// "Error: ipv4: Address already assigned".
func TestRenderConfigDedupesAddresses(t *testing.T) {
	r := BootstrapResult{
		ServerPrivkey:    "PRIV",
		NodeEndpoint:     "n1.example.com:51820",
		NodeTunnelPubkey: "PUB1",
		NodeTunnelSubnet: "100.96.0.0/24",
		Peer:             Peer{AssignedIP: "100.96.0.4"},
		HAPeers: []HAPeerInfo{
			{AssignedIP: "100.96.0.4", Endpoint: "n2.example.com:51820", TunnelPubkey: "PUB2", TunnelSubnet: "100.96.0.0/24"},
			{AssignedIP: "100.96.1.7", Endpoint: "n3.example.com:51820", TunnelPubkey: "PUB3", TunnelSubnet: "100.96.1.0/24"},
		},
	}
	conf := RenderConfig(r)

	var addrLine string
	for _, ln := range strings.Split(conf, "\n") {
		if strings.HasPrefix(ln, "Address = ") {
			addrLine = ln
			break
		}
	}
	if addrLine == "" {
		t.Fatalf("no Address line in:\n%s", conf)
	}
	if got := strings.Count(addrLine, "100.96.0.4/32"); got != 1 {
		t.Fatalf("want 100.96.0.4/32 exactly once, got %d: %q", got, addrLine)
	}
	if !strings.Contains(addrLine, "100.96.1.7/32") {
		t.Fatalf("distinct HA IP missing: %q", addrLine)
	}
	// All three nodes still get their [Peer] block (distinct pubkeys).
	if got := strings.Count(conf, "[Peer]"); got != 3 {
		t.Fatalf("want 3 peer blocks, got %d:\n%s", got, conf)
	}
}

// Fully-identical peers (same pubkey + endpoint) collapse to one block.
func TestRenderConfigDedupesIdenticalPeers(t *testing.T) {
	r := BootstrapResult{
		ServerPrivkey:    "PRIV",
		NodeEndpoint:     "n1.example.com:51820",
		NodeTunnelPubkey: "PUB1",
		NodeTunnelSubnet: "100.96.0.0/24",
		Peer:             Peer{AssignedIP: "100.96.0.4"},
		HAPeers: []HAPeerInfo{
			{AssignedIP: "100.96.0.4", Endpoint: "n1.example.com:51820", TunnelPubkey: "PUB1", TunnelSubnet: "100.96.0.0/24"},
		},
	}
	conf := RenderConfig(r)
	if got := strings.Count(conf, "[Peer]"); got != 1 {
		t.Fatalf("want 1 peer block, got %d:\n%s", got, conf)
	}
}

// Every [Peer] carries its own PresharedKey; a peer without one stays classic.
func TestRenderConfigEmitsPerPeerPresharedKey(t *testing.T) {
	r := BootstrapResult{
		ServerPrivkey:    "PRIV",
		NodeEndpoint:     "n1.example.com:51820",
		NodeTunnelPubkey: "PUB1",
		NodeTunnelSubnet: "100.96.0.0/24",
		PresharedKey:     "PSK1",
		Peer:             Peer{AssignedIP: "100.96.0.4"},
		HAPeers: []HAPeerInfo{
			{AssignedIP: "100.96.1.7", Endpoint: "n2.example.com:51820", TunnelPubkey: "PUB2", TunnelSubnet: "100.96.1.0/24", PresharedKey: "PSK2"},
			{AssignedIP: "100.96.2.9", Endpoint: "n3.example.com:51820", TunnelPubkey: "PUB3", TunnelSubnet: "100.96.2.0/24"},
		},
	}
	conf := RenderConfig(r)
	if got := strings.Count(conf, "PresharedKey = "); got != 2 {
		t.Fatalf("want 2 PresharedKey lines, got %d:\n%s", got, conf)
	}
	for _, want := range []string{"PublicKey = PUB1\nPresharedKey = PSK1\n", "PublicKey = PUB2\nPresharedKey = PSK2\n"} {
		if !strings.Contains(conf, want) {
			t.Fatalf("missing %q in:\n%s", want, conf)
		}
	}
	// The PSK-less node must not inherit a sibling's key.
	if !strings.Contains(conf, "PublicKey = PUB3\nEndpoint = ") {
		t.Fatalf("classic peer got a PresharedKey line:\n%s", conf)
	}
}
