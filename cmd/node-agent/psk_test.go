package main

import (
	"io"
	"log/slog"
	"strings"
	"testing"
)

// A valid PSK/pubkey is 32 bytes base64 = 44 chars ending in '='.
const (
	testPub = "aGVsbG8gd29ybGQgaGVsbG8gd29ybGQgMTIzNDU2Nzg="
	testPSK = "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI="
)

func testLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func peerReply(pubkey, allowedIP, psk string) peerListReply {
	return peerListReply{Peers: []peerEntry{
		{Pubkey: pubkey, AllowedIP: allowedIP, Status: "active", PresharedKey: psk},
	}}
}

func TestBuildSyncconfEmitsPresharedKey(t *testing.T) {
	conf, n := buildSyncconf(testLogger(), config{ListenPort: "51821", PrivateKey: "PRIV"},
		peerReply(testPub, "100.96.0.4/32", testPSK))
	if n != 1 {
		t.Fatalf("peers = %d, want 1", n)
	}
	if !strings.Contains(conf, "PresharedKey = "+testPSK+"\n") {
		t.Fatalf("PresharedKey line missing:\n%s", conf)
	}
}

func TestBuildSyncconfOmitsPresharedKeyWhenAbsent(t *testing.T) {
	conf, n := buildSyncconf(testLogger(), config{ListenPort: "51821", PrivateKey: "PRIV"},
		peerReply(testPub, "100.96.0.4/32", ""))
	if n != 1 {
		t.Fatalf("peers = %d, want 1", n)
	}
	if strings.Contains(conf, "PresharedKey") {
		t.Fatalf("unexpected PresharedKey line:\n%s", conf)
	}
}

// One bad line makes `wg syncconf` reject the WHOLE config, so a peer with a
// malformed PSK must be dropped entirely - not emitted without the key.
func TestBuildSyncconfSkipsPeerWithBadPresharedKey(t *testing.T) {
	conf, n := buildSyncconf(testLogger(), config{ListenPort: "51821", PrivateKey: "PRIV"},
		peerReply(testPub, "100.96.0.4/32", "not-a-valid-psk"))
	if n != 0 {
		t.Fatalf("peers = %d, want 0", n)
	}
	if strings.Contains(conf, "[Peer]") {
		t.Fatalf("peer with bad PSK was emitted:\n%s", conf)
	}
}
