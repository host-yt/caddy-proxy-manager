package main

import (
	"context"
	"io"
	"log/slog"
	"os"
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

// fakeWG puts a stub `wg` first on PATH: `wg show <if> dump` prints the given
// dump, everything else is appended to a log file. Returns that log's path.
func fakeWG(t *testing.T, dump string) string {
	t.Helper()
	dir := t.TempDir()
	logPath := dir + "/calls.log"
	dumpPath := dir + "/dump.txt"
	if err := os.WriteFile(dumpPath, []byte(dump), 0o600); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\nif [ \"$1\" = show ]; then cat " + dumpPath + "; exit 0; fi\necho \"$@\" >> " + logPath + "\n"
	if err := os.WriteFile(dir+"/wg", []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return logPath
}

func wgCalls(t *testing.T, logPath string) string {
	t.Helper()
	b, err := os.ReadFile(logPath)
	if err != nil {
		return ""
	}
	return string(b)
}

// One dump line per peer, in `wg show <if> dump` field order.
func dumpLine(pubkey, psk string) string {
	return pubkey + "\t" + psk + "\t1.2.3.4:51820\t100.96.0.4/32\t1700000000\t100\t200\t25\n"
}

const otherPub = "b3RoZXIgcGVlciBvdGhlciBwZWVyIDEyMzQ1Njc4OTA="

// The panel said it is managing keys, so a peer it listed without one really
// did lose it and the live key has to go - `wg syncconf` cannot remove it.
func TestClearDroppedPSKsClearsWhenPanelManagesKeys(t *testing.T) {
	dump := "IFACE\tPRIV\t51821\toff\n" + dumpLine(testPub, testPSK) + dumpLine(otherPub, testPSK)
	calls := fakeWG(t, dump)
	reply := peerReply(testPub, "100.96.0.4/32", testPSK)
	reply.Peers = append(reply.Peers, peerEntry{Pubkey: otherPub, AllowedIP: "100.96.0.5/32", Status: "active"})
	reply.PSKManaged = true

	clearDroppedPSKs(context.Background(), testLogger(), config{Interface: "wg-tun0"}, reply)

	got := wgCalls(t, calls)
	if !strings.Contains(got, "peer "+otherPub+" preshared-key") {
		t.Errorf("the peer whose PSK the panel dropped was not cleared: %q", got)
	}
	if strings.Contains(got, testPub) {
		t.Errorf("cleared the PSK of a peer that still has one: %q", got)
	}
}

// Without psk_managed an omitted preshared_key carries no intent: the panel
// may simply not have known this agent applies keys (a rollback then upgrade
// leaves the stored flag at 0). Clearing here wipes every tunnel on the node.
func TestClearDroppedPSKsKeepsKeysWhenPanelSaysNothing(t *testing.T) {
	dump := "IFACE\tPRIV\t51821\toff\n" + dumpLine(testPub, testPSK) + dumpLine(otherPub, testPSK)
	calls := fakeWG(t, dump)
	reply := peerReply(testPub, "100.96.0.4/32", "")
	reply.Peers = append(reply.Peers, peerEntry{Pubkey: otherPub, AllowedIP: "100.96.0.5/32", Status: "active"})

	clearDroppedPSKs(context.Background(), testLogger(), config{Interface: "wg-tun0"}, reply)

	if got := wgCalls(t, calls); got != "" {
		t.Errorf("wiped live preshared keys the panel never asked to drop: %q", got)
	}
}
