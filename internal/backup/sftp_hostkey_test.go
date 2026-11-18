package backup

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func testSigner(t *testing.T, kind string) ssh.Signer {
	t.Helper()
	var key any
	var err error
	switch kind {
	case "ed25519":
		_, key, err = ed25519.GenerateKey(rand.Reader)
	case "ecdsa":
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "rsa":
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	}
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// handshake runs the destination's client config against an in-process SSH
// server that offers hostKeys, like a NAS offering ECDSA, RSA and Ed25519 at once.
func handshake(t *testing.T, d *sftpDest, hostKeys ...ssh.Signer) error {
	t.Helper()
	srvCfg := &ssh.ServerConfig{
		PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) { return nil, nil },
	}
	for _, k := range hostKeys {
		srvCfg.AddHostKey(k)
	}
	// A real TCP socket: net.Pipe is unbuffered and both SSH sides write their
	// version line first, which deadlocks.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		srvConn, err := ln.Accept()
		if err != nil {
			return
		}
		defer srvConn.Close()
		_ = srvConn.SetDeadline(time.Now().Add(10 * time.Second))
		if sc, chans, reqs, err := ssh.NewServerConn(srvConn, srvCfg); err == nil {
			go ssh.DiscardRequests(reqs)
			go func() {
				for c := range chans {
					_ = c.Reject(ssh.Prohibited, "test")
				}
			}()
			_ = sc.Close()
		}
	}()
	cliConn, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer cliConn.Close()
	_ = cliConn.SetDeadline(time.Now().Add(10 * time.Second))
	cfg, err := d.clientConfig()
	if err != nil {
		t.Fatal(err)
	}
	c, _, _, err := ssh.NewClientConn(cliConn, "nas:22", cfg)
	if err != nil {
		return d.handshakeError(err)
	}
	_ = c.Close()
	return nil
}

func pinnedDest(pinned ssh.PublicKey) *sftpDest {
	return &sftpDest{user: "backup", password: "pw", hostKey: pinned}
}

// #151: the server offers several host keys; whichever one is pinned must be
// the one negotiated and accepted.
func TestSFTPPinnedHostKeyAmongSeveral(t *testing.T) {
	ed, ec, rs := testSigner(t, "ed25519"), testSigner(t, "ecdsa"), testSigner(t, "rsa")
	for name, pin := range map[string]ssh.Signer{"ed25519": ed, "ecdsa": ec, "rsa": rs} {
		if err := handshake(t, pinnedDest(pin.PublicKey()), ec, rs, ed); err != nil {
			t.Errorf("pinned %s among ecdsa+rsa+ed25519: %v", name, err)
		}
	}
}

func TestSFTPHostKeyAlgorithms(t *testing.T) {
	rs := testSigner(t, "rsa").PublicKey()
	got := hostKeyAlgorithms(rs)
	if len(got) != 2 || got[0] != ssh.KeyAlgoRSASHA512 || got[1] != ssh.KeyAlgoRSASHA256 {
		t.Errorf("rsa pin offers %v, want SHA-2 only (no SHA-1 ssh-rsa)", got)
	}
	ed := testSigner(t, "ed25519").PublicKey()
	if got := hostKeyAlgorithms(ed); len(got) != 1 || got[0] != ssh.KeyAlgoED25519 {
		t.Errorf("ed25519 pin offers %v", got)
	}
	if hostKeyAlgorithms(nil) != nil {
		t.Error("no pin must leave the library default")
	}
}

// Same type, different key: refused, with both fingerprints in the error.
func TestSFTPHostKeyChanged(t *testing.T) {
	pinned, actual := testSigner(t, "ed25519"), testSigner(t, "ed25519")
	err := handshake(t, pinnedDest(pinned.PublicKey()), testSigner(t, "ecdsa"), actual)
	if err == nil {
		t.Fatal("a different ed25519 key was accepted")
	}
	msg := err.Error()
	if !strings.Contains(msg, "host key mismatch") ||
		!strings.Contains(msg, ssh.FingerprintSHA256(pinned.PublicKey())) ||
		!strings.Contains(msg, ssh.FingerprintSHA256(actual.PublicKey())) {
		t.Errorf("mismatch error lacks fingerprints: %s", msg)
	}
}

// Pinned type not offered at all: an explicit error, never a fallback to a
// key the server does offer.
func TestSFTPPinnedTypeNotOffered(t *testing.T) {
	err := handshake(t, pinnedDest(testSigner(t, "ed25519").PublicKey()), testSigner(t, "ecdsa"), testSigner(t, "rsa"))
	if err == nil {
		t.Fatal("connected although the server offers no ed25519 host key")
	}
	if !strings.Contains(err.Error(), "does not offer a ssh-ed25519 host key") {
		t.Errorf("unclear error: %v", err)
	}
}
