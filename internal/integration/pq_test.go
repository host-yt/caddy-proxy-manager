//go:build integration

package integration

import (
	"crypto/tls"
	"net"
	"os"
	"testing"
	"time"
)

// TestEdgePQHandshake probes a live edge (the merged Caddy image at release
// time, or any node) for two properties:
//
//  1. a stock Go client negotiates the hybrid post-quantum key exchange
//     X25519MLKEM768 — this is Caddy's default curve list, so a regression
//     here means someone pinned `curves` or set a GODEBUG kill switch;
//  2. a classical X25519-only client still completes the handshake — the
//     edge must not become PQ-only by accident (that is opt-in per host).
//
// Gated on HPG_TEST_EDGE_ADDR (host:port) + HPG_TEST_EDGE_SNI.
func TestEdgePQHandshake(t *testing.T) {
	addr := os.Getenv("HPG_TEST_EDGE_ADDR")
	sni := os.Getenv("HPG_TEST_EDGE_SNI")
	if addr == "" || sni == "" {
		t.Skip("set HPG_TEST_EDGE_ADDR (host:port) and HPG_TEST_EDGE_SNI to run the edge handshake probe")
	}

	dial := func(t *testing.T, curves []tls.CurveID) tls.ConnectionState {
		t.Helper()
		conn, err := tls.DialWithDialer(
			&net.Dialer{Timeout: 10 * time.Second},
			"tcp", addr,
			&tls.Config{
				ServerName: sni,
				// `tls internal` serves a local-CA cert; this test asserts on
				// the negotiated key exchange, not on the chain.
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS12,
				CurvePreferences:   curves,
			})
		if err != nil {
			t.Fatalf("tls dial %s (sni %s): %v", addr, sni, err)
		}
		defer conn.Close()
		return conn.ConnectionState()
	}

	t.Run("hybrid_mlkem", func(t *testing.T) {
		st := dial(t, nil) // Go defaults put X25519MLKEM768 first.
		if st.Version != tls.VersionTLS13 {
			t.Fatalf("negotiated TLS 0x%04x, want TLS 1.3", st.Version)
		}
		if st.CurveID != tls.X25519MLKEM768 {
			t.Fatalf("negotiated key exchange %v, want X25519MLKEM768 (edge lost post-quantum support)", st.CurveID)
		}
	})

	t.Run("classical_still_accepted", func(t *testing.T) {
		st := dial(t, []tls.CurveID{tls.X25519})
		if st.CurveID != tls.X25519 {
			t.Fatalf("negotiated key exchange %v, want X25519", st.CurveID)
		}
	})
}
