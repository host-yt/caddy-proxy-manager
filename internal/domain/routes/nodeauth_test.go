package routes

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// seedAuthNode inserts one node with the given admin-proxy ciphertext and
// legacy allowance, and returns a Service wired to that DB.
func seedAuthNode(t *testing.T, apiURL, keyEnc string, allowPlain bool, decrypt func(string) (string, error)) *Service {
	t.Helper()
	db := newPushTestDB(t)
	var enc any
	if keyEnc != "" {
		enc = keyEnc
	}
	allow := 0
	if allowPlain {
		allow = 1
	}
	if _, err := db.Exec(`INSERT INTO node_groups (id, name, mode) VALUES (1, 'default', 'single')`); err != nil {
		t.Fatalf("seed group: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO caddy_nodes (id, name, api_url, public_hostname, node_group_id,
	        max_routes, current_routes, is_enabled, health_status, admin_proxy_key_enc, allow_unauthenticated_admin)
	      VALUES (1, 'edge1', ?, 'edge1.example', 1, 100, 0, 1, 'up', ?, ?)`, apiURL, enc, allow); err != nil {
		t.Fatalf("seed node: %v", err)
	}
	return &Service{DB: db, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), DecryptNodeSecret: decrypt}
}

// tryLoad pushes an empty config with a short deadline, so a client that is
// allowed to reach the network fails on the dial instead of blocking the test.
func tryLoad(t *testing.T, s *Service, apiURL string) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	return s.NodeClient(ctx, 1, apiURL).Load(ctx, map[string]any{})
}

// blockedByGuard reports whether the fail-closed transport guard refused the
// call, as opposed to the node simply not answering.
func blockedByGuard(err error) bool {
	return err != nil && (strings.Contains(err.Error(), "admin-proxy key") ||
		strings.Contains(err.Error(), "transport unavailable"))
}

// HPG-SEC-002: a key that will not decrypt used to be treated as "no key", so
// the panel silently pushed to the node over an unauthenticated connection.
func TestNodeClient_DecryptFailureNeverDegradesToUnauthenticated(t *testing.T) {
	boom := errors.New("wrong APP_SECRET")
	s := seedAuthNode(t, "http://10.66.0.2:2021", "v2:nodeadmin:garbage", false,
		func(string) (string, error) { return "", boom })

	err := tryLoad(t, s, "http://10.66.0.2:2021")
	if err == nil {
		t.Fatal("a push must fail when the node's admin key cannot be decrypted")
	}
	if !errors.Is(err, boom) {
		t.Fatalf("the decrypt failure must be the reported cause, got %v", err)
	}
}

// A remote node with no key at all must not get an unauthenticated control
// plane just because nobody has migrated it yet.
func TestNodeClient_RemoteNodeWithoutKeyIsBlocked(t *testing.T) {
	s := seedAuthNode(t, "http://10.66.0.2:2019", "", false, nil)
	if err := tryLoad(t, s, "http://10.66.0.2:2019"); !blockedByGuard(err) {
		t.Fatalf("an unauthenticated remote admin endpoint must not be pushed to, got %v", err)
	}
}

// The escape hatch is per-node and explicit, and a node-local endpoint (the
// manager's own bundled Caddy) never needed one.
func TestNodeClient_LegacyPathIsPerNode(t *testing.T) {
	s := seedAuthNode(t, "http://10.66.0.2:2019", "", true, nil)
	if err := tryLoad(t, s, "http://10.66.0.2:2019"); blockedByGuard(err) {
		t.Fatalf("the per-node allowance must let the push reach the network, got %v", err)
	}
	local := seedAuthNode(t, "http://caddy:2019", "", false, nil)
	if err := tryLoad(t, local, "http://caddy:2019"); blockedByGuard(err) {
		t.Fatalf("the manager's own compose-local Caddy must not be blocked, got %v", err)
	}
}

// A key that decrypts clears the legacy allowance: keeping it would leave a
// silent downgrade waiting for the next crypto failure.
func TestNodeClient_SuccessfulKeyClearsLegacyAllowance(t *testing.T) {
	s := seedAuthNode(t, "http://10.66.0.2:2021", "enc", true,
		func(string) (string, error) { return "a-real-admin-proxy-key-32-chars-ok", nil })
	if _, allow, err := s.nodeAdminAuth(context.Background(), 1); err != nil || allow {
		t.Fatalf("nodeAdminAuth = allow %v, err %v; want an authenticated node", allow, err)
	}
	var allow bool
	if err := s.DB.QueryRow("SELECT allow_unauthenticated_admin FROM caddy_nodes WHERE id = 1").Scan(&allow); err != nil {
		t.Fatalf("read node: %v", err)
	}
	if allow {
		t.Error("the legacy allowance must be cleared once the node authenticates")
	}
}
