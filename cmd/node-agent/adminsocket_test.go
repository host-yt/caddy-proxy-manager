package main

import (
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The agent must follow Caddy across the admin-endpoint switch: prefer the
// socket while it is live, fall back to TCP otherwise - including when the
// socket FILE is left behind after Caddy moved the endpoint back to TCP.
func TestAdminProxyPrefersLiveSocketAndFallsBack(t *testing.T) {
	const key = "0123456789abcdef0123456789abcdef"

	tcp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("tcp"))
	}))
	defer tcp.Close()

	// Not t.TempDir(): a unix socket path is capped near 104 bytes and the
	// per-test temp dir blows past it on macOS.
	dir, err := os.MkdirTemp("/tmp", "hpgsock")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sockPath := filepath.Join(dir, "admin.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	sock := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("socket"))
	}))
	sock.Listener.Close()
	sock.Listener = ln
	sock.Start()

	cfg := adminProxyConfig{
		Listen:      "127.0.0.1:2021",
		Key:         key,
		AdminURL:    tcp.URL,
		AdminSocket: sockPath,
	}
	if err := cfg.validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	h := adminProxyHandler(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))

	get := func() string {
		r := httptest.NewRequest(http.MethodGet, "/config/", nil)
		r.Header.Set("Authorization", "Bearer "+key)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("status %d", w.Code)
		}
		return w.Body.String()
	}

	if got := get(); got != "socket" {
		t.Fatalf("with a live socket the agent used %q, want the socket", got)
	}

	// Caddy leaves the socket file behind when the endpoint moves back to TCP.
	sock.Close()
	if _, err := os.Stat(sockPath); err != nil {
		t.Skipf("socket file removed on close by this platform: %v", err)
	}
	if got := get(); got != "tcp" {
		t.Fatalf("with a stale socket file the agent used %q, want the TCP fallback", got)
	}
}

func TestAdminProxyRejectsRelativeSocket(t *testing.T) {
	cfg := adminProxyConfig{
		Listen:      "10.66.0.2:2021",
		Key:         strings.Repeat("k", 32),
		AdminURL:    "http://127.0.0.1:2019",
		AdminSocket: "admin.sock",
	}
	if err := cfg.validate(); err == nil {
		t.Fatal("a relative HPG_CADDY_ADMIN_SOCKET must be refused")
	}
	if _, err := url.Parse(cfg.AdminURL); err != nil {
		t.Fatal(err)
	}
}
