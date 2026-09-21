package caddyapi

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// The panel must reach a node whose admin endpoint is a filesystem socket
// exactly as it reaches a TCP one - same Client, same paths.
func TestClientOverUnixSocket(t *testing.T) {
	// Not t.TempDir(): a unix socket path is capped near 104 bytes and the
	// per-test temp dir blows past it on macOS.
	dir, err := os.MkdirTemp("/tmp", "hpgsock")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "admin.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/config/admin/listen" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(`"unix/` + sock + `"`))
	}))
	srv.Listener.Close()
	srv.Listener = ln
	srv.Start()
	defer srv.Close()

	c := New("unix://" + sock)
	got, err := c.GetRaw(context.Background(), "/config/admin/listen")
	if err != nil {
		t.Fatalf("GetRaw over socket: %v", err)
	}
	if string(got) != `"unix/`+sock+`"` {
		t.Fatalf("unexpected body %q", got)
	}
}

func TestAdminSocketPath(t *testing.T) {
	for in, want := range map[string]string{
		"unix:///sockets/a.sock": "/sockets/a.sock",
		"unix:/sockets/a.sock":   "/sockets/a.sock",
		"http://caddy:2019":      "",
		"":                       "",
	} {
		if got := AdminSocketPath(in); got != want {
			t.Errorf("AdminSocketPath(%q) = %q, want %q", in, got, want)
		}
	}
}
