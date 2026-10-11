package routes

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Moving a node's admin endpoint is per node: a fleet-wide flip would push
// every node onto a bind its agent may not be able to reach yet.
func TestAdminListenFor(t *testing.T) {
	const sock = "unix//sockets/caddy-admin.sock|0666"
	cases := []struct {
		listen, nodes string
		nodeID        int64
		want          string
	}{
		{"", "", 1, ""},            // untouched deployment
		{sock, "", 7, sock},        // no allow-list: fleet-wide, as before
		{sock, "2,7 , 9", 7, sock}, // listed node migrates
		{sock, "2,9", 7, ""},       // unlisted node keeps the default bind
		{sock, "  ", 7, sock},      // blank list is not a list
		{sock, "70", 7, ""},        // no prefix match
	}
	for _, c := range cases {
		s := &Service{CaddyAdminListen: c.listen, CaddyAdminListenNodes: c.nodes}
		if got := s.adminListenFor(c.nodeID); got != c.want {
			t.Errorf("adminListenFor(%d) with nodes=%q = %q, want %q", c.nodeID, c.nodes, got, c.want)
		}
	}
}

// Decommission cleanup must keep the node's admin bind, not reset it to TCP.
func TestClearNodeKeepsAdminListen(t *testing.T) {
	const sock = "unix//sockets/caddy-admin.sock|0666"
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&body)
	}))
	defer srv.Close()
	s := &Service{CaddyAdminListen: sock}
	if err := s.ClearNode(context.Background(), 7, srv.URL); err != nil {
		t.Fatalf("ClearNode: %v", err)
	}
	admin, _ := body["admin"].(map[string]any)
	if admin["listen"] != sock || body["apps"] != nil {
		t.Fatalf("cleanup config = %v, want only admin.listen=%s", body, sock)
	}
}
