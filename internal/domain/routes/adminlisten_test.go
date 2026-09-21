package routes

import "testing"

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
