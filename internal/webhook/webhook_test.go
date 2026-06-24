package webhook

import "testing"

func TestEventMatches(t *testing.T) {
	cases := []struct {
		filter, evt string
		want        bool
	}{
		{"*", "anything", true},
		{"route.created", "route.created", true},
		{"route.created", "route.failed", false},
		{"route.*", "route.created", true},
		{"route.*", "node.created", false},
		{"route.created,node.*", "node.joined", true},
		{"", "x", false},
		{"  route.* ,  *", "x", true},
	}
	for _, c := range cases {
		got := eventMatches(c.evt, c.filter)
		if got != c.want {
			t.Errorf("eventMatches(%q, %q) = %v, want %v", c.evt, c.filter, got, c.want)
		}
	}
}
