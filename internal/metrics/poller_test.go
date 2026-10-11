package metrics

import "testing"

func TestSplitMetric(t *testing.T) {
	cases := []struct {
		line string
		name string
		host string
		val  float64
	}{
		{`caddy_http_requests_total 42`, "caddy_http_requests_total", "", 42},
		{`caddy_http_requests_total 42 1710000000000`, "caddy_http_requests_total", "", 42},
		{`caddy_http_requests_total{server_name="a b"} 7 1710000000000`, "caddy_http_requests_total", "a b", 7},
		{`caddy_http_requests_total{server_name="x"} 3`, "caddy_http_requests_total", "x", 3},
	}
	for _, c := range cases {
		name, labels, val, ok := splitMetric(c.line)
		if !ok || name != c.name || val != c.val || labels["server_name"] != c.host {
			t.Errorf("%q -> %q %v %v %v", c.line, name, labels, val, ok)
		}
	}
	if _, _, _, ok := splitMetric("lonely"); ok {
		t.Error("value-less line accepted")
	}
}
