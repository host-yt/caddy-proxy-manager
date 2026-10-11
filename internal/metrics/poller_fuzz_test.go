package metrics

import "testing"

func FuzzSplitMetric(f *testing.F) {
	for _, s := range []string{
		`caddy_http_requests_total{handler="x",code="200"} 12`,
		`up 1`, `m{a="b c"} 1.5 1700000000`, `m{a="\"}"} 3`, `}{`, `{`, ``, `m 1 2 3`, `m{} NaN`, "m\t1",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, line string) {
		name, _, _, ok := splitMetric(line)
		if ok && name != "" && (name[0] == ' ' || name[len(name)-1] == ' ') {
			t.Fatalf("untrimmed name %q", name)
		}
	})
}
