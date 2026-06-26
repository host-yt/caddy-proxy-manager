package geoip

import "testing"

func TestNormalizeCountries(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"valid", "PL,DE,US", "DE,PL,US"},
		{"lowercase", "pl,de", "DE,PL"},
		{"junk dropped", "PL,XYZ,1,D,USA,US", "PL,US"},
		{"dupes", "PL,pl,PL,DE", "DE,PL"},
		{"spaces and mixed seps", "  pl ; de , US ", "DE,PL,US"},
		{"only junk", "123,!!,usa", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := NormalizeCountries(c.in); got != c.want {
				t.Errorf("NormalizeCountries(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}
