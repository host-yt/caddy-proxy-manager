package backup

import (
	"os"
	"testing"
)

// insecureTransportAllowed must deny (return false) unless APP_ENV is
// explicitly set to something other than "production" - unset/empty must
// behave exactly like the production default (DB-02/DB-03).
func TestInsecureTransportAllowed(t *testing.T) {
	orig, had := os.LookupEnv("APP_ENV")
	t.Cleanup(func() {
		if had {
			os.Setenv("APP_ENV", orig)
		} else {
			os.Unsetenv("APP_ENV")
		}
	})

	cases := []struct {
		name  string
		env   string
		unset bool
		want  bool
	}{
		{name: "unset", unset: true, want: false},
		{name: "empty", env: "", want: false},
		{name: "production", env: "production", want: false},
		{name: "development", env: "development", want: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.unset {
				os.Unsetenv("APP_ENV")
			} else {
				os.Setenv("APP_ENV", c.env)
			}
			if got := insecureTransportAllowed(); got != c.want {
				t.Errorf("APP_ENV=%q (unset=%v): got %v, want %v", c.env, c.unset, got, c.want)
			}
		})
	}
}
