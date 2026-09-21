package main

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/host-yt/caddy-proxy-manager/internal/config"
)

// SEC-002: doctor must refuse exactly what the push path refuses. A key that
// will not decrypt used to fall back to a direct probe, so doctor called a node
// reachable that the control plane would not talk to.
func TestDoctorNodeClientMirrorsPushRefusals(t *testing.T) {
	const remote = "http://10.66.0.2:2019" // unauthenticated admin endpoint
	cfg := &config.Config{}
	cfg.App.Secret = "" // no secret available here

	cases := []struct {
		name        string
		apiURL      string
		keyEnc      sql.NullString
		allowPlain  bool
		wantBlocked bool
	}{
		{"remote, no key, not opted in", remote, sql.NullString{}, false, true},
		{"remote, no key, legacy allowance", remote, sql.NullString{}, true, false},
		{"compose bridge, no key", "http://caddy:2019", sql.NullString{}, false, false},
		{"remote, key present but undecryptable", remote, sql.NullString{String: "v2:bogus", Valid: true}, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := doctorNodeClient(tc.apiURL, tc.keyEnc, tc.allowPlain, cfg)
			// A blocked client must refuse locally, so it cannot need the
			// deadline; an allowed one is expected to spend it on the dial.
			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			defer cancel()
			start := time.Now()
			_, err := c.GetRaw(ctx, "/config/")
			if tc.wantBlocked {
				if err == nil {
					t.Fatal("expected the probe to be refused")
				}
				if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
					t.Errorf("refusal took %s: it should never reach the network", elapsed)
				}
			}
		})
	}
}
